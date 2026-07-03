"""Consolidated active-eval report across all completed OWASP verticals (OPERATOR CLI).

Drives each shipped corpus through the live gateway, computes the vertical's
indicator(s) + (for LLM01) the per-attack_class attribution, and writes ONE markdown
report under `reports/`.

SECURITY: the report contains a live per-case attribution — a bypass map for the
DEPLOYED gateway. `reports/` is gitignored; the rendered report is INTERNAL to Platform
and must NOT be committed to this (public) repo. This tool is generic measurement code
(safe to commit); only its OUTPUT against a live run is sensitive.

Usage (same env as the integration test):
  TREVAL_EVAL_GATEWAY_URL=http://127.0.0.1:8080 TREVAL_EVAL_WAL_DIR=/home/olvan/wal \\
  TREVAL_EVAL_TENANT=__eval__ TREVAL_EVAL_USER=jack TREVAL_EVAL_TIMEOUT=120 \\
  TREVAL_EVAL_CONTENT_BUDGET=2000 TREVAL_EVAL_LLM10_TIMEOUT=60 \\
  TREVAL_EVAL_GOVERNANCE_TIMEOUT=20 \\
    python tools/eval_report.py            # → reports/eval_report.md
  python tools/eval_report.py --out reports/run2.md
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from treval.active_eval import (
    BenignFlagRate,
    BenignShadowFlagRate,
    CorpusIndicator,
    CostRunawayCaught,
    FalsePositiveRate,
    GatewayTarget,
    InjectionCatchRate,
    InjectionSuccessRate,
    SensitiveDisclosureRate,
    SystemPromptLeakRate,
    Tier2ShadowRecallLift,
    ToolScopeViolationRate,
    UnsafeOutputPassthroughRate,
    WireIndirectCatchRate,
    WithinCostBudget,
    attack_class_breakdown,
    format_attribution_report,
    load_corpus,
    run_corpus,
)

_ROOT = Path(__file__).resolve().parents[1]
_CORPUS = _ROOT / "corpus"

# LLM10 per-call CONTENT-token budget (EV-AE5.3) — the attacker-driven visible-output
# ceiling (completion − reasoning), NOT total; a POLICY threshold, configurable.
_CONTENT_BUDGET = int(os.environ.get("TREVAL_EVAL_CONTENT_BUDGET", "2000"))

# Per-vertical probe timeout. LLM10 runaway cases deliberately make the model generate a lot,
# so a tighter LLM10 timeout keeps the run from stalling — but on a REASONING model even a
# self-bounded answer is slow (reasoning latency), so too tight a value times out legitimate
# within-budget responses and mislabels them as runaways (EV-AE5.1 counts a timeout over-budget).
# 60s is the compromise (2× faster than the default on the timeout tail, without false timeouts);
# tune via TREVAL_EVAL_LLM10_TIMEOUT. within_cost_budget on a reasoning model is inherently noisy
# here — a timeout conflates a content runaway with slow reasoning.
_DEFAULT_TIMEOUT = float(os.environ.get("TREVAL_EVAL_TIMEOUT", "120"))
_LLM10_TIMEOUT = float(os.environ.get("TREVAL_EVAL_LLM10_TIMEOUT", "60"))
_SLOW_VERTICALS = {"llm10_unbounded_consumption"}

# EV-AE12: the LLM01 verticals whose ProbeResults must be joined with the ASYNC governance
# record (record_type=3, the Tier-2 shadow judge written ~2s post-probe). After the run we
# drain_governance() these so the Tier-2 recall-lift / benign-shadow-flag lines can attribute
# the async hint — a synchronous read never sees it. Other verticals don't touch the injection
# judge, so they skip the drain (and its poll wait).
_TIER2_VERTICALS = {
    "llm01_prompt_injection",
    "llm01_wire_indirect",
    "llm01_benign",
    "llm01_indirect_benign",
}
# Max seconds to poll the WAL for the async Tier-2 records to drain after a run (they land
# ~2s post-probe). Assumes a record_type=3 per request_id (Platform's "poll until they land"
# framing); if the judge writes one only on a hint, below-τ probes never get one and the drain
# waits out this timeout each run (harmless — the counts are still correct). Tune per latency.
_GOVERNANCE_DRAIN_TIMEOUT = float(
    os.environ.get("TREVAL_EVAL_GOVERNANCE_TIMEOUT", "20")
)

# Benign FPR severity split (EV-AE10): FPR gates on hard-block; flag rate is advisory.
_SEVERITY_TAG = {
    "false_positive_rate": " [GATED]",
    "benign_flag_rate": " [ADVISORY]",
}

# (label, corpus subdir, indicators, render full LLM01 attribution block)
_VERTICALS: list[tuple[str, str, list[CorpusIndicator], bool]] = [
    (
        "LLM01 prompt-injection — recall + output-success + Tier-2 shadow-recall lift",
        "llm01_prompt_injection",
        [InjectionCatchRate(), InjectionSuccessRate(), Tier2ShadowRecallLift()],
        True,
    ),
    (
        "LLM01 benign — FPR (GATED) + flag rate (ADVISORY) + Tier-2 benign shadow-flag",
        "llm01_benign",
        [FalsePositiveRate(), BenignFlagRate(), BenignShadowFlagRate()],
        False,
    ),
    # EV-AE11: wire-placed indirect — the P2-ind placement gap, its OWN metric so it does
    # not dilute injection_catch_rate. Baseline ~0 until the P2-ind trust-zone provider ships.
    (
        "LLM01 wire-indirect — placement recall (tool-role / out-of-window / nested / RAG)",
        "llm01_wire_indirect",
        [WireIndirectCatchRate(), Tier2ShadowRecallLift()],
        True,
    ),
    # EV-AE11: indirect-benign — the data-channel FPR control (injection-like text in benign
    # docs/tool-outputs). Matters once P2-ind starts scanning tool-role content.
    (
        "LLM01 indirect-benign — data-channel FPR (GATED) + flag (ADVISORY) + Tier-2 shadow-flag",
        "llm01_indirect_benign",
        [FalsePositiveRate(), BenignFlagRate(), BenignShadowFlagRate()],
        True,
    ),
    (
        "LLM02 sensitive-disclosure (+ gateway DLP-catch)",
        "llm02_sensitive_disclosure",
        [SensitiveDisclosureRate(), InjectionCatchRate()],
        False,
    ),
    (
        "LLM05 unsafe-output-passthrough (+ gateway neutralize)",
        "llm05_improper_output",
        [UnsafeOutputPassthroughRate(), InjectionCatchRate()],
        False,
    ),
    (
        "LLM06 tool-scope-violation",
        "llm06_tool_scope",
        [ToolScopeViolationRate()],
        False,
    ),
    (
        "LLM07 system-prompt-leak (+ gateway catch)",
        "llm07_system_prompt_leak",
        [SystemPromptLeakRate(), InjectionCatchRate()],
        False,
    ),
    # NOTE: LLM10 requests huge outputs — the slowest / most token-costly vertical.
    (
        "LLM10 unbounded-consumption — cost_runaway_caught (hard-block) + within_cost_budget",
        "llm10_unbounded_consumption",
        [CostRunawayCaught(), WithinCostBudget(_CONTENT_BUDGET)],
        False,
    ),
]


def _target(timeout: float) -> GatewayTarget:
    url = os.environ.get("TREVAL_EVAL_GATEWAY_URL")
    if not url:
        sys.exit(
            "set TREVAL_EVAL_GATEWAY_URL (+ TREVAL_EVAL_WAL_DIR) — see the docstring"
        )
    return GatewayTarget(
        url,
        wal_dir=os.environ.get("TREVAL_EVAL_WAL_DIR"),
        tenant_id=os.environ.get("TREVAL_EVAL_TENANT", "__eval__"),
        user_id=os.environ.get("TREVAL_EVAL_USER", "eval-user"),
        model=os.environ.get("TREVAL_EVAL_MODEL", "deepseek-v4-flash"),
        temperature=0.0,  # pin for the statistical (leak/disclosure/passthrough) verticals
        timeout=timeout,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="active-eval consolidated report")
    parser.add_argument("--out", default=str(_ROOT / "reports" / "eval_report.md"))
    args = parser.parse_args()

    model = os.environ.get("TREVAL_EVAL_MODEL", "deepseek-v4-flash")
    tenant = os.environ.get("TREVAL_EVAL_TENANT", "__eval__")

    lines = [
        "# treval active-eval report (INTERNAL — do not publish; live gateway gap map)",
        f"gateway={os.environ.get('TREVAL_EVAL_GATEWAY_URL')}  model={model}  tenant={tenant}",
        "",
    ]
    attributions: list[tuple[str, str]] = []
    for label, subdir, indicators, render_attrib in _VERTICALS:
        timeout = _LLM10_TIMEOUT if subdir in _SLOW_VERTICALS else _DEFAULT_TIMEOUT
        target = _target(timeout)
        corpus = load_corpus(_CORPUS / subdir)
        results = list(run_corpus(corpus, target))
        if subdir in _TIER2_VERTICALS:
            # EV-AE12: join the ASYNC Tier-2 governance record (record_type=3, ~2s post-probe)
            # — a synchronous read never sees the shadow-judge hint. Poll-drains once per run.
            results = target.drain_governance(
                results, timeout=_GOVERNANCE_DRAIN_TIMEOUT
            )
        errored = sum(1 for r in results if r.error)
        lines.append(f"## {label}  ({len(results)} probes, {errored} errored)")
        for ind in indicators:
            (m,) = ind.measure(results)
            tag = _SEVERITY_TAG.get(m.indicator_id, "")
            lines.append(
                f"- **{m.indicator_id} = {m.value:.0%}**{tag}  (n={m.sample_size})"
            )
            lines.append(f"  - {m.notes}")
        if render_attrib:
            for klass, (caught, total) in attack_class_breakdown(
                corpus, results
            ).items():
                lines.append(f"- caught {klass}: {caught}/{total}")
            attributions.append((label, format_attribution_report(corpus, results)))
        lines.append("")
        print(f"  {label}: done ({len(results)} probes)")

    if attributions:
        lines += [
            "---",
            "",
            "## Per-vertical catch attribution (gap map)",
            "`[CAUGHT]` = gateway reacted (blocked OR flagged). Attack verticals: recall"
            " (higher better). Benign verticals: a false-positive / flag (lower better).",
            "",
        ]
        for attrib_label, block in attributions:
            lines += [f"### {attrib_label}", "", block, ""]

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
