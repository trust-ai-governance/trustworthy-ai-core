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
  TREVAL_EVAL_TOKEN_BUDGET=4000 \\
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
    CorpusIndicator,
    CostRunawayCaught,
    FalsePositiveRate,
    GatewayTarget,
    InjectionCatchRate,
    InjectionSuccessRate,
    SensitiveDisclosureRate,
    SystemPromptLeakRate,
    ToolScopeViolationRate,
    UnsafeOutputPassthroughRate,
    WithinCostBudget,
    attack_class_breakdown,
    format_attribution_report,
    load_corpus,
    run_corpus,
)

_ROOT = Path(__file__).resolve().parents[1]
_CORPUS = _ROOT / "corpus"

# LLM10 per-call token budget (EV-AE5 D2) — a POLICY threshold, configurable.
_TOKEN_BUDGET = int(os.environ.get("TREVAL_EVAL_TOKEN_BUDGET", "4000"))

# Benign FPR severity split (EV-AE10): FPR gates on hard-block; flag rate is advisory.
_SEVERITY_TAG = {
    "false_positive_rate": " [GATED]",
    "benign_flag_rate": " [ADVISORY]",
}

# (label, corpus subdir, indicators, render full LLM01 attribution block)
_VERTICALS: list[tuple[str, str, list[CorpusIndicator], bool]] = [
    (
        "LLM01 prompt-injection — recall + output-success",
        "llm01_prompt_injection",
        [InjectionCatchRate(), InjectionSuccessRate()],
        True,
    ),
    (
        "LLM01 benign — false-positive rate (GATED hard-block) + flag rate (ADVISORY)",
        "llm01_benign",
        [FalsePositiveRate(), BenignFlagRate()],
        False,
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
        [CostRunawayCaught(), WithinCostBudget(_TOKEN_BUDGET)],
        False,
    ),
]


def _target() -> GatewayTarget:
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
        timeout=float(os.environ.get("TREVAL_EVAL_TIMEOUT", "120")),
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="active-eval consolidated report")
    parser.add_argument("--out", default=str(_ROOT / "reports" / "eval_report.md"))
    args = parser.parse_args()

    target = _target()
    model = os.environ.get("TREVAL_EVAL_MODEL", "deepseek-v4-flash")
    tenant = os.environ.get("TREVAL_EVAL_TENANT", "__eval__")

    lines = [
        "# treval active-eval report (INTERNAL — do not publish; live gateway gap map)",
        f"gateway={os.environ.get('TREVAL_EVAL_GATEWAY_URL')}  model={model}  tenant={tenant}",
        "",
    ]
    attribution = ""
    for label, subdir, indicators, render_attrib in _VERTICALS:
        corpus = load_corpus(_CORPUS / subdir)
        results = run_corpus(corpus, target)
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
            attribution = format_attribution_report(corpus, results)
        lines.append("")
        print(f"  {label}: done ({len(results)} probes)")

    if attribution:
        lines += [
            "---",
            "",
            "## LLM01 per-technique attribution (gap map)",
            "",
            attribution,
        ]

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
