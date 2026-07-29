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
  TREVAL_EVAL_TENANT=__eval__ TREVAL_EVAL_USER=<provisioned-eval-user> TREVAL_EVAL_TIMEOUT=120 \\
  TREVAL_EVAL_CONTENT_BUDGET=2000 TREVAL_EVAL_LLM10_TIMEOUT=60 \\
  TREVAL_EVAL_GOVERNANCE_TIMEOUT=20 \\
    python tools/eval_report.py            # → reports/eval_report.md
  python tools/eval_report.py --out reports/run2.md

Environment (GATE-LASTMILE P7):
  TREVAL_EVAL_GATEWAY_URL  data-plane URL (required; e.g. http://127.0.0.1:8080)
  TREVAL_EVAL_WAL_DIR      eval WAL bind-mount — REQUIRED for reproducible (WAL-anchored)
                           numbers; unset ⇒ the report declares itself non-reproducible (P3).
  TREVAL_EVAL_TENANT       eval tenant (default __eval__)
  TREVAL_EVAL_USER         🔴 use a DEDICATED, PROVISIONED eval identity (a deployment-specific id — NOT hardcoded here). An
                           unregistered user makes every probe unmeasurable — and unless the
                           P4 guard catches it, that silently reads as a fake 0% (this bit us:
                           C2-2). The default `eval-user` is often NOT provisioned.
  TREVAL_EVAL_MODEL        deployment model id (default deepseek-v4-flash)
  TREVAL_EVAL_ADMIN_URL    admin plane for the Tier-2 drain cursor. Optional: derived from the
                           gateway URL (data-plane port +1 ⇒ 8081) when unset (P5).
  TREVAL_EVAL_TIMEOUT / _LLM10_TIMEOUT / _CONTENT_BUDGET / _GOVERNANCE_TIMEOUT  tuning knobs.

🔴 A LISTENING PORT IS NOT A READY GATEWAY. The port can accept requests, and entry records
can already be in the WAL, while the governance pipeline is still loading — it then evaluates
ZERO rules and returns UNDECIDED. Confirm governance is loaded before trusting numbers; if it
was not, the P4 guard marks the affected metrics `insufficient_data` (not 0%) rather than let
a wall of zeros look authoritative.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
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
    OutputNeutralizeFidelityRate,
    OutputNeutralizeInertRate,
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
from treval.active_eval.checks import gateway_undecided
from treval.active_eval.target import ProbeResult
from treval.models import IntegrityStatus
from treval.rubric.serialize import derive_evidence_basis

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
    # EV-AE13: output-neutralize efficacy on the DECLARED HTML sink (builtin.chat) — the
    # two-sided inert ∧ fidelity gate (both τ=1.0) + the undeclared-control (control.chat)
    # passthrough baseline. render_attrib=True so A2-neutralize vs P2-out scoped-block (403)
    # vs control-verbatim is legible per case (Table-B per-source attribution, never global 0%).
    (
        "LLM05 output-neutralize — inert ∧ fidelity (declared sink) + control passthrough",
        "llm05_neutralize",
        [
            OutputNeutralizeInertRate(),
            OutputNeutralizeFidelityRate(),
            UnsafeOutputPassthroughRate(),
        ],
        True,
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


# eval_report always drives a GatewayTarget (see _target), so the report's target_kind is
# fixed here; a standalone/raw_model runtime is EV-FWD, out of scope (GATE-LASTMILE §4).
_TARGET_KIND = "gateway"


def _evidence_coverage(results: Sequence[ProbeResult]) -> tuple[int, int, int]:
    """(verified, unverified, broken) over probes that carried a WAL record (GATE-LASTMILE P6).

    Only a VERIFIED chain is replayable, so ONLY VERIFIED counts as anchored. An UNVERIFIED or
    BROKEN record is present but NOT reproducible (a broken chain is exactly what "可复算" must
    exclude) — surfaced separately, never merged into the anchored count. Mirrors the report
    schema's `integrity_summary{verified, unverified, broken}`."""
    verified = unverified = broken = 0
    for r in results:
        ev = r.evidence
        if ev is None:
            continue
        if ev.integrity == IntegrityStatus.VERIFIED:
            verified += 1
        elif ev.integrity == IntegrityStatus.BROKEN:
            broken += 1
        else:
            unverified += 1
    return verified, unverified, broken


def _wal_anchored_count(results: Sequence[ProbeResult]) -> int:
    """VERIFIED-chain WAL records — the replayable ones (GATE-LASTMILE P6). A run with
    TREVAL_EVAL_WAL_DIR unset yields 0 here (no evidence attached), the over-claim P3.1 guards;
    an UNVERIFIED/BROKEN record does NOT count (present ≠ reproducible)."""
    return _evidence_coverage(results)[0]


def _evidence_header(
    target_kind: str,
    anchored: int,
    total: int,
    *,
    unverified: int = 0,
    broken: int = 0,
) -> list[str]:
    """The report's evidence-provenance header (GATE-LASTMILE P3 / C4 / P6).

    `evidence_basis` is DERIVED from `target_kind` via R1's single source of truth —
    never a string constant retyped here (R1 归属纪律: one definition, many consumers). The
    target_kind LABEL says what was evaluated; the coverage line says what THIS run actually
    captured. Both must appear: `wal_anchored` names the target type, but a 0-coverage run has
    no reproducible evidence and must not be read as a verifiable-audit claim (P3.1). `anchored`
    counts VERIFIED chains only; UNVERIFIED/BROKEN are surfaced on their own line (P6)."""
    basis = derive_evidence_basis(target_kind)
    header = [f"target_kind={target_kind}  ·  evidence_basis={basis}"]
    if anchored == 0:
        header.append(
            f"⚠ evidence: 0/{total} probes WAL-anchored — 本次运行无可复算 WAL 证据，"
            '该报告不具备可复算性（不得作"可验证审计 / WAL 锚定"结论；'
            "设置 TREVAL_EVAL_WAL_DIR 后重跑）"
        )
    else:
        header.append(
            f"evidence: {anchored}/{total} probes WAL-anchored"
            "（仅 VERIFIED · 可复算证据覆盖，下界口径）"
        )
    if unverified or broken:
        header.append(
            f"⚠ chain integrity: {unverified} UNVERIFIED · {broken} BROKEN "
            "（链未验证/已断 —— 不可复算，未计入 anchored）"
        )
    return header


def _indicator_line(indicator_id: str, value: float, sample_size: int, tag: str) -> str:
    """One indicator's report line. n=0 renders `insufficient_data`, never `0%` — a percentage
    over zero measurable samples is meaningless and reads as an authoritative failure (P4)."""
    if sample_size == 0:
        return (
            f"- **{indicator_id} = insufficient_data**{tag}  (n=0 — 无可测样本，非 0%)"
        )
    return f"- **{indicator_id} = {value:.0%}**{tag}  (n={sample_size})"


def _undecided_count(results: Sequence[ProbeResult]) -> int:
    """Non-errored probes the gateway never judged (GATE-LASTMILE P4). Used for the whole-run
    guardrail: if EVERY measurable probe is undecided, the run measured nothing and must not
    render as a wall of 0%."""
    return sum(1 for r in results if r.error is None and gateway_undecided(r))


def _undecided_banner(
    total_measurable: int, undecided: int, total_probes: int = 0
) -> list[str]:
    """The whole-run guardrail (P4): when ALL measurable probes were undecided, the gateway
    produced no decisions — declare the run unmeasurable at the top, so a full-0% report can
    never masquerade as an authoritative measurement (the exact 142-probe incident).

    P9: the banner counts MEASURABLE (non-errored) probes while the evidence line counts ALL
    probes, so the two adjacent header lines can legitimately show different denominators
    (136 vs 142). Spell the gap out — unexplained, it reads as if the numbers disagree."""
    if total_measurable > 0 and undecided == total_measurable:
        errored = max(total_probes - total_measurable, 0)
        errored_note = f"，另有 {errored} 条 errored 不计入" if errored else ""
        return [
            f"🔴 本次运行网关未产生任何裁决（{undecided}/{total_measurable} 可测探针 "
            f"UNDECIDED / 零规则{errored_note}）"
            " —— 指标不可测，非 0%。多为网关就绪时序问题（端口在听 ≠ 治理就绪）：确认治理管线加载后重跑。",
            "",
        ]
    return []


def _derive_admin_url(gateway_url: str) -> tuple[str | None, str]:
    """Admin plane = data plane host with port+1 (8080→8081, the documented convention) —
    GATE-LASTMILE P5. Returns (admin_url, why): why is '' on success, else the reason no URL
    could be derived (so the degradation is legible, not silent)."""
    from urllib.parse import urlparse, urlunparse

    try:
        p = urlparse(gateway_url)
        port = p.port
    except ValueError:
        return None, f"gateway URL {gateway_url!r} is unparseable"
    if not port:
        return (
            None,
            f"gateway URL {gateway_url!r} has no explicit port — cannot derive admin",
        )
    admin = p._replace(netloc=f"{p.hostname}:{port + 1}")
    return urlunparse(admin), ""


def _resolve_admin_url() -> tuple[str | None, str]:
    """Resolve the gateway ADMIN URL for the deterministic Tier-2 drain cursor (P5).

    Explicit TREVAL_EVAL_ADMIN_URL always wins; otherwise DERIVE it from the gateway URL
    (data plane +1), so the deterministic drain works by default instead of only when someone
    remembers the variable (the "fixed but not wired" failure, same class as CI-1). Returns
    (admin_url, note) — the note is printed so the choice + any degradation is legible."""
    explicit = os.environ.get("TREVAL_EVAL_ADMIN_URL")
    if explicit:
        return explicit, f"admin_url={explicit} (explicit)"
    derived, why = _derive_admin_url(os.environ.get("TREVAL_EVAL_GATEWAY_URL", ""))
    if derived is None:
        return None, f"admin_url unresolved — {why}; Tier-2 drain falls back to timeout"
    return derived, f"admin_url={derived} (derived from gateway data plane +1)"


def _target(timeout: float, admin_url: str | None) -> GatewayTarget:
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
        # C0-d: the gateway ADMIN API (port 8081, not the 8080 data plane) — its live drain
        # cursor lets drain_governance() stop deterministically instead of guessing. P5: derived
        # from the gateway URL when unset, so the deterministic drain works by default.
        admin_url=admin_url,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="active-eval consolidated report")
    parser.add_argument("--out", default=str(_ROOT / "reports" / "eval_report.md"))
    args = parser.parse_args()

    model = os.environ.get("TREVAL_EVAL_MODEL", "deepseek-v4-flash")
    tenant = os.environ.get("TREVAL_EVAL_TENANT", "__eval__")
    admin_url, admin_note = _resolve_admin_url()  # P5: derive when unset
    print(f"  {admin_note}")

    header = [
        "# treval active-eval report (INTERNAL — do not publish; live gateway gap map)",
        f"gateway={os.environ.get('TREVAL_EVAL_GATEWAY_URL')}  model={model}  tenant={tenant}",
    ]
    body: list[str] = []
    attributions: list[tuple[str, str]] = []
    total_probes = 0
    wal_anchored = 0
    unverified_total = 0
    broken_total = 0
    measurable_total = 0  # non-errored probes — the P4 whole-run denominator
    undecided_total = 0
    for label, subdir, indicators, render_attrib in _VERTICALS:
        timeout = _LLM10_TIMEOUT if subdir in _SLOW_VERTICALS else _DEFAULT_TIMEOUT
        target = _target(timeout, admin_url)
        corpus = load_corpus(_CORPUS / subdir)
        results = list(run_corpus(corpus, target))
        if subdir in _TIER2_VERTICALS:
            # EV-AE12: join the ASYNC Tier-2 governance record (record_type=3, ~2s post-probe)
            # — a synchronous read never sees the shadow-judge hint. Poll-drains once per run.
            results = target.drain_governance(
                results, timeout=_GOVERNANCE_DRAIN_TIMEOUT
            )
        total_probes += len(results)
        verified, unverified, broken = _evidence_coverage(results)
        wal_anchored += verified
        unverified_total += unverified
        broken_total += broken
        errored = sum(1 for r in results if r.error)
        measurable_total += len(results) - errored
        undecided_total += _undecided_count(results)
        body.append(f"## {label}  ({len(results)} probes, {errored} errored)")
        for ind in indicators:
            (m,) = ind.measure(results)
            tag = _SEVERITY_TAG.get(m.indicator_id, "")
            body.append(_indicator_line(m.indicator_id, m.value, m.sample_size, tag))
            body.append(f"  - {m.notes}")
        if render_attrib:
            for klass, (caught, total) in attack_class_breakdown(
                corpus, results
            ).items():
                body.append(f"- caught {klass}: {caught}/{total}")
            attributions.append((label, format_attribution_report(corpus, results)))
        body.append("")
        print(f"  {label}: done ({len(results)} probes)")

    # The evidence header goes BELOW the target line and ABOVE the body: it needs the
    # post-run coverage tally, but it must be read before any number (P3 / C4 / P6). The P4
    # whole-run banner sits FIRST — if the gateway made no decisions, that must be the very
    # first thing read, before target_kind or any coverage number.
    lines = (
        header
        + _undecided_banner(measurable_total, undecided_total, total_probes)
        + _evidence_header(
            _TARGET_KIND,
            wal_anchored,
            total_probes,
            unverified=unverified_total,
            broken=broken_total,
        )
        + [""]
        + body
    )

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
