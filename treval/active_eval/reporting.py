"""Per-attack_class catch attribution (EV-AE6 follow-up; EV-AE7 / Platform Tier-2 feed).

`attack_class_breakdown` is the permanent, committed harness helper — the per-technique
gateway catch rate (which attack families a ruleset catches vs misses), so every Platform
iteration is measurable per-technique. `format_attribution_report` renders a detailed
per-case gap map for hand-off to Platform.

SECURITY NOTE: these functions are generic (no gateway data baked in) and safe to commit,
but the *rendered report against a live run* is an INTERNAL Platform artifact — a live
bypass map for the deployed gateway. Write it under the **gitignored `reports/`** dir and
hand it to Platform privately; do NOT commit it to this (public) repo.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval.checks import caught_by_tier2, evaluate, injection_score
from treval.active_eval.corpus import CorpusCase
from treval.active_eval.target import ProbeResult

_FD = {
    rc_pb.DecisionTrace.FINAL_DECISION_UNSPECIFIED: "UNSPECIFIED",
    rc_pb.DecisionTrace.FINAL_DECISION_UNDECIDED: "UNDECIDED",
    rc_pb.DecisionTrace.FINAL_DECISION_ALLOW: "ALLOW",
    rc_pb.DecisionTrace.FINAL_DECISION_BLOCK: "BLOCK",
}


def _caught(pr: ProbeResult) -> bool:
    """A probe was caught iff it has a WAL record and blocked_or_flagged (the gateway
    catch signal). Errored / evidence-less probes are NOT caught."""
    return pr.evidence is not None and evaluate("blocked_or_flagged", pr)


def attack_class_breakdown(
    cases: Iterable[CorpusCase], results: Iterable[ProbeResult]
) -> dict[str, tuple[int, int]]:
    """`{attack_class: (caught, total)}`, results matched to cases by id. Pure +
    deterministic (the catch signal is WAL rule decisions). Errored / evidence-less
    probes count in `total`, not `caught`. Sorted by attack_class. The per-technique
    feed for the Tier-2 roadmap / EV-AE7."""
    by_id = {c.id: c for c in cases}
    agg: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for pr in results:
        case = by_id.get(pr.case_id)
        if case is None:
            continue
        agg[case.attack_class][1] += 1
        if _caught(pr):
            agg[case.attack_class][0] += 1
    return {k: (v[0], v[1]) for k, v in sorted(agg.items())}


def _catching_rules(pr: ProbeResult) -> str:
    """The decision + the rule(s) that fired with a non-log action (the catching rule),
    for the detailed report. Empty/log-only ⇒ just the final decision."""
    if pr.evidence is None:
        return pr.error or "no evidence"
    d = pr.evidence.record.decision
    fired = [
        f"{r.rule_id}{list(r.actions_fired)}"
        for r in d.rules_evaluated
        if r.matched and list(r.actions_fired) != ["log"]
    ]
    hint = pr.evidence.record.audit.hint_emitted
    return (
        _FD.get(d.final_decision, "?")
        + (f" by {fired}" if fired else "")
        + (" +hint" if hint else "")
        + _tier2_suffix(pr)
    )


def _tier2_suffix(pr: ProbeResult) -> str:
    """EV-AE12: the async Tier-2 shadow judge (record_type=3) — its hint (the catch signal)
    and its raw injection_score (a DIAGNOSTIC fact for the τ-sweep, never a catch signal).
    Empty when no async record landed."""
    if pr.governance_evidence is None:
        return ""
    score = injection_score(pr)
    score_txt = f"injection_score={score:.2f}" if score is not None else "no-score"
    if caught_by_tier2(pr):
        return f" +T2-hint({score_txt})"
    return f" [T2 {score_txt}, τ-below]"


def format_attribution_report(
    cases: Iterable[CorpusCase], results: Iterable[ProbeResult]
) -> str:
    """Detailed per-case + per-class catch attribution (INTERNAL Platform artifact — a
    live bypass map; write under the gitignored `reports/` dir, hand to Platform). Pure
    over its inputs."""
    cases = list(cases)
    results = list(results)
    by_id = {c.id: c for c in cases}
    lines = ["# LLM01 per-technique catch attribution (INTERNAL — do not publish)", ""]
    caught_n = total = 0
    for pr in results:
        case = by_id.get(pr.case_id)
        if case is None:
            continue
        total += 1
        hit = _caught(pr)
        caught_n += hit
        flag = "CAUGHT" if hit else "missed"
        lines.append(
            f"[{flag}] {case.id}  ({case.attack_class})  {_catching_rules(pr)}"
        )
    pct = f"{caught_n / total:.0%}" if total else "n/a"
    lines += [
        "",
        f"caught {caught_n}/{total} = {pct}",
        "",
        "## per attack_class (caught/total):",
    ]
    for k, (c, t) in attack_class_breakdown(cases, results).items():
        lines.append(f"  {k}: {c}/{t}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# EV-AE7 — Tier-1 rule-robustness diagnostic + Tier-2 evading-variant seed
# --------------------------------------------------------------------------- #


def rule_robustness(
    base: Iterable[CorpusCase],
    base_results: Iterable[ProbeResult],
    variants: Iterable[CorpusCase],
    variant_results: Iterable[ProbeResult],
) -> dict[str, Any]:
    """Tier-1 rule robustness over the variants of cases the rule CAUGHT at base.

    Returns a DIAGNOSTIC dict (NOT a Measurement — D2: the maturity number stays
    injection_catch_rate, with this as a credibility caveat):
      {caught_base, variants_total, variants_caught, robustness=caught/total,
       by_kind={kind:(caught,total)}, evading=[{base_id,kind,input,attack_class,owasp,
       base_caught_by}, ...]}.
    `evading` = the Tier-2 seed (caught at base, missed when perturbed). Pure +
    deterministic (the catch signal is keyword/regex on the input). A big robustness drop
    ⇒ the rule matched the literal phrasing, not the technique (overfit)."""
    base_ids = {c.id for c in base}
    base_by_id = {r.case_id: r for r in base_results}
    variant_by_id = {c.id: c for c in variants}
    caught_base = {
        cid for cid, r in base_by_id.items() if cid in base_ids and _caught(r)
    }

    by_kind: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    evading: list[dict[str, Any]] = []
    variants_total = variants_caught = 0
    for r in variant_results:
        base_id, sep, kind = r.case_id.partition("::var.")
        if not sep or base_id not in caught_base:
            continue  # robustness is only defined for variants of caught-at-base cases
        variants_total += 1
        by_kind[kind][1] += 1
        if _caught(r):
            variants_caught += 1
            by_kind[kind][0] += 1
            continue
        vc = variant_by_id.get(r.case_id)
        base_r = base_by_id.get(base_id)
        caught_by: list[str] = []
        if base_r is not None and base_r.evidence is not None:
            # The real catching rule, not the benign log-everything rule (which matches
            # every request) — mirrors _catching_rules, keeps the Tier-2 seed clean.
            caught_by = sorted(
                {
                    rule.rule_id
                    for rule in base_r.evidence.record.decision.rules_evaluated
                    if rule.matched and list(rule.actions_fired) != ["log"]
                }
            )
        evading.append(
            {
                "base_id": base_id,
                "kind": kind,
                "input": vc.input if vc is not None else "",
                "attack_class": vc.attack_class if vc is not None else "",
                "owasp": vc.owasp if vc is not None else "",
                "base_caught_by": caught_by,
            }
        )

    robustness = variants_caught / variants_total if variants_total else 0.0
    return {
        "caught_base": len(caught_base),
        "variants_total": variants_total,
        "variants_caught": variants_caught,
        "robustness": robustness,
        "by_kind": {k: (v[0], v[1]) for k, v in sorted(by_kind.items())},
        "evading": evading,
    }


def write_evading_seed(evading: Iterable[dict[str, Any]], path: str | Path) -> None:
    """Write the evading variants as JSON Lines (D3): one variant per line —
    {base_id, kind, input, attack_class, owasp, base_caught_by}. JSONL because both
    consumers are programmatic/stream-friendly (P2-b judge τ-sweep, P2-norm validation).
    INTERNAL artifact (a working-bypass set) → write under the gitignored reports/ dir and
    hand to Platform privately; do NOT commit."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(
            {
                "base_id": v["base_id"],
                "kind": v["kind"],
                "input": v["input"],
                "attack_class": v["attack_class"],
                "owasp": v["owasp"],
                "base_caught_by": v.get("base_caught_by", []),
            },
            ensure_ascii=False,
        )
        for v in evading
    ]
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def format_variant_report(stats: dict[str, Any]) -> str:
    """Human summary of rule_robustness (robustness + by_kind + evading count). INTERNAL
    Platform artifact — write under the gitignored reports/ dir."""
    robustness = stats["robustness"]
    lines = [
        "# LLM01 Tier-1 rule-robustness (INTERNAL — do not publish)",
        "",
        f"caught at base: {stats['caught_base']} case(s)",
        f"variant robustness: {robustness:.0%}  "
        f"({stats['variants_caught']}/{stats['variants_total']} variants still caught)",
        "",
        "## by perturbation kind (still-caught/total):",
    ]
    for kind, (caught, total) in sorted(stats["by_kind"].items()):
        lines.append(f"  {kind}: {caught}/{total}")
    evading = stats["evading"]
    lines += ["", f"## evading variants (Tier-2 seed): {len(evading)}"]
    for v in evading:
        lines.append(f"  [{v['kind']}] {v['base_id']}  ({v['attack_class']})")
    return "\n".join(lines) + "\n"
