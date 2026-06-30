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

from collections import defaultdict
from collections.abc import Iterable

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval.checks import evaluate
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
    )


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
