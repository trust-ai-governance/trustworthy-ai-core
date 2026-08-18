"""序8 件4 — the case-level contract carries `tier2_scored` per row (scored / not_scored / prefiltered),
so "why wasn't this row's Tier-2 hint counted" is answerable PER CASE, not only as a total in
tier2_shadow_recall_lift's notes. 🔴 Pure WAL read; the row three-state counts re-add to the indicator's
no_async / skipped_prefiltered totals (契约自洽).
"""

from __future__ import annotations

from collections import Counter

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval import Tier2ShadowRecallLift
from treval.active_eval.cases import _tier2_scored, build_cases
from treval.active_eval.corpus import CorpusCase
from treval.active_eval.target import ProbeResult
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW


def _ev(cid, ctx):
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=0, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="__eval__",
        received_at_ns=0,
        record=ctx,
    )


def _dec(cid, final):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.decision.final_decision = final  # type: ignore[assignment]
    r = ctx.decision.rules_evaluated.add()
    r.rule_id = "inj-1"
    r.matched = final == _BLOCK
    return _ev(cid, ctx)


def _gov(cid, hint):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    if hint:
        ctx.audit.hint_emitted = True
        r = ctx.decision.rules_evaluated.add()
        r.rule_id = "t2"
        r.matched = True
        r.tags["tier"] = "2"
    return _ev(cid, ctx)


def _probe(cid, *, final=_ALLOW, scored=False, hint=False):
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="",
        response_text="",
        evidence=_dec(cid, final),
        governance_evidence=_gov(cid, hint) if scored else None,
        tier2_drain_executed=True,  # so the lift MEASURES (drain ran), not not_measured
        attack_class="direct_prompt_injection",
    )


def _case(cid):
    return CorpusCase(
        id=cid,
        owasp="LLM01",
        dimension="robustness",
        attack_class="direct_prompt_injection",
        input="x",
        success_when="blocked_or_flagged",
        severity="high",
        source="core-authored",
    )


# --------------------------------------------------------------------------- #
# ①②③ — the three states
# --------------------------------------------------------------------------- #
def test_tier2_scored_three_states_acceptance1_2_3():
    # ① a type-3 governance record ⇒ scored
    assert _tier2_scored(_probe("s", scored=True)) == "scored"
    # ② no record AND Tier-1 did not block ⇒ not_scored (= our no_async)
    assert _tier2_scored(_probe("n", final=_ALLOW, scored=False)) == "not_scored"
    # ③ 🔴 Tier-1 already HARD-blocked ⇒ prefiltered, NEVER folded into not_scored
    p = _probe("p", final=_BLOCK, scored=False)
    assert _tier2_scored(p) == "prefiltered" and _tier2_scored(p) != "not_scored"


def test_build_cases_carries_tier2_scored():
    (row,) = build_cases(
        [_case("s")], [_probe("s", scored=True)], target_kind="gateway"
    )
    assert row["tier2_scored"] == "scored"


# --------------------------------------------------------------------------- #
# ④ 🔴 the row three-state counts re-add to the indicator's notes totals (契约自洽)
# --------------------------------------------------------------------------- #
def test_case_row_counts_match_lift_notes_acceptance4():
    probes = [
        _probe("s", final=_ALLOW, scored=True, hint=True),  # scored (rescued)
        _probe("p", final=_BLOCK, scored=False),  # prefiltered (Tier-1 hard block)
        _probe("n", final=_ALLOW, scored=False),  # not_scored (no record, not blocked)
    ]
    rows = build_cases(
        [_case(p.case_id) for p in probes], probes, target_kind="gateway"
    )
    counts = Counter(r["tier2_scored"] for r in rows)
    assert counts == {"scored": 1, "prefiltered": 1, "not_scored": 1}

    (lift,) = Tier2ShadowRecallLift().measure(probes)
    # 🔴 the case rows and the indicator notes must AGREE (no two-sides-computing-separately)
    assert f"{counts['not_scored']} probe(s) had NO async record" in lift.notes
    assert f"{counts['prefiltered']} Tier-1-hard-blocked" in lift.notes
