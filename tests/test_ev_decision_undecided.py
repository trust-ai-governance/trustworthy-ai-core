"""序8 件1 — a benign case the gateway never JUDGED at the DECISION stage (final_decision UNDECIDED, or
zero rules evaluated) is NOT a clean allow: it EXITS the false_positive_rate / benign_flag_rate
denominator and is counted, decision-stage only (a response-side reaction never re-enters the benign
口径, E3-n①). 没法判 不许伪装成 判了.
"""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval import BenignFlagRate, FalsePositiveRate
from treval.active_eval.target import ProbeResult
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_UNDECIDED = rc_pb.DecisionTrace.FINAL_DECISION_UNDECIDED


def _ev(cid, ctx):
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=0, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="__eval__",
        received_at_ns=0,
        record=ctx,
    )


def _benign(cid, *, final=_ALLOW, rules=1, response_block=False):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.decision.final_decision = final  # type: ignore[assignment]
    for i in range(rules):
        r = ctx.decision.rules_evaluated.add()
        r.rule_id = f"r{i}"
        r.matched = final == _BLOCK
    resp_ev = None
    if response_block:
        rctx = rc_pb.RequestContext()
        rctx.envelope.request_id = f"req-{cid}"
        rctx.response.final_terminal = "BLOCKED"
        resp_ev = _ev(cid, rctx)
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="",
        response_text="ok",
        evidence=_ev(cid, ctx),
        response_evidence=resp_ev,
        attack_class="benign_hard_negative",
    )


def _fpr(probes):
    (m,) = FalsePositiveRate().measure(probes)
    return m


# --------------------------------------------------------------------------- #
# false_positive_rate
# --------------------------------------------------------------------------- #
def test_fpr_decision_undecided_exits_denominator_acceptance1_2():
    # ① final_decision=UNDECIDED ⇒ exits (was a clean allow in the denominator before)
    m = _fpr([_benign("u", final=_UNDECIDED)])
    assert m.sample_size == 0 and "decision-undecided" in m.notes
    # ② zero rules evaluated ⇒ exits too
    m2 = _fpr([_benign("z", final=_ALLOW, rules=0)])
    assert m2.sample_size == 0 and "decision-undecided" in m2.notes
    # a mix: one clean allow + one undecided ⇒ denominator is 1, not 2
    m3 = _fpr([_benign("ok", final=_ALLOW), _benign("u2", final=_UNDECIDED)])
    assert m3.sample_size == 1


def test_fpr_block_counts_and_response_only_reaction_stays_clean_acceptance3_4():
    # ④ a DECISION-stage BLOCK on benign IS a false positive (regression)
    m = _fpr([_benign("b", final=_BLOCK)])
    assert m.sample_size == 1 and m.value == 1.0
    # ③ 🔴 a benign with ONLY a response-side block is NOT an FPR and is NOT exited (decision ALLOW is a
    # verdict) — the fix must not pull the response side into the benign口径 (E3-n①).
    m2 = _fpr([_benign("r", final=_ALLOW, response_block=True)])
    assert m2.sample_size == 1 and m2.value == 0.0
    assert "decision-undecided" not in m2.notes


def test_fpr_all_undecided_is_not_measured_acceptance5():
    # ⑤ flagship — all benign UNDECIDED ⇒ not_measured (n=0), NEVER a pretty "FPR 0%"
    m = _fpr([_benign(f"u{i}", final=_UNDECIDED) for i in range(4)])
    assert m.sample_size == 0 and m.value == 0.0


# --------------------------------------------------------------------------- #
# benign_flag_rate — same exit (hard_only isolates it from the F9 Tier-2 three-state)
# --------------------------------------------------------------------------- #
def test_benign_flag_decision_undecided_exits():
    bf = BenignFlagRate(arm_parity="hard_only")
    (m,) = bf.measure([_benign("ok", final=_ALLOW), _benign("u", final=_UNDECIDED)])
    assert (
        m.sample_size == 1 and "decision-undecided" in m.notes
    )  # undecided exited, clean stayed
    (m2,) = bf.measure([_benign(f"u{i}", final=_UNDECIDED) for i in range(3)])
    assert m2.sample_size == 0  # all never-judged ⇒ not_measured
