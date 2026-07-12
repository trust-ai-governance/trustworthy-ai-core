"""EV-5b — the A↔B join helper (`join_ab`). Pure + deterministic; orphans never raise."""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.indicators import join_ab
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_DECISION = rc_pb.AUDIT_RECORD_TYPE_DECISION_MADE
_RESPONSE = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED
_GOVERNANCE = rc_pb.AUDIT_RECORD_TYPE_GOVERNANCE_OBSERVED


def _ev(rid, *, record_type, seq=0, decision_seq=0):
    ctx = rc_pb.RequestContext()
    ctx.record_type = record_type  # type: ignore[assignment]
    if rid:
        ctx.envelope.request_id = rid
    if record_type == _RESPONSE:
        ctx.response.decision_seq = decision_seq
    return AuditEvidence(
        ref=EvidenceRef(source="wal:t", seq=seq, request_id=rid),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="t",
        received_at_ns=0,
        record=ctx,
    )


def _a(rid, **kw):
    return _ev(rid, record_type=_DECISION, **kw)


def _b(rid, **kw):
    return _ev(rid, record_type=_RESPONSE, **kw)


def test_basic_pair():
    j = join_ab([_a("r1"), _b("r1")])
    assert len(j.paired) == 1
    assert j.paired[0][0].ref.request_id == "r1"
    assert j.orphan_a == () and j.orphan_b == ()


def test_orphan_a_and_orphan_b():
    j = join_ab([_a("r1"), _b("r1"), _a("r2"), _b("r3")])
    assert [a.ref.request_id for a, _ in j.paired] == ["r1"]
    assert [a.ref.request_id for a in j.orphan_a] == ["r2"]  # decision, no response
    assert [b.ref.request_id for b in j.orphan_b] == ["r3"]  # response, no decision


def test_seq_backpointer_mismatch_is_a_note_not_a_drop():
    j = join_ab([_a("r1", seq=5), _b("r1", decision_seq=9)])
    assert len(j.paired) == 1  # still paired (cross-instance is legal)
    assert j.seq_mismatches == ("r1",)


def test_seq_backpointer_match_no_note():
    j = join_ab([_a("r1", seq=5), _b("r1", decision_seq=5)])
    assert j.seq_mismatches == ()


def test_absent_decision_seq_skips_the_check():
    j = join_ab([_a("r1", seq=5), _b("r1", decision_seq=0)])
    assert j.seq_mismatches == ()  # 0 = back-pointer absent


def test_empty_request_id_becomes_an_orphan():
    j = join_ab([_a(""), _b("")])
    assert len(j.paired) == 0
    assert len(j.orphan_a) == 1 and len(j.orphan_b) == 1  # cannot correlate


def test_non_ab_records_are_ignored():
    j = join_ab([_a("r1"), _b("r1"), _ev("r1", record_type=_GOVERNANCE)])
    assert len(j.paired) == 1
    assert j.orphan_a == () and j.orphan_b == ()  # governance record not in the loop


def test_duplicate_first_wins():
    a1, a2 = _a("r1", seq=1), _a("r1", seq=2)
    j = join_ab([a1, a2, _b("r1")])
    assert len(j.paired) == 1
    assert j.paired[0][0].ref.seq == 1  # first A kept


def test_deterministic():
    stream = [_a("r1"), _b("r1"), _a("r2"), _b("r2")]
    assert join_ab(stream) == join_ab(stream)
