"""Tests for the block_rate reference indicator (EV-4 §4/§5)."""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval import build_default_registry, load_registry, validate_against
from treval.indicators import BlockRate
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_DECISION = rc_pb.AUDIT_RECORD_TYPE_DECISION_MADE
_RESPONSE = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED
_UNSPEC_RT = rc_pb.AUDIT_RECORD_TYPE_UNSPECIFIED
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
_UNDECIDED = rc_pb.DecisionTrace.FINAL_DECISION_UNDECIDED


def _evidence(seq, *, record_type=_DECISION, final=_ALLOW, integrity=None):
    ctx = rc_pb.RequestContext()
    ctx.record_type = record_type  # type: ignore[assignment]
    ctx.envelope.request_id = f"req-{seq}"
    ctx.envelope.tenant_id = "t"
    ctx.envelope.received_at_ns = seq
    if final is not None:
        ctx.decision.final_decision = final  # type: ignore[assignment]
    return AuditEvidence(
        ref=EvidenceRef(source="wal:test", seq=seq, request_id=f"req-{seq}"),
        integrity=integrity or IntegrityStatus.VERIFIED,
        tenant_id="t",
        received_at_ns=seq,
        record=ctx,
    )


# --------------------------------------------------------------------------- #
# 1. Worked example
# --------------------------------------------------------------------------- #


def test_worked_example_3allow_1block():
    evidence = [
        _evidence(0, final=_ALLOW),
        _evidence(1, final=_ALLOW),
        _evidence(2, final=_ALLOW),
        _evidence(3, final=_BLOCK),
    ]
    (m,) = BlockRate().measure(evidence)  # a 1-tuple
    assert m.value == 0.25
    assert m.sample_size == 4
    assert m.subject == ""
    assert len(m.evidence_refs) == 4
    assert m.dimension == "security_alignment"
    assert m.indicator_id == "block_rate"
    assert m.unit == "ratio"


# --------------------------------------------------------------------------- #
# 2. Empty input — sample_size==0 (insufficient data), value==0.0
# --------------------------------------------------------------------------- #


def test_empty_input_is_insufficient_data():
    result = BlockRate().measure([])
    assert len(result) == 1
    (m,) = result
    assert m.sample_size == 0
    assert m.value == 0.0
    assert m.evidence_refs == ()


# --------------------------------------------------------------------------- #
# 3. B records excluded
# --------------------------------------------------------------------------- #


def test_response_observed_records_excluded():
    evidence = [
        _evidence(0, final=_ALLOW),
        _evidence(1, final=_BLOCK),
        # A response.observed record in the stream must not change the rate.
        _evidence(2, record_type=_RESPONSE, final=_BLOCK),
    ]
    (m,) = BlockRate().measure(evidence)
    assert m.sample_size == 2
    assert m.value == 0.5


# --------------------------------------------------------------------------- #
# 4. Undecided / unspecified excluded from the denominator
# --------------------------------------------------------------------------- #


def test_undecided_excluded_from_denominator():
    evidence = [
        _evidence(0, final=_ALLOW),
        _evidence(1, final=_BLOCK),
        _evidence(2, final=_UNDECIDED),
        _evidence(3, final=None),  # decision absent → UNSPECIFIED (0)
    ]
    (m,) = BlockRate().measure(evidence)
    assert m.sample_size == 2  # only ALLOW + BLOCK counted
    assert m.value == 0.5


def test_legacy_record_type_still_counts():
    # Legacy (UNSPECIFIED record_type) decision records still count (not B records).
    evidence = [
        _evidence(0, record_type=_UNSPEC_RT, final=_ALLOW),
        _evidence(1, record_type=_UNSPEC_RT, final=_BLOCK),
    ]
    (m,) = BlockRate().measure(evidence)
    assert m.sample_size == 2
    assert m.value == 0.5


# --------------------------------------------------------------------------- #
# Integrity: BROKEN records still counted (indicator stays dumb — §4)
# --------------------------------------------------------------------------- #


def test_broken_integrity_still_counted():
    evidence = [
        _evidence(0, final=_ALLOW, integrity=IntegrityStatus.BROKEN),
        _evidence(1, final=_BLOCK, integrity=IntegrityStatus.BROKEN),
    ]
    (m,) = BlockRate().measure(evidence)
    assert m.sample_size == 2
    assert m.value == 0.5


# --------------------------------------------------------------------------- #
# 5. Purity
# --------------------------------------------------------------------------- #


def test_purity_same_evidence_same_result():
    evidence = [_evidence(0, final=_ALLOW), _evidence(1, final=_BLOCK)]
    assert BlockRate().measure(evidence) == BlockRate().measure(evidence)


# --------------------------------------------------------------------------- #
# 8. EV-6 bridge — block_rate resolves once registered
# --------------------------------------------------------------------------- #


def test_ev6_bridge_block_rate_not_flagged():
    sdk = build_default_registry()
    problems = validate_against(load_registry(), indicator_ids=sdk.ids())
    # Other indicator ids still flag until EV-5/EV-9 land; block_rate must not.
    assert not any("block_rate" in p for p in problems)
    assert "block_rate" in sdk.ids()
