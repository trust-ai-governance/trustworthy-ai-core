"""Track B read-side compatibility: type-7 decodes without exception and keeps its shape,
and pre-E1 records (no `audit_schema_version`) still read as legacy decisions.

Decision/response exclusion is covered in test_block_rate and test_ev_terminal_whitelist.
These tests use synthetic RequestContext records only; they do not read an operator
WAL or carry measured values.
"""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.indicators import BlockRate
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK


def _type7() -> rc_pb.RequestContext:
    ctx = rc_pb.RequestContext()
    ctx.record_type = rc_pb.AUDIT_RECORD_TYPE_COMPLIANCE_OPERATION  # type: ignore[assignment]
    ctx.envelope.request_id = "req-type7"
    ctx.envelope.tenant_id = "t"
    ctx.audit_schema_version = 3
    ctx.body_state = rc_pb.BODY_STATE_NOT_APPLICABLE  # type: ignore[assignment]
    ctx.compliance_operation.operation_type = (  # type: ignore[assignment]
        rc_pb.COMPLIANCE_OPERATION_DELETE_REQUESTED
    )
    ctx.compliance_operation.result = (  # type: ignore[assignment]
        rc_pb.COMPLIANCE_OPERATION_RESULT_PENDING
    )
    ctx.compliance_operation.operation_id = "op-1"
    return ctx


def test_type7_decodes_without_exception_and_keeps_shape():
    decoded = rc_pb.RequestContext.FromString(_type7().SerializeToString())
    assert decoded.record_type == rc_pb.AUDIT_RECORD_TYPE_COMPLIANCE_OPERATION
    assert decoded.audit_schema_version == 3
    assert decoded.body_state == rc_pb.BODY_STATE_NOT_APPLICABLE
    assert (
        decoded.compliance_operation.operation_type
        == rc_pb.COMPLIANCE_OPERATION_DELETE_REQUESTED
    )
    assert decoded.compliance_operation.operation_id == "op-1"


def _pre_e1(seq: int, final: int) -> AuditEvidence:
    """A pre-E1 decision record: `audit_schema_version` absent, no tags/scores."""
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{seq}"
    ctx.envelope.tenant_id = "t"
    ctx.decision.final_decision = final  # type: ignore[assignment]
    assert not ctx.HasField("audit_schema_version")
    return AuditEvidence(
        ref=EvidenceRef(source="wal:test", seq=seq, request_id=f"req-{seq}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="t",
        received_at_ns=seq,
        record=ctx,
    )


def test_pre_e1_record_without_schema_version_still_counts_as_decision():
    """Version absence means pre-E1 (legacy), not 0 and not an error. The legacy
    UNSPECIFIED record_type still enters block_rate, and empty tags/scores do not
    trip a read."""
    evidence = [_pre_e1(0, _ALLOW), _pre_e1(1, _BLOCK)]
    assert all(not ev.record.decision.scores for ev in evidence)
    (m,) = BlockRate().measure(evidence)
    assert m.sample_size == 2
    assert m.value == 0.5
