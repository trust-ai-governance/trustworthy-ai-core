"""Track B read-side compatibility: type-7 decodes without exception and keeps its shape.

Decision/response exclusion is covered in test_block_rate and test_ev_terminal_whitelist.
These tests use synthetic RequestContext records only; they do not read an operator
WAL or carry measured values.
"""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb


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
