"""B-04b: 残余 response_evidence 直读统一经 response_record()。

type-6 与 type-7 都不是响应记录。把手构的、带满响应字段的 type-6 与 type-7 放进
ProbeResult.response_evidence（生产 join 今天不会这么做，但读端不能靠写端保证），
所有 response-side 读取必须保持 fail-closed：不印 RESP: 后缀、不 credit cap-hit、
不读 WAL reasoning/content token、不进 Cost/Tier-2 分母、不读 neutralize 标记。

type-2 对照用同一组字段，证明过滤没有误伤正常响应记录。
"""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval.checks import response_record
from treval.active_eval.indicators import (
    CostRunawayCaught,
    Tier2JudgeCoverage,
    _cap_hit,
    _content_tokens,
    _neutralize_markers,
    _reasoning_tokens,
)
from treval.active_eval.reporting import _response_suffix
from treval.active_eval.target import ProbeResult
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_TYPE2 = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED
_TYPE6 = rc_pb.AUDIT_RECORD_TYPE_PROCESSING_RESTRICTED
_TYPE7 = rc_pb.AUDIT_RECORD_TYPE_COMPLIANCE_OPERATION


def _response_like(cid: str, record_type: int) -> AuditEvidence:
    """A record carrying every response-side field the sweep reads — with the given
    record_type. Only type-2 is a response record by contract."""
    ctx = rc_pb.RequestContext()
    ctx.record_type = record_type  # type: ignore[assignment]
    ctx.envelope.request_id = f"req-{cid}"
    ctx.response.final_terminal = "BLOCKED"
    rule = ctx.response.on_tool_response_rules.add()
    rule.rule_id = "out-dlp-1"
    rule.matched = True
    rule.actions_fired.append("block")
    ctx.response.token_usage.completion_tokens = 100
    ctx.response.token_usage.extra["max_tokens_cap_hit"] = 1
    ctx.response.token_usage.extra["completion_tokens_details.reasoning_tokens"] = 40
    ctx.audit.hint_variables["output_neutralized"] = "1"
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=1, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="__eval__",
        received_at_ns=0,
        record=ctx,
    )


def _probe(
    cid: str,
    ev: AuditEvidence | None,
    *,
    reasoning_tokens: int = 10,
    completion_tokens: int = 30,
    **kwargs: object,
) -> ProbeResult:
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="ALLOW",
        response_text="ok",
        evidence=None,
        response_evidence=ev,
        reasoning_tokens=reasoning_tokens,
        completion_tokens=completion_tokens,
        **kwargs,  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- #
# type-6 / type-7 —— none of the response-side readings may fire
# --------------------------------------------------------------------------- #
def test_non_response_record_is_not_a_response_record():
    for rt in (_TYPE6, _TYPE7):
        assert response_record(_response_like("c", rt)) is None


def test_response_suffix_ignores_non_response_records():
    for rt in (_TYPE6, _TYPE7):
        assert _response_suffix(_probe("c", _response_like("c", rt))) == ""


def test_cap_hit_ignores_non_response_records():
    for rt in (_TYPE6, _TYPE7):
        assert _cap_hit(_probe("c", _response_like("c", rt))) is False


def test_reasoning_and_content_tokens_fall_back_to_http_fields():
    for rt in (_TYPE6, _TYPE7):
        pr = _probe("c", _response_like("c", rt))
        assert _reasoning_tokens(pr) == 10
        assert _content_tokens(pr) == 20


def test_content_tokens_is_none_without_any_completion_count():
    pr = _probe("c", _response_like("c", _TYPE6), completion_tokens=0)
    assert _content_tokens(pr) is None


def test_cost_runaway_excludes_non_response_records_from_denominator():
    for rt in (_TYPE6, _TYPE7):
        (m,) = CostRunawayCaught().measure([_probe("c", _response_like("c", rt))])
        assert m.sample_size == 0
        assert m.value == 0.0
        assert "no-decision-record" in m.notes
        assert m.notes.count("1 no-decision-record") == 1


def test_tier2_coverage_does_not_count_non_response_records_as_forwarded():
    for rt in (_TYPE6, _TYPE7):
        pr = _probe("c", _response_like("c", rt), tier2_drain_executed=True)
        (m,) = Tier2JudgeCoverage().measure([pr])
        assert m.sample_size == 0
        assert m.value == 0.0
        assert "insufficient_data" in m.notes


def test_neutralize_markers_ignore_non_response_records():
    for rt in (_TYPE6, _TYPE7):
        assert _neutralize_markers(_probe("c", _response_like("c", rt))) == {}


# --------------------------------------------------------------------------- #
# type-2 对照 —— the same fields still produce the original readings
# --------------------------------------------------------------------------- #
def test_response_observed_control_keeps_original_readings():
    pr = _probe("c", _response_like("c", _TYPE2))
    assert response_record(pr.response_evidence) is not None
    suffix = _response_suffix(pr)
    assert "RESP:BLOCKED" in suffix and "out-dlp-1" in suffix
    assert _cap_hit(pr) is True
    assert _reasoning_tokens(pr) == 40
    assert _content_tokens(pr) == 60
    assert _neutralize_markers(pr) == {"output_neutralized": "1"}
    (m,) = CostRunawayCaught().measure([pr])
    assert m.sample_size == 1 and m.value == 1.0
    coverage = _probe("c", _response_like("c", _TYPE2), tier2_drain_executed=True)
    (c,) = Tier2JudgeCoverage().measure([coverage])
    assert c.sample_size == 1 and c.value == 0.0
