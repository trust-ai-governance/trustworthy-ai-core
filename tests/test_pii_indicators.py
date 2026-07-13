"""EV-9 §2 — PII indicators (redaction_hit_ratio + pii_exposure_surface) over the B1 marker
`audit.hint_variables["pii_types"]`. Fixtures build AuditEvidence directly (EV-4 pattern);
live-verified separately over /home/olvan/wal (email surface).
"""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval import (
    PiiExposureSurface,
    RedactionHitRatio,
    evaluate,
    load_registry,
)
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_V = IntegrityStatus.VERIFIED
_U = IntegrityStatus.UNVERIFIED
_DECISION = rc_pb.AUDIT_RECORD_TYPE_DECISION_MADE
_RESPONSE = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED


def _rec(rid, record_type, *, pii=None, integrity=_V):
    ctx = rc_pb.RequestContext()
    ctx.record_type = record_type  # type: ignore[assignment]
    ctx.envelope.request_id = rid
    if pii is not None:
        ctx.audit.hint_variables["pii_types"] = pii
    return AuditEvidence(
        ref=EvidenceRef(source="wal:t", seq=0, request_id=rid),
        integrity=integrity,
        tenant_id="t",
        received_at_ns=0,
        record=ctx,
    )


def _a(rid, **kw):
    return _rec(rid, _DECISION, **kw)


def _b(rid, **kw):
    return _rec(rid, _RESPONSE, **kw)


def _redaction(ev):
    return RedactionHitRatio().measure(ev)[0]


def _surface(ev):
    return PiiExposureSurface().measure(ev)[0]


# --------------------------------------------------------------------------- #
# redaction_hit_ratio
# --------------------------------------------------------------------------- #


def test_no_pii_markers_is_zero_hit_ratio():
    m = _redaction([_a("r1"), _a("r2")])
    assert m.value == 0.0
    assert m.sample_size == 2  # measurable requests, PII or not
    assert m.dimension == "privacy_data_protection"


def test_redaction_hit_ratio_fraction():
    m = _redaction([_a("r1", pii="email"), _a("r2")])
    assert m.value == 0.5 and m.sample_size == 2


def test_redaction_marker_on_response_record():
    m = _redaction([_a("r1"), _b("r1", pii="email")])  # marker on B, one paired request
    assert m.value == 1.0 and m.sample_size == 1


def test_redaction_per_request_union_counts_once():
    # marker on BOTH the decision and response record of one request → one hit, one request.
    m = _redaction([_a("r1", pii="email"), _b("r1", pii="email")])
    assert m.value == 1.0 and m.sample_size == 1


def test_redaction_integrity_min():
    m = _redaction([_a("r1", pii="email", integrity=_U), _a("r2")])
    assert m.integrity is _U


def test_redaction_empty():
    m = _redaction([])
    assert m.sample_size == 0 and m.value == 0.0


# --------------------------------------------------------------------------- #
# pii_exposure_surface
# --------------------------------------------------------------------------- #


def test_surface_counts_distinct_types_across_window():
    m = _surface([_a("r1", pii="email"), _a("r2", pii="phone"), _a("r3", pii="email")])
    assert m.value == 2.0  # {email, phone}
    assert m.unit == "count"
    assert m.sample_size == 3


def test_surface_multi_type_value_is_split():
    m = _surface([_a("r1", pii="email,phone")])  # multi-type in one marker value
    assert m.value == 2.0 and m.sample_size == 1


def test_surface_no_pii_is_zero():
    m = _surface([_a("r1"), _a("r2")])
    assert m.value == 0.0 and m.sample_size == 2


def test_surface_integrity_min_and_empty():
    assert _surface([_a("r1", pii="email", integrity=_U)]).integrity is _U
    empty = _surface([])
    assert empty.sample_size == 0 and empty.value == 0.0


# --------------------------------------------------------------------------- #
# determinism + EV-6/EV-7 bridge
# --------------------------------------------------------------------------- #


def test_deterministic():
    ev = [_a("r1", pii="email"), _a("r2"), _b("r2", pii="phone")]
    assert RedactionHitRatio().measure(ev) == RedactionHitRatio().measure(ev)
    assert PiiExposureSurface().measure(ev) == PiiExposureSurface().measure(ev)


def test_redaction_lights_up_privacy_row_in_rubric():
    reg = load_registry()
    (m,) = RedactionHitRatio().measure(
        [_a("r1", pii="email"), _a("r2")]
    )  # sample_size 2
    report = evaluate(reg, [m], [], window=(0, 1), tenant_id="t")
    prv = next(d for d in report.dimensions if d.dimension == "privacy_data_protection")
    obj = next(o for o in prv.objectives if o.objective_id == "prv.l2.redaction")
    assert (
        obj.status == "met"
    )  # satisfied_when sample_size>=1 (was NotMeasured before EV-9)
