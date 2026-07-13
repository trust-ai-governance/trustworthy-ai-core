"""EV-9 — boundary_breach_rate: the composite (untrusted-channel shadow rule OR authz denial),
identified by rule_id (NOT the dimension tag, which would over-count injection detection).

Fixtures build AuditEvidence directly (EV-4 pattern); the A↔B grouping via join_ab is tested
in test_correlate.py. Only drift_alert_count is deferred (EV-9 §3, no code); the PII pair is
tested in test_pii_indicators.py.
"""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval import BoundaryBreachRate
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_V = IntegrityStatus.VERIFIED
_U = IntegrityStatus.UNVERIFIED
_DECISION = rc_pb.AUDIT_RECORD_TYPE_DECISION_MADE
_RESPONSE = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW

_CHANNEL = "inj-indirect-channel-shadow"
_PHRASING = "inj-indirect-phrasing-shadow"


def _a(rid, *, allowed=None, rules=(), integrity=_V):
    ctx = rc_pb.RequestContext()
    ctx.record_type = _DECISION  # type: ignore[assignment]
    ctx.envelope.request_id = rid
    ctx.decision.final_decision = _ALLOW  # type: ignore[assignment]
    if allowed is not None:
        ctx.decision.authorization.allowed = allowed  # touching sets HasField
    for rule_id, matched in rules:
        r = ctx.decision.rules_evaluated.add()
        r.rule_id = rule_id
        r.matched = matched
    return AuditEvidence(
        ref=EvidenceRef(source="wal:t", seq=0, request_id=rid),
        integrity=integrity,
        tenant_id="t",
        received_at_ns=0,
        record=ctx,
    )


def _b(rid, *, response_rules=(), integrity=_V):
    ctx = rc_pb.RequestContext()
    ctx.record_type = _RESPONSE  # type: ignore[assignment]
    ctx.envelope.request_id = rid
    for rule_id, matched in response_rules:
        r = ctx.response.on_tool_response_rules.add()
        r.rule_id = rule_id
        r.matched = matched
    return AuditEvidence(
        ref=EvidenceRef(source="wal:t", seq=0, request_id=rid),
        integrity=integrity,
        tenant_id="t",
        received_at_ns=0,
        record=ctx,
    )


def _measure(evidence):
    return BoundaryBreachRate().measure(evidence)[0]


# --------------------------------------------------------------------------- #
# The composite (a) OR (b)
# --------------------------------------------------------------------------- #


def test_all_clean_is_zero():
    m = _measure([_a("r1", allowed=True), _b("r1")])
    assert m.value == 0.0
    assert m.sample_size == 1  # one request (paired A+B counts once)
    assert m.dimension == "robustness"


def test_authz_denial_only_is_a_breach():
    m = _measure([_a("r1", allowed=False)])  # orphan-A, authz denied
    assert m.value == 1.0 and m.sample_size == 1


def test_channel_shadow_on_response_record_is_a_breach():
    m = _measure([_a("r1", allowed=True), _b("r1", response_rules=[(_CHANNEL, True)])])
    assert m.value == 1.0


def test_channel_shadow_on_decision_record_is_a_breach():
    m = _measure([_a("r1", allowed=True, rules=[(_CHANNEL, True)]), _b("r1")])
    assert m.value == 1.0


def test_orphan_b_channel_shadow_is_a_breach():
    m = _measure([_b("r1", response_rules=[(_CHANNEL, True)])])  # response, no decision
    assert m.value == 1.0 and m.sample_size == 1


def test_both_signals_counted_once_per_request():
    m = _measure([_a("r1", allowed=False, rules=[(_CHANNEL, True)])])
    assert m.value == 1.0 and m.sample_size == 1  # one breach, not two


# --------------------------------------------------------------------------- #
# The over-count guards (the architect's precision point)
# --------------------------------------------------------------------------- #


def test_phrasing_shadow_does_not_count_channel_only():
    m = _measure([_a("r1", allowed=True, rules=[(_PHRASING, True)]), _b("r1")])
    assert m.value == 0.0  # phrasing is injection phrasing, not a channel crossing


def test_other_robustness_rule_does_not_count():
    # a direct-block injection rule (same dimension tag, different rule_id) must NOT count —
    # matching by rule_id, not by tags["dimension"], is what prevents the over-count.
    m = _measure([_a("r1", allowed=True, rules=[("inj-direct-block", True)]), _b("r1")])
    assert m.value == 0.0


def test_unmatched_channel_rule_is_not_a_breach():
    m = _measure([_a("r1", allowed=True, rules=[(_CHANNEL, False)])])
    assert m.value == 0.0  # evaluated but did not match


def test_unset_authorization_is_not_a_denial():
    # proto3 bool default: an A record that never ran authz has allowed=false, but HasField
    # is False → NOT a denial (would be a false positive without the guard).
    m = _measure([_a("r1", allowed=None)])
    assert m.value == 0.0


def test_authz_allowed_true_is_not_a_breach():
    m = _measure([_a("r1", allowed=True)])
    assert m.value == 0.0


# --------------------------------------------------------------------------- #
# Aggregate + integrity + determinism
# --------------------------------------------------------------------------- #


def test_mixed_rate():
    evidence = [
        _a("clean", allowed=True),
        _b("clean"),
        _a("denied", allowed=False),  # breach (b)
        _a("shadow", allowed=True),
        _b("shadow", response_rules=[(_CHANNEL, True)]),  # breach (a)
        _a("clean2", allowed=True),
    ]
    m = _measure(evidence)
    assert m.sample_size == 4  # clean, denied, shadow, clean2
    assert m.value == 0.5  # denied + shadow


def test_integrity_is_min_over_consumed_records():
    m = _measure([_a("r1", allowed=True, integrity=_U), _b("r1")])
    assert m.integrity is _U


def test_empty_is_zero_sample():
    m = _measure([])
    assert m.sample_size == 0 and m.value == 0.0


def test_deterministic():
    ev = [_a("r1", allowed=False), _a("r2", allowed=True), _b("r2")]
    assert BoundaryBreachRate().measure(ev) == BoundaryBreachRate().measure(ev)


# --------------------------------------------------------------------------- #
# EV-6 bridge — boundary_breach_rate now resolves its registry bindings
# --------------------------------------------------------------------------- #


def test_boundary_breach_registered_and_resolves():
    from treval import build_default_registry, load_registry, validate_against

    sdk = build_default_registry()
    assert "boundary_breach_rate" in sdk.ids()
    problems = validate_against(load_registry(), indicator_ids=sdk.ids())
    # rob.l3.unified_risk_score + rob.l4.breach_baseline bind boundary_breach_rate → resolved.
    assert not any("boundary_breach_rate" in p for p in problems)
