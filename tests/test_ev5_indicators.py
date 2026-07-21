"""EV-5a/5b — passive WAL indicators (chain_integrity, duration_p99, terminal_error_ratio,
unclosed_loop_rate) + the ② min-integrity flow into the EV-7 rubric gate.

Fixtures build AuditEvidence directly (the EV-4 block_rate pattern) — walgen writes WAL bytes
for the reader tests; an indicator only needs the decoded AuditEvidence stream.
"""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval import (
    ChainIntegrity,
    DurationP50,
    DurationP95,
    DurationP99,
    TerminalErrorRatio,
    UnclosedLoopRate,
    evaluate,
    load_registry,
)
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_V = IntegrityStatus.VERIFIED
_U = IntegrityStatus.UNVERIFIED
_BR = IntegrityStatus.BROKEN
_DECISION = rc_pb.AUDIT_RECORD_TYPE_DECISION_MADE
_RESPONSE = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK


def _a(rid, *, final=_ALLOW, ts=0, seq=0, integrity=_V):
    ctx = rc_pb.RequestContext()
    ctx.record_type = _DECISION  # type: ignore[assignment]
    ctx.envelope.request_id = rid
    ctx.envelope.received_at_ns = ts
    ctx.decision.final_decision = final  # type: ignore[assignment]
    return AuditEvidence(
        ref=EvidenceRef(source="wal:t", seq=seq, request_id=rid),
        integrity=integrity,
        tenant_id="t",
        received_at_ns=ts,
        record=ctx,
    )


def _b(
    rid,
    *,
    duration_ms=0,
    final_terminal="ALLOWED",
    errors=0,
    audit_errors=0,
    ts=0,
    integrity=_V,
):
    ctx = rc_pb.RequestContext()
    ctx.record_type = _RESPONSE  # type: ignore[assignment]
    ctx.envelope.request_id = rid
    ctx.envelope.received_at_ns = ts
    ctx.response.duration_ms = duration_ms
    ctx.response.final_terminal = final_terminal
    for _ in range(errors):
        ctx.response.errors.add()
    for _ in range(audit_errors):
        ctx.audit.errors.add()
    return AuditEvidence(
        ref=EvidenceRef(source="wal:t", seq=0, request_id=rid),
        integrity=integrity,
        tenant_id="t",
        received_at_ns=ts,
        record=ctx,
    )


def _rec(integrity=_V, rid="r"):
    """A bare record (for chain_integrity, which is record-type-agnostic)."""
    ctx = rc_pb.RequestContext()
    ctx.record_type = _DECISION  # type: ignore[assignment]
    ctx.envelope.request_id = rid
    return AuditEvidence(
        ref=EvidenceRef(source="wal:t", seq=0, request_id=rid),
        integrity=integrity,
        tenant_id="t",
        received_at_ns=0,
        record=ctx,
    )


# --------------------------------------------------------------------------- #
# chain_integrity — the requires_integrity moat
# --------------------------------------------------------------------------- #


def test_chain_integrity_all_verified():
    (m,) = ChainIntegrity().measure([_rec(_V), _rec(_V), _rec(_V)])
    assert m.value == 1.0
    assert m.sample_size == 3
    assert m.integrity is _V
    assert m.dimension == "transparency_accountability"


def test_chain_integrity_broken_tail_value_below_one_and_integrity_broken():
    # a chain break poisons the tail (EV-1) → those records BROKEN.
    (m,) = ChainIntegrity().measure([_rec(_V), _rec(_V), _rec(_BR), _rec(_BR)])
    assert m.value == 0.5  # 2 of 4 verified
    assert m.integrity is _BR  # min → BROKEN (rubric will resolve unverified_evidence)


def test_chain_integrity_unverified_source_flows_to_measurement():
    (m,) = ChainIntegrity().measure([_rec(_U), _rec(_U)])
    assert m.value == 0.0  # UNVERIFIED is not "verified"
    assert m.integrity is _U


def test_chain_integrity_empty_is_zero_sample():
    (m,) = ChainIntegrity().measure([])
    assert m.sample_size == 0 and m.value == 0.0
    assert (
        m.integrity is _V
    )  # empty → default (rubric short-circuits on sample_size==0)


# --------------------------------------------------------------------------- #
# duration_p99
# --------------------------------------------------------------------------- #


def test_duration_p99_nearest_rank():
    evidence = [_b(f"r{i}", duration_ms=i) for i in range(1, 101)]  # 1..100 ms
    (m,) = DurationP99().measure(evidence)
    assert m.value == 99.0  # nearest-rank p99 of 1..100
    assert m.unit == "ms"
    assert m.sample_size == 100


def test_duration_p50_p95_nearest_rank():
    # P3C-harness C1: the distribution, not just the tail. Same nearest-rank formula,
    # different rank. 1..100 → p50 = ceil(0.50·100) = 50th, p95 = 95th.
    evidence = [_b(f"r{i}", duration_ms=i) for i in range(1, 101)]
    (p50,) = DurationP50().measure(evidence)
    (p95,) = DurationP95().measure(evidence)
    assert p50.value == 50.0 and p50.indicator_id == "duration_p50"
    assert p95.value == 95.0 and p95.indicator_id == "duration_p95"
    assert p50.dimension == p95.dimension == "efficient_reliability"


def test_duration_percentiles_share_exclusions_and_ordering():
    # The three read the SAME sample (B records, duration > 0); only the rank differs, so
    # p50 <= p95 <= p99 always and all agree on sample_size.
    evidence = [_a("r0"), _b("z", duration_ms=0)] + [
        _b(f"r{i}", duration_ms=i) for i in (5, 200, 30, 90, 9999)
    ]
    p50, p95, p99 = (
        cls().measure(evidence)[0] for cls in (DurationP50, DurationP95, DurationP99)
    )
    assert p50.sample_size == p95.sample_size == p99.sample_size == 5
    assert p50.value <= p95.value <= p99.value


def test_duration_p99_excludes_a_records_and_zero_durations():
    evidence = [
        _a("r1"),  # decision record — no latency
        _b("r2", duration_ms=0),  # absent duration
        _b("r3", duration_ms=42),
    ]
    (m,) = DurationP99().measure(evidence)
    assert m.sample_size == 1 and m.value == 42.0


def test_duration_p99_integrity_min():
    (m,) = DurationP99().measure(
        [_b("r1", duration_ms=10, integrity=_U), _b("r2", duration_ms=20)]
    )
    assert m.integrity is _U


def test_duration_p99_empty():
    (m,) = DurationP99().measure([_a("r1")])  # no B with a duration
    assert m.sample_size == 0 and m.value == 0.0


# --------------------------------------------------------------------------- #
# terminal_error_ratio
# --------------------------------------------------------------------------- #


def test_terminal_error_ratio_counts_errors_over_b_records():
    evidence = [
        _b("r1", final_terminal="ALLOWED"),
        _b("r2", final_terminal="BLOCKED"),  # a block is NOT a reliability error
        _b("r3", final_terminal="ERROR"),  # terminal string
        _b("r4", errors=1),  # response.errors non-empty
    ]
    (m,) = TerminalErrorRatio().measure(evidence)
    assert m.sample_size == 4
    assert m.value == 0.5  # r3 + r4


def test_terminal_error_ratio_audit_errors_and_timeout():
    evidence = [_b("r1", final_terminal="TIMEOUT"), _b("r2", audit_errors=1), _b("r3")]
    (m,) = TerminalErrorRatio().measure(evidence)
    assert m.value == round(2 / 3, 10) or abs(m.value - 2 / 3) < 1e-9


def test_terminal_error_ratio_excludes_a_records():
    (m,) = TerminalErrorRatio().measure([_a("r1"), _b("r2")])
    assert m.sample_size == 1  # only the B record


# --------------------------------------------------------------------------- #
# unclosed_loop_rate
# --------------------------------------------------------------------------- #


def test_unclosed_loop_rate_closed_vs_unclosed_vs_inflight():
    window = 100
    # newest ts = 1000 → cutoff = 900. An allowed-A at ts<=900 with no B = unclosed;
    # an allowed-A at ts>900 with no B = in-flight (not counted).
    evidence = [
        _a("closed", ts=500),
        _b("closed", ts=510),  # paired → closed
        _a("stale", ts=500),  # allowed, no B, old → UNCLOSED
        _a("inflight", ts=1000),  # allowed, no B, recent → in-flight
        _a("blocked", final=_BLOCK, ts=500),  # not forwarded → not in denominator
    ]
    (m,) = UnclosedLoopRate(close_window_ns=window).measure(evidence)
    assert m.sample_size == 3  # closed + stale + inflight (allowed-A only)
    assert m.value == round(1 / 3, 10) or abs(m.value - 1 / 3) < 1e-9  # only "stale"


def test_unclosed_loop_rate_all_closed_is_zero():
    ev = [_a("r1", ts=1), _b("r1", ts=2), _a("r2", ts=1), _b("r2", ts=2)]
    (m,) = UnclosedLoopRate(close_window_ns=0).measure(ev)
    assert m.value == 0.0 and m.sample_size == 2


def test_unclosed_loop_rate_integrity_min():
    ev = [_a("r1", ts=1, integrity=_U)]  # window 0, no B, older-than-cutoff(=newest)
    (m,) = UnclosedLoopRate(close_window_ns=0).measure(ev)
    assert m.integrity is _U


def test_unclosed_loop_rate_empty():
    (m,) = UnclosedLoopRate().measure([])
    assert m.sample_size == 0 and m.value == 0.0


def test_unclosed_window_env_default_and_fallback(monkeypatch):
    from treval.indicators.unclosed_loop_rate import (
        _DEFAULT_WINDOW_NS,
        UnclosedLoopRate,
    )

    monkeypatch.delenv("TREVAL_UNCLOSED_WINDOW_NS", raising=False)
    assert UnclosedLoopRate()._window_ns == _DEFAULT_WINDOW_NS  # unset → 5 min
    monkeypatch.setenv("TREVAL_UNCLOSED_WINDOW_NS", "30000000000")
    assert UnclosedLoopRate()._window_ns == 30_000_000_000  # 30 s (eval-fast)
    monkeypatch.setenv("TREVAL_UNCLOSED_WINDOW_NS", "not-a-number")
    assert UnclosedLoopRate()._window_ns == _DEFAULT_WINDOW_NS  # garbage → default


# --------------------------------------------------------------------------- #
# ② → EV-7: a BROKEN/UNVERIFIED chain_integrity can't satisfy the requires_integrity
# objective it binds (end-to-end with the shipped registry).
# --------------------------------------------------------------------------- #


def test_chain_integrity_broken_resolves_unverified_evidence_in_rubric():
    reg = load_registry()
    (broken,) = ChainIntegrity().measure(
        [_rec(_V), _rec(_BR)]
    )  # value<1, integrity BROKEN
    report = evaluate(reg, [broken], [], window=(0, 1), tenant_id="t")
    trn = next(
        d for d in report.dimensions if d.dimension == "transparency_accountability"
    )
    obj = next(
        o for o in trn.objectives if o.objective_id == "trn.l3.audit_chain_intact"
    )
    assert obj.status == "unverified_evidence"  # a broken chain can't verify itself


def test_chain_integrity_verified_meets_the_integrity_objective():
    reg = load_registry()
    (ok,) = ChainIntegrity().measure([_rec(_V), _rec(_V)])  # value 1.0, VERIFIED
    report = evaluate(reg, [ok], [], window=(0, 1), tenant_id="t")
    trn = next(
        d for d in report.dimensions if d.dimension == "transparency_accountability"
    )
    obj = next(
        o for o in trn.objectives if o.objective_id == "trn.l3.audit_chain_intact"
    )
    assert obj.status == "met"  # value>=1 AND VERIFIED source
