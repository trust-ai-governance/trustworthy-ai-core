"""EV-AE12 — async Tier-2 shadow-judge attribution (caught_by_tier2 + lift/flag indicators).

Pure logic is CI-tested with fabricated record_type=3 governance evidence; the live async
drain (GatewayTarget.drain_governance) is operator-run and not exercised here.
"""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval import (
    BenignShadowFlagRate,
    ProbeResult,
    Tier2ShadowRecallLift,
    caught_by_tier2,
    injection_score,
)
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK


def _ev(ctx: rc_pb.RequestContext, cid: str) -> AuditEvidence:
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=0, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="__eval__",
        received_at_ns=0,
        record=ctx,
    )


def _decision(cid: str, *, block: bool) -> AuditEvidence:
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.decision.final_decision = _BLOCK if block else _ALLOW  # type: ignore[assignment]
    return _ev(ctx, cid)


def _governance(
    cid: str, *, hint: bool, tier: str | None = "2", score: float | None = None
) -> AuditEvidence:
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.record_type = (
        rc_pb.AUDIT_RECORD_TYPE_GOVERNANCE_OBSERVED
    )  # async Tier-2 governance
    ctx.audit.hint_emitted = hint
    rule = ctx.decision.rules_evaluated.add()
    rule.rule_id = "inj-tier2-judge"
    rule.matched = True
    if tier is not None:
        rule.tags["tier"] = tier
    if score is not None:
        ctx.decision.scores["injection_score"] = score
    return _ev(ctx, cid)


def _probe(
    cid: str,
    *,
    tier1: bool = False,
    gov: AuditEvidence | None = None,
    error: str | None = None,
) -> ProbeResult:
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="BLOCK" if tier1 else "ALLOW",
        response_text="",
        evidence=None if error else _decision(cid, block=tier1),
        governance_evidence=gov,
        error=error,
        # E3-n ②: these tests all model a run where the async drain DID execute (they assert the
        # measured lift/no-async/no-WAL behavior), so the drain-executed flag is set — the n/a gate
        # (drain-never-ran) is covered by the dedicated E3-n ② tests, not these.
        tier2_drain_executed=True,
    )


def test_caught_by_tier2_requires_hint_and_tier2_tag():
    assert caught_by_tier2(_probe("a", gov=_governance("a", hint=True))) is True
    # a hint from a NON-tier-2 rule is not a Tier-2 catch
    assert (
        caught_by_tier2(_probe("b", gov=_governance("b", hint=True, tier="1"))) is False
    )
    # a tier-2 rule that did NOT emit a hint (score below τ) is not a catch
    assert caught_by_tier2(_probe("c", gov=_governance("c", hint=False))) is False
    # no async record ⇒ not caught (never a silent True)
    assert caught_by_tier2(_probe("d", gov=None)) is False


def test_injection_score_is_diagnostic_only():
    pr = _probe("a", gov=_governance("a", hint=True, score=0.95))
    assert injection_score(pr) == 0.95
    assert injection_score(_probe("b", gov=_governance("b", hint=True))) is None
    assert injection_score(_probe("c", gov=None)) is None


def test_tier2_lift_counts_only_lexical_missed_rescues():
    results = [
        _probe(
            "a", tier1=True, gov=_governance("a", hint=True)
        ),  # already Tier-1 → not lift
        _probe(
            "b", tier1=False, gov=_governance("b", hint=True)
        ),  # lexical-missed → RESCUED
        _probe(
            "c", tier1=False, gov=_governance("c", hint=False)
        ),  # missed, judge below τ
        _probe("d", tier1=False, gov=None),  # missed, no async record → no-async
    ]
    (m,) = Tier2ShadowRecallLift().measure(results)
    assert m.indicator_id == "tier2_shadow_recall_lift"
    assert m.sample_size == 4
    assert m.value == 0.25  # 1 rescued / 4 measurable
    assert "rescued 1 of 3" in m.notes  # 3 lexical-missed (b, c, d)
    assert "combined recall = 50%" in m.notes  # (1 Tier-1 + 1 rescue) / 4
    assert "1 probe(s) had NO async record" in m.notes


def test_benign_shadow_flag_rate():
    results = [
        _probe("a", gov=_governance("a", hint=True)),  # Tier-2 flagged a benign
        _probe("b", gov=_governance("b", hint=False)),  # judge below τ → not flagged
        _probe("c", gov=None),  # no async record
    ]
    (m,) = BenignShadowFlagRate().measure(results)
    assert m.indicator_id == "benign_shadow_flag_rate"
    assert m.sample_size == 3
    assert abs(m.value - 1 / 3) < 1e-9
    assert "1/3 benign flagged" in m.notes
    assert "1 probe(s) had NO async record" in m.notes


def test_errored_probe_excluded_from_lift_denominator():
    results = [
        _probe("a", tier1=False, gov=_governance("a", hint=True)),
        _probe("e", error="Timeout"),
    ]
    (m,) = Tier2ShadowRecallLift().measure(results)
    assert m.sample_size == 1  # errored probe excluded
    assert m.value == 1.0
    assert "1 error(s) excluded" in m.notes


# --------------------------------------------------------------------------- #
# GATE-LASTMILE P8 — no WAL ⇒ Tier-2 is UNOBSERVABLE, not a zero lift/rate.
# --------------------------------------------------------------------------- #


def _no_wal_probe(cid: str) -> ProbeResult:
    """A probe from a run with no WAL access: no decision record, so nothing about Tier-2
    can be observed. Distinct from `gov=None` (WAL present, Tier-2 simply did not fire)."""
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="ALLOW",
        response_text="",
        evidence=None,
        governance_evidence=None,
        tier2_drain_executed=True,  # E3-n ②: the drain ran; this probe simply had no WAL to read
    )


def test_lift_without_wal_is_insufficient_data_not_zero():
    """The live no-WAL run reported `tier2_shadow_recall_lift = 0% (n=28)` — a confident zero
    over probes where Tier-2 could not be observed at all (P4's failure mode, other family)."""
    (m,) = Tier2ShadowRecallLift().measure([_no_wal_probe(str(i)) for i in range(28)])
    assert m.sample_size == 0, (
        "28 unobservable probes must not become a 28-sample 0% lift"
    )
    assert "insufficient_data" in m.notes
    assert "28 with no WAL record" in m.notes


def test_benign_shadow_flag_without_wal_is_insufficient_data_not_zero():
    (m,) = BenignShadowFlagRate().measure([_no_wal_probe(str(i)) for i in range(20)])
    assert m.sample_size == 0
    assert "insufficient_data" in m.notes
    assert "20 with no WAL record" in m.notes


def test_p8_does_not_change_a_governed_run_missing_only_async_records():
    """🔴 The P8 regression red line: a probe WITH a WAL record but no Tier-2 record stays in
    the denominator — Tier-2 genuinely added nothing there (a Tier-1 block is never Tier-2
    scored). Live evidence: `rescued 3 of 3 lexical-missed (Tier-1 caught 25/28)` — every
    lexical miss HAD an async record, so the 19 missing ones were all Tier-1 catches.
    P8 must therefore leave the working numbers untouched."""
    results = [_probe("m", tier1=False, gov=_governance("m", hint=True))] + [
        _probe(f"t{i}", tier1=True, gov=None) for i in range(9)
    ]
    (m,) = Tier2ShadowRecallLift().measure(results)
    assert m.sample_size == 10, "WAL-present probes stay in the denominator"
    assert abs(m.value - 0.1) < 1e-9  # 1 rescued / 10 — unchanged by P8
    # 🔴 E3F §3.2-3 — the 9 Tier-1-HARD-blocked probes are `skipped_prefiltered` (judge never scores a
    # blocked request, by design), NOT `no_async`. The old assertion conflated the two; F3 splits them.
    assert "9 Tier-1-hard-blocked (judge pre-filtered" in m.notes
    assert "had NO async record" not in m.notes  # none were genuinely missing a record
    assert "no WAL record" not in m.notes  # nothing was excluded for lack of WAL


def test_mixed_wal_and_no_wal_splits_the_denominator():
    results = [
        _probe("a", tier1=False, gov=_governance("a", hint=True)),
        _probe("b", tier1=True, gov=None),
        _no_wal_probe("c"),
        _no_wal_probe("d"),
    ]
    (m,) = Tier2ShadowRecallLift().measure(results)
    assert m.sample_size == 2  # only the WAL-backed probes
    assert "2 with no WAL record" in m.notes
