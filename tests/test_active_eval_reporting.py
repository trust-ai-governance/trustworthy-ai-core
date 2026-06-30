"""Tests for the per-attack_class catch attribution helper (EV-AE6 follow-up).

The pure helper is CI-tested; the rendered report against a live gateway is an
internal Platform artifact (gitignored), not exercised here.
"""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval import (
    CorpusCase,
    ProbeResult,
    attack_class_breakdown,
    format_attribution_report,
)
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK


def _case(cid, attack_class):
    return CorpusCase(
        id=cid,
        owasp="LLM01",
        dimension="robustness",
        attack_class=attack_class,
        input="x",
        success_when="blocked_or_flagged",
        severity="high",
        source="core-authored",
    )


def _probe(cid, *, caught=False, evidence=True, error=None):
    ev = None
    if error is None and evidence:
        ctx = rc_pb.RequestContext()
        ctx.envelope.request_id = f"req-{cid}"
        ctx.decision.final_decision = _BLOCK if caught else _ALLOW  # type: ignore[assignment]
        ev = AuditEvidence(
            ref=EvidenceRef(source="wal:x", seq=0, request_id=f"req-{cid}"),
            integrity=IntegrityStatus.VERIFIED,
            tenant_id="__eval__",
            received_at_ns=0,
            record=ctx,
        )
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="BLOCK" if caught else "ALLOW",
        response_text="",
        evidence=ev,
        error=error,
    )


def test_breakdown_groups_caught_and_total_by_class():
    cases = [
        _case("a1", "direct"),
        _case("a2", "direct"),
        _case("a3", "direct"),
        _case("b1", "indirect"),
        _case("b2", "indirect"),
    ]
    results = [
        _probe("a1", caught=True),
        _probe("a2", caught=False),
        _probe("a3", caught=True),
        _probe("b1", caught=False),
        _probe("b2", caught=True),
    ]
    assert attack_class_breakdown(cases, results) == {
        "direct": (2, 3),
        "indirect": (1, 2),
    }


def test_breakdown_matches_by_id_not_order():
    cases = [_case("x", "direct"), _case("y", "indirect")]
    results = [_probe("y", caught=True), _probe("x", caught=False)]  # reversed
    assert attack_class_breakdown(cases, results) == {
        "direct": (0, 1),
        "indirect": (1, 1),
    }


def test_breakdown_errored_and_evidence_less_count_in_total_not_caught():
    cases = [_case("e", "direct"), _case("n", "direct")]
    results = [_probe("e", error="Timeout"), _probe("n", evidence=False)]
    # both unmeasurable as "caught" → in total, not in caught
    assert attack_class_breakdown(cases, results) == {"direct": (0, 2)}


def test_breakdown_is_sorted_and_deterministic():
    cases = [_case("z", "zeta"), _case("a", "alpha")]
    results = [_probe("z", caught=True), _probe("a", caught=False)]
    out = attack_class_breakdown(cases, results)
    assert list(out) == ["alpha", "zeta"]  # sorted by attack_class
    assert attack_class_breakdown(cases, results) == out  # deterministic


def test_breakdown_ignores_probes_without_a_matching_case():
    cases = [_case("a", "direct")]
    results = [_probe("a", caught=True), _probe("orphan", caught=True)]
    assert attack_class_breakdown(cases, results) == {"direct": (1, 1)}


def test_format_report_is_internal_and_lists_per_case():
    cases = [_case("a1", "direct"), _case("b1", "indirect")]
    results = [_probe("a1", caught=True), _probe("b1", caught=False)]
    report = format_attribution_report(cases, results)
    assert "INTERNAL — do not publish" in report
    assert "[CAUGHT] a1" in report and "[missed] b1" in report
    assert "caught 1/2" in report
    assert "direct: 1/1" in report and "indirect: 0/1" in report
