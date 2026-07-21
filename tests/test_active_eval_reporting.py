"""Tests for the per-attack_class catch attribution helper (EV-AE6 follow-up).

The pure helper is CI-tested; the rendered report against a live gateway is an
internal Platform artifact (gitignored), not exercised here.
"""

from __future__ import annotations

import dataclasses

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval import (
    CorpusCase,
    ProbeResult,
    attack_class_breakdown,
    false_positive_by_content_class,
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


# --------------------------------------------------------------------------- #
# false_positive_by_content_class (P3C-harness C3-2): per-content_class FPR slice.
# On the FPR side `_probe(caught=True)` = a HARD block on a BENIGN case = a false
# positive; errored / evidence-less probes are `excluded` (Option C 3-tuple), NOT
# folded into the denominator (that would be §C2-2's fake 0%, per class).
# --------------------------------------------------------------------------- #


def _benign(cid, content_class):
    """A benign case carrying a content_class slice key (P3C-harness C3-2)."""
    return dataclasses.replace(_case(cid, "benign"), content_class=content_class)


def test_fp_by_content_class_unclassified_is_own_bucket_never_folded():
    cases = [
        _benign("p1", "政治"),
        _benign("p2", "政治"),
        _benign("v1", "暴恐"),
        _benign("u1", ""),
        _benign("u2", ""),
    ]
    results = [
        _probe("p1", caught=True),  # HARD block on benign → false positive
        _probe("p2", caught=False),  # allowed → measurable, clean
        _probe("v1", caught=True),  # false positive
        _probe("u1", caught=False),  # unclassified, measurable
        _probe("u2", error="Timeout"),  # unclassified, excluded
    ]
    out = false_positive_by_content_class(cases, results)
    # ① "" is an independent key alongside the classified classes, sorted.
    assert set(out) == {"政治", "暴恐", ""}
    assert list(out) == sorted(out)  # deterministic, sorted by content_class
    assert out["政治"] == (1, 2, 0)  # 1 false_pos / 2 measurable / 0 excluded
    assert out["暴恐"] == (1, 1, 0)
    assert out[""] == (0, 1, 1)  # unclassified: 0 fp, 1 measurable, 1 excluded
    # ② §5.1-B1: sum(measurable) + sum(excluded) == matched probes (nothing vanishes),
    #    and the "" probes are NOT folded into any classified class's counts.
    matched = len(results)
    measurable = sum(m for _, m, _ in out.values())
    excluded = sum(e for _, _, e in out.values())
    assert measurable + excluded == matched
    classified = sum(m + e for cc, (_, m, e) in out.items() if cc != "")
    assert classified == 3  # p1, p2, v1 only — u1/u2 live solely in the "" bucket


def test_fp_by_content_class_all_unclassified_single_bucket():
    # The current shipped-corpus shape (every case content_class == "") → one "" bucket.
    cases = [_benign("a", ""), _benign("b", ""), _benign("c", "")]
    results = [
        _probe("a", caught=True),
        _probe("b", caught=False),
        _probe("c", caught=False),
    ]
    assert false_positive_by_content_class(cases, results) == {"": (1, 3, 0)}


def test_fp_by_content_class_empty_results():
    assert false_positive_by_content_class([_benign("a", "政治")], []) == {}


def test_fp_by_content_class_errored_and_evidence_less_are_excluded_not_measurable():
    # The crux of the Option-C ruling: excluded probes are NOT in the denominator. A
    # 2-tuple (0, 2) here would read as a clean 0% FPR; (0, 0, 2) shows measurable=0 —
    # nothing was actually measured, so no 0% is claimed.
    cases = [_benign("e", "政治"), _benign("n", "政治")]
    results = [_probe("e", error="Timeout"), _probe("n", evidence=False)]
    assert false_positive_by_content_class(cases, results) == {"政治": (0, 0, 2)}
