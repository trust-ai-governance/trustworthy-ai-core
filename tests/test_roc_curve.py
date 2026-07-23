"""C1-STABILITY-CURVE §3 — roc_curve / recall_at_fpr (score-driven two-sided curve).

The curve consumes the StabilityReport as its gate (points-vs-band) and per-case spectrum
(the band). Reuses the three-tuple denominator discipline + content_class slice + ""
bucket from C3-2 — but the criterion is `score >= τ` (no WAL), so a logprob judge is NOT
batch-excluded. §6-8 normalization guard also lives here.
"""

from __future__ import annotations

import dataclasses

import pytest

from treval.active_eval import (
    CorpusCase,
    ProbeResult,
    VendorLabel,
    first_vendor_label_score,
    normalization_attested,
    roc_curve,
    score_stability,
    two_way_normalized,
)


def _case(cid, content_class=""):
    return CorpusCase(
        id=cid,
        owasp="LLM01",
        dimension="robustness",
        attack_class="content",
        input="x",
        success_when="blocked_or_flagged",
        severity="high",
        source="core-authored",
        content_class=content_class,
    )


def _pr(cid, score=None, *, error=None, contaminated=False):
    labels = (VendorLabel(label="违规", score=score),) if score is not None else ()
    return ProbeResult(
        case_id=cid,
        request_id=f"r-{cid}",
        decision="ALLOW",
        response_text="",
        evidence=None,
        error=error,
        vendor_labels=labels,
        judge_reload_contaminated=contaminated,
    )


def _stable(results):
    """A curve_eligible StabilityReport: warmup + two identical measured passes over `results`."""
    return score_stability(
        [list(results), list(results), list(results)], score_of=first_vendor_label_score
    )


# --- §6-7: matched-FPR interpolation on the step curve --------------------------------- #


def test_recall_at_fpr_linear_interpolation():
    # benign: one at 0.5, nine at 0.0 ⇒ FPR grid steps 0.1 (τ<=0.5) → 0.0 (τ>0.5).
    # violating: one at 0.5, three at 0.9 ⇒ recall 1.0 (τ<=0.5) → 0.75 (τ in (0.5,0.9]).
    benign = [_case(f"b{i}") for i in range(10)]
    violating = [_case(f"v{i}") for i in range(4)]
    results = (
        [_pr("b0", 0.5)]
        + [_pr(f"b{i}", 0.0) for i in range(1, 10)]
        + [_pr("v0", 0.5), _pr("v1", 0.9), _pr("v2", 0.9), _pr("v3", 0.9)]
    )
    rep = roc_curve(
        benign, violating, results, _stable(results), score_of=first_vendor_label_score
    )
    # (fpr, recall) has (0.0, 0.75) and (0.1, 1.0); at fpr=0.05 → midpoint recall 0.875.
    low, point, high = rep.recall_at_fpr(0.05)
    assert point == pytest.approx(0.875)
    assert low == point == high  # curve_eligible ⇒ band collapses to a point


# --- §6-4: the stability gate — eligible emits points, jittery emits None + a band ----- #


def test_curve_eligible_emits_points_and_a_degenerate_band():
    benign = [_case("b0"), _case("b1")]
    violating = [_case("v0"), _case("v1")]
    results = [_pr("b0", 0.1), _pr("b1", 0.2), _pr("v0", 0.8), _pr("v1", 0.9)]
    rep = roc_curve(
        benign, violating, results, _stable(results), score_of=first_vendor_label_score
    )
    assert rep.points is not None and rep.by_class is not None  # curve is emitted
    lo, pt, hi = rep.recall_at_fpr(0.0)
    assert lo == pt == hi  # deterministic ⇒ no band


def test_not_curve_eligible_suppresses_points_but_still_gives_a_band():
    # Benign is deterministic (fixes the FPR grid); the violating case v0 jitters 0.4↔0.9 across
    # repeats — that spread straddles the matched-FPR threshold, so recall is genuinely uncertain.
    benign = [_case("b0"), _case("b1")]
    violating = [_case("v0")]
    results = [_pr("b0", 0.5), _pr("b1", 0.5), _pr("v0", 0.6)]  # representative pass
    jitter = score_stability(
        [
            [_pr("b0", 0.5), _pr("b1", 0.5), _pr("v0", 0.6)],  # warmup (dropped)
            [_pr("b0", 0.5), _pr("b1", 0.5), _pr("v0", 0.4)],
            [_pr("b0", 0.5), _pr("b1", 0.5), _pr("v0", 0.9)],
        ],
        score_of=first_vendor_label_score,
    )
    assert jitter.curve_eligible is False  # v0 not deterministic ⇒ gate closed
    rep = roc_curve(
        benign, violating, results, jitter, score_of=first_vendor_label_score
    )
    assert rep.points is None and rep.by_class is None  # jitter ⇒ no curve drawn
    low, point, high = rep.recall_at_fpr(0.5)
    assert low <= point <= high  # the "点 + 波动带" shape (§3.1-1)
    assert low < high  # v0's 0.4↔0.9 spread feeds through to a real band


# --- §6-5 / §6-6: three-tuple denominator + "" bucket; all-excluded ≠ 0% FPR ----------- #


def test_denominator_discipline_and_unclassified_bucket():
    benign = [_case("b_pol", "政治"), _case("b_un", "")]
    violating = [_case("v_pol", "政治"), _case("v_un", ""), _case("v_err", "政治")]
    results = [
        _pr("b_pol", 0.1),
        _pr("b_un", 0.2),
        _pr("v_pol", 0.8),
        _pr("v_un", 0.9),
        _pr(
            "v_err", error="Timeout"
        ),  # excluded (no score) — must NOT read as 0% anything
    ]
    rep = roc_curve(
        benign, violating, results, _stable(results), score_of=first_vendor_label_score
    )
    # "" is its own bucket, never folded into a classified class (§6-6 / §5.1-B1)
    assert set(rep.measurable) == {"政治", ""} == set(rep.excluded)
    assert rep.measurable["政治"] == (1, 1)  # v_pol measurable, b_pol measurable
    assert rep.excluded["政治"] == (1, 0)  # v_err excluded on the violating side
    assert rep.measurable[""] == (1, 1) and rep.excluded[""] == (0, 0)
    # §6-5 invariant: sum(measurable)+sum(excluded) == matched probes (nothing vanishes)
    matched = len(results)
    tot = sum(
        m + e
        for cc in rep.measurable
        for m, e in [(sum(rep.measurable[cc]), sum(rep.excluded[cc]))]
    )
    assert tot == matched


def test_all_excluded_benign_side_surfaces_in_excluded_not_a_fake_zero_fpr():
    # A class whose benign side is all-errored has benign measurable==0 — it must land in
    # `excluded`, never be read as 0% FPR (§6-5). (An all-errored case is also `insufficient`
    # in stability ⇒ the whole report is not curve_eligible ⇒ points/by_class None anyway.)
    benign = [_case("b_pol", "政治")]
    violating = [_case("v_pol", "政治")]
    results = [_pr("b_pol", error="Timeout"), _pr("v_pol", 0.8)]
    stab = _stable(results)
    assert (
        stab.curve_eligible is False
    )  # b_pol has no score ⇒ insufficient ⇒ gate closed
    rep = roc_curve(benign, violating, results, stab, score_of=first_vendor_label_score)
    assert rep.points is None and rep.by_class is None  # no fake curve drawn
    assert rep.excluded["政治"] == (0, 1)  # benign excluded, surfaced (not a hidden 0%)
    assert rep.measurable["政治"] == (1, 0)  # benign measurable == 0 (honestly)


def test_one_sided_class_absent_from_by_class_but_surfaced_in_measurable():
    # Even on a curve_eligible report, a class measurable on ONLY one side gets no by_class curve
    # (a one-sided curve would be a fake 0% on the missing side); it still surfaces in measurable.
    benign = [_case("b_pol", "政治")]
    violating = [
        _case("v_pol", "政治"),
        _case("v_terror", "暴恐"),
    ]  # 暴恐 violating-only
    results = [_pr("b_pol", 0.1), _pr("v_pol", 0.8), _pr("v_terror", 0.9)]
    rep = roc_curve(
        benign, violating, results, _stable(results), score_of=first_vendor_label_score
    )
    assert rep.by_class is not None  # curve_eligible ⇒ curves emitted
    assert "政治" in rep.by_class  # both sides measurable
    assert "暴恐" not in rep.by_class  # violating-only ⇒ no FPR side ⇒ no curve
    assert rep.measurable["暴恐"] == (1, 0)  # but surfaced: 1 violating, 0 benign


# --- §6-8: normalization first-check guard --------------------------------------------- #


def test_two_way_normalized_and_attestation_guard():
    # Self-built path: 违规 + 安全 sum to 1.0 by softmax construction ⇒ normalized + attested.
    softmax = ProbeResult(
        case_id="a",
        request_id="r",
        decision="ALLOW",
        response_text="",
        evidence=None,
        vendor_labels=(VendorLabel("违规", score=0.7), VendorLabel("安全", score=0.3)),
    )
    assert two_way_normalized(softmax) is True
    assert normalization_attested(softmax) is True
    # A remote read that is NOT a normalized 2-way distribution AND records no read-strategy in
    # vendor_version is unattributable ⇒ the guard goes red (证据缺席≠证据).
    remote_unrecorded = dataclasses.replace(
        softmax, vendor_labels=(VendorLabel("politics", score=0.6),), vendor_version=""
    )
    assert two_way_normalized(remote_unrecorded) is False
    assert normalization_attested(remote_unrecorded) is False
    # Same read, but the contract-id IS stamped ⇒ attributable again.
    remote_recorded = dataclasses.replace(
        remote_unrecorded, vendor_version="sm:v3:contract-B"
    )
    assert normalization_attested(remote_recorded) is True
