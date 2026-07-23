"""C1-STABILITY-CURVE §2 — score_stability (repeated-run variance + bit-level determinism).

The ProbeResult carrier seam + the stability metric. `curve_eligible` is the gate §3's
roc_curve consumes; determinism is EPS=0 (bit-level), insufficient is surfaced not faked.
"""

from __future__ import annotations

from treval.active_eval import (
    ProbeResult,
    VendorLabel,
    first_vendor_label_score,
    score_stability,
)


def _pr(case_id, score=None, *, contaminated=False):
    labels = (VendorLabel(label="违规", score=score),) if score is not None else ()
    return ProbeResult(
        case_id=case_id,
        request_id=f"r-{case_id}",
        decision="ALLOW",
        response_text="",
        evidence=None,
        vendor_labels=labels,
        judge_reload_contaminated=contaminated,
    )


def _run(case_scores):  # {case_id: score} → one full pass
    return [_pr(cid, s) for cid, s in case_scores.items()]


# --- §6-1: ×6 bit-identical ⇒ deterministic_fraction=1.0, curve_eligible=True ---------- #


def test_six_repeats_bit_identical_is_deterministic_and_curve_eligible():
    warmup = _run({"a": 0.9998, "b": 0.0001})
    measured = [_run({"a": 0.9998, "b": 0.0001}) for _ in range(6)]
    rep = score_stability([warmup, *measured], score_of=first_vendor_label_score)
    assert rep.deterministic_fraction == 1.0
    assert rep.max_variance == 0.0 and rep.mean_variance == 0.0
    assert rep.curve_eligible is True
    assert rep.insufficient_cases == 0
    assert rep.warmup_dropped == 2  # the whole run[0]
    assert rep.per_case["a"].deterministic and rep.per_case["b"].deterministic


# --- §6-2: contamination dropped + surfaced, does NOT pollute variance ----------------- #


def test_contaminated_samples_dropped_and_surfaced_not_polluting_variance():
    warmup = _run({"a": 0.5})
    measured = [
        [_pr("a", 0.7)],
        [_pr("a", 0.7)],
        [_pr("a", 0.7)],
        [_pr("a", 0.10, contaminated=True)],  # would blow variance if kept
        [_pr("a", 0.99, contaminated=True)],
    ]
    rep = score_stability([warmup, *measured], score_of=first_vendor_label_score)
    assert rep.contaminated_dropped == 2
    assert rep.per_case["a"].scores == (
        0.7,
        0.7,
        0.7,
    )  # n_used counts only clean samples
    assert rep.per_case["a"].deterministic is True
    assert rep.max_variance == 0.0 and rep.curve_eligible is True


# --- §6-3: n_used<2 ⇒ insufficient, NOT faked as deterministic/0-variance -------------- #


def test_case_with_fewer_than_two_scores_is_insufficient_not_deterministic():
    warmup = _run({"a": 0.5, "lonely": 0.5})
    measured = [
        _run({"a": 0.8, "lonely": 0.8}),
        _run({"a": 0.8}),  # 'lonely' absent this pass ⇒ n_used(lonely)=1
    ]
    rep = score_stability([warmup, *measured], score_of=first_vendor_label_score)
    assert rep.per_case["lonely"].insufficient is True
    assert (
        rep.per_case["lonely"].deterministic is False
    )  # not faked as 0-variance/determined
    assert rep.insufficient_cases == 1
    # deterministic_fraction is 1.0 (a is the only n_used>=2 case, deterministic) YET the gate is
    # CLOSED because insufficient_cases>0 — the two conditions are independent (§2 line 96).
    assert rep.deterministic_fraction == 1.0
    assert rep.curve_eligible is False


# --- the "remote jitter" path: nonzero span ⇒ not deterministic ⇒ gate closed ---------- #


def test_nonzero_span_is_nondeterministic_and_closes_the_gate():
    warmup = _run({"a": 0.5})
    measured = [_run({"a": 0.10}), _run({"a": 0.95})]  # the 0.10→0.95 remote-API jitter
    rep = score_stability([warmup, *measured], score_of=first_vendor_label_score)
    assert rep.per_case["a"].deterministic is False
    assert rep.per_case["a"].span > 0.0
    assert rep.max_variance > 0.0
    assert rep.deterministic_fraction == 0.0
    assert rep.curve_eligible is False


def test_warmup_pass_is_dropped_whole():
    warmup = _run({"a": 0.01})  # a wild warmup score that must NOT count
    measured = [_run({"a": 0.9}), _run({"a": 0.9})]
    rep = score_stability([warmup, *measured], score_of=first_vendor_label_score)
    assert rep.per_case["a"].scores == (0.9, 0.9)
    assert rep.per_case["a"].deterministic is True
    assert rep.warmup_dropped == 1


def test_none_score_samples_carry_no_score_and_can_make_a_case_insufficient():
    warmup = _run({"a": 0.5})
    measured = [
        [_pr("a", 0.8)],
        [_pr("a")],
    ]  # second sample has no vendor_labels ⇒ None score
    rep = score_stability([warmup, *measured], score_of=first_vendor_label_score)
    assert rep.per_case["a"].scores == (0.8,)  # the None-score sample carries nothing
    assert rep.per_case["a"].insufficient is True


# --- §8: the injected extractor; §6-9: additive fields are default (WAL golden zero churn) - #


def test_first_vendor_label_score_extractor():
    assert first_vendor_label_score(_pr("a", 0.7)) == 0.7
    assert first_vendor_label_score(_pr("a")) is None  # no labels ⇒ no score


def test_probe_result_new_fields_are_additive_and_default():
    # A pre-C1 construction (no vendor/judge kwargs) still builds — WAL golden zero churn (§6-9).
    pr = ProbeResult(
        case_id="a", request_id="r", decision="ALLOW", response_text="", evidence=None
    )
    assert pr.vendor_labels == () and pr.vendor_version == ""
    assert pr.judge_load_duration_ns == 0 and pr.judge_reload_contaminated is False


def test_empty_runs_is_not_curve_eligible():
    assert (
        score_stability([], score_of=first_vendor_label_score).curve_eligible is False
    )
