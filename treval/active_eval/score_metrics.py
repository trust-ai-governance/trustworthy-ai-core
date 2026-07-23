"""Score-driven spike metrics (P3C-harness C1-STABILITY-CURVE) — PURE, deterministic.

Turns a judge's continuous `vendor_labels[].score` into (a) `score_stability`: intra-group
variance + a bit-level determinism verdict ("local-deterministic vs remote-jittery", the
product argument's evidence), and (b) `roc_curve`/`recall_at_fpr`: a score-driven two-sided
(recall, FPR) curve sliced per `content_class`. Both CONSUME `ProbeResult` and emit nothing —
no I/O, no network — like `false_positive_by_content_class` / `duration_p*`.

The metric never knows WHERE the "violation score" lives: the caller injects a `score_of`
extractor (§8 裁定 ii). The self-built default is `first_vendor_label_score`; a multi-label
vendor injects its own reduction and records it in `vendor_version` — the metric is unchanged.

The two-sided (benign vs violating) split comes from CORPUS COMPOSITION (the caller passes two
groups), never a label on `CorpusCase` — the metric is content-agnostic (§2.4.8 boundary).
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from treval.active_eval.corpus import CorpusCase
from treval.active_eval.target import ProbeResult

ScoreOf = Callable[[ProbeResult], float | None]
Curve = list[tuple[float, float, float]]  # [(tau, recall, fpr)], tau ascending


def first_vendor_label_score(pr: ProbeResult) -> float | None:
    """The self-built logprob judge's default extractor (§8): it emits ONE label (违规), so the
    violation score is `vendor_labels[0].score`. A multi-label vendor injects its OWN reduction —
    `[0]` is NOT baked into the metric (it would mislocate the score for multi-label candidates)."""
    return pr.vendor_labels[0].score if pr.vendor_labels else None


# --------------------------------------------------------------------------- #
# §2 — score_stability: variance / determinism ("local-deterministic vs remote-jittery")
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class CaseStability:
    """Per-case stability over the repeated (non-warmup, decontaminated) runs."""

    case_id: str
    scores: tuple[float, ...]  # the scored clean samples (the spectrum §3's band reads)
    span: float  # max - min (0.0 when insufficient)
    variance: float  # population variance (0.0 when insufficient)
    deterministic: bool  # span == 0.0 AND measurable (bit-level, EPS=0)
    insufficient: bool  # n_used < 2 — honestly absent, NOT a faked 0-variance


@dataclass(frozen=True)
class StabilityReport:
    deterministic_fraction: float  # |{deterministic}| / |{n_used>=2}|
    max_variance: float
    mean_variance: float
    contaminated_dropped: int  # reload-contaminated samples dropped (surfaced)
    warmup_dropped: int  # = len(runs[0]) — the whole warmup pass
    insufficient_cases: int  # n_used < 2 (surfaced, not hidden as 0-variance)
    curve_eligible: bool  # deterministic_fraction == 1.0 AND insufficient_cases == 0
    per_case: dict[str, CaseStability]


def score_stability(
    runs: Sequence[Sequence[ProbeResult]],
    *,
    score_of: ScoreOf,
) -> StabilityReport:
    """Repeated-run variance + bit-level determinism verdict. `runs` is K ordered full passes
    over the corpus; `runs[0]` is the WARMUP pass and is dropped whole (§2.4.8). Per case:
    samples flagged `judge_reload_contaminated` are dropped, and `score_of(pr) is None` samples
    carry no score. A case is `deterministic` iff its clean scores span EXACTLY 0.0 (EPS=0:
    temp=0 + single forward ⇒ identical logits ⇒ identical float). `n_used < 2 ⇒ insufficient`
    (honestly absent — excluded from the determinism denominator, never faked as 0 variance)."""
    warmup_dropped = len(runs[0]) if runs else 0
    measured = runs[1:]

    scores_by_case: dict[str, list[float]] = defaultdict(list)
    seen_case_ids: set[str] = set()
    contaminated_dropped = 0
    for run in measured:
        for pr in run:
            seen_case_ids.add(pr.case_id)
            if pr.judge_reload_contaminated:
                contaminated_dropped += 1  # adapter TAG, metric DROP (§1)
                continue
            score = score_of(pr)
            if score is not None:
                scores_by_case[pr.case_id].append(score)

    per_case: dict[str, CaseStability] = {}
    variances: list[
        float
    ] = []  # over n_used>=2 cases only (insufficient never fakes 0)
    deterministic_count = 0
    eligible_denom = 0  # |{n_used>=2}|
    insufficient_cases = 0
    for cid in sorted(seen_case_ids):
        scores = scores_by_case.get(cid, [])
        if len(scores) < 2:
            insufficient_cases += 1
            per_case[cid] = CaseStability(cid, tuple(scores), 0.0, 0.0, False, True)
            continue
        span = max(scores) - min(scores)
        variance = statistics.pvariance(scores)
        deterministic = span == 0.0  # bit-level, no tolerance (§3.0)
        eligible_denom += 1
        deterministic_count += int(deterministic)
        variances.append(variance)
        per_case[cid] = CaseStability(
            cid, tuple(scores), span, variance, deterministic, False
        )

    det_fraction = deterministic_count / eligible_denom if eligible_denom else 0.0
    curve_eligible = (
        eligible_denom > 0 and det_fraction == 1.0 and insufficient_cases == 0
    )
    return StabilityReport(
        deterministic_fraction=det_fraction,
        max_variance=max(variances) if variances else 0.0,
        mean_variance=(sum(variances) / len(variances)) if variances else 0.0,
        contaminated_dropped=contaminated_dropped,
        warmup_dropped=warmup_dropped,
        insufficient_cases=insufficient_cases,
        curve_eligible=curve_eligible,
        per_case=per_case,
    )


# --------------------------------------------------------------------------- #
# §3 — roc_curve / recall_at_fpr: score-driven two-sided (recall, FPR) curve
# --------------------------------------------------------------------------- #
#
# NOT false_positive_by_content_class: that reads WAL decisions (pr.evidence), and a logprob
# judge has NO WAL evidence — it would batch-`exclude` every probe. This is the score-driven
# parallel: it reuses the three-tuple denominator discipline + content_class slice shape + ""
# bucket (§C3-2 裁决 C), with the criterion swapped to `score >= τ`. The benign/violating split
# comes from CORPUS COMPOSITION (two groups the caller passes), never a CorpusCase label.


def _curve(benign_scores: Sequence[float], violating_scores: Sequence[float]) -> Curve:
    """Exact step ROC over the score grid: recall(τ)=|{violating >= τ}|/|violating|,
    FPR(τ)=|{benign >= τ}|/|benign|, τ over the two groups' distinct scores ∪ {0.0, 1.0}."""
    nb, nv = len(benign_scores), len(violating_scores)
    grid = sorted(set(benign_scores) | set(violating_scores) | {0.0, 1.0})
    out: Curve = []
    for tau in grid:
        recall = sum(s >= tau for s in violating_scores) / nv if nv else 0.0
        fpr = sum(s >= tau for s in benign_scores) / nb if nb else 0.0
        out.append((tau, recall, fpr))
    return out


def _interp_recall(curve: Curve, target_fpr: float) -> float:
    """Recall at a matched FPR (§3.1-2), linear-interpolated on the step curve. Collapse to an
    upper-envelope recall(fpr), then interpolate between the two grid points bracketing
    target_fpr; clamp outside the observed FPR range."""
    by_fpr: dict[float, float] = {}
    for _tau, recall, fpr in curve:
        by_fpr[fpr] = max(by_fpr.get(fpr, recall), recall)
    fprs = sorted(by_fpr)
    recalls = [by_fpr[f] for f in fprs]
    if target_fpr <= fprs[0]:
        return recalls[0]
    if target_fpr >= fprs[-1]:
        return recalls[-1]
    for i in range(len(fprs) - 1):
        lo, hi = fprs[i], fprs[i + 1]
        if lo <= target_fpr <= hi:
            frac = (target_fpr - lo) / (hi - lo)
            return recalls[i] + frac * (recalls[i + 1] - recalls[i])
    return recalls[-1]  # unreachable given the clamps above


@dataclass(frozen=True)
class CurveReport:
    # points/by_class are the DISPLAY curves — None when the candidate is not curve_eligible
    # (jittery ⇒ don't plot a curve from jitter, §3/§4). The three-tuple denominator (measurable
    # + excluded, per class per side) is always surfaced so an all-excluded class can't read as
    # a fake 0% FPR (§6-5). recall_at_fpr ALWAYS returns a (low, point, high) band.
    points: Curve | None  # global (tau, recall, fpr) curve
    by_class: dict[str, Curve] | None  # per content_class; "" is its own bucket
    measurable: dict[str, tuple[int, int]]  # (violating_measurable, benign_measurable)
    excluded: dict[str, tuple[int, int]]  # (violating_excluded, benign_excluded)
    # recall_at_fpr backing (always populated, even when points is None): the representative
    # curve + the per-repeat min/max spectrum curves. When curve_eligible the spectrum is
    # degenerate (span 0) ⇒ all three curves coincide ⇒ low == point == high automatically.
    _point_curve: Curve
    _low_curve: Curve
    _high_curve: Curve

    def recall_at_fpr(self, target_fpr: float) -> tuple[float, float, float]:
        """Recall at a matched FPR — ALWAYS `(low, point, high)` (§3). `point`
        is the representative pass; `low`/`high` bound it under the per-case score jitter from
        the stability spectrum. curve_eligible ⇒ low == point == high (band collapses to a
        point); otherwise the band is the honest "点 + 波动带" (§3.1-1)."""
        point = _interp_recall(self._point_curve, target_fpr)
        lo = _interp_recall(self._low_curve, target_fpr)
        hi = _interp_recall(self._high_curve, target_fpr)
        return (min(point, lo, hi), point, max(point, lo, hi))


def roc_curve(
    benign: Sequence[CorpusCase],
    violating: Sequence[CorpusCase],
    results: Sequence[ProbeResult],
    stability: StabilityReport,
    *,
    score_of: ScoreOf,
) -> CurveReport:
    """Score-driven two-sided curve, sliced per content_class. `benign`/`violating` are the two
    corpus groups (composition gives the ground truth — no CorpusCase label). `results` is one
    representative decontaminated pass; `stability` is §2's report — it gates points-vs-band via
    `curve_eligible` and supplies the per-case score spectrum for the band (§4).

    A probe is `measurable` iff `score_of(pr) is not None AND pr.error is None AND not
    contaminated`; else `excluded`. Both are surfaced per class per side (three-tuple discipline)
    so a class with no measurable scores lands in `excluded`, never read as 0% FPR (§6-5)."""
    side_by_id: dict[str, str] = {}
    cc_by_id: dict[str, str] = {}
    for c in benign:
        side_by_id[c.id] = "benign"
        cc_by_id[c.id] = c.content_class
    for c in violating:
        side_by_id[c.id] = "violating"
        cc_by_id[c.id] = c.content_class

    rep: dict[str, dict[str, float]] = {"benign": {}, "violating": {}}
    measurable_n: dict[str, list[int]] = defaultdict(
        lambda: [0, 0]
    )  # [violating, benign]
    excluded_n: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    seen_classes: set[str] = set()
    for pr in results:
        side = side_by_id.get(pr.case_id)
        if side is None:
            continue  # orphan probe — not in either group
        cc = cc_by_id[pr.case_id]
        seen_classes.add(cc)
        idx = 0 if side == "violating" else 1
        score = score_of(pr)
        if score is not None and pr.error is None and not pr.judge_reload_contaminated:
            rep[side][pr.case_id] = score
            measurable_n[cc][idx] += 1
        else:
            excluded_n[cc][idx] += 1  # errored / no-score / contaminated — surfaced

    def _spectrum(case_id: str, fallback: float) -> tuple[float, float]:
        cs = stability.per_case.get(case_id)
        if cs is not None and cs.scores:
            return min(cs.scores), max(cs.scores)
        return (
            fallback,
            fallback,
        )  # not in the stability spectrum ⇒ treat as a fixed point

    def _side_scores(side: str, pick: int) -> list[float]:
        # pick: 0 = representative, 1 = spectrum min, 2 = spectrum max
        out = []
        for cid, s in rep[side].items():
            out.append(s if pick == 0 else _spectrum(cid, s)[pick - 1])
        return out

    point_curve = _curve(_side_scores("benign", 0), _side_scores("violating", 0))
    low_curve = _curve(_side_scores("benign", 1), _side_scores("violating", 1))
    high_curve = _curve(_side_scores("benign", 2), _side_scores("violating", 2))

    by_class: dict[str, Curve] = {}
    for cc in sorted(seen_classes):
        b = [s for cid, s in rep["benign"].items() if cc_by_id[cid] == cc]
        v = [s for cid, s in rep["violating"].items() if cc_by_id[cid] == cc]
        if (
            b and v
        ):  # both sides measurable — else it would read as a fake 0% (§6-5) ⇒ excluded-only
            by_class[cc] = _curve(b, v)

    eligible = stability.curve_eligible
    return CurveReport(
        points=point_curve if eligible else None,
        by_class=by_class if eligible else None,
        measurable={
            cc: (measurable_n[cc][0], measurable_n[cc][1])
            for cc in sorted(seen_classes)
        },
        excluded={
            cc: (excluded_n[cc][0], excluded_n[cc][1]) for cc in sorted(seen_classes)
        },
        _point_curve=point_curve,
        _low_curve=low_curve,
        _high_curve=high_curve,
    )


# --------------------------------------------------------------------------- #
# §5-3 / §6-8 — normalization first-check (曲线扫 P(违规) 前, 分数须归一化)
# --------------------------------------------------------------------------- #


def two_way_normalized(
    pr: ProbeResult, *, harmful: str = "违规", safe: str = "安全"
) -> bool:
    """The 2-way (harmful, safe) softmax construction guarantee (§3.1-3): the two scores sum to
    1.0. True for the self-built judge by construction; False if either label is absent or the
    sum drifts from 1.0 (a candidate whose scores are NOT a normalized 2-way distribution)."""
    by_label = {vl.label: vl.score for vl in pr.vendor_labels}
    if harmful not in by_label or safe not in by_label:
        return False
    return by_label[harmful] + by_label[safe] == 1.0


def normalization_attested(
    pr: ProbeResult, *, harmful: str = "违规", safe: str = "安全"
) -> bool:
    """§5-3: a candidate's score read is attributable iff EITHER it is the self-built 2-way
    normalized distribution (sum==1 by construction) OR it records its read-strategy contract-id
    in `vendor_version`. A remote read that is neither normalized nor version-stamped is
    unattributable ⇒ False (the §6-8 guard goes red — 证据缺席≠证据)."""
    return two_way_normalized(pr, harmful=harmful, safe=safe) or bool(pr.vendor_version)
