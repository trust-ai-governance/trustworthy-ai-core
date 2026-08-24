"""EV-CN-BENIGN-N180 件8 — operator-only (Tier-0) family diagnostics for the CN holdout FPR. THREE pure
computations, each 🔴 with ZERO detection results in it (a boundary-map is where we mis-block; these are
"what our denominator looks like", not that):

  • 件8.1 single-case LEVERAGE table — "若恰有一件误拦落在族 f，总 FPR 在三种口径下各是多少". Input is ONLY
    prior weights + per-family COUNTS (from post-hoc labels); the one mis-block is HYPOTHETICAL, so no
    observed detection result enters. Answers「最坏情况下加权能把这个数搬多远」BEFORE the freeze run (the
    observed sensitivity band degenerates at k=0 — zero mis-blocks, any weighting gives zero — and arrives
    too late; this does not).
  • 件8.3 two-arm HARDNESS comparison — the machine signal for「下意识少去找难件」: each arm clears its own
    floor (per-ARM, never merged), and the holdout being much softer than the calib arm (which was expanded
    by someone who saw no numbers — a natural control) warns. 静默即红: a warn is never swallowed.
  • 件8.2 the family-distribution-vs-prior comparison drives NO threshold-gated action: BOTH outcomes record
    the SAME pending item (「族构成为 attested，未经流量实测」— true regardless), the comparison only shades
    its urgency. 🔴 "大体吻合" must NOT be read as「先验被验证」(same-source, not independent confirmation).
"""

from __future__ import annotations

from dataclasses import dataclass


# --------------------------------------------------------------------------- #
# 件8.1 — single-case leverage table (ZERO detection results)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class FamilyLeverage:
    family: str
    n: int  # per-family case count (a grouped COUNT — operator_only, §1.2)
    natural: float  # 留出臂自然构成口径: 1/N (weight = sample share, cancels — same for every family)
    prior: float  # 先验权重口径: ŵ_f / n_f (normalized prior weight over the family's own n)
    equal: float  # 平权口径: 1 / (K · n_f)


def leverage_table(
    family_counts: dict[str, int], prior_weights: dict[str, float]
) -> list[FamilyLeverage]:
    """🔴 件8.1 — for each family f, the TOTAL FPR that a SINGLE hypothetical mis-block in f would produce,
    under three weighting口径. Input is prior weights + per-family counts ONLY — 🔴 zero detection results
    (the mis-block is hypothetical). Returned sorted by the PRIOR-口径 leverage (highest first): a high-
    prior, low-count family is where reweighting moves the number the most."""
    if not family_counts:
        return []
    fams = sorted(family_counts)
    total_n = sum(family_counts.values())
    k = len(fams)
    # normalize the attested prior weights over the families we actually have (missing ⇒ 0 weight)
    wsum = sum(prior_weights.get(f, 0.0) for f in fams)
    rows: list[FamilyLeverage] = []
    for f in fams:
        n_f = family_counts[f]
        if n_f <= 0:
            continue
        w_f = (prior_weights.get(f, 0.0) / wsum) if wsum > 0 else 0.0
        rows.append(
            FamilyLeverage(
                family=f,
                n=n_f,
                natural=1.0 / total_n,
                prior=w_f / n_f,
                equal=1.0 / (k * n_f),
            )
        )
    rows.sort(key=lambda r: r.prior, reverse=True)
    return rows


def leverage_swing(rows: list[FamilyLeverage]) -> float:
    """The magnitude PM asked for: how many× the NATURAL口径 the worst-leverage family reaches under the
    PRIOR口径 (max prior / natural). 1.0 ⇒ reweighting cannot move it; large ⇒ the number is weight-fragile."""
    if not rows:
        return 0.0
    natural = rows[0].natural
    return max(r.prior for r in rows) / natural if natural > 0 else 0.0


# --------------------------------------------------------------------------- #
# 件8.3 — two-arm hardness comparison (per-arm floor + relative-softness warning)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ArmComparison:
    status: str  # "ok" | "warn" | "fail"
    calib_ratio: float
    holdout_ratio: float
    lines: tuple[str, ...]


def two_arm_comparison(
    calib: tuple[int, int],
    holdout: tuple[int, int],
    *,
    floor: float,
    margin: float,
) -> ArmComparison:
    """🔴 件3/件8.3 — each arm judged AGAINST ITS OWN floor (never merged), plus the relative check. `calib`
    / `holdout` are (hard_count, n). A hard calib may NOT rescue a soft holdout (they are separate arms);
    the holdout falling below the floor is a FAIL (§5-3 易例超限即红). The holdout being softer than the
    calib by more than `margin`, even if both clear the floor, is the「下意识少找难件」WARN (件8.3) — the
    calib arm, expanded by someone who saw no numbers, is the control. floor/margin are DECLARED values."""
    c_hard, c_n = calib
    h_hard, h_n = holdout
    c_ratio = c_hard / c_n if c_n else 0.0
    h_ratio = h_hard / h_n if h_n else 0.0
    lines = [
        f"两臂硬负例占比：标定 {c_ratio:.1%}（{c_hard}/{c_n}）· 留出 {h_ratio:.1%}（{h_hard}/{h_n}）"
        f"· 下限 {floor:.1%}（声明值·按臂）· 告警边际 {margin:.1%}"
    ]
    below = [
        name
        for name, r, n in (("标定臂", c_ratio, c_n), ("留出臂", h_ratio, h_n))
        if n and r < floor
    ]
    if below:
        lines.append(
            f"🔴 FAIL —— {'、'.join(below)}硬负例占比低于下限（按臂判，不许两臂合起来算，§5-3）"
        )
        return ArmComparison("fail", c_ratio, h_ratio, tuple(lines))
    if c_n and h_n and h_ratio < c_ratio - margin:
        lines.append(
            "⚠️ WARN —— 留出臂显著软于标定臂（差值超告警边际）：这正是「下意识少找难件」的机器信号"
            "（标定臂由没看过数的人扩，是天然对照）⇒ 进 notes，勿静默"
        )
        return ArmComparison("warn", c_ratio, h_ratio, tuple(lines))
    return ArmComparison("ok", c_ratio, h_ratio, tuple(lines))


# --------------------------------------------------------------------------- #
# 件8.2 — the comparison drives NO threshold-gated action (same pending item both directions)
# --------------------------------------------------------------------------- #
_PENDING_ITEM = "族构成为 attested，未经流量实测（同源判断，不构成独立确认）"


def family_prior_pending_item(roughly_agrees: bool) -> tuple[str, str]:
    """🔴 件8.2 — return the (pending_item, urgency) for the family-distribution-vs-prior comparison. The
    pending ITEM is IDENTICAL either way (it is true regardless of the comparison, so no action hangs on a
    threshold ⇒ no "看了数再定判据" hole); only the urgency wording differs. 🔴 agree must NOT claim the
    prior was validated (same-source, not confirmation); disagree does NOT reweight/rework — it promotes
    "试点日志测族占比" up the backlog. Neither direction changes the frozen FPR."""
    if roughly_agrees:
        urgency = "大体吻合：维持既有未决项，🔴 不得据此宣称先验被验证（同源判断，非独立确认）"
    else:
        urgency = "明显不吻合：不重新加权、不返工取材、不改已冻结的 FPR —— 把「试点日志测族占比」提到 backlog 前列"
    return _PENDING_ITEM, urgency
