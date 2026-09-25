"""Pure statistics for the eval line — no deps, importable from both the harness and the CLI.

Wilson score interval for a binomial proportion (EV-ATTRIB §2.3 / EV-CAPCTRL §3 / PROV-CLOSEOUT §5.3).
🔴 Wilson, NOT Wald: Wald's half-width is `z*sqrt(p(1-p)/n)`, which is **0 at p=0 and p=1** — it
turns "0 of 14" into a zero-error CERTAINTY, the same boundary-fakery as a fake 0%. Wilson stays
strictly > 0 at the boundaries. Follows the repo's existing `(low, point, high)` tuple convention
(active_eval.score_metrics.recall_at_fpr) so callers read one shape everywhere.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# 95% two-sided normal quantile (z_{0.975}); the eval line reports 95% CIs everywhere.
Z_95 = 1.959963984540054


def wilson_interval(
    successes: int, n: int, *, z: float = Z_95
) -> tuple[float, float, float]:
    """`(low, point, high)` Wilson score interval for `successes`/`n` at confidence implied by `z`.
    `point` is the plain proportion k/n. Raises on `n <= 0` — there is NO interval over zero samples
    (that state is `insufficient_data`, which the caller must render, never a spurious point)."""
    if n <= 0:
        raise ValueError(
            "wilson_interval needs n > 0 (n=0 is insufficient_data, not an interval)"
        )
    if not 0 <= successes <= n:
        raise ValueError(f"successes {successes} out of range [0, {n}]")
    p = successes / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return (max(0.0, center - half), p, min(1.0, center + half))


def wilson_half_width(successes: int, n: int, *, z: float = Z_95) -> float:
    """Half of the Wilson interval's total width — the ± a delta must clear to be a conclusion
    (PROV-CLOSEOUT §5.3). > 0 even at p=0/p=1 (that is the whole point of Wilson)."""
    low, _point, high = wilson_interval(successes, n, z=z)
    return (high - low) / 2.0


def binomial_ci(value: float, n: int, *, z: float = Z_95) -> tuple[float, float]:
    """`(low, high)` Wilson interval for a BINOMIAL PROPORTION whose point estimate is `value` over
    `n` trials (EV-CIGATE §7-A) — the entry an INDICATOR calls to say "my value is k/n" so its
    Measurement can carry an interval. 🔴 Only valid for a proportion in [0,1]: `round(value*n)`
    recovers k, so a NON-rate value would get a plausible-but-wrong interval — the indicator, not the
    engine, must decide it is a proportion (§7-A invariant 2). Raises on value∉[0,1] and on n<=0
    (n=0 is insufficient_data, which has NO interval — the caller passes None, never (0,1))."""
    if not 0.0 <= value <= 1.0:
        raise ValueError(
            f"binomial_ci expects a proportion in [0,1], got {value!r} (non-rate indicator?)"
        )
    low, _point, high = wilson_interval(round(value * n), n, z=z)
    return (low, high)


@dataclass(frozen=True)
class CapacitySearch:
    """`min_n` 的三格返回 —— 🔴 三格【必须一起交出去】，理由在 `gaps` 那一格上。

    `first_n` 是首个达标的样本量，而它常常**卡在边界上**：实证过一组 (p, target)，其
    `first_n` 的下界只比 target 高出万分之一，而 **first_n + 1 就不过**。只交出 `first_n`
    的后果是「补到 309 就能过」→ 实际补到 310 → 不过 → 没有人解释得了。

    🔴 不单调的成因是取整：分子按 `round(p*n)` 走，n 加 1 时 k 不一定加 1，于是实际比率
    掉到 p 之下，下界随之回落。**这不是数值噪声，是判据本身的形状** —— 所以它是一个
    要报出来的事实，不是一个要平滑掉的瑕疵。
    """

    # 🔴 `n` 是【给排期用的那个数】＝稳健值。首达值只作诊断，不作默认 ——
    # 实证（规则专家提）：某一组参数下首达值达标，而 **首达值 + 1 不达标**。
    # 「多造一件反而不过」的操作点不能拿去排期，而一个只返回首达值的函数
    # 会让下一个人直接用它。⇒ 默认值挑稳健的那个，陷阱那个要显式去取。
    n: int | None  # = stable_n；排期用这个
    first_n: int | None  # 诊断用：首个达标的 n，常卡在边界且其后会回落
    stable_n: int | None  # 从此连续达标的 n（此后不再回落）
    gaps: tuple[int, ...]  # first_n 之后仍不达标的 n —— 排期不能选的那些
    p: float
    target: float
    hi: int  # 搜索上界
    # 🔴 `n is None` 的两个理由，必须分得开（2026-09-16，一次真实误判当场抓到）：
    #   "unreachable"    p <= target ⇒ **任何 n 都过不了**。扩样只收窄区间、不抬点估计。
    #   "beyond_hi"      p >  target ⇒ 可达，只是所需 n 超过了本次搜索上界 hi。
    # ⚠️ 这两件事此前都返回裸 None ⇒ 在读的人眼里【同形】。而它已经造成过一次误判：
    #    d=13(combined 0.8116 > 0.80)在 hi=2000 下返回 None，差点被报成"任何 n 都过不了"——
    #    而它其实可达，只是要 4498 件。**同一个规则专家两轮前刚因为 cap=4000 撤回过同形的结论。**
    # 🔴 判别是数学的，不是经验的：Wilson 下界恒 < p ⇒ p <= target 时下界永不达标。
    #    所以 "unreachable" 是定理，"beyond_hi" 是本次搜索的边界 —— 两者不可混写。
    reason: str | None = None  # None（找到了）| "unreachable" | "beyond_hi"


def min_n(
    p: float, target: float, *, z: float = Z_95, lo: int = 1, hi: int = 2000
) -> CapacitySearch:
    """在同率假设 `p` 下，Wilson 下界要达到 `target` 所需的样本量 —— **搜索得出，不是取样**。

    🔴 本函数存在的理由是一次实际损失（2026-09-14）：容量数是从一份**取样清单**里挑一个
    最小值报出来的，而"最小"这个词承诺的是"再小一个就不行"——**取样证明不了那一半**。
    那一次多报了相当一批件，直接打在一条 L 级工作量的排期上。

    🔴 `first_n is None` 有【两个】理由，由 `reason` 分开，调用者必须读它：
      `"unreachable"`  p <= target ⇒ 任何样本量都过不了（Wilson 下界恒 < p，这是定理）
      `"beyond_hi"`    p >  target ⇒ 可达，只是所需 n 超出本次 `hi`（调大 `hi` 再搜）
    ⚠️ 两者此前都是裸 None ⇒ 同形，而它已经误导过一次：combined 0.8116 在 `hi=2000` 下
    返回 None，差点被报成"任何 n 都过不了"——实际可达，需 4498 件。
    返回 None 而不是 `hi`，是为了不让读的人以为方向对；但 None 自己也要说清是哪一种。

    ⚠️ 判据固定为 `k = round(p * n)`：它是"新件与现有件同率"这个假设的算术形式。
    调用者要换假设（例如新件更难），换的是 `p`，不是这里的取整方式。
    """
    if not 0.0 <= p <= 1.0:
        raise ValueError(f"min_n expects a proportion in [0,1], got {p!r}")
    if not 0.0 <= target <= 1.0:
        raise ValueError(f"min_n expects target in [0,1], got {target!r}")
    if lo < 1 or hi < lo:
        raise ValueError(f"min_n needs 1 <= lo <= hi (got lo={lo}, hi={hi})")

    ok = {
        n: wilson_interval(round(p * n), n, z=z)[0] >= target for n in range(lo, hi + 1)
    }
    first_n = next((n for n in range(lo, hi + 1) if ok[n]), None)
    if first_n is None:
        # 🔴 判别用 p 与 target 的关系，不用"搜到 hi 还没找到"这个经验事实：
        # 前者是定理（Wilson 下界恒 < p），后者只是本次搜索的边界。
        reason = "unreachable" if p <= target else "beyond_hi"
        return CapacitySearch(None, None, None, (), p, target, hi, reason)

    # stable_n：从它起到 hi 为止无一回落。倒着扫一遍即可 —— 正着扫是 O(n²)，而这个函数
    # 会被排期反复调用。
    stable_n: int | None = None
    for n in range(hi, lo - 1, -1):
        if not ok[n]:
            break
        stable_n = n
    gaps = tuple(n for n in range(first_n + 1, hi + 1) if not ok[n])
    return CapacitySearch(stable_n, first_n, stable_n, gaps, p, target, hi)
