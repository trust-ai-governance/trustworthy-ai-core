"""Pure statistics for the eval line — no deps, importable from both the harness and the CLI.

Wilson score interval for a binomial proportion (EV-ATTRIB §2.3 / EV-CAPCTRL §3 / PROV-CLOSEOUT §5.3).
🔴 Wilson, NOT Wald: Wald's half-width is `z*sqrt(p(1-p)/n)`, which is **0 at p=0 and p=1** — it
turns "0 of 14" into a zero-error CERTAINTY, the same boundary-fakery as a fake 0%. Wilson stays
strictly > 0 at the boundaries. Follows the repo's existing `(low, point, high)` tuple convention
(active_eval.score_metrics.recall_at_fpr) so callers read one shape everywhere.
"""

from __future__ import annotations

import math

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
