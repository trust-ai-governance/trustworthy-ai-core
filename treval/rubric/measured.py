"""EV-CITE 件二 — the SINGLE definition of *which kind of `None`* a `measured_ceiling` is, plus
the per-objective fact sentence that must ride with it.

Why here (not in `web/view.py` and again in `cli/render.py`): the bug this fixes is a criterion that
was copied into two places — the CLI had the right one, the Web derived a wrong one, and the same
report said opposite things (EV-CITE §2.2). So this is computed ONCE in the engine, serialized onto
the dimension, and BOTH the CLI and the Web *read the field* — nobody re-derives it (acceptance 10).

Four/five states, driven by the ceiling BREAKPOINT (the level where the ladder broke), each mapping
to a DIFFERENT operator action (C9 + C11):

    certified            measured_ceiling non-null                      — (nothing to say)
    below_floor          breakpoint has an `unmet`                      扩样本 / 补能力
    evidence_unverified  breakpoint's non-met are UNVERIFIED sources    换一个可链校验的证据源   (cause B)
    blocked_no_data      breakpoint's non-met are all insufficient_data 查那个指标为什么没产出
    not_measured         no usable measured signal at all              这维度这次没测

🔴 `unverified_evidence` (the 4th ObjectiveResult status) is TWO causes (C11):
  A. BROKEN chain  → already a REPORT-level blocker; the dimension layer must NOT re-tell it as a
                     level-story (double-counting). When the report has any BROKEN measurement, every
                     non-certified dimension's gap collapses to one pointer sentence (acceptance 20).
  B. UNVERIFIED source on a `requires_integrity` objective → has NO report-level outlet
     (`derive_evidence_basis` reads only target_kind), so the dimension layer is its only home →
     the `evidence_unverified` state (acceptance 19). B is distinguishable from A with zero extra
     plumbing: `broken == 0` ⇒ every `unverified_evidence` status is cause B.

`measured_state` (a coarse pill) and `measured_gap` (the facts) never derive from each other (C10):
the gap is emitted PER non-met objective at the breakpoint, so a mixed breakpoint (`unmet` +
`insufficient_data`) yields both sentences — neither swallows the other.
"""

from __future__ import annotations

from dataclasses import dataclass

from treval.registry.satisfied_when import SatisfiedWhenError, parse_satisfied_when
from treval.stats import Z_95, wilson_interval

_LEVELS = ("L1", "L2", "L3", "L4", "L5")
_LEVEL_INDEX = {level: i for i, level in enumerate(_LEVELS, start=1)}

# measured_state values (a closed set — the Web pill / radar switch on these strings).
CERTIFIED = "certified"
BELOW_FLOOR = "below_floor"
EVIDENCE_UNVERIFIED = "evidence_unverified"
BLOCKED_NO_DATA = "blocked_no_data"
NOT_MEASURED = "not_measured"

# The pointer sentence for a BROKEN chain (cause A): the report-level blocker owns the fact; the
# dimension only points at it (C11 / acceptance 20).
_CHAIN_BROKEN_GAP = (
    "证据链破损 —— 见报告级 blocker；本维度（以及本报告）的结论均不成立。"
)
_CHAIN_BROKEN_GAP_TUPLE = (_CHAIN_BROKEN_GAP,)

_KS = (0, 1, 2, 3)  # the benign false-positive "how many mis-flags" ladder (§2.3.1)


@dataclass(frozen=True)
class MeasuredObjective:
    """One measured objective as the engine sees it while grading a dimension — enough to write the
    fact sentence without re-consulting the registry or the measurements downstream."""

    level: str
    objective_id: str
    indicator_id: str | None
    status: str  # met | unmet | insufficient_data | unverified_evidence
    value: float | None  # the measurement's point estimate (None if no measurement)
    sample_size: int | None
    satisfied_when: str | None


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _f3(x: float) -> str:
    return f"{x:.3f}"


def _thr(x: float) -> str:
    return f"{x:.2f}"


def _level_below(level: str) -> str | None:
    i = _LEVEL_INDEX[level]
    return _LEVELS[i - 2] if i >= 2 else None


def _breakpoint(measured: list[MeasuredObjective]) -> str:
    """First level (ascending) carrying a non-`met` measured objective. Well-defined whenever
    `measured_ceiling` is None and the dimension has a met/unmet/unverified signal."""
    for level in _LEVELS:
        if any(o.level == level and o.status != "met" for o in measured):
            return level
    # Unreachable for a null-ceiling dimension with a non-insufficient signal; fall back to top.
    return _LEVELS[-1]


# --------------------------------------------------------------------------- #
# "How much more n" — computed LIVE from treval.stats, never hardcoded (acceptance 12/16).
# --------------------------------------------------------------------------- #
def stable_n_for_lower_bound(
    point: float, threshold: float, *, z: float = Z_95, cap: int = 20000
) -> tuple[int | None, int | None]:
    """Hold the point estimate `point` and ask: from what n does `ci_low(round(point*n), n)` STAY
    ≥ `threshold`? Returns `(first_pass, stable_n)`:
      - `first_pass` — smallest n whose ci_low clears the bar (None if it never does within cap);
      - `stable_n`   — smallest n from which it clears AND never dips back below (the honest target).
    🔴 The bar is NON-MONOTONE (round(point*n) jumps), so `first_pass < stable_n` means the range in
    between crosses back and forth and must NOT be used as a milestone (§2.3.1). If `point <=
    threshold`, growing n can never help (ci_low → point from below) → `(None, None)`."""
    if not 0.0 <= point <= 1.0 or point <= threshold:
        return (None, None)
    first_pass: int | None = None
    last_fail: int | None = None
    streak = 0
    n = 1
    while n <= cap:
        clears = wilson_interval(round(point * n), n, z=z)[0] >= threshold
        if clears:
            if first_pass is None:
                first_pass = n
            streak += 1
            # A long unbroken pass-run means the round(p·n) jitter has shrunk below the p−threshold
            # margin — it won't dip again; stop rather than scan to `cap` (keeps grading fast).
            if streak >= 500:
                break
        else:
            last_fail = n
            streak = 0
        n += 1
    if first_pass is None:
        return (None, None)
    stable_n = (
        (last_fail + 1)
        if last_fail is not None and last_fail >= first_pass
        else first_pass
    )
    return (first_pass, stable_n)


def n_ladder_for_upper_bound(
    threshold: float, *, ks: tuple[int, ...] = _KS, z: float = Z_95, cap: int = 20000
) -> dict[int, int | None]:
    """For a `ci_high <= threshold` gate: for each mis-flag count k, the smallest n whose
    `ci_high(k, n)` clears the bar. The benign story is a LADDER not a target — each extra
    false-positive bumps the required n to the next rung (§2.3.1)."""
    out: dict[int, int | None] = {}
    for k in ks:
        found: int | None = None
        for n in range(max(k, 1), cap + 1):
            if wilson_interval(k, n, z=z)[2] <= threshold:
                found = n
                break
        out[k] = found
    return out


def _attack_guidance(point: float, threshold: float) -> str:
    first_pass, stable_n = stable_n_for_lower_bound(point, threshold)
    if stable_n is None:
        return (
            f"点估计 ~{point * 100:.0f}% 不高于 {_thr(threshold)}，扩样本无法过线 —— "
            "需提高命中率本身，而非加样本。"
        )
    cross = ""
    if first_pass is not None and first_pass < stable_n:
        cross = f"（{first_pass}–{stable_n - 1} 之间会来回穿越，不可作阶段目标）"
    return (
        f"若新增用例的命中率维持在 ~{point * 100:.0f}%，区间下界自 n≈{stable_n} 起稳定过 "
        f"{_thr(threshold)}{cross}；n 是必要非充分：扩的是新样本，点估计会动 —— "
        f"扩到 {stable_n} 而命中率下移，照样不过。"
    )


def _benign_guidance(threshold: float) -> str:
    ladder = n_ladder_for_upper_bound(threshold)
    rungs = "/".join(str(ladder[k]) if ladder[k] is not None else "?" for k in _KS)
    base = ladder[_KS[0]]
    tail = f"「扩到 {base}」只在一个都不误拦时成立。" if base is not None else ""
    return (
        f"上界随样本量下降，但误拦数每 +1 就跳一档（k=0→3 依次需 n≥ {rungs}）；{tail}"
    )


# --------------------------------------------------------------------------- #
# Per-objective fact sentences
# --------------------------------------------------------------------------- #
def _unmet_sentence(o: MeasuredObjective) -> str:
    ind = o.indicator_id or o.objective_id
    val = o.value if o.value is not None else 0.0
    n = o.sample_size or 0
    field, op, tau = _parse(o.satisfied_when)
    if field == "ci_low" and n > 0:
        cl = wilson_interval(round(val * n), n)[0]
        return (
            f"实测未达 {o.level} —— {ind} {_pct(val)} (n={n})，ci_low {_f3(cl)} < {_thr(tau)}"
            f"（样本不足，非能力不足）。{_attack_guidance(val, tau)}"
        )
    if field == "ci_high" and n > 0:
        ch = wilson_interval(round(val * n), n)[2]
        return (
            f"实测未达 {o.level} —— {ind} {_pct(val)} (n={n})，ci_high {_f3(ch)} > {_thr(tau)}"
            f"（样本不足，非能力不足）。{_benign_guidance(tau)}"
        )
    # A `value`-predicate failure (no interval gate): a real quality miss, no n-projection to give.
    op_txt = f"{field} {op} {_thr(tau)}" if field else "判据"
    return f"实测未达 {o.level} —— {ind} {_pct(val)} (n={n})，未过 {op_txt}。"


def _short(objective_id: str) -> str:
    """The human control name — the last dotted segment (sec.l3.guardrail_blocking → guardrail_blocking).
    The objective is what a reader recognizes; its backing indicator (e.g. block_rate) is the technical
    id to go chase."""
    return objective_id.split(".")[-1]


def _blocked_sentence(
    bp: str, missing: list[MeasuredObjective], met_siblings: list[str]
) -> str:
    # Name the CONTROL (recognizable) AND the indicator that actually didn't produce (the thing to
    # investigate) — they differ (guardrail_blocking ← block_rate), and the operator needs both.
    parts = []
    for o in missing:
        short = _short(o.objective_id)
        parts.append(
            f"{short}（指标 {o.indicator_id} 本次未产出）"
            if o.indicator_id and o.indicator_id != short
            else f"{short}（本次未产出）"
        )
    below = _level_below(bp)
    lead = f"达 {below}；" if below else ""
    sib = f"（同级 {'、'.join(met_siblings)} 已达标）" if met_siblings else ""
    return f"{lead}{bp} 缺 {'、'.join(parts)}{sib}。"


def _unverified_sentence(o: MeasuredObjective) -> str:
    ind = o.indicator_id or o.objective_id
    return (
        f"{o.level} 的 {ind} 证据来自不可链校验的来源，不予采信 —— 换 WAL 证据源可解。"
    )


def _not_measured_sentence(measured: list[MeasuredObjective]) -> str:
    names = [
        o.indicator_id or o.objective_id
        for o in measured
        if o.indicator_id or o.objective_id
    ]
    if not names:
        return "无实测信号 —— 本维度没有实测指标。"
    return f"无实测信号 —— 本维度未产出任何实测指标：{'、'.join(names)}。"


def _parse(expr: str | None) -> tuple[str | None, str | None, float]:
    if not expr:
        return (None, None, 0.0)
    try:
        return parse_satisfied_when(expr)
    except SatisfiedWhenError:
        return (None, None, 0.0)


# --------------------------------------------------------------------------- #
# The one entry point the engine calls.
# --------------------------------------------------------------------------- #
def classify(
    measured: list[MeasuredObjective],
    measured_ceiling: str | None,
    *,
    chain_broken: bool,
) -> tuple[str, str | None, tuple[str, ...]]:
    """Return `(measured_state, measured_breakpoint, measured_gap)` for one dimension.

    `measured_breakpoint` is the level where the ladder broke — the "未达 L2" the pill/radar show,
    serialized so nobody re-derives it from the prose (None for certified / not_measured).
    `chain_broken` = the whole report has ≥1 BROKEN measurement (cause A) — then every non-certified
    dimension collapses to the pointer gap (acceptance 20). `measured_gap` is empty ONLY for
    `certified` (C8: every non-certified dimension MUST carry a fact)."""
    if measured_ceiling is not None:
        return (CERTIFIED, None, ())

    # ---- state (the coarse pill), by the breakpoint's non-met reason -----------------------
    if not measured or all(o.status == "insufficient_data" for o in measured):
        state, bp, bp_nonmet = NOT_MEASURED, None, []
    else:
        bp = _breakpoint(measured)
        bp_nonmet = [o for o in measured if o.level == bp and o.status != "met"]
        statuses = {o.status for o in bp_nonmet}
        if "unmet" in statuses:
            state = BELOW_FLOOR
        elif "unverified_evidence" in statuses:
            state = EVIDENCE_UNVERIFIED
        else:
            state = BLOCKED_NO_DATA

    # ---- gap (the facts) — required for every non-certified dimension (C8) ------------------
    if chain_broken:
        # Cause A anywhere ⇒ the whole report is void; no dimension tells a level-story (acc. 20).
        return (state, bp, _CHAIN_BROKEN_GAP_TUPLE)
    if (
        bp is None
    ):  # not_measured (the only null-breakpoint state) — also narrows bp to str below
        return (state, None, (_not_measured_sentence(measured),))

    met_siblings = [
        _short(o.objective_id) for o in measured if o.level == bp and o.status == "met"
    ]
    insufficient = [o for o in bp_nonmet if o.status == "insufficient_data"]
    sentences: list[str] = []
    # Emit PER non-met objective (C10), in registry/level order, each with its own evidence — a
    # mixed breakpoint yields both an unmet line (with interval) and a missing-data line.
    for o in bp_nonmet:
        if o.status == "unmet":
            sentences.append(_unmet_sentence(o))
        elif o.status == "unverified_evidence":
            sentences.append(_unverified_sentence(o))
    if insufficient:
        sentences.append(_blocked_sentence(bp, insufficient, met_siblings))
    return (state, bp, tuple(sentences))
