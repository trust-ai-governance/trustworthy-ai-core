"""UI-3 §5.1 / C1 — the case contract's READ half is pure (stdlib only) and importing it (or the
`cases verify` CLI) must NOT drag in the active-eval harness. That isolation is what lets the case
SERVICE and the verify CLI read contracts with ZERO ability to fire a probe (EV-W1 §7-5)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _no_harness(module: str) -> None:
    code = (
        f"import sys; import {module}; "
        "leaked = [m for m in sys.modules if m.startswith('treval.active_eval')]; "
        f"assert not leaked, '{module} pulled the harness: ' + repr(leaked)"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=_ROOT
    )
    assert proc.returncode == 0, proc.stderr


def test_case_contract_is_engine_free():
    """🔴 import the pure reader ⇒ the harness stays out of sys.modules. Add an active_eval import
    to treval/case_contract.py and this goes red."""
    _no_harness("treval.case_contract")


def test_cases_verify_cli_is_engine_free():
    """🔴 C1: `cases verify` reads the pure module now (module-level import), so the CLI no longer
    pulls the harness either."""
    _no_harness("treval.cli.cases_verify")


def test_read_half_is_reexported_unchanged():
    """The split is invisible to existing import paths: the names re-exported from active_eval.cases
    ARE the pure module's objects (not copies)."""
    from treval import case_contract
    from treval.active_eval import cases

    for name in (
        "CaseContractError",
        "recompute_from_cases",
        "compare_cases_to_aggregates",
        "validate_case_contract",
        "SCHEMA_VERSION",
        "VERDICTS",
    ):
        assert getattr(cases, name) is getattr(case_contract, name)


# ── 序8 件5 · 结构性守卫 —— 把"记住"换成"忘不掉"
#
# 🔴 catch 分母今天有五类排除（attribution_excluded / errors / undecided / unattributable /
# no_verdict）。每加一类，案级行都必须有一个能复现它的信号，否则 recompute_from_cases 与
# 聚合分道扬镳 ⇒ 契约 fork。这条规矩是 F1 时立的，而件3 加 `no_verdict` 时【我自己没照做】——
# 于是它在一次 41 分钟的真跑之后才被发现。
#
# 这条测试的作用不是验今天对不对（冒烟已经在验），是让【下一次忘记】立刻变红：
# 谁在 _CatchCounts 里新增一个排除计数，就必须在下面的映射里登记它对应的案级字段，
# 而登记时会被迫回答"案级行怎么复现这个排除"。答不上来 ⇒ 那个排除本身就不该加。
_EXCLUSION_TO_ROW_SIGNAL = {
    # 排除计数（_CatchCounts 字段）      → 案级行里复现它所需的字段
    "attribution_excluded": ("attack_class", "control_for"),
    "errors": ("verdict",),
    "undecided": ("verdict",),
    "unattributable": ("catch_attribution",),
    "no_verdict": ("terminal_verdict",),
}
# 不是排除、无需案级信号的计数字段（分子/证据/诊断），显式列出以便新增时必须归类
# 🔴 A3 — evaluated_miss 不是排除：它【留在分母】当漏检（reacted via non-injection while injection was
# evaluated）。recompute 用 catch_attribution=null 复现它当 miss（与"未反应"的 null 同为分母内漏检），
# 故它无需独立案级信号 ⇒ 归为非排除。
_NON_EXCLUSION_FIELDS = {"refs", "caught", "prefix_fallback", "evaluated_miss"}


def test_every_catch_exclusion_has_a_case_row_signal():
    """🔴 结构性守卫：_CatchCounts 的每一个字段，要么是排除且在映射里登记了案级信号，
    要么被显式列为非排除。新增一个排除却不登记 ⇒ 本测试红。

    什么输入让它红：在 _CatchCounts 里加一个新的排除计数（如 `foo_excluded`）而不动本文件。
    这正是件3 发生过的事 —— 那次没有守卫，代价是一次 41 分钟的真跑。"""
    from treval.active_eval.indicators import _CatchCounts

    fields = set(_CatchCounts._fields)
    known = set(_EXCLUSION_TO_ROW_SIGNAL) | _NON_EXCLUSION_FIELDS
    unclassified = fields - known
    assert not unclassified, (
        f"_CatchCounts 新增了未归类的字段 {sorted(unclassified)} —— "
        "若它是分母排除，请在 _EXCLUSION_TO_ROW_SIGNAL 登记它对应的案级字段"
        "（并确认 recompute_from_cases 真的读了那个字段）；"
        "若不是排除，请加进 _NON_EXCLUSION_FIELDS。"
        "🔴 不许两边都不填 —— 件3 就是这样让契约 fork 的。"
    )
    stale = set(_EXCLUSION_TO_ROW_SIGNAL) - fields
    assert not stale, f"映射里登记了已不存在的排除 {sorted(stale)}，请清理"


def test_registered_row_signals_are_actually_emitted_and_read():
    """登记不等于兑现：每个登记的案级字段必须①真的出现在 build_cases 产出的行里
    ②真的被 recompute_from_cases 读到。防"登记了但没接线"。"""
    import inspect

    from treval.active_eval import cases as cases_mod
    from treval import case_contract

    emitted = inspect.getsource(cases_mod.build_cases)
    read = inspect.getsource(case_contract.recompute_from_cases) + inspect.getsource(
        case_contract.catch_excluded_case_ids
    )
    for exclusion, signals in _EXCLUSION_TO_ROW_SIGNAL.items():
        for sig in signals:
            assert f'"{sig}"' in emitted, (
                f"排除 {exclusion} 登记的案级字段 {sig} 没有出现在 build_cases 的行里"
            )
            assert f'"{sig}"' in read, (
                f"排除 {exclusion} 登记的案级字段 {sig} 没有被 recompute/exclusion 读到 —— "
                "登记了却没接线，契约仍会 fork"
            )
