"""B/C/D —— 判别器两列 · 被动侧在 echo 上量错了对象 · 跑前门形态改判。

施工单：`trustworthy-ai-platform/docs/collab/BCD_SUPPRESSION_PASSIVE_WINDOW_PREFLIGHT_WORK_ORDER.md`

🔴 三件（B1 / C1 / C2）是同一条失效的三个实例：**一个数看起来正常，而它量的不是
它声称的那件事**。B1 恒为 0 读成"没有代价"·C1 量输入读成"输出泄漏"·C2 两个分母
各自自洽而口径不同。**三者都不会让任何一道门变红** —— 这正是它们要被单独测的理由。

每个测试的 docstring 第一行写【什么输入让它红】。
"""

from __future__ import annotations

import pytest

from treval.cli import collect as _collect
from treval.cli.collect import (
    BASELINE_EXPECT_DIFFERENT,
    BASELINE_EXPECT_SAME,
    BASELINE_MATCHED,
    BASELINE_MISMATCH,
    BASELINE_NOT_DECLARED,
    baseline_gate_verdict,
)

# --------------------------------------------------------------------------- #
# 探针助手 —— 造一件带 type-3 治理记录的探针（B1/B2 要的）
# --------------------------------------------------------------------------- #


class _Rule:
    def __init__(self, rule_id: str, matched: bool, tags: dict[str, str]) -> None:
        self.rule_id, self.matched, self.tags = rule_id, matched, tags


class _Decision:
    def __init__(self, rules: list[_Rule]) -> None:
        self.rules_evaluated = rules
        self.final_decision = 0
        self.scores: dict[str, float] = {}


class _Audit:
    def __init__(self, hint: bool) -> None:
        self.hint_emitted = hint


class _Record:
    def __init__(self, rules: list[_Rule], hint: bool) -> None:
        self.decision, self.audit = _Decision(rules), _Audit(hint)


class _Ev:
    def __init__(self, rules: list[_Rule], hint: bool) -> None:
        self.record = _Record(rules, hint)


class _PR:
    """只带 governance_evidence 的最小探针 —— B1/B2 读的就是这一格。"""

    def __init__(
        self,
        *,
        matched: bool = False,
        verdict: str | None = None,
        legacy: str | None = None,
        hint: bool = False,
        governed: bool = True,
    ) -> None:
        tags: dict[str, str] = {"tier": "2"}
        if verdict:
            tags["speech_act_verdict"] = verdict
        if legacy:
            tags["suppressed_by"] = legacy
        rules = [_Rule("inj.tier2.shadow", matched, tags)]
        self.governance_evidence = _Ev(rules, hint) if governed else None
        # `_ref()` 要这两格 —— 没有 WAL ref 时退回 request_id ref（可审性不变式）
        self.evidence = None
        self.request_id = "req-x"


# =========================================================================== #
# B1 · would_suppress 两列 —— 换键，口径一字不改
# =========================================================================== #
def test_b1_reads_the_new_key_not_the_one_that_is_now_always_zero():
    """🔴 验收 1 —— 什么让它红：仍读 `suppressed_by`。

    A4 撤线之后 `suppressed_by` 的计数**恒为 0**，而"恒为 0"与"没有代价"在
    产物行上长得一模一样。判别器仍然常开、票仍然留痕，只是换了键。
    """
    from treval.active_eval.checks import speech_act_verdict

    assert speech_act_verdict(_PR(verdict="would_suppress")) == "would_suppress"
    # 只有旧键 ⇒ 新读法读不到（这正是"恒为 0"的来源）
    assert speech_act_verdict(_PR(legacy="speech_act")) is None


def test_b1_the_legacy_key_still_reads_on_historical_artifacts():
    """🔴 验收 2（要害）—— 什么让它红：换键时把历史产物读废了。

    2026-09-12 那一跑里 `suppressed_by="speech_act"` 是**真的**（件数在私有仓的跑批产物里，
    🔴 纪律②不进公开仓 —— 而这条测试要说的事不依赖那个数：它非零）。
    两个键各自对应一段时间，**不是一个替换另一个** —— 合成一个读法，
    就会把"那时真的被抑制了"读成"从来没有过"。
    """
    from treval.active_eval.checks import suppressed_by_legacy

    assert suppressed_by_legacy(_PR(legacy="speech_act")) == "speech_act"
    assert suppressed_by_legacy(_PR(verdict="would_suppress")) is None


def test_b1_cost_and_no_cost_are_two_columns_never_one_bare_count():
    """🔴 验收 3 —— 什么让它红：合成一个裸计数 ⇒ 混两种含义。

    打标有两条通道：无条件打标那条会产出 `would_suppress ∧ ¬matched`
    —— **打标 ≠ 吃掉 hint**，那一件是【无代价】的。
    """
    from treval.active_eval.indicators import WouldSuppressCost, WouldSuppressNoCost

    probes = [
        _PR(matched=True, verdict="would_suppress"),  # 有代价
        _PR(matched=True, verdict="would_suppress"),  # 有代价
        _PR(matched=False, verdict="would_suppress"),  # 无代价
        _PR(matched=True),  # flag 了但没被投票
    ]
    (cost,) = WouldSuppressCost().measure(probes)
    (nocost,) = WouldSuppressNoCost().measure(probes)
    assert cost.value == 2.0 and nocost.value == 1.0
    assert cost.indicator_id != nocost.indicator_id
    # 🔴 两列的 id 都带 tier2_ 前缀 —— 那是射程：A4 也作用在决策记录上，而这两列看不见那一半
    assert cost.indicator_id.startswith("tier2_")
    assert nocost.indicator_id.startswith("tier2_")


# =========================================================================== #
# B2 · tier2_flag_rate —— 与 combined_recall 分子不同
# =========================================================================== #
def test_b2_flag_rate_counts_matched_while_combined_recall_is_untouched():
    """🔴 验收 4 —— 什么让它红：有人把 `matched` 并进 `combined_recall`。

    改它与认证跑冻结件逐字矛盾（notes：「catch = hint_emitted, never the raw score」）。
    这里验的是：flag 率数 `matched`（不看 hint），而 catch 那一侧的判据一字未变。
    """
    import inspect

    from treval.active_eval.indicators import InjectionCombinedRecall, Tier2FlagRate

    probes = [
        _PR(matched=True, hint=False),  # 判官抓到了，而 hint 没发出去
        _PR(matched=True, hint=True),
        _PR(matched=False, hint=False),
    ]
    (m,) = Tier2FlagRate().measure(probes)
    assert m.value == pytest.approx(2 / 3)
    assert m.sample_size == 3
    # combined_recall 仍然读 caught_by_tier2（hint ∧ matched），不读 matched 单独
    src = inspect.getsource(InjectionCombinedRecall)
    assert "tier2_flagged" not in src


def test_b2_the_denominator_is_what_the_judge_actually_scored():
    """🔴 什么让它红：把判官没看过的件放进分母。

    入口期已拦下的件不转发 ⇒ 判官不评分 ⇒ 它们**没有进过这条路**。
    把它们放进分母，两个率都会被一个与它们无关的量稀释。
    """
    from treval.active_eval.indicators import Tier2FlagRate

    probes = [_PR(matched=True), _PR(governed=False), _PR(governed=False)]
    (m,) = Tier2FlagRate().measure(probes)
    assert m.sample_size == 1 and m.value == 1.0


# =========================================================================== #
# C1 · 被动输出侧在 echo 上量的是输入
# =========================================================================== #
def test_c1_output_side_passive_indicators_are_named_not_pattern_matched():
    """🔴 什么让它红：用名字里含 "pii"/"output" 之类的模式去挑 —— 那是按形状数。

    集合是**显式枚举**：加一个成员要有人回答"它读的是模型输出吗"。
    """
    assert _collect._OUTPUT_SIDE_PASSIVE == frozenset(
        {"pii_exposure_surface", "redaction_hit_ratio", "boundary_breach_rate"}
    )
    passive_ids = {i.indicator_id for i in _collect.PASSIVE}
    # 枚举里的每一个都必须真的在被动集合里 —— 否则它是一条过期的豁免
    assert _collect._OUTPUT_SIDE_PASSIVE <= passive_ids


def test_c1_blanking_keeps_the_row_and_kills_the_number():
    """🔴 验收 5（要害）—— 什么让它红：给一个 1.0，或者干脆把行删掉。

    删掉会让"这一跑没有这个指标"与"这一跑不可测"同形，而两者的处置相反
    （前者去接线，后者去换目标）。实证 2026-09-14：`pii_exposure_surface`
    在 echo 上报 **1.0**，而在有真实上游的那一跑上是 **0.0** —— echo 回显请求。
    """
    from treval.models import Measurement

    m = Measurement(
        indicator_id="pii_exposure_surface",
        dimension="privacy",
        value=1.0,
        unit="ratio",
        sample_size=219,
        evidence_refs=(),
        notes="orig",
    )
    blanked = _collect._blank_output_side(m)
    assert blanked.indicator_id == m.indicator_id  # 行还在
    assert blanked.sample_size == 0 and blanked.value == 0.0  # 数没了
    assert blanked.ci_low is None and blanked.ci_high is None
    assert "不可测" in blanked.notes and "输入" in blanked.notes


# =========================================================================== #
# C2 · probe_window 覆盖对账
# =========================================================================== #
def test_c2_counts_distinct_requests_not_records(tmp_path):
    """🔴 验收 6（要害）—— 什么让它红：按【记录条数】数，或不按 type-1 过滤。

    一次探针会写多条记录（决策 / 响应 / 异步治理）⇒ 按条数数会**恒不等**，
    那样这条对账就成了一条恒红的门 —— 而恒红与恒绿一样没有信息。

    ⚠️ 本条此前写成 `inspect.getsource(...)` 里 grep 两个标识符 —— 售后研发 2026-09-15
    指出那不是行为断言：**标识符写在注释里也能过**，有人把计数改回按条数、标识符仍留在
    注释中，它不会红。⇒ 改成真的写一段 WAL 再读。

    构造：同一个 request_id 写 **2 条** type-1 + 另一个 request_id 写 1 条 type-3。
        按条数数 ⇒ 3（红）· 不按类型过滤 ⇒ 2（红）· 正确答案 ⇒ **1**
    """
    from tests import walgen
    from trustworthy_ai.v1 import request_context_pb2 as rc_pb

    from treval.active_eval.target import _DECISION_MADE, _GOVERNANCE_OBSERVED

    def _rec(request_id: str, rtype: int, at_ns: int) -> bytes:
        ctx = rc_pb.RequestContext()
        ctx.envelope.request_id = request_id
        ctx.envelope.tenant_id = "t"
        ctx.envelope.received_at_ns = at_ns
        ctx.record_type = rtype
        return ctx.SerializeToString()

    d = tmp_path / "wal"
    d.mkdir()
    walgen.write_v2_segment(
        d / walgen.NAME.format(0),
        0,
        [
            _rec("req-A", _DECISION_MADE, 10),  # 同一件探针的两条决策记录
            _rec("req-A", _DECISION_MADE, 11),
            _rec("req-B", _GOVERNANCE_OBSERVED, 12),  # 另一件，但是异步治理记录
        ],
        walgen.GENESIS,
    )
    warnings: list[str] = []
    got = _collect._probes_covered_by_window(str(d), "t", (0, 100), warnings=warnings)
    assert got == 1, "按条数数会得 3，不按 type-1 过滤会得 2 —— 正确答案是 1"
    assert warnings == []


def test_c2_an_unreadable_wal_is_none_not_zero():
    """🔴 什么让它红：读不出来时兜成 0 ⇒ 变成"窗口一件都没盖住"的假发现。

    一次失败的读取不是一次"零覆盖"的观测（与 `judge_imprint` 0 字节即拒同族）。
    """
    warnings: list[str] = []
    got = _collect._probes_covered_by_window(
        "/nonexistent/wal", "t", (0, 1), warnings=warnings
    )
    assert got is None
    assert warnings and "读取失败" in warnings[0]


# =========================================================================== #
# D1 · 跑前门形态改判 —— 双向守
# =========================================================================== #
@pytest.mark.parametrize(
    ("compared", "expect", "halt", "speaks"),
    [
        # 🔴 验收 7：不一致 + 未声明 ⇒ 红
        (BASELINE_MISMATCH, None, True, True),
        # 🔴 验收 8：不一致 + 声明"预期不同" ⇒ 放行并记录
        #   （会拦住我们正要跑的那一跑 —— 规则专家 2026-09-13 提的正是这个）
        (BASELINE_MISMATCH, BASELINE_EXPECT_DIFFERENT, False, True),
        # 🔴 验收 9（要害）：一致 + 声明"预期不同" ⇒ 不停机，但【也要出声】
        (BASELINE_MATCHED, BASELINE_EXPECT_DIFFERENT, False, True),
        # 一致 + 声明"预期相同" ⇒ 最强的一种通过，不出声
        (BASELINE_MATCHED, BASELINE_EXPECT_SAME, False, False),
        # 没做过比对 ⇒ 任何声明都没有对照物
        (BASELINE_NOT_DECLARED, BASELINE_EXPECT_DIFFERENT, False, True),
        (BASELINE_NOT_DECLARED, None, False, False),
    ],
)
def test_d1_the_gate_guards_both_directions(
    compared: str, expect: str | None, halt: bool, speaks: bool
) -> None:
    """🔴 什么让它红：只守"不一致"那一个方向。

    声明与事实**反方向**不符一样是错：它说明操作者对本跑的认识与实际不一致，
    而下一步很可能是把这一跑当成"改动已生效"来读。
    """
    got_halt, msg = baseline_gate_verdict(compared, expect)
    assert got_halt is halt, (compared, expect)
    assert bool(msg) is speaks, (compared, expect)


def test_d1_the_cli_choices_match_the_module_vocabulary():
    """🔴 什么让它红：两处取值域漂开。

    `main.py` 用字面量（collect 是惰性导入的，为一个 choices 破坏那条隔离不值），
    ⇒ 代价是两份取值域，**由这条测试钉住它们必须相等**。
    """
    from treval.cli.main import build_parser

    import argparse

    parser = build_parser()
    # `--baseline-expect` 挂在 collect 子命令上，不在顶层 —— 走一层子解析器
    subs = [a for a in parser._actions if isinstance(a, argparse._SubParsersAction)]
    collect_parser = next(
        sp for s_ in subs for name, sp in s_.choices.items() if name == "collect"
    )
    action = next(
        a
        for a in collect_parser._actions
        if getattr(a, "dest", "") == "baseline_expect"
    )
    assert tuple(action.choices or ()) == _collect.BASELINE_EXPECTATIONS


# =========================================================================== #
# D2 · citability.py 那句话的射程
# =========================================================================== #
def test_d2_the_path_requirement_states_which_comparison_it_covers():
    """🔴 验收 10 —— 什么让它红：留下一条指向没人遵守的规则的过期指令。

    该行原文要求"ruleset_sha256 参与比较须带 ruleset_path"，而 C2A0 的跑前比对
    **刻意不比路径**。不写明射程，它就是一条与实现直接矛盾的指令。
    """
    from treval import citability

    fix = citability._BUILD_UNCOVERED_FIX
    assert "印记" in fix or "指纹身份" in fix  # 说明它管哪一种比较
    assert "跑前比对" in fix and "不比路径" in fix  # 且点名另一种不适用
