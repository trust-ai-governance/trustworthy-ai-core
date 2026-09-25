"""C-3a-1 —— 给三个「已建好没接上」的指标接消费方。每条先说【什么输入让它红】。

🔴 本单的要害**不在新指标的数上**：接错了，新指标照样出数，而被动的是**别的门和别的跑批** ——
载体率门的臂（`carrier_arm_dirs`）与认证跑的编组（`curation_for("inj")` / `("w2")`）。
所以本文件里最重的两组断言（第二节、第三节）一个都不读新指标的 value。

🔴 三处「单与代码不符」，在这里逐条钉住，因为它们都属于**读了一份快照就动手**会踩的那一类：
  ① `CURATION_INJ` **不只**按 corpus_subdir 过滤，它还过滤 `_DECISION_SIDE_ONLY`
     ⇒ 只加 Producer，覆盖率进不了认证跑，于是 lift 出数、覆盖率不出数 —— 正是该指标存在的
     理由所描述的那个缺陷，原样保留在编组里（第四节）。
  ② A 件是「零改动」而它的数又必须带一句臂级限定，两者只能同时成立在**绑定**那一层（第五节）。
  ③ 那句「n 太小」限定对 C 件是**假的** —— C 跑在完整注入臂上（第五节最后一条）。
"""

from __future__ import annotations

from pathlib import Path

import pytest
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval import EVIDENCE_REQUIREMENTS, load_corpus
from treval.active_eval.indicators import (
    InjectionCatchRate,
    WireIndirectBenignFlagRate,
    WireIndirectCatchRate,
)
from treval.active_eval.target import ProbeResult
from treval.cli import collect as _collect
from treval.cli.collect import (
    SMALL_ARM_NOTE,
    assert_no_output_side_is_legitimate,
    carrier_arm_dirs,
    collect_measurements,
    curation_for,
)
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_REPO = Path(__file__).resolve().parents[1]
_CORPUS = _REPO / "corpus"

_WIRE_ARM = "llm01_wire_indirect"
_WIRE_BENIGN_ARM = "llm01_indirect_benign"
_BENIGN_ID = "wire_indirect_benign_flag_rate"

_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_UNSPEC = rc_pb.DecisionTrace.FINAL_DECISION_UNSPECIFIED


# --------------------------------------------------------------------------- #
# 夹具
# --------------------------------------------------------------------------- #
def _ev(cid: str, *, decision=_ALLOW, hint: bool = False, rules: int = 1):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.decision.final_decision = decision  # type: ignore[assignment]
    for i in range(rules):
        r = ctx.decision.rules_evaluated.add()
        r.rule_id = f"inj-{i}"
        r.matched = decision == _BLOCK
        r.tags["owasp"] = "LLM01"
    ctx.audit.hint_emitted = hint
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=0, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="__eval__",
        received_at_ns=0,
        record=ctx,
    )


def _pr(
    cid: str,
    *,
    decision=_ALLOW,
    hint: bool = False,
    rules: int = 1,
    evidence: bool = True,
    error: str | None = None,
    attack_class: str = "benign_hard_negative",
) -> ProbeResult:
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="",
        response_text="ok",
        evidence=(
            _ev(cid, decision=decision, hint=hint, rules=rules)
            if evidence and error is None
            else None
        ),
        error=error,
        attack_class=attack_class,
    )


class _GovernedTarget:
    """每件都回一条**真的决策记录**（ALLOW，评过规则）—— 良性侧那几个指标只有拿到决策记录
    才进得了分母。`_FakeTarget`（evidence=None）会让整条臂算成"无决策记录"，于是分母恒 0，
    而 0/0 与"量过、没有误伤"在产物上长得一样。"""

    target_id = "fake-governed"

    def probe(self, case):
        return ProbeResult(
            case_id=case.id,
            request_id=f"req-{case.id}",
            decision="ALLOW",
            response_text="",
            evidence=_ev(case.id),
            attack_class=getattr(case, "attack_class", "") or "",
        )


def _rows(measurements):
    return {m.indicator_id: m for m in measurements if m.subject == ""}


@pytest.fixture(scope="module")
def collected():
    warnings: list[str] = []
    scan = collect_measurements(
        _GovernedTarget(), corpus_root=_CORPUS, warnings=warnings
    )
    assert warnings == [], warnings
    return scan


# =========================================================================== #
# 一 · 接线本身（验收 1、7、8）
# =========================================================================== #
def test_all_three_are_wired_to_the_arm_the_order_names():
    """🔴 什么让它红：漏接任意一件，或接到别的臂上。

    这三件此前的状态都是「指标建好了、分类登记了、语料写了、**没有消费方**」——
    语料被运维 CLI 跑过，而「这条路径测过没有」在**产物**上答不出来。
    """
    bound = {(p.indicator_id, p.corpus_subdir) for p in curation_for("en")}
    assert ("wire_indirect_catch_rate", _WIRE_ARM) in bound
    assert (_BENIGN_ID, _WIRE_BENIGN_ARM) in bound
    assert ("tier2_judge_coverage", "llm01_prompt_injection") in bound


def test_no_longer_declared_absent(caplog):
    """验收 8 —— 缺席声明门对三者都不再报"未接线"。

    🔴 什么让它红：接了线却不把条目从 `_NOT_IN_CURATION` 里撤掉 —— 那是一条**过期的豁免**，
    它会掩盖后来的一次反向拆线（拆掉之后一切照绿）。那道门自己会红，这条是它的正面陈述。
    """
    from tests.test_ev_judge_union import _NOT_IN_CURATION, _curation_indicator_ids

    wired = _curation_indicator_ids()
    for iid in ("wire_indirect_catch_rate", _BENIGN_ID, "tier2_judge_coverage"):
        assert iid in wired
        assert iid not in _NOT_IN_CURATION


def test_the_new_benign_indicator_declares_its_evidence_class():
    """验收 7 —— 🔴 什么让它红：不登记。

    漏登记不会报错：它走 `None ⇒ needs_wal` 兜底，在 gateway 上一律解析成 `measured`
    ⇒ 一个**从没被分类**的指标和一个正确分类的指标，在产物上一模一样。本仓已因此栽过三次。
    """
    assert EVIDENCE_REQUIREMENTS[_BENIGN_ID] == "needs_decision"


def test_each_new_producer_actually_emits_a_row(collected):
    """验收 1 —— 三件各产出一行。🔴 什么让它红：Producer 接了臂却拿不到探针结果（静默跳过）。

    ⚠️ 覆盖率那一行在 collect 上**必然**是 not_measured：collect 从不排空异步治理记录
    （与 `tier2_shadow_recall_lift` 同一个生命周期）。所以这里断言的是"它出了一行、且那行的
    不可测理由是**排空没跑**"，不是"它出了一个数" —— 后者在 collect 上做不到，
    而把做不到的事写成验收，等于把一条门写成永远红或永远靠豁免。
    """
    rows = _rows(collected.measurements)
    assert rows["wire_indirect_catch_rate"].sample_size > 0
    assert rows[_BENIGN_ID].sample_size > 0
    cov = rows["tier2_judge_coverage"]
    assert cov.sample_size == 0 and "未排空" in cov.notes


# =========================================================================== #
# 🔴 二 · 载体率门（验收 2）—— 要害之一：接错了新指标照样出数，被动的是这道门
# =========================================================================== #
def test_the_two_new_arms_are_in_neither_carrier_arm():
    """🔴 什么让它红：把 `wire_indirect_benign_flag_rate` 加进 `_BENIGN_ARM_INDICATOR_IDS`，
    或把件B 的 id 写成 `false_positive_rate` / `benign_flag_rate`。

    两种改法**都不会动新指标的值**：那条臂照跑、那个数照出。被动的是载体率门 ——
    它的臂是从【指标↔语料绑定】派生的（这是**设计**：一个已知的良性指标绑到新语料上会把那条
    语料自动拉进臂），于是门的分母悄悄变宽，而「载体率差 ≤ 20pp」不再是它声称的那个量。
    """
    for corpus_set in _collect.CORPUS_SETS:
        attack, benign = carrier_arm_dirs(curation_for(corpus_set))
        assert _WIRE_ARM not in attack and _WIRE_ARM not in benign, corpus_set
        assert _WIRE_BENIGN_ARM not in attack and _WIRE_BENIGN_ARM not in benign, (
            corpus_set
        )


def test_the_new_ids_are_in_neither_arm_indicator_set():
    """同一件事的**另一条路**：上一条读派生结果，这一条读派生的**输入**。

    🔴 什么让它红：任何一次「顺手把新指标归进良性臂」。两条都在，是因为它们会在不同的改法下红：
    上一条对"换成既有 id"红，这一条对"新 id 被加进集合"红。
    """
    both = _collect._ATTACK_ARM_INDICATOR_IDS | _collect._BENIGN_ARM_INDICATOR_IDS
    assert "wire_indirect_catch_rate" not in both
    assert _BENIGN_ID not in both
    assert "tier2_judge_coverage" not in both


def test_the_real_carrier_gate_still_reads_only_its_two_original_dirs(capsys):
    """🔴 **对账门，不是防分叉门** —— 上面两条读的是 `carrier_arm_dirs`，与门读的是同一个函数；
    这一条跑**门自己**（`tools/check_canary`），读它**印出来的作用域**。

    什么让它红：本单的任何一条新臂进了门的作用域 —— 那时门印出的目录名里会多出一条，
    而它的两个臂数会是在另一个分母上算的。
    """
    import tools.check_canary as _cc

    rc = _cc.main([])
    out = capsys.readouterr().out
    assert rc == 0 and "PASS" in out
    assert "llm01_prompt_injection" in out and "llm01_benign_holdout" in out
    assert _WIRE_ARM not in out and _WIRE_BENIGN_ARM not in out


# =========================================================================== #
# 🔴 三 · 认证跑编组（验收 3）—— 要害之二：被动的是跑批编组，不是新指标
# =========================================================================== #
def test_certification_groupings_are_stated_by_hand_not_re_derived():
    """🔴 逐条手写期望集合，而**不是**把过滤条件再念一遍。

    「所有 CURATION_INJ 成员都绑注入臂且是决策侧」是把过滤器写两遍 —— 恒等式，零信息。
    手写的期望集合是**第二条独立的路**：它说的是「认证跑该跑哪几件」，与代码里的过滤条件
    在两个地方各自成立才携带信息。

    什么让它红：① 编组过滤被绕过（A/B 漏进认证跑）；② 覆盖率没进 inj（件C 落空）；
    ③ 任何一个既有 producer 被本单挤掉 —— 门 A / 门 B 的数就换了分母。
    """
    assert {
        (p.indicator_id, p.corpus_subdir, p.subject) for p in curation_for("inj")
    } == {
        ("injection_catch_rate", "llm01_prompt_injection", ""),
        ("injection_catch_rate", "llm01_prompt_injection", "outcome_observable"),
        # 🔴 C-0a 入口期拦截率 —— 2026-09-12 接线。指标与三条判据早就在位，
        # 缺的只有这一行；而 2026-09-12 的 C-2a 诊断跑正是因为它不在，
        # 主判据【产不出数】。手写在这里，因为"认证跑该跑哪几件"必须是第二条独立的路。
        ("injection_decision_block_rate", "llm01_prompt_injection", ""),
        ("injection_combined_recall", "llm01_prompt_injection", ""),
        ("tier2_shadow_recall_lift", "llm01_prompt_injection", ""),
        ("tier2_judge_coverage", "llm01_prompt_injection", ""),
    }
    assert {
        (p.indicator_id, p.corpus_subdir, p.subject) for p in curation_for("w2")
    } == {
        ("false_positive_rate", _collect.BENIGN_ARM_DEFAULT, ""),
        ("benign_flag_rate", _collect.BENIGN_ARM_DEFAULT, ""),
        ("benign_flag_rate", _collect.BENIGN_ARM_DEFAULT, "arm_parity:hard_only"),
    }


def test_the_two_new_arms_are_absent_from_every_certification_grouping():
    """🔴 什么让它红：把件A 或件B 绑到认证跑跑的那条臂上（例如件B 图省事绑良性留出臂）。

    那种改法**同样不体现在新指标的数上** —— 数照出，只是分母换成了另一条臂，
    而认证跑会多探一批它没声明过的件。
    """
    for corpus_set in ("inj", "w2"):
        dirs = {p.corpus_subdir for p in curation_for(corpus_set)}
        assert _WIRE_ARM not in dirs and _WIRE_BENIGN_ARM not in dirs, corpus_set


def test_the_certification_run_is_still_a_legitimate_no_output_side_run():
    """🔴 件C 进认证跑的前提：那一跑在 echo 转发器上（`--no-output-side`）。

    什么让它红：把 `tier2_judge_coverage` 从 `_DECISION_SIDE_ONLY` 拿掉 —— 那时它既进不了
    `CURATION_INJ`（上一条红），也会被这道守卫拒；或者相反，把一个真读正文的指标塞进认证跑。
    """
    assert_no_output_side_is_legitimate(curation_for("inj"))  # 不抛即通过
    with pytest.raises(ValueError, match="输出侧指标"):
        assert_no_output_side_is_legitimate(curation_for("en"))


def test_coverage_landing_in_inj_is_why_it_needs_the_decision_side_declaration():
    """🔴 单里写着「CURATION_INJ 按 corpus_subdir 过滤」—— 那是一份**快照**，代码里还有第二道
    过滤。这条把差异钉成断言，免得下一个人照着单再推一遍。

    什么让它红：`CURATION_INJ` 退回只按 subdir 过滤（那时认证跑会多出四个读模型输出的 producer，
    在 echo 上它们测不了），或 `tier2_judge_coverage` 退出 `_DECISION_SIDE_ONLY`。
    """
    assert "tier2_judge_coverage" in _collect._DECISION_SIDE_ONLY
    inj_ids = {p.indicator_id for p in curation_for("inj")}
    assert inj_ids <= _collect._DECISION_SIDE_ONLY
    # 注入臂上**有**读模型输出的 producer，而它们不在认证跑里 —— 证明第二道过滤真的在起作用
    en_inj_arm = {
        p.indicator_id
        for p in curation_for("en")
        if p.corpus_subdir == "llm01_prompt_injection"
    }
    assert en_inj_arm - inj_ids, (
        "注入臂上所有 producer 都进了认证跑 ⇒ 第二道过滤没起作用"
    )


# --------------------------------------------------------------------------- #
# 🔴 `_DECISION_SIDE_ONLY` 的成员表 —— 把注释变成门（架构师 2026-09-11 改判，随 #1 并入）
#
# 起因是一发变异，不是推测：往集合里加一个【只放宽守卫、不动编组】的 id，**全量门全绿**
# （另一个方向被那张手写的认证跑期望集合借力拦住了，而那不是这个集合自己的门）。
# 🔴 而漏掉的恰是守卫那一边 —— 集合对 `assert_no_output_side_is_legitimate` 是**白名单**，
# 加错一个成员就等于默许它和「本目标没有上游模型」并存，失效形态是本仓头号缺陷族里最贵的
# 那一种：把【没测到】读成【没问题】。
#
# 形状照 `_NOT_IN_CURATION`：两问的答案是 dict 的**值**，所以「加成员不答」在结构上做不到。
# ⚠️ 它挡不住一个敷衍的 ①答案（散文没法机器核）。它挡的是「没想过」，不是「想岔了」——
# 而 ②答案挡得住想岔了，因为它是一句关于世界的话，下面那条会去核实它。
# --------------------------------------------------------------------------- #
_NOT_IN_INJ_GROUPING = "不绑注入臂 ⇒ 对认证跑编组无影响"

# id → (① 它凭什么可以与 --no-output-side 并存, ② 它在认证跑编组里落在哪)
_DECISION_SIDE_RATIONALE: dict[str, tuple[str, str]] = {
    "injection_catch_rate": (
        "读 type-1 决策记录的 final_decision / hint，不读正文",
        "门 A 的召回 —— 认证跑的主数",
    ),
    "tier2_shadow_recall_lift": (
        "读 type-3 异步治理记录，不读正文",
        "Tier-2 买到了什么 —— 与覆盖率成对出",
    ),
    "injection_combined_recall": (
        "Tier-1 ∪ Tier-2 的并集，两侧读的都是记录不是正文",
        "门 A 缺的那一格（并集必须是一个数，不许读者自己加）",
    ),
    "tier2_judge_coverage": (
        "数 type-2 / type-3 记录【在不在】，不读记录里的 completion —— "
        "记录的存在与否在 echo 转发器上是真的",
        "lift 出数而覆盖率不出数，那个缺陷就原样保留着",
    ),
    "injection_decision_block_rate": (
        "分子逐字是 decision.final_decision == BLOCK —— 只读 type-1 决策记录，"
        "一个字节的响应正文都不读，所以它是集合里最纯的决策侧成员",
        "在认证跑编组里，与 injection_catch_rate 同一条臂、同一个分母（_catch_counts）；"
        "它是「拦住 X%」那句话唯一的来源，hard_blocked 在响应期 fail-closed 的栈上饱和成 n/n",
    ),
    "false_positive_rate": ("读 type-1 决策记录", _NOT_IN_INJ_GROUPING),
    "benign_flag_rate": ("读 type-1 决策记录 + type-3 hint", _NOT_IN_INJ_GROUPING),
    "benign_shadow_flag_rate": ("读 type-3 异步治理记录", _NOT_IN_INJ_GROUPING),
}


def test_every_decision_side_member_answers_both_questions():
    """🔴 什么让它红：往 `_DECISION_SIDE_ONLY` 加一个 id 而不答两问（或答空）。

    这是本集合自己的门。此前它没有门 —— 变异实测：加一个只放宽守卫、不动编组的 id，全量绿。
    """
    assert set(_collect._DECISION_SIDE_ONLY) == set(_DECISION_SIDE_RATIONALE), (
        "加成员必须同时在这张表里答两问：① 它凭什么可以与 --no-output-side 并存"
        "（＝它真的不读模型输出）② 它在认证跑编组里落在哪"
    )
    for iid, answers in _DECISION_SIDE_RATIONALE.items():
        assert len(answers) == 2 and all(a.strip() for a in answers), iid


def test_the_grouping_answers_are_verified_not_believed():
    """🔴 ②那一问的答案是**一句关于世界的话**，会过期 —— 所以核实它，不是相信它。

    什么让它红：① 一个声明"不绑注入臂"的 id 后来被绑上了（它悄悄进了认证跑产物，
    而表上仍写着对编组无影响）；② 一个声明了编组理由的 id 其实根本没进编组（理由是假的）。
    这正是 `_NOT_IN_CURATION` 那条「过期的豁免」教训，用在另一张表上。
    """
    in_inj = {p.indicator_id for p in curation_for("inj")}
    for iid, (_, grouping) in _DECISION_SIDE_RATIONALE.items():
        claims_absent = grouping == _NOT_IN_INJ_GROUPING
        assert claims_absent != (iid in in_inj), (
            f"{iid}：表上写「{grouping}」，而认证跑编组里它"
            f"{'在' if iid in in_inj else '不在'} —— 两者必须一致"
        )


# =========================================================================== #
# 🔴 四 · 那句限定（验收 4）—— 它挂在【绑定】上，不挂在指标上
# =========================================================================== #
def test_the_small_arm_limitation_rides_on_both_small_arms(collected):
    """验收 4 —— 🔴 什么让它红：把限定只写进文档（数会被摘出去引用，而文档不跟着走）。"""
    rows = _rows(collected.measurements)
    assert SMALL_ARM_NOTE in rows["wire_indirect_catch_rate"].notes
    assert SMALL_ARM_NOTE in rows[_BENIGN_ID].notes


def test_the_limitation_does_not_come_from_the_indicator(collected):
    """🔴 件A 是**零改动**（验收 5 的另一半）：那句限定必须来自**绑定**，不来自指标。

    什么让它红：把限定写进 `InjectionCatchRate.measure()` —— 那一份 notes 是完整注入臂
    共用的，于是一句只对小臂成立的话会被印到完整注入臂的数上。
    """
    (m,) = WireIndirectCatchRate().measure([_pr("x", attack_class="wire_indirect")])
    assert SMALL_ARM_NOTE not in m.notes  # 指标自己不带
    assert (
        SMALL_ARM_NOTE
        in _rows(collected.measurements)["wire_indirect_catch_rate"].notes
    )  # 绑定带上了


def test_the_limitation_is_absent_from_the_full_arm(collected):
    """🔴 那句限定对件C 是**假的** —— 它跑在完整注入臂上，不是六件九件的小臂。

    什么让它红：给件C 也挂上 `arm_note`（"三个指标都带同一句限定"的字面执行）。
    印一句假的限定不是保守：它给一个不需要打折的数打折，并且把这句话读成套话 ——
    下一个人在它**真**成立的臂上也就不读它了。
    """
    rows = _rows(collected.measurements)
    assert SMALL_ARM_NOTE not in rows["tier2_judge_coverage"].notes
    assert SMALL_ARM_NOTE not in rows["injection_catch_rate"].notes


def test_an_unannotated_binding_is_untouched(collected):
    """🔴 绝大多数绑定不声明限定 —— 它们的 notes 必须**一个字符不差**地原样通过。

    什么让它红：把追加写成无条件的（例如总是补一个分号），那时每一行的 notes 都变了，
    而下游按前缀/整串比对 notes 的东西会在一次"只加一句话"的改动里一起动。
    """
    (expected,) = InjectionCatchRate().measure(
        [_pr("a", attack_class="direct_prompt_injection")]
    )
    prod = next(
        p for p in curation_for("en") if p.indicator_id == "injection_catch_rate"
    )
    assert prod.arm_note == ""
    assert _collect._apply_arm_note(prod, expected).notes == expected.notes


# =========================================================================== #
# 五 · 件A 一行未改（验收 5）
# =========================================================================== #
def test_wire_indirect_catch_rate_indicator_is_bit_untouched():
    """🔴 什么让它红：给 `WireIndirectCatchRate` 写一个 `measure()` 覆盖，或改它的证据分类。

    它是**空类体 + 继承**，而那正是它当初被分类器漏掉的原因（§4.1 trap：
    "grep 类体找 pr.evidence" 的分类器看不见它）。本单只接线，不碰它。
    """
    assert "measure" not in WireIndirectCatchRate.__dict__, "件A 的 measure() 被覆盖了"
    assert WireIndirectCatchRate.measure is InjectionCatchRate.measure
    assert EVIDENCE_REQUIREMENTS["wire_indirect_catch_rate"] == "needs_decision"


# =========================================================================== #
# 六 · 件B 的判据与分母（验收 6）
# =========================================================================== #
def test_benign_denominator_is_this_arm_not_the_holdout_arm(collected):
    """验收 6 —— 🔴 什么让它红：复用良性留出臂的分母（或把件B 绑到那条臂上）。

    两条臂的分母不同，合用一个 id 就是「标签与数字不是同一个东西」。
    ⚠️ 件数从语料算出来，不写死 —— 写死的期望值会在下一次扩件时红，而红的是测试不是缺陷。
    """
    rows = _rows(collected.measurements)
    own_arm = len(load_corpus(_CORPUS / _WIRE_BENIGN_ARM))
    holdout = len(load_corpus(_CORPUS / "llm01_benign_holdout"))
    assert rows[_BENIGN_ID].sample_size == own_arm
    assert own_arm != holdout, "两条臂件数恰好相等 ⇒ 本条判据分辨不了对错，需要换判据"
    assert rows[_BENIGN_ID].arm_size == own_arm


def test_numerator_is_hard_union_soft_and_both_are_printed():
    """🔴 什么让它红：只数软标（照抄 `benign_flag_rate` 的口径），或只数硬拒。

    本 id 的分子比仓内 `benign_flag_rate` 宽，所以硬软两个数必须**分列**印出 ——
    否则读的人只能从名字去推口径，而名字沿用的是只数软标的那一族。
    """
    (m,) = WireIndirectBenignFlagRate().measure(
        [
            _pr("hard", decision=_BLOCK),
            _pr("soft", hint=True),
            _pr("clean1"),
            _pr("clean2"),
        ]
    )
    assert m.sample_size == 4 and m.value == 0.5
    assert "硬拒 1" in m.notes and "软标 1" in m.notes
    assert "2/4" in m.notes


def test_a_hard_denial_is_not_double_counted_as_a_flag():
    """🔴 什么让它红：把 `elif` 写成第二个 `if`，**并且**放松 `flagged_at_decision`
    的"非 BLOCK"前提。两格互斥必须落在**本处**，不靠读另一个函数的内部才成立。
    """
    (m,) = WireIndirectBenignFlagRate().measure([_pr("x", decision=_BLOCK, hint=True)])
    assert m.value == 1.0 and m.sample_size == 1
    assert "硬拒 1" in m.notes and "软标 0" in m.notes


def test_a_case_the_gateway_never_judged_exits_the_denominator():
    """🔴 什么让它红：把「没判过」折进"干净放行"。

    折进去的方向永远是"看起来更好"：分母涨、分子不动。三态各自计数，一个都不许合并。
    """
    (m,) = WireIndirectBenignFlagRate().measure(
        [
            _pr("ok"),
            _pr("undecided", decision=_UNSPEC),
            _pr("zero-rules", rules=0),
            _pr("no-record", evidence=False),
            _pr("boom", error="harness-transport: connection refused"),
            _pr("ctrl", attack_class="control_bare_payload"),
        ]
    )
    assert m.sample_size == 1, "只有一件真被判过"
    assert m.arm_size == 6 and m.excluded_count == 1
    assert m.not_measured_count == 4  # 2 undecided + 1 无记录 + 1 control
    for frag in ("decision-undecided", "no-decision-record", "error(s)", "control_*"):
        assert frag in m.notes


def test_an_empty_arm_is_insufficient_data_not_a_clean_zero():
    """🔴 什么让它红：分母为 0 时输出一个好看的 0%（"一件都没误伤"）。"""
    (m,) = WireIndirectBenignFlagRate().measure([])
    assert m.sample_size == 0 and m.value == 0.0
    assert "not_measured" in m.notes and "insufficient_data" in m.notes


def test_the_notes_say_which_quantity_this_is():
    """🔴 一个数进留痕，必须同时写「它量的是什么」。

    什么让它红：把那句"分子=硬拒 ∪ 软标，与 benign_flag_rate 不是同一个量"删掉 ——
    那时产物上只剩一个叫 `..._benign_flag_rate` 的数，而读的人会按仓内那一族的口径读它。
    """
    (m,) = WireIndirectBenignFlagRate().measure([_pr("a")])
    assert "硬拒 ∪ 软标" in m.notes and "benign_flag_rate" in m.notes
    assert "**不是同一个量**" in m.notes
    assert "**不是**良性留出臂" in m.notes
