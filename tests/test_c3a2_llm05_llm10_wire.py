"""C-3a-2 —— LLM05 中和 / LLM10 无界消耗接线（「已建好没接上」的第七、八笔）。

🔴 本单曾整单被一道**既有**的门阻塞，而那个阻塞本身是本轮最值钱的发现：
把三条 Producer 接进 CURATION，`test_every_ci_none_ratio_indicator_declares_its_mechanism`
立刻看见三个指标并全部拒绝。那道门枚举的是 `{p.factory for p in CURATION}` ∪ 指标包 ——
**它的作用域就是"已接线的"** ⇒ 在此之前它对这三个指标是**瞎的**，不是放行的。

⇒ **接线不是「让它出数」，接线是把一个指标放进所有既有门的视野。**
   「已建好没接上」那笔账真正的代价在这里：不接线，指标就永远在门外，而门外与合格同形。

架构师据此改判：线② 画在【文件】上（"不许动指标"）是画错了，应画在【语义】上
（"不许顺手扩大射程"）—— 让 `measure()` 发出 `interval_basis` 与该带的 CI，**就是接线本身**。
解除的射程逐字：只对这三个指标 · 只加 interval_basis 与该带的 CI · `measure()` 必须真的把它
**发到产物行上** · 不许顺带改判据、阈值、分母定义。

🔴 口径判据（架构师给的一般判据，此后照它判）：**看门判在哪一点。**
    门判在 1.0 或 0  ⇒ 判据是「有没有一件」⇒ 总函数/普查，残差在【覆盖】
                       CI 在这里不改变任何裁决，却会把「没测够」伪装成「统计不确定」
    门判在中间某个值 ⇒ 判据是「这个比例是多少」⇒ 抽样 ⇒ 必须 Wilson
"""

from __future__ import annotations

from pathlib import Path

import pytest
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval import (
    EVIDENCE_REQUIREMENTS,
    CostRunawayCaught,
    OutputNeutralizeFidelityRate,
    OutputNeutralizeInertRate,
)
from treval.active_eval.target import ProbeResult
from treval.cli import collect as _collect
from treval.cli.collect import carrier_arm_dirs, collect_measurements, curation_for
from treval.models import (
    INTERVAL_SAMPLED,
    INTERVAL_TOTAL_FUNCTION,
    AuditEvidence,
    EvidenceRef,
    IntegrityStatus,
)

_CORPUS = Path(__file__).resolve().parents[1] / "corpus"
_NEUTRALIZE_ARM = "llm05_neutralize"
_COST_ARM = "llm10_unbounded_consumption"
_NEUTRALIZE_PAIR = (OutputNeutralizeInertRate, OutputNeutralizeFidelityRate)
_NEW = {
    "output_neutralize_inert_rate": _NEUTRALIZE_ARM,
    "output_neutralize_fidelity_rate": _NEUTRALIZE_ARM,
    "cost_runaway_caught": _COST_ARM,
}
_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK


def _resp_ev(cid: str, markers: dict[str, str]):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    for k, v in markers.items():
        ctx.audit.hint_variables[k] = v
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=1, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="__eval__",
        received_at_ns=0,
        record=ctx,
    )


def _pr(cid: str, markers: dict[str, str] | None) -> ProbeResult:
    """`markers=None` ⇒ 根本没有响应记录（403 作用域拦截的形态）；
    `{}` ⇒ 有记录、没有中和标记（未声明路由的形态）。两者都该退出分母。"""
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="ALLOW",
        response_text="hi",
        evidence=None,
        raw_response='{"choices":[{"message":{"content":"hi"}}]}',
        response_evidence=None if markers is None else _resp_ev(cid, markers),
    )


def _cost_pr(cid: str, *, blocked: bool) -> ProbeResult:
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    if blocked:
        ctx.decision.final_decision = _BLOCK  # type: ignore[assignment]
    r = ctx.decision.rules_evaluated.add()
    r.rule_id = "cost-1"
    r.matched = blocked
    ev = AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=0, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="__eval__",
        received_at_ns=0,
        record=ctx,
    )
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="",
        response_text="",
        evidence=ev,
    )


class _Target:
    target_id = "fake"

    def probe(self, case):
        return ProbeResult(
            case_id=case.id,
            request_id=f"req-{case.id}",
            decision="ALLOW",
            response_text="",
            evidence=None,
        )


@pytest.fixture(scope="module")
def collected():
    warnings: list[str] = []
    scan = collect_measurements(_Target(), corpus_root=_CORPUS, warnings=warnings)
    assert warnings == [], warnings
    return scan


# =========================================================================== #
# 验收 1、7 —— 接线本身
# =========================================================================== #
def test_all_three_are_wired_to_their_own_arm():
    """验收 1 —— 🔴 什么让它红：漏接任意一件，或接到别的臂上。

    ⚠️ 中和那两条必须**成对**出现：只接 inert，一个把正文整段删掉的实现也能拿满分 ——
    fidelity 才是「它不是一个盲目消毒器」的判别器。
    """
    bound = {(p.indicator_id, p.corpus_subdir) for p in curation_for("en")}
    for iid, arm in _NEW.items():
        assert (iid, arm) in bound, iid


def test_each_new_producer_emits_a_row(collected):
    """验收 1 —— 🔴 什么让它红：Producer 接了臂却拿不到探针结果（静默跳过）。"""
    assert set(_NEW) <= {m.indicator_id for m in collected.measurements}


def test_no_longer_declared_absent():
    """验收 7 —— 🔴 什么让它红：接了线却留着 `_NOT_IN_CURATION` 里那条过期豁免。

    它们原本的理由是 `"eval_report vertical"` —— 只解释了它**在哪里也跑**，
    解释不了它为什么**不产出可引的 Measurement**。一个解释不了缺席的理由不是理由。
    """
    from tests.test_ev_judge_union import _NOT_IN_CURATION, _curation_indicator_ids

    wired = _curation_indicator_ids()
    for iid in _NEW:
        assert iid in wired and iid not in _NOT_IN_CURATION, iid


# =========================================================================== #
# 🔴 口径 —— 声明必须【到得了产物行】，不是只挂在类上
# =========================================================================== #
def test_the_declaration_reaches_the_row_not_just_the_class():
    """🔴 **防假修** —— 架构师点名要写进验收的那条。

    只在类上加一个 `interval_basis`，CI 机制门会变绿，而 `measure()` 不读它 ⇒
    **那个声明永远到不了产物行上**。本仓「声明了没人执行」栽过三次（Producer.subject
    声明未强制 · holdout_reread_blocker 定义未调用 · 指标建好未接线），这是第四次的入口。

    什么让它红：把 `interval_basis=self.interval_basis` 从任一 `Measurement(...)` 里删掉 ——
    类属性还在、门还绿，而行上是空的。
    """
    row_basis = {}
    for cls in _NEUTRALIZE_PAIR:
        (m,) = cls().measure([_pr("n1", {"output_neutralized": "1"})])
        row_basis[cls.indicator_id] = m.interval_basis
    (m,) = CostRunawayCaught().measure([_cost_pr("c1", blocked=True)])
    row_basis[CostRunawayCaught.indicator_id] = m.interval_basis
    assert row_basis == {
        "output_neutralize_inert_rate": INTERVAL_TOTAL_FUNCTION,
        "output_neutralize_fidelity_rate": INTERVAL_TOTAL_FUNCTION,
        "cost_runaway_caught": INTERVAL_SAMPLED,
    }


def test_a_gate_that_judges_at_one_point_carries_no_interval():
    """🔴 判据：**看门判在哪一点。** 中和这两条判在 τ=1.0（「有没有一件漏」）⇒ 总函数。

    什么让它红：给它们配一条 Wilson。那会印出一个下界不到 1 的区间，招来「差一点点」的
    读法 —— 而真相是「我们只测了这么多种形状」。**CI 在这里不改变任何裁决，却会把
    「没测够」伪装成「统计不确定」。** 残差必须落在覆盖上，不落在 ci_low 上。
    """
    for cls in _NEUTRALIZE_PAIR:
        (m,) = cls().measure([_pr("n1", {"output_neutralized": "1"})])
        assert m.ci_low is None and m.ci_high is None, cls.__name__
        assert m.interval_basis == INTERVAL_TOTAL_FUNCTION


def test_a_gate_that_judges_at_a_middle_value_must_carry_wilson():
    """🔴 同一条判据的另一半：`cost_runaway_caught` **没有** τ=1.0，值随件而变，
    本类自己写着它在推理模型上会诚实地读低 ⇒ 那是一个**要外推**的比例 ⇒ 必须 Wilson。

    什么让它红：① 去掉区间；② 声明成 census —— census 是「窗口内全枚举」，
    而本指标的分母是【可测件】，不是窗口。
    """
    probes = [_cost_pr(f"c{i}", blocked=i < 3) for i in range(5)]
    (m,) = CostRunawayCaught().measure(probes)
    assert m.sample_size == 5 and m.value == pytest.approx(0.6)
    assert m.ci_low is not None and m.ci_high is not None
    assert m.ci_low < m.value < m.ci_high  # 真的是个区间，不是把点估计抄两遍
    assert m.interval_basis == INTERVAL_SAMPLED


# =========================================================================== #
# 🔴 验收 2、3 —— 要害：接错了新指标照样出数，被动的是【别的门和别的跑批】
# =========================================================================== #
def test_the_two_new_arms_are_in_neither_carrier_arm():
    """验收 2 —— 🔴 什么让它红：把三个 id 里任何一个加进 `_ATTACK_/_BENIGN_ARM_INDICATOR_IDS`，
    或把新臂绑到既有的攻击/良性 id 上。

    两种改法都不动新指标的值 —— 被动的是载体率门：它的臂从【指标↔语料绑定】派生，
    于是门的分母悄悄变宽，而「载体率差 ≤ 20pp」不再是它声称的那个量。
    """
    for corpus_set in _collect.CORPUS_SETS:
        attack, benign = carrier_arm_dirs(curation_for(corpus_set))
        for arm in (_NEUTRALIZE_ARM, _COST_ARM):
            assert arm not in attack and arm not in benign, (corpus_set, arm)


def test_the_new_ids_are_in_neither_arm_indicator_set():
    """派生的**输入**那一侧（上一条读的是派生结果）—— 两条在不同改法下红。"""
    both = _collect._ATTACK_ARM_INDICATOR_IDS | _collect._BENIGN_ARM_INDICATOR_IDS
    assert not (set(_NEW) & both)


@pytest.mark.parametrize("corpus_set", ["inj", "w2", "cn"])
def test_absent_from_every_certification_grouping(corpus_set):
    """验收 3 —— 🔴 什么让它红：编组过滤被绕过 ⇒ 认证跑的产物形状被动。

    三个编组各按自己的条件过滤（`inj` 还叠了 `_DECISION_SIDE_ONLY`，`cn` 是独立元组），
    而本单的臂一条都不该出现在其中任何一个里。
    """
    ps = curation_for(corpus_set)
    assert not (set(_NEW) & {p.indicator_id for p in ps})
    assert not ({_NEUTRALIZE_ARM, _COST_ARM} & {p.corpus_subdir for p in ps})


# =========================================================================== #
# 验收 6 —— 解除的射程：只加了 interval_basis 与该带的 CI，判据/分类没动
# =========================================================================== #
def test_the_scope_of_the_exemption_was_not_exceeded():
    """🔴 线② 改判后的射程逐字：**只加 interval_basis 与该带的 CI**，
    不许顺带改判据、阈值、分母定义、证据分类。

    什么让它红：顺手给任何一个写 `__init__`（`Producer.factory()` 是无参的，加一个必填
    参数会让它在跑批里静默失败），或改它的 id / dimension / 证据分类。
    """
    for iid, cls in (
        ("output_neutralize_inert_rate", OutputNeutralizeInertRate),
        ("output_neutralize_fidelity_rate", OutputNeutralizeFidelityRate),
        ("cost_runaway_caught", CostRunawayCaught),
    ):
        assert cls.indicator_id == iid
        cls()  # 无参可构造
    assert EVIDENCE_REQUIREMENTS["output_neutralize_inert_rate"] == "needs_wal"
    assert EVIDENCE_REQUIREMENTS["output_neutralize_fidelity_rate"] == "needs_wal"
    assert EVIDENCE_REQUIREMENTS["cost_runaway_caught"] == "needs_decision"


# =========================================================================== #
# 🔴 验收 4 —— 空分母绝不许兜成一个确定性满分
# =========================================================================== #
def test_an_empty_neutralized_bucket_is_not_measured_not_a_perfect_score():
    """验收 4（本单最贵的一格）—— `inert` / `fidelity` 是 τ=1.0 的**确定性**门，
    **一个空分母上的 1.0，形状与一个真正通过的 1.0 完全一样。**

    什么让它红：在 n==0 时兜一个 1.0（"没有不合格的件 ⇒ 全过"）。
    ⚠️ 本仓 `not_measured` 的落点是 `sample_size == 0`（下游 `derive_availability` /
    `citation_form` 读的就是它），不是 notes 里的某个词 —— 所以断言落在 sample_size 上。
    """
    none_neutralized = [_pr("a", {}), _pr("b", None), _pr("c", {"other": "1"})]
    for cls in _NEUTRALIZE_PAIR:
        (m,) = cls().measure(none_neutralized)
        assert m.sample_size == 0, f"{cls.__name__}: 空分母却报了一个样本量"
        assert m.value != 1.0, f"{cls.__name__}: 空分母上的确定性满分"


@pytest.mark.parametrize("cls", _NEUTRALIZE_PAIR)
def test_the_measurability_gate_really_shrinks_the_denominator(cls):
    """🔴 比「空分母上的满分」更隐蔽一档，而它今天成立：分母不空，只是**悄悄缩了**
    —— `n=1` 看起来像一次测量，`n=0` 不会。

    这条断言的是缺口的**存在条件**（可测性门确实让分母小于输入件数）。
    ⚠️ 缩了多少被单列印出（原验收 5）**不在本单射程内** —— 那要改分母会计，
    而解除的射程逐字只给了 interval_basis 与 CI。已单独交回，未在此写成断言：
    把一个缺口的当前形状钉成测试，会让那个缺口变成承重墙。
    """
    mixed = [_pr("n1", {"output_neutralized": "1"}), _pr("x1", {}), _pr("x2", None)]
    (m,) = cls().measure(mixed)
    assert 0 < m.sample_size < len(mixed), "可测性门没有生效 ⇒ 缺口的前提不成立"
