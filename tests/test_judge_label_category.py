"""判官 label / category 两格 —— 规则 R 三支分解的原料。

🔴 本文件钉的是【三态】，不是"能读出来"。因为这两格的价值全在分支上：
    规则 R 判据 = `label == "Unsafe"`  ∨  (`类目 ∈ flagging` ∧ `score >= τ`)
新增的那一支（`label=="Unsafe"` 而 `score < τ`）**整支落在未 flag 的件上** —— 网关把这两格写在
`outcome` 同级（async_governance.py:230 那段带「⛔ 不要挪进 if」的守卫注释），正是为了这个。
若 Core 这一侧把「键不出现」和「空串」合并，分解同样做不了：
    键不出现  这条栈【没有这个概念】（rubric 栈两格皆无；无类目登记表时 category 无）
    空串      有概念，而【这一次】为空
    有值      该值
"""

from __future__ import annotations

import pytest
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval.cases import build_cases
from treval.active_eval.checks import judge_category, judge_label
from treval.active_eval.corpus import CorpusCase
from treval.active_eval.indicators import ProbeResult
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus


def _governance(cid: str, *, hinted: bool, tags: dict[str, str], tier: str = "2"):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.record_type = rc_pb.AUDIT_RECORD_TYPE_GOVERNANCE_OBSERVED
    ctx.audit.hint_emitted = hinted
    r = ctx.decision.rules_evaluated.add()
    r.rule_id = "t2-judge"
    r.matched = hinted
    r.tags["tier"] = tier
    for k, v in tags.items():
        r.tags[k] = v
    return AuditEvidence(
        ref=EvidenceRef(source="wal:g", seq=1, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="t",
        received_at_ns=0,
        record=ctx,
    )


def _probe(cid: str, *, gov) -> ProbeResult:
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="",
        response_text="",
        evidence=None,
        governance_evidence=gov,
        tier2_drain_executed=True,
        attack_class="direct_prompt_injection",
    )


def _case(cid: str) -> CorpusCase:
    return CorpusCase(
        id=cid,
        owasp="LLM01",
        dimension="robustness",
        attack_class="direct_prompt_injection",
        input="x",
        success_when="blocked_or_flagged",
        severity="info",
        source="core-authored",
    )


# --------------------------------------------------------------------------- #
# 三态 —— 本文件的核心
# --------------------------------------------------------------------------- #
def test_absent_tag_reads_as_none_not_empty_string() -> None:
    """🔴 键不出现 ⇒ None。合并成空串会让「这条栈没有类目这个概念」与
    「判官给了空类目」在产物上同形 —— 而规则 R 的类目支正是按这个分支的。"""
    pr = _probe("a1", gov=_governance("a1", hinted=False, tags={}))
    assert judge_label(pr) is None
    assert judge_category(pr) is None


def test_empty_string_tag_stays_empty_string() -> None:
    """空串是第三个事实（有概念、这次为空），不得被折成 None。"""
    pr = _probe("a2", gov=_governance("a2", hinted=False, tags={"judge_category": ""}))
    assert judge_category(pr) == ""
    assert judge_category(pr) is not None


def test_values_are_read_verbatim() -> None:
    """取值域不可枚举（随判官型号变）⇒ 原样落盘，不做映射、不做白名单。"""
    pr = _probe(
        "a3",
        gov=_governance(
            "a3",
            hinted=True,
            tags={"judge_label": "Unsafe", "judge_category": "Jailbreak"},
        ),
    )
    assert judge_label(pr) == "Unsafe"
    assert judge_category(pr) == "Jailbreak"


def test_written_for_unflagged_cases_too() -> None:
    """🔴 本件存在的全部理由：规则 R 新增的那一支整支落在【未 flag】的件上。
    若这两格只在 flag 时可读，问「这一支贡献了多少」时分母那一侧是空的。"""
    pr = _probe(
        "a4",
        gov=_governance(
            "a4", hinted=False, tags={"judge_label": "Unsafe", "judge_category": ""}
        ),
    )
    assert pr.governance_evidence is not None
    assert not pr.governance_evidence.record.audit.hint_emitted
    assert judge_label(pr) == "Unsafe"  # 未 flag 而 label 仍读得到


def test_no_async_record_reads_as_none() -> None:
    """没有 type-3 记录 ⇒ None（没查过），与「查了没有这个键」同为 None 是有意的：
    两者都表示【这一件我们没有判官自报的 label】，而 `injection_score` 同一支同样处理。"""
    assert judge_label(_probe("a5", gov=None)) is None
    assert judge_category(_probe("a5", gov=None)) is None


def test_non_tier2_rule_tags_are_not_read() -> None:
    """🔴 射程写死在 tier=2 那条规则上。一条 Tier-1 规则若也带了同名 tag，
    不得被当成判官自报 —— 否则「判官说的」和「规则说的」在产物上合流。"""
    pr = _probe(
        "a6",
        gov=_governance("a6", hinted=False, tags={"judge_label": "Unsafe"}, tier="1"),
    )
    assert judge_label(pr) is None


# --------------------------------------------------------------------------- #
# 接线 —— 两张逐件表都要有（门 B 跑的是良性侧）
# --------------------------------------------------------------------------- #
def test_both_fields_ride_the_attack_case_table() -> None:
    pr = _probe(
        "a7",
        gov=_governance(
            "a7",
            hinted=True,
            tags={"judge_label": "Unsafe", "judge_category": "Jailbreak"},
        ),
    )
    (row,) = build_cases([_case("a7")], [pr], target_kind="gateway")
    assert row["judge_label"] == "Unsafe"
    assert row["judge_category"] == "Jailbreak"


def test_both_fields_are_present_as_keys_even_when_none() -> None:
    """🔴 键必须在，值可以是 null —— 键缺席读成「这一跑没这个概念」，
    而实际是「这一件没有」。三态在产物上同样要站得住。"""
    (row,) = build_cases([_case("a8")], [_probe("a8", gov=None)], target_kind="gateway")
    assert "judge_label" in row and row["judge_label"] is None
    assert "judge_category" in row and row["judge_category"] is None


# --------------------------------------------------------------------------- #
# 🔴 caught_by_tier2 列 —— 钉的是【表能复算出分子】，不是「列在那儿」
# --------------------------------------------------------------------------- #
# 🔴 纪律②：实测数字不进公开仓。某次良性跑暴露的缺口 —— flagged_at_decision 【整臂为 0】，
# 而 benign_flag_rate 的分子不是 0。差额整个来自判官的 hint —— 它写在 type-3 记录上，
# 决策记录上没有。⇒ 在这一列之前，良性逐件表【复算不出自己那个指标的分子】。
def test_caught_by_tier2_rides_both_case_tables() -> None:
    hinted = _probe(
        "c1",
        gov=_governance("c1", hinted=True, tags={"judge_label": "Controversial"}),
    )
    (row,) = build_cases([_case("c1")], [hinted], target_kind="gateway")
    assert row["caught_by_tier2"] is True


def test_caught_by_tier2_is_separate_from_flagged_at_decision() -> None:
    """🔴 hint 有【两个写入点】（pipeline 入口期 / async_governance 判官期），三个读名。
    合成一列就再也分不开「规则标的」和「判官标的」—— 而 benign_soft_flagged 正是两者的 OR。
    这一件正是 p3 上的形态：决策期 0、判官期有。"""
    pr = _probe(
        "c2", gov=_governance("c2", hinted=True, tags={"judge_label": "Controversial"})
    )
    (row,) = build_cases([_case("c2")], [pr], target_kind="gateway")
    assert row["caught_by_tier2"] is True
    assert row["flagged_at_decision"] is False  # 决策记录上没有 hint
    assert row["caught_by_tier2"] != row["flagged_at_decision"]


def test_caught_by_tier2_is_not_a_core_side_threshold() -> None:
    """🔴 emit-vs-interpret：catch 读的是网关在【它自己的 τ】上发出的 hint，
    不是 Core 对 injection_score 重新划线。规则 R 之后这一点更要紧 ——
    `label=="Unsafe"` 那一支不看 τ，任何 Core 侧的 score≥τ 都复现不出它。
    这里造一件【分数低而网关发了 hint】的：按分数它不该中，按 hint 它中。"""
    gov = _governance("c3", hinted=True, tags={"judge_label": "Unsafe"})
    gov.record.decision.scores["injection_score"] = 0.01  # 远低于任何 τ
    pr = _probe("c3", gov=gov)
    (row,) = build_cases([_case("c3")], [pr], target_kind="gateway")
    assert row["injection_score"] == pytest.approx(0.01)
    assert row["caught_by_tier2"] is True, "catch 必须跟 hint 走，不跟分数走"


def test_no_async_record_reads_as_not_caught() -> None:
    """没有 type-3 记录 ⇒ False（与 checks.caught_by_tier2 同一支：
    没有异步记录不是一次静默漏检，Tier-2 指标把它算作 no-async）。"""
    (row,) = build_cases([_case("c4")], [_probe("c4", gov=None)], target_kind="gateway")
    assert row["caught_by_tier2"] is False
