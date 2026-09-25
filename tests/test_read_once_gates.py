"""一次性臂的两道跑前门 —— 每一条先说【什么输入让它红】。

🔴 两道门各对应一次【已经发生过、而且是事后才发现】的失效（PM 2026-09-23 认领并要求落门）：

  ① A2 被完整读了两次（2026-09-21 留出跑 · 2026-09-22 折扣探测跑，ruleset 与 τ 都不同）
     ⇒ `assert_read_once_not_spent`
  ② F1 的 576 个请求落进 `wal-a2` —— 语料没被重读，而留出臂的证据卷里混进了别人的流量
     ⇒ `assert_wal_belongs_to_this_run`

⚠️ 「留出臂不可重复读」此前只写在文档与注释里。**规矩在、门不在** —— 与
`test_no_corpus_path_literals` 开头记的那条同形：一条只靠人记得的纪律，
覆盖的是记得的那几次，不是那条纪律。
"""

from __future__ import annotations

import pytest

from treval.cli.collect import (
    CURATION_EN_A2,
    CURATION_EN_F1,
    CURATION_P3,
    Producer,
    _assert_read_once_arms_intact,
)
from treval.label_freeze import (
    READ_ONCE_ARMS,
    READ_ONCE_CONSUMED,
    READ_ONCE_WAL_TOKEN,
    ReadOnceViolation,
    assert_read_once_not_spent,
    assert_wal_belongs_to_this_run,
)

A2 = "llm01_en_holdout_a2"
A3 = "llm01_en_holdout_a3"
P2 = "llm01_benign_holdout_p2"
F1 = "llm01_en_factorial_f1"


# --------------------------------------------------------------------------- #
# 门① 读取次数
# --------------------------------------------------------------------------- #
def test_a2_second_read_is_refused() -> None:
    """🔴 复现 2026-09-22 那次：A2 已消耗，再打它当场红。"""
    with pytest.raises(ReadOnceViolation, match="已消耗"):
        assert_read_once_not_spent([A2])


def test_a3_and_a4c_are_also_refused() -> None:
    """两条 2026-09-22 夜里花掉的臂，同样拦。"""
    for arm in (A3, "llm01_en_interim_a4c"):
        with pytest.raises(ReadOnceViolation, match="已消耗"):
            assert_read_once_not_spent([arm])


def test_p2_is_not_refused_because_it_was_never_spent() -> None:
    """🔴 一道对什么都红的门会被关掉。p2 实核未消耗（卷为空、无跑批产物）⇒ 必须放行。"""
    assert_read_once_not_spent([P2])


def test_a_rerunnable_arm_is_never_touched_by_this_gate() -> None:
    """射程写死：本门只管一次性臂。"""
    assert_read_once_not_spent([F1, "llm01_benign_design_p3", "llm01_en_grid_attack"])


def test_absent_from_the_table_does_not_mean_unconsumed() -> None:
    """🔴 本门的【限度】也要有测试，否则下一个人会把它当成全覆盖。

    不在 READ_ONCE_CONSUMED 里 = 没有记录，既不是"未消耗"也不是"可以读"。
    中文 B 档就是这一格：私有仓一份预登记写着"不碰"，那是禁令不是观测。
    什么让它红：有人把本表当成"未列出即安全"，去掉这条注释或改成默认拒绝。
    """
    assert "llm01_cn_benign_mt_holdout" in READ_ONCE_ARMS
    assert "llm01_cn_benign_mt_holdout" not in READ_ONCE_CONSUMED
    assert_read_once_not_spent(["llm01_cn_benign_mt_holdout"])  # 放行，而这是已知缺口


def test_every_consumed_arm_is_actually_a_read_once_arm() -> None:
    """登记成"已消耗"却不是一次性臂 ⇒ 本表在说一件它管不着的事。"""
    assert set(READ_ONCE_CONSUMED) <= READ_ONCE_ARMS


# --------------------------------------------------------------------------- #
# 门② 卷归属
# --------------------------------------------------------------------------- #
def test_f1_into_the_a2_volume_is_refused() -> None:
    """🔴 逐字复现 F1 那次：可反复读的臂，带着 A2 的卷开跑。"""
    with pytest.raises(ReadOnceViolation, match="标记段"):
        assert_wal_belongs_to_this_run("/tmp/wal-a2", [F1])


def test_a2_into_its_own_volume_is_allowed() -> None:
    """同一个卷名，打的是它自己那条臂 ⇒ 放行。门分的是【谁在写】，不是【卷叫什么】。"""
    assert_wal_belongs_to_this_run("/tmp/wal-a2", [A2])


def test_a_neutral_volume_is_allowed_for_anything() -> None:
    assert_wal_belongs_to_this_run("/tmp/wal-sweep", [F1])
    assert_wal_belongs_to_this_run("/tmp/wal-ruleR", ["llm01_en_grid_attack"])


def test_an_empty_wal_dir_is_a_declared_skip_not_a_pass() -> None:
    """没有卷可判 ⇒ 跳过。什么让它红：把"没给卷"当成"卷没问题"。"""
    assert_wal_belongs_to_this_run("", [F1])


def test_the_match_is_whole_segment_not_substring() -> None:
    """🔴 有意不做子串匹配：`wal-data2` 含 "a2" 而与 A2 无关 —— 假红一样贵。

    代价写在这里：`wal-a3p2` 这种复合名两条臂都拦不住，这是【已知限度】不是缺陷。
    什么让它红：有人把判据改成 `token in name`（那会让下一行放行的这个卷当场误红）。
    """
    assert_wal_belongs_to_this_run("/tmp/wal-data2", [F1])
    assert_wal_belongs_to_this_run("/tmp/wal-a3p2", [F1])  # ⚠️ 拦不住，登记在案


def test_every_read_once_arm_has_a_wal_token() -> None:
    """🔴 漏登一个标记 = 那条臂的卷对本门【完全透明】，而它与"没有这条臂"同形。
    与 KNOWN_VOLUME_ENVS 同一条纪律：判据建在封闭词表上，词表必须是满的。"""
    missing = READ_ONCE_ARMS - set(READ_ONCE_WAL_TOKEN)
    assert not missing, f"一次性臂缺卷标记：{sorted(missing)}"


def test_wal_tokens_are_unique() -> None:
    """两条臂共用一个标记 ⇒ 门分不开它们，会把合法的跑判红。"""
    vals = list(READ_ONCE_WAL_TOKEN.values())
    assert len(set(vals)) == len(vals), f"标记撞了：{vals}"


# --------------------------------------------------------------------------- #
# 接线：两道门真的在跑前判据链上
# --------------------------------------------------------------------------- #
def test_the_gates_are_reached_from_the_production_path() -> None:
    """🔴 这一条防的是本仓已经数到第七个的那一族：**建了、测了、文档写了，就是没人调。**
    什么让它红：把 `_assert_read_once_arms_intact` 从 collect_measurements 里摘掉。"""
    import inspect

    from treval.cli.collect import collect_measurements

    src = inspect.getsource(collect_measurements)
    assert "_assert_read_once_arms_intact(producers, wal_dir)" in src
    assert "wal_dir" in inspect.signature(collect_measurements).parameters


def test_the_call_site_actually_passes_the_wal_dir() -> None:
    """🔴 本条是上一条【漏掉的那一半】，而它漏掉的正是本仓付过两次学费的那个形状：
    `--benign-arm` 与 `--drain-timeout-s` 都曾经"参数解析了、签名收了、判据写了，
    唯独调用点没传"—— 门于是永远看到默认值。

    ⚠️ 我第一版只断言了签名与函数体，摘掉调用点的传参之后 17 条测试【全绿】。
    一条查不到最后一米的接线测试，与没有接线测试是同一个东西。
    什么让它红：调用点去掉 `wal_dir=`（门从此永远收到空串 ⇒ 卷归属那道恒放行）。
    """
    import inspect
    import re as _re

    import treval.cli.collect as mod

    src = inspect.getsource(mod)
    # 🔴 找【调用点】不是 `def` —— 第一版用 "collect_measurements(" 匹配，抓到的是定义行，
    # 于是这条测试在未变异的源码上就红了。锚到赋值形式，且断言只命中一处。
    anchor = "= collect_measurements("
    assert src.count(anchor) == 1, f"调用点不止一处或已改形：{src.count(anchor)}"
    i = src.index(anchor)
    depth, j = 0, src.index("(", i)
    for k in range(j, len(src)):
        if src[k] == "(":
            depth += 1
        elif src[k] == ")":
            depth -= 1
            if depth == 0:
                break
    call = src[j : k + 1]
    assert _re.search(r"\bwal_dir\s*=", call), (
        "collect_measurements 的调用点没有传 wal_dir —— 卷归属那道门会永远收到空串而恒放行。"
        f"实际调用：{call[:400]}"
    )


def test_the_chain_refuses_a_spent_arm_and_a_foreign_volume() -> None:
    """整条判据链上的两种红，各走一次。"""
    with pytest.raises(ReadOnceViolation, match="已消耗"):
        _assert_read_once_arms_intact(CURATION_EN_A2, "/tmp/wal-a2")
    with pytest.raises(ReadOnceViolation, match="标记段"):
        _assert_read_once_arms_intact(CURATION_EN_F1, "/tmp/wal-a2")


def test_the_chain_lets_a_legitimate_rerun_through() -> None:
    """P3 可反复读、卷中性 ⇒ 两道门都放行。"""
    _assert_read_once_arms_intact(CURATION_P3, "/tmp/wal-recalib")


def test_a_bare_producer_tuple_still_reaches_both_gates() -> None:
    """谓词读的是 producer 的 corpus_subdir，不是编组名 —— 换个编组名绕不过去。"""
    fake = (Producer(CURATION_EN_A2[0].indicator_id, CURATION_EN_A2[0].factory, A3),)
    with pytest.raises(ReadOnceViolation, match="已消耗"):
        _assert_read_once_arms_intact(fake, "")


# --------------------------------------------------------------------------- #
# 🔴 臂名解析必须排在跑前门【之前】—— 2026-09-24 实测缺口
# --------------------------------------------------------------------------- #
def test_arm_name_is_resolved_before_the_gates_see_it() -> None:
    """🔴 什么让它红：把 `_with_arm_resolved` 从 collect_measurements 的判据链之前挪走，
    或挪到四道门之后。

    这一格是实测出来的，不是设想的：良性验收臂走
    `--corpus-set w2 --benign-arm <新臂>` 进来，而重映射原本排在四道门【之后】⇒
      ① 冻结门射程内找不到臂 ⇒ 静默跳过 ⇒ 一次性臂的标签跑时不校验
      ② 一次性门看到默认名 ⇒ 空过 ⇒ "已消耗"拦不住
      ③ 卷归属门看到默认名而卷名带着新臂标记 ⇒ 反而拦下【合法的跑】
    三种表现、一个根因。⚠️ ②最危险：不报错、不吭声，与"这条臂没问题"完全同形。
    """
    import inspect

    from treval.cli.collect import collect_measurements

    src = inspect.getsource(collect_measurements)
    i_resolve = src.index("_with_arm_resolved(producers, benign_arm)")
    for gate in (
        "_assert_no_id_subdir_collision(producers)",
        "_assert_no_calib_producer(",
        "_assert_frozen_arms_unchanged(producers, corpus_root)",
        "_assert_read_once_arms_intact(producers, wal_dir)",
    ):
        assert i_resolve < src.index(gate), (
            f"臂名解析排在 {gate} 之后 —— 那道门看到的不是要打的臂"
        )


def test_the_resolved_producers_carry_the_new_arm_name() -> None:
    """解析要真的换掉 corpus_subdir，而 subject / arm_note 原样保留 ——
    subject 是口径键，换臂不该动它（换了会把口径行压成另一个键）。"""
    from treval.cli.collect import CURATION_W2, _with_arm_resolved

    R = _with_arm_resolved(CURATION_W2, "llm01_benign_holdout_p4")
    assert {p.corpus_subdir for p in R} == {"llm01_benign_holdout_p4"}
    assert [p.subject for p in R] == [p.subject for p in CURATION_W2]
    assert [p.arm_note for p in R] == [p.arm_note for p in CURATION_W2]


def test_no_benign_arm_means_no_rewrite() -> None:
    """不给 --benign-arm ⇒ 原样返回同一个对象，不制造一份看起来不同的副本。"""
    from treval.cli.collect import CURATION_W2, _with_arm_resolved

    assert _with_arm_resolved(CURATION_W2, "") is CURATION_W2


def test_the_benign_acceptance_arm_reaches_all_three_gates() -> None:
    """🔴 端到端：p4 经这条路进来时，三道门都必须【看得见它】。
    什么让它红：p4 漏登任一表，或解析被挪回门之后。"""
    from treval.cli.collect import CURATION_W2, _with_arm_resolved
    from treval.label_freeze import (
        FROZEN_LABEL_SHA as F,
        READ_ONCE_ARMS as R1,
        READ_ONCE_WAL_TOKEN as T,
    )

    A = "llm01_benign_holdout_p4"
    R = _with_arm_resolved(CURATION_W2, A)
    assert {p.corpus_subdir for p in R} == {A}
    assert A in F and A in R1 and T[A] == "p4"
    _assert_read_once_arms_intact(R, "/tmp/wal-p4-frozen-tau077")  # 自己的卷 ⇒ 放行
    with pytest.raises(ReadOnceViolation, match="标记段"):
        _assert_read_once_arms_intact(R, "/tmp/wal-a6-frozen-tau077")  # 别人的卷 ⇒ 红
