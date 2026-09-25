"""A4c 中途探测臂的登记与通道。

🔴 A4c 是本仓第一条【两表都进】的臂，而在它之前 `READ_ONCE_ARMS ∩ FIT_ARMS = ∅` ——
登记表里现有的注释把两表写成了一对反义词（见 A2 那段），照着它推，A4c 无处可放。
两表其实答的是两个不同的问题，本文件把这张表钉下来：

                    READ_ONCE_ARMS        FIT_ARMS
                  「还能不能再读一次」  「它的数能不能作验收数」
    A2 留出臂          ✅ 不能              ⛔ 能（它不参与定 τ ⇒ 其数是测量数）
    P3 设计臂          ⛔ 能                ✅ 不能
    F1 证伪臂          ⛔ 能                ✅ 不能
    A4a 探测臂         ⛔ 能（已实测重跑过） ✅ 不能
    A4b 探测臂         ⛔ 能                ✅ 不能
    🔴 A4c 探测臂      ✅ 不能              ✅ 不能   ← 两个都是"不能"

A4c 落在这一格的理由，两条各自独立成立，不得互相推导：
  • READ_ONCE ——「最后一个未见子集，用掉没有第三次」（PM 2026-09-22 写死）
  • FIT_ARMS  ——【其数不作验收数】；它减 A4b 得到的是一个【决策输入】，
    不是门 A 的读数。门 A 的读数只出自 llm01_en_holdout_a3。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from treval.cli.collect import (
    CORPUS_SETS,
    CURATION_EN_A4C,
    CURATION_EN_GRID,
    Producer,
    _assert_no_calib_producer,
    curation_for,
)
from treval.label_freeze import (
    ARM_VOLUME_ENV,
    FIT_ARMS,
    FROZEN_LABEL_SHA,
    KNOWN_VOLUME_ENVS,
    READ_ONCE_ARMS,
    label_map,
    label_sha256,
)
from treval.rubric.serialize import derive_offline_recomputable

A4C = "llm01_en_interim_a4c"
A4B = "llm01_en_interim_a4b"
A4A = "llm01_en_interim_a4a"
A2 = "llm01_en_holdout_a2"
P3 = "llm01_benign_design_p3"


def test_registered_in_all_three_slots() -> None:
    assert A4C in FROZEN_LABEL_SHA
    assert len(FROZEN_LABEL_SHA[A4C]) == 64
    assert ARM_VOLUME_ENV[A4C] == "TREVAL_EN_A4C_CORPUS"
    assert "TREVAL_EN_A4C_CORPUS" in KNOWN_VOLUME_ENVS


def test_a4c_is_the_first_arm_in_both_tables() -> None:
    """🔴 两表都进 —— 这是本仓的第一次，所以断言的是【这个组合】，不是两条单独的成员关系。

    什么让它红：有人照 A2 那段注释的"反义词"读法，把 A4c 从其中一表里挪走。
    """
    assert A4C in READ_ONCE_ARMS, "A4c 一次性 —— 用掉没有第三次"
    assert A4C in FIT_ARMS, "A4c 其数不作验收数 —— 验收归 A3"
    assert READ_ONCE_ARMS & FIT_ARMS == {A4C}, (
        "今天只有 A4c 落在两表交集里；多一条或少一条都说明有人改了别的臂的档位，"
        f"实得 {sorted(READ_ONCE_ARMS & FIT_ARMS)}"
    )


def test_three_a4_arms_differ_on_the_read_once_slot() -> None:
    """🔴 同族、同构、同轴分布的三条臂，在 read-once 这一格【不同】—— 防的是照抄上一条。

    A4a 事实上已经重跑过一次（同一批件、两套栈），A4b 没有被写死"不再读"；
    只有 A4c 被 PM 逐字写成一次性。三者在 FIT_ARMS 上则一致。
    """
    assert A4A not in READ_ONCE_ARMS
    assert A4B not in READ_ONCE_ARMS
    assert A4C in READ_ONCE_ARMS
    assert {A4A, A4B, A4C} <= FIT_ARMS


def test_a4c_does_not_share_a_volume_env_with_any_other_arm() -> None:
    """闸门规则：A4c 与 A2/P2/P3/F1 同卷，而同卷里躺着两条 read-once 臂。

    变量是【访问闸门】不是【位置指针】—— 共用任何一个现有变量，都等于每次读 A4c
    都顺手把与它共用的那条臂一并打开。
    """
    env = ARM_VOLUME_ENV[A4C]
    sharers = [a for a, v in ARM_VOLUME_ENV.items() if v == env and a != A4C]
    assert not sharers, f"A4c 的闸门 {env} 还被 {sharers} 用着"


def test_every_a4c_producer_carries_a_subject_and_the_arm_note() -> None:
    """🔴 带 subject 是 A4c 能通过 FIT_ARMS 那道门的唯一理由；
    arm_note 让"这是 diagnostic_only"在数被摘出去引用时还跟着走。"""
    assert CURATION_EN_A4C
    for p in CURATION_EN_A4C:
        assert p.subject == "arm:en_a4c", f"{p.indicator_id} 的 subject 不对"
        assert "diagnostic_only" in p.arm_note
        assert A4C in p.arm_note
        assert p.corpus_subdir == A4C


def test_a_subjectless_a4c_producer_is_refused() -> None:
    """门没放宽：去掉 subject 仍然当场红。"""
    bare = Producer(CURATION_EN_A4C[0].indicator_id, CURATION_EN_A4C[0].factory, A4C)
    with pytest.raises(ValueError, match="FIT_ARMS"):
        _assert_no_calib_producer((bare,))


def test_same_indicator_shape_as_the_arm_it_will_be_subtracted_from() -> None:
    """🔴 判读线是 `Δ = 93 − k_A4c`，两边必须由【同一组指标】算出来。

    A4b 与 A4c 都镜像 CURATION_EN_GRID ⇒ 指标 id 集合逐个相同。
    什么让它红：给 A4c 少接一个 producer —— 那会让 combined 这一格取不出来，
    而 PM 已写死 k_A4c 取 combined，这一格不可换。
    """
    assert {p.indicator_id for p in CURATION_EN_A4C} == {
        p.indicator_id for p in CURATION_EN_GRID
    }
    assert "injection_combined_recall" in {p.indicator_id for p in CURATION_EN_A4C}


def test_subject_keys_unique() -> None:
    keys = [(p.indicator_id, p.subject) for p in CURATION_EN_A4C]
    assert len(set(keys)) == len(keys), f"(id, subject) 撞了：{keys}"


def test_corpus_set_wired_and_offline_declared() -> None:
    assert "en_a4c" in CORPUS_SETS
    assert curation_for("en_a4c") == CURATION_EN_A4C
    assert derive_offline_recomputable("en_a4c") == "holder_only"


def test_no_other_corpus_set_touches_a4c() -> None:
    """射程写死：A4c 只出现在它自己的编组里 —— 一次性臂尤其，
    它若挂在别的编组上，跑那个编组就顺手把它花掉了。"""
    for name in CORPUS_SETS:
        if name == "en_a4c":
            continue
        assert not any(p.corpus_subdir == A4C for p in curation_for(name)), (
            f"编组 {name!r} 里出现了 A4c"
        )


def test_the_real_a4c_corpus_still_matches_its_frozen_labels() -> None:
    """🔴 真语料上的实跑。变量未设 ⇒ 声明式跳过，不是通过。"""
    import os

    root = os.environ.get(ARM_VOLUME_ENV[A4C], "")
    if not root:
        pytest.skip(f"{ARM_VOLUME_ENV[A4C]} 未设 ⇒ A4c 未校验（不是通过）")
    d = Path(root) / A4C
    if not d.is_dir():
        pytest.skip(f"{d} 不存在 ⇒ A4c 未校验（不是通过）")
    assert label_sha256(label_map(d)) == FROZEN_LABEL_SHA[A4C]
