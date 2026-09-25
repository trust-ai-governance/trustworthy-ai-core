"""F1 析因证伪臂的登记与通道。

🔴 F1 与 A2、P3 三条臂同卷、同期登记，而在四个槽上的取值两两不同 —— 这正是「照着上一条抄」
最容易出错的形状，所以本文件逐槽对照，不只断言 F1 自己：

            READ_ONCE_ARMS   FIT_ARMS   理由
    A2 留出臂      ✅ 在        ⛔ 不在    一次性；进 FIT_ARMS 会让那道门对它放行
    P3 设计臂      ⛔ 不在      ✅ 在      可反复读；其数不作验收数（理由 = 可据它拟合）
    🔴 F1 证伪臂   ⛔ 不在      ✅ 在      可反复读；其数不作验收数
                                        ⚠️ 理由【不是】"可据它拟合 τ" —— F1 从来不用来
                                          拟合工作点。进 FIT_ARMS 收的是【后果】不是【名字】。
"""

from __future__ import annotations

from treval.cli.collect import (
    CORPUS_SETS,
    CURATION_EN_F1,
    CURATION_W2,
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
)
from treval.rubric.serialize import derive_offline_recomputable

F1 = "llm01_en_factorial_f1"
P3 = "llm01_benign_design_p3"
A2 = "llm01_en_holdout_a2"


def test_registered_in_all_three_slots() -> None:
    assert F1 in FROZEN_LABEL_SHA
    assert ARM_VOLUME_ENV[F1] == "TREVAL_EN_F1_CORPUS"
    assert "TREVAL_EN_F1_CORPUS" in KNOWN_VOLUME_ENVS


def test_f1_is_not_read_once_but_is_a_fit_arm() -> None:
    """可反复读 ⇒ 不进 READ_ONCE；其数不作验收数 ⇒ 进 FIT_ARMS。"""
    assert F1 not in READ_ONCE_ARMS
    assert F1 in FIT_ARMS


def test_three_arms_differ_slot_by_slot() -> None:
    """🔴 同卷、同期登记的三条臂，四个槽两两不同 —— 防的是照抄上一条。"""
    assert (
        (A2 in READ_ONCE_ARMS)
        and (P3 not in READ_ONCE_ARMS)
        and (F1 not in READ_ONCE_ARMS)
    )
    assert (A2 not in FIT_ARMS) and (P3 in FIT_ARMS) and (F1 in FIT_ARMS)
    envs = {ARM_VOLUME_ENV[a] for a in (A2, P3, F1)}
    assert len(envs) == 3, f"三条臂的卷变量必须各不相同，实得 {envs}"


def test_f1_does_not_share_a_volume_env_with_a_read_once_arm() -> None:
    """闸门规则：F1 可反复读，与 read-once 臂共用变量 = 每次读 F1 都顺手打开它们。"""
    shared = [a for a in READ_ONCE_ARMS if ARM_VOLUME_ENV.get(a) == ARM_VOLUME_ENV[F1]]
    assert not shared, f"F1 与 read-once 臂 {shared} 共用卷变量"


def test_every_f1_producer_carries_a_subject_and_the_arm_note() -> None:
    """🔴 带 subject 是 F1 能通过 FIT_ARMS 那道门的唯一理由；
    arm_note 则让"这是 diagnostic_only"在数被摘出去引用时还跟着走。"""
    assert CURATION_EN_F1
    for p in CURATION_EN_F1:
        assert p.subject, f"{p.indicator_id} 没带 subject"
        assert "diagnostic_only" in p.arm_note
        assert F1 in p.arm_note


def test_a_subjectless_f1_producer_is_refused() -> None:
    """门没放宽：去掉 subject 仍然当场红。"""
    import pytest

    bare = Producer(CURATION_EN_F1[0].indicator_id, CURATION_EN_F1[0].factory, F1)
    with pytest.raises(ValueError, match="FIT_ARMS"):
        _assert_no_calib_producer((bare,))


def test_subject_keys_unique_and_original_口径_keys_survive() -> None:
    """W2 的 `benign_flag_rate` 有两行（聚合 + hard_only）。
    subject 一律盖成臂名会把它们压成同一个键 —— P3 那次已经栽过一回。"""
    keys = [(p.indicator_id, p.subject) for p in CURATION_EN_F1]
    assert len(set(keys)) == len(keys), f"(id, subject) 撞了：{keys}"
    src = {p.subject for p in CURATION_W2 if p.subject}
    assert src <= {p.subject for p in CURATION_EN_F1}


def test_corpus_set_wired_and_offline_declared() -> None:
    assert "en_f1" in CORPUS_SETS
    assert curation_for("en_f1") == CURATION_EN_F1
    assert derive_offline_recomputable("en_f1") == "holder_only"


def test_no_other_corpus_set_touches_f1() -> None:
    """射程写死：F1 只出现在它自己的编组里。"""
    for name in CORPUS_SETS:
        if name == "en_f1":
            continue
        assert not any(p.corpus_subdir == F1 for p in curation_for(name)), (
            f"编组 {name!r} 里出现了 F1"
        )
