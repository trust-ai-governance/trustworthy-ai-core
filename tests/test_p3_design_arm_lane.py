"""P3 设计臂的 diagnostic-only 通道 —— 路通了，而「不得进验收」仍是机制。

🔴 本文件钉的是一件事：**p3 能被跑，同时它的数结构上进不了验收。**
两半缺一都不成立：
  · 只有前一半 ⇒ 拟合集的数可以当验收数（`_assert_no_calib_producer` 存在的理由）
  · 只有后一半 ⇒ 唯一一条在【生产刻度】上给 p3 打分的路是关的，而离线复刻规则 R 的
    `label=="Unsafe"` 那一支，实现偏差没有任何东西查得出来

判据按【状态】分，不按【臂】分：带 subject = 诊断行 ⇒ 放行；不带 = 想当验收数 ⇒ 红。
"""

from __future__ import annotations

import pytest

from treval.cli.collect import (
    CORPUS_SETS,
    CURATION_P3,
    CURATION_W2,
    Producer,
    _assert_no_calib_producer,
    curation_for,
)
from treval.label_freeze import FIT_ARMS

P3 = "llm01_benign_design_p3"


# --------------------------------------------------------------------------- #
# 路通了
# --------------------------------------------------------------------------- #
def test_p3_is_a_selectable_corpus_set() -> None:
    assert "p3" in CORPUS_SETS
    assert curation_for("p3") == CURATION_P3
    assert CURATION_P3, "p3 编组不能是空的 —— 空编组会让这条路看起来通、实际一件都不跑"


def test_every_p3_producer_binds_the_p3_arm() -> None:
    assert all(p.corpus_subdir == P3 for p in CURATION_P3)


def test_p3_lane_passes_the_fit_arm_gate() -> None:
    """🔴 这一条红 = 路又被关上了。"""
    _assert_no_calib_producer(CURATION_P3)


# --------------------------------------------------------------------------- #
# 而「不得进验收」仍是机制
# --------------------------------------------------------------------------- #
def test_every_p3_producer_carries_a_subject() -> None:
    """带 subject 的行永不绑定 rubric objective、永不参与评级（仓里既有机制）。
    🔴 少一个 subject，那一行就成了可评级的聚合行 —— 在拟合集上。"""
    missing = [p.indicator_id for p in CURATION_P3 if not p.subject]
    assert not missing, f"这些 p3 producer 没带 subject：{missing}"
    # 🔴 要求是【非空】，不是「以臂名开头」—— 后者是我第一版的错设计，
    # 而 hard_only 那一行的 subject 由指标自己盖成 `arm_parity:hard_only`，
    # 按契约不许改。不绑评级靠的是非空，不是臂名。臂名走 arm_note。
    assert all(p.subject for p in CURATION_P3)


def test_a_subjectless_p3_producer_is_still_refused() -> None:
    """门没有被放宽 —— 它只是改成按状态分。去掉 subject 仍然当场红。"""
    bare = Producer(CURATION_P3[0].indicator_id, CURATION_P3[0].factory, P3)
    with pytest.raises(ValueError, match="FIT_ARMS"):
        _assert_no_calib_producer((bare,))


def test_p3_is_registered_as_a_fit_arm() -> None:
    """放行的前提是它【被声明为拟合臂】。不在词表里 ⇒ 这套判据根本没作用到它身上。"""
    assert P3 in FIT_ARMS


def test_every_p3_producer_carries_the_arm_note() -> None:
    """subject 让机器分得出来，arm_note 让人分得出来 —— 一行被复制进某份材料之后，
    只剩 subject 的话就只是一个看不出性质的字符串。"""
    for p in CURATION_P3:
        assert "diagnostic_only" in p.arm_note
        assert P3 in p.arm_note


# --------------------------------------------------------------------------- #
# 🔴 subject 契约 —— 本节是这一跑失败之后补的，它抓的是【仓里的契约】，不是我的意图
# --------------------------------------------------------------------------- #
# 第一版把 subject 拼成 "arm:fit_p3|<原键>"。11 条单测全绿，而真跑到第 17 分钟被
# `_apply_declared_subject` 拦下：`BenignFlagRateHardOnly` 自己盖 `arm_parity:hard_only`，
# 声明值与它不等 ⇒ raise。
# ⇒ 教训不是"少写了一条用例"，是**我钉的是自己的意图**（复合键唯一、原键存活）——
#   那两条测试在错误的设计下同样会绿。下面这条改成钉 `Producer.subject` 与
#   `factory` 实际盖的值之间那条契约，它在【第一版设计下会红】。
def test_declared_subject_matches_what_the_indicator_stamps() -> None:
    """🔴 `_apply_declared_subject` 的契约：指标自己盖 subject 时，Producer 声明的必须等于它。
    这条测试是那道运行期门的【测试期副本】—— 它把同一次失败从 17 分钟的真跑
    提前到接线当天。"""
    for p in CURATION_P3:
        stamped = getattr(p.factory, "_subject", "")
        if stamped:
            assert p.subject == stamped, (
                f"{p.indicator_id} 声明 subject={p.subject!r}，而 {p.factory.__name__} "
                f"自己盖的是 {stamped!r} —— 运行期 _apply_declared_subject 会 raise"
            )


def test_indicator_subject_keys_are_unique() -> None:
    """🔴 W2 里 `benign_flag_rate` 有两行（聚合口径 + hard_only 口径）。
    把 subject 一律盖成臂名会把它们压成同一个 (id, subject) ⇒ 撞，
    而两种口径之差正是这条臂上最该看的东西之一。"""
    keys = [(p.indicator_id, p.subject) for p in CURATION_P3]
    assert len(set(keys)) == len(keys), f"(id, subject) 撞了：{keys}"


def test_arm_name_travels_on_every_row_even_without_it_in_subject() -> None:
    """🔴 hard_only 那一行的 subject 里【没有臂名】（契约不允许），所以臂名必须靠
    `arm_note` 随数走 —— Lead 裁定「任何数不带臂名不得出现」在这一行上只剩这一条路。
    subject 是口径键，arm_note 是限定，两件事不能互相顶替。"""
    for p in CURATION_P3:
        assert P3 in p.arm_note


def test_p3_lane_mirrors_w2_indicator_set() -> None:
    """p3 是 W2 的【同构】臂：同一组 producer、换一条语料。
    不同构就意味着在 p3 上标定出来的工作点，落到 p2 上量的是另一组指标。"""
    assert [p.indicator_id for p in CURATION_P3] == [
        p.indicator_id for p in CURATION_W2
    ]


# --------------------------------------------------------------------------- #
# 它不许污染别的编组
# --------------------------------------------------------------------------- #
def test_no_other_corpus_set_touches_p3() -> None:
    """🔴 射程写死：p3 只出现在它自己的编组里。任何其它编组带上它，
    都会让一次普通跑顺手在拟合集上出数。"""
    for name in CORPUS_SETS:
        if name == "p3":
            continue
        assert not any(p.corpus_subdir == P3 for p in curation_for(name)), (
            f"编组 {name!r} 里出现了 p3"
        )
