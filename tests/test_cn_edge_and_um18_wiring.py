"""C-3c 贴边臂 与 use-mention-18 的接线门。

🔴 每条测试先说【什么输入让它红】—— 一个不可能失败的检查项打勾，和没检查是一回事。

⚠️ 本文件存在的直接原因：接线初稿把两条新臂并进了 `CURATION_CN`，而它们与既有臂共用
`false_positive_rate` / `speech_act_separation_rate` 两个 id。`corpus_sha` 按 indicator_id 建键
⇒ 同一编组里两条臂会互相覆盖指纹。这一错由既有的 `_assert_no_id_subdir_collision` 当场挡下，
不是靠 review 看出来的 —— 下面几条是把"当场挡下"变成"以后也挡得下"。
"""

from __future__ import annotations

import pytest

from treval.cli.collect import (
    CORPUS_SETS,
    CURATION_ARMB,
    CURATION,
    CURATION_CN,
    CURATION_CN_EDGE,
    CURATION_CN_UM18,
    Producer,
    _assert_no_id_subdir_collision,
    curation_for,
)
from treval.active_eval import FalsePositiveRate

_NEW_SETS = ("cn_edge", "cn_um18", "armb", "arma")


@pytest.mark.parametrize("name", _NEW_SETS)
def test_new_sets_are_selectable(name: str) -> None:
    """红条件：编组写了 tuple 却没登记进 CORPUS_SETS ⇒ `--corpus-set` 拒绝它，臂接了等于没接。"""
    assert name in CORPUS_SETS
    assert curation_for(name), f"{name} 编组是空的"


@pytest.mark.parametrize("name", _NEW_SETS)
def test_each_new_set_has_one_subdir_per_indicator(name: str) -> None:
    """红条件：把两条臂塞进同一编组 —— `corpus_sha` 按 id 建键，其中一条的指纹会被静默覆盖。"""
    _assert_no_id_subdir_collision(curation_for(name))


def test_merging_edge_into_cn_is_refused() -> None:
    """🔴 这一条【复现那次错法】，而不是描述它：把贴边臂并进 `cn` 必须当场抛错。

    红条件：有人"顺手"把两条臂并进 CURATION_CN 而这道门没响。
    """
    with pytest.raises(ValueError, match="two corpus_subdirs"):
        _assert_no_id_subdir_collision(CURATION_CN + CURATION_CN_EDGE)
    with pytest.raises(ValueError, match="two corpus_subdirs"):
        _assert_no_id_subdir_collision(CURATION + CURATION_CN_UM18)


def test_edge_arm_is_never_the_calibration_set() -> None:
    """红条件：有人把贴边臂指到 `_calib` 目录 —— τ 在标定臂上拟合，在它上面报 FPR 是自证。"""
    for p in CURATION_CN_EDGE:
        assert not p.corpus_subdir.endswith("_calib"), p.corpus_subdir


def test_edge_and_holdout_read_different_corpora() -> None:
    """红条件：贴边臂被接到留出臂的目录上 ⇒ 两条臂读同一批件，而报出来像两个数。"""
    edge = {p.corpus_subdir for p in CURATION_CN_EDGE}
    holdout = {
        p.corpus_subdir for p in CURATION_CN if p.indicator_id == "false_positive_rate"
    }
    assert edge == {"llm01_cn_benign_edge"}
    assert holdout == {"llm01_cn_benign_holdout"}
    assert edge.isdisjoint(holdout)


def test_um18_does_not_disturb_the_english_arm() -> None:
    """红条件：中文 use/mention 接到了英文那条臂上，或英文那条被改了。"""
    assert [p.corpus_subdir for p in CURATION_CN_UM18] == ["llm01_cn_speech_act"]
    en = [p for p in CURATION if p.indicator_id == "speech_act_separation_rate"]
    assert len(en) == 1 and en[0].corpus_subdir == "llm01_speech_act"
    assert en[0].subject == "", "英文那条是聚合行，带上 subject 会让它不再绑目标"


def test_no_staging_suffix_leaks_into_wiring() -> None:
    """红条件：把 `_STAGING` 目录名写进接线。

    🔴 `_STAGING` 是语料侧的暂存标记；接线引它，等于把"还没定稿"固化进口径。
    目录不存在时 `MissingArmError` 会响（fail-closed）⇒ 引终名是安全的。
    """
    for name in CORPUS_SETS:
        for p in curation_for(name):
            assert "STAGING" not in p.corpus_subdir, (name, p.corpus_subdir)


def test_english_default_set_is_untouched_by_cn_wiring() -> None:
    """红条件：CN 行漏进 CURATION ⇒ 每一次英文跑都会去探中文语料。"""
    assert not any(p.corpus_subdir.startswith("llm01_cn_") for p in CURATION)


def test_the_guard_itself_can_fail() -> None:
    """🔴 判据的判据：构造一对必然冲突的 Producer，确认这道门真的会红。

    红条件：`_assert_no_id_subdir_collision` 被改成恒真（例如有人给它加了 try/except）。
    """
    with pytest.raises(ValueError, match="two corpus_subdirs"):
        _assert_no_id_subdir_collision(
            (
                Producer("false_positive_rate", FalsePositiveRate, "dir_a"),
                Producer("false_positive_rate", FalsePositiveRate, "dir_b"),
            )
        )


def test_armb_does_not_collide_with_the_cn_injection_arm() -> None:
    """红条件：臂 B 被并进 `cn` —— 两者共用 injection 三个 id，corpus_sha 会互相覆盖。"""
    with pytest.raises(ValueError, match="two corpus_subdirs"):
        _assert_no_id_subdir_collision(CURATION_CN + CURATION_ARMB)


def test_armb_subject_is_an_arm_not_a_language() -> None:
    """🔴 红条件：给臂 B 标 `language:zh`。

    它是 120 中文 + 40 英文的【混合】臂 —— 一个语种标签在这里是假的，
    而假的地方在于它读起来像个事实。臂名回答"哪批件"，语种由件自己带。
    """
    for p in CURATION_ARMB:
        assert p.subject == "arm:cn_armb", p.subject


def test_cn_inj_never_reaches_the_one_shot_holdout_arm() -> None:
    """🔴 红条件：Tier-1 单侧那一跑碰到 `llm01_cn_benign_holdout`。

    那是门 B 的 125 件一次性留出臂。这一跑只要攻击侧的逐件判定，
    在留出臂上花掉一次观测就让"看了不满意再看一次"在结构上成为可能
    —— 而堵法是【够不着】，不是【记得别看】。
    """
    from treval.cli.collect import CURATION_CN_INJ

    subdirs = {p.corpus_subdir for p in CURATION_CN_INJ}
    assert subdirs == {"llm01_cn_injection"}, subdirs
    assert not any("holdout" in p.corpus_subdir for p in CURATION_CN_INJ)


def test_cn_inj_is_derived_from_cn_not_hand_listed() -> None:
    """🔴 红条件：有人往 `cn` 加一个攻击侧 producer，而 `cn_inj` 手写清单没跟着加。

    手写清单只在抄写当天正确 —— 所以这一组是从 `cn` 过滤出来的，不是抄的。
    本测试钉住"过滤"这个关系本身。
    """
    from treval.cli.collect import CURATION_CN, CURATION_CN_INJ

    assert CURATION_CN_INJ == tuple(
        p for p in CURATION_CN if p.corpus_subdir == "llm01_cn_injection"
    )
    assert len(CURATION_CN_INJ) < len(CURATION_CN), "过滤掉的那几行没了 ⇒ 等于没过滤"
