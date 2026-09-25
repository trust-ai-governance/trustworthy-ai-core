"""拟合臂词表 —— 一条不带 `_calib` 后缀的拟合臂，必须同样够不着任何 producer。

🔴 本文件存在的理由是一处实测缺口（2026-09-21）：`_assert_no_calib_producer` 认拟合集靠
**名字后缀**，而 P3（`llm01_benign_design_p3`，300 件，可反复读、可据它拟合）不带那个后缀
⇒ 那道门对它是瞎的，而瞎的方式与「它本来就不是拟合臂」在名字上完全同形。

与卷变量名那次同形：判据不能建在【命名约定】上，要建在【词表】上。
"""

from __future__ import annotations

import pytest

from treval.cli.collect import Producer, _assert_no_calib_producer
from treval.label_freeze import (
    ARM_VOLUME_ENV,
    FIT_ARMS,
    FROZEN_LABEL_SHA,
    KNOWN_VOLUME_ENVS,
    READ_ONCE_ARMS,
)


def _producer(subdir: str) -> Producer:
    """一个只用来喂守卫的 Producer —— 守卫只读 `corpus_subdir` 与 `indicator_id`。"""
    return Producer("false_positive_rate", object, subdir)  # type: ignore[arg-type]


def test_fit_arm_without_calib_suffix_is_refused() -> None:
    """🔴 本门的全部价值：P3 不带 `_calib`，后缀那道放行，词表这道必须红。"""
    with pytest.raises(ValueError, match="FIT_ARMS"):
        _assert_no_calib_producer((_producer("llm01_benign_design_p3"),))


def test_calib_suffix_still_refused_without_registry_entry() -> None:
    """后缀那道不许因为加了词表而失效 —— 它挡的是反向的疏忽：
    随手叫了 `_calib`、却没人登记进词表的新臂。"""
    unregistered = "llm01_something_new_calib"
    assert unregistered not in FIT_ARMS, "本用例要的就是一条【未登记】的 _calib 臂"
    with pytest.raises(ValueError, match="CALIBRATION arm"):
        _assert_no_calib_producer((_producer(unregistered),))


def test_reporting_arms_are_not_refused() -> None:
    """射程写死：报数臂照常通过。一道会误伤报数臂的门会被人关掉。"""
    for arm in (
        "llm01_benign_holdout",
        "llm01_benign_holdout_p2",
        "llm01_en_grid_attack",
    ):
        _assert_no_calib_producer((_producer(arm),))


def test_p3_registered_in_all_three_slots() -> None:
    """语料作者报的「三条臂 × 三处登记槽」—— P3 那一行。
    🔴 少登记一处不会红，只会让它在那一处【静默未校验】，所以这里逐槽点名。"""
    assert "llm01_benign_design_p3" in FROZEN_LABEL_SHA
    assert ARM_VOLUME_ENV["llm01_benign_design_p3"] == "TREVAL_EN_P3_CORPUS"
    assert "TREVAL_EN_P3_CORPUS" in KNOWN_VOLUME_ENVS


def test_p3_is_not_read_once() -> None:
    """🔴 P3 的定义性质：可反复读。把它误登记进 read-once 会让标定跑一次就没了。"""
    assert "llm01_benign_design_p3" not in READ_ONCE_ARMS


def test_p3_does_not_share_a_volume_env_with_a_read_once_arm() -> None:
    """闸门规则：可重跑臂不得与 read-once 臂共用变量。
    P3 与 P2 今天物理同卷，共用变量就等于每次读 P3 都顺手打开 P2。"""
    p3_env = ARM_VOLUME_ENV["llm01_benign_design_p3"]
    shared = [a for a in READ_ONCE_ARMS if ARM_VOLUME_ENV.get(a) == p3_env]
    assert not shared, f"P3 与 read-once 臂 {shared} 共用变量 {p3_env}"


def test_every_fit_arm_is_frozen() -> None:
    """🔴 拟合臂同样要冻 —— 不是为了"跑完对得上"，是为了让「拟合用的是哪一批件」
    在半年后还答得出来。一条允许反复读的臂最容易在无人注意时长大或缩小。"""
    missing = sorted(a for a in FIT_ARMS if a not in FROZEN_LABEL_SHA)
    # 仓内 en/cn 的老 calib 臂不住在仓外卷、不进冻结表 —— 只对登记了卷变量的那些要求冻结。
    missing = [a for a in missing if a in ARM_VOLUME_ENV]
    assert not missing, f"这些拟合臂登记了卷变量却没冻结标签：{missing}"
