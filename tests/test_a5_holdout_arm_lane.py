"""A5 留出臂的登记与通道 —— 攻击侧【最后一条】未见臂。

🔴 A5 与 A3 在每一格上都同档（一次性 · 攻击侧 · 验收数 · ⛔ 不进 FIT_ARMS），
而它与同卷同轴的 A4a/A4b/A4c 三条在 FIT_ARMS 上【相反】。三比一的多数在那边，
照抄最近的一条就会把它登记成 diagnostic_only —— 那等于宣布门 A 没有读数。

⚠️ 它比 A3 还多一条性质，写在这里因为它没有别处可写：
    A3 不过之后还有 A5；A5 不过之后【没有下一条】。
    而"没有下一条"最容易变成"那就再造一条" —— 那等于把验收臂变成可重试的，
    与 read-once 的全部价值相反。
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from treval.cli.collect import (
    CORPUS_SETS,
    CURATION_EN_A3,
    CURATION_EN_A5,
    CURATION_EN_GRID,
    _assert_read_once_arms_intact,
    curation_for,
)
from treval.label_freeze import (
    ARM_VOLUME_ENV,
    FIT_ARMS,
    FROZEN_LABEL_SHA,
    KNOWN_VOLUME_ENVS,
    READ_ONCE_ARMS,
    READ_ONCE_CONSUMED,
    READ_ONCE_WAL_TOKEN,
    ReadOnceViolation,
    label_map,
    label_sha256,
)
from treval.rubric.serialize import derive_offline_recomputable

A5 = "llm01_en_holdout_a5"
A3 = "llm01_en_holdout_a3"
A4C = "llm01_en_interim_a4c"


def test_registered_in_all_slots() -> None:
    assert A5 in FROZEN_LABEL_SHA
    assert len(FROZEN_LABEL_SHA[A5]) == 64
    assert ARM_VOLUME_ENV[A5] == "TREVAL_EN_A5_CORPUS"
    assert "TREVAL_EN_A5_CORPUS" in KNOWN_VOLUME_ENVS
    assert READ_ONCE_WAL_TOKEN[A5] == "a5"


def test_a5_is_read_once_and_must_not_be_a_fit_arm() -> None:
    """🔴 进 FIT_ARMS = 声明"这条臂上的数不得进验收"。A5 就是门 A 的验收数本身。"""
    assert A5 in READ_ONCE_ARMS
    assert A5 not in FIT_ARMS, (
        "A5 是门 A 的验收臂；登记进 FIT_ARMS 会让它的数永远 diagnostic_only，"
        "而它是攻击侧最后一条未见臂 —— 之后没有别的臂能补这个数"
    )


def test_a5_is_in_the_same_档_as_a3_and_the_opposite_of_a4c() -> None:
    """🔴 三比一：同卷同轴的 A4a/A4b/A4c 都在 FIT_ARMS，A5 不在。防的是照抄最近那条。"""
    assert (A5 in READ_ONCE_ARMS) and (A3 in READ_ONCE_ARMS) and (A4C in READ_ONCE_ARMS)
    assert (A5 not in FIT_ARMS) and (A3 not in FIT_ARMS)
    assert A4C in FIT_ARMS
    assert {"llm01_en_interim_a4a", "llm01_en_interim_a4b"} <= FIT_ARMS


def test_a5_is_not_yet_marked_consumed() -> None:
    """🔴 跑之前它必须【不在】已消耗表里，否则那道门会拒绝这一跑。
    ⚠️ 而跑完之后必须由人加一行 —— 本表故意不自动追加。
    什么让它红：有人跑完顺手让程序自动登记（那会让"花掉一条一次性臂"不再需要人点头），
    或者跑之前误登（那会让这一跑开不了）。"""
    assert A5 not in READ_ONCE_CONSUMED
    _assert_read_once_arms_intact(CURATION_EN_A5, "")  # 门放行


def test_a5_producers_mirror_a3_producer_for_producer() -> None:
    """🔴 A3 的读数与 A5 的读数要能相减，必须由同一组指标算出来。
    （🔴 纪律②：实测值不写进公开仓。）"""
    assert {p.indicator_id for p in CURATION_EN_A5} == {
        p.indicator_id for p in CURATION_EN_A3
    }
    assert {p.indicator_id for p in CURATION_EN_A5} == {
        p.indicator_id for p in CURATION_EN_GRID
    }
    assert "injection_combined_recall" in {p.indicator_id for p in CURATION_EN_A5}
    for p in CURATION_EN_A5:
        assert p.corpus_subdir == A5
        assert p.subject == "arm:en_a5"


def test_a5_does_not_share_a_volume_env_with_any_other_arm() -> None:
    env = ARM_VOLUME_ENV[A5]
    sharers = [a for a, v in ARM_VOLUME_ENV.items() if v == env and a != A5]
    assert not sharers, f"A5 的闸门 {env} 还被 {sharers} 用着"


def test_corpus_set_wired_and_offline_declared() -> None:
    assert "en_a5" in CORPUS_SETS
    assert curation_for("en_a5") == CURATION_EN_A5
    assert derive_offline_recomputable("en_a5") == "holder_only"


def test_no_other_corpus_set_touches_a5() -> None:
    for name in CORPUS_SETS:
        if name == "en_a5":
            continue
        assert not any(p.corpus_subdir == A5 for p in curation_for(name)), (
            f"编组 {name!r} 里出现了 A5"
        )


def test_no_corpus_set_pairs_two_read_once_attack_arms() -> None:
    """🔴 两条一次性攻击臂同处一个编组 = 跑一条就花掉两条。
    攻击侧现在有 A2/A3/A5 三条一次性臂，两两都不许同组。"""
    once = {"llm01_en_holdout_a2", A3, A5}
    for name in CORPUS_SETS:
        subs = {p.corpus_subdir for p in curation_for(name)} & once
        assert len(subs) <= 1, f"编组 {name!r} 同时含一次性攻击臂 {sorted(subs)}"


def test_a_foreign_volume_is_still_refused_for_a5() -> None:
    """卷归属门对 A5 同样有效：拿 A3 的卷跑 A5 ⇒ 当场红。"""
    with pytest.raises(ReadOnceViolation, match="标记段"):
        _assert_read_once_arms_intact(CURATION_EN_A5, "/tmp/wal-a3")


def test_the_real_a5_corpus_still_matches_its_frozen_labels() -> None:
    """🔴 真语料上的实跑。变量未设 ⇒ 声明式跳过，不是通过。"""
    root = os.environ.get(ARM_VOLUME_ENV[A5], "")
    if not root:
        pytest.skip(f"{ARM_VOLUME_ENV[A5]} 未设 ⇒ A5 未校验（不是通过）")
    d = Path(root) / A5
    if not d.is_dir():
        pytest.skip(f"{d} 不存在 ⇒ A5 未校验（不是通过）")
    assert label_sha256(label_map(d)) == FROZEN_LABEL_SHA[A5]
