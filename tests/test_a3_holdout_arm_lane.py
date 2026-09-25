"""A3 留出臂的登记与通道 —— 门 A 的【验收数】所在的那条臂。

🔴 A3 与 A4c 是同卷、同轴、同为 read-once 的攻击臂，而在 FIT_ARMS 上【方向相反】。
这是本文件存在的全部理由：A4c 是 2026-09-22 刚登记的上一条，照抄它就会把 A3
登记成"其数不作验收数"，而那等于宣布门 A 没有读数。

                 READ_ONCE_ARMS   FIT_ARMS
    A2 留出臂          ✅            ⛔     其数是测量数
    🔴 A3 留出臂       ✅            ⛔     其数【就是】门 A 的验收数
    A4a/A4b 探测臂     ⛔            ✅     可重读 · 其数只作诊断
    A4c 探测臂         ✅            ✅     一次性 · 其数只作诊断
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from treval.cli.collect import (
    CORPUS_SETS,
    CURATION_EN_A2,
    CURATION_EN_A3,
    CURATION_EN_GRID,
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

A3 = "llm01_en_holdout_a3"
A2 = "llm01_en_holdout_a2"
A4C = "llm01_en_interim_a4c"


def test_registered_in_all_three_slots() -> None:
    assert A3 in FROZEN_LABEL_SHA
    assert len(FROZEN_LABEL_SHA[A3]) == 64
    assert ARM_VOLUME_ENV[A3] == "TREVAL_EN_A3_CORPUS"
    assert "TREVAL_EN_A3_CORPUS" in KNOWN_VOLUME_ENVS


def test_a3_is_read_once_and_must_not_be_a_fit_arm() -> None:
    """🔴 进 FIT_ARMS = 声明"这条臂上的数不得进验收"。A3 就是验收数本身。"""
    assert A3 in READ_ONCE_ARMS
    assert A3 not in FIT_ARMS, (
        "A3 是门 A 的验收臂；登记进 FIT_ARMS 会让它的数永远是 diagnostic_only，"
        "门 A 从此没有读数"
    )


def test_a3_and_a4c_differ_on_the_fit_slot() -> None:
    """🔴 两条同卷、同轴、同为一次性的攻击臂，在 FIT_ARMS 上相反 —— 防的是照抄上一条。"""
    assert A3 in READ_ONCE_ARMS and A4C in READ_ONCE_ARMS
    assert A3 not in FIT_ARMS and A4C in FIT_ARMS


def test_a3_does_not_share_a_volume_env_with_any_other_arm() -> None:
    """闸门规则：同卷里现在躺着四条 read-once 臂（P2 · A2 · A4c · A3）——
    共用任何一个现有变量，都等于读一条时顺手把另外三条也打开。"""
    env = ARM_VOLUME_ENV[A3]
    sharers = [a for a, v in ARM_VOLUME_ENV.items() if v == env and a != A3]
    assert not sharers, f"A3 的闸门 {env} 还被 {sharers} 用着"


def test_a3_mirrors_a2_producer_for_producer() -> None:
    """🔴 门 A 的两条留出臂必须由【同一组指标】算出来，否则 A2 的读数与 A3 的读数不可比。
    （🔴 纪律②：两条臂的实测值不写进公开仓，它们在私有仓的跑批产物里。）"""
    assert {p.indicator_id for p in CURATION_EN_A3} == {
        p.indicator_id for p in CURATION_EN_A2
    }
    assert {p.indicator_id for p in CURATION_EN_A3} == {
        p.indicator_id for p in CURATION_EN_GRID
    }
    assert "injection_combined_recall" in {p.indicator_id for p in CURATION_EN_A3}
    for p in CURATION_EN_A3:
        assert p.corpus_subdir == A3
        assert p.subject == "arm:en_a3"


def test_corpus_set_wired_and_offline_declared() -> None:
    assert "en_a3" in CORPUS_SETS
    assert curation_for("en_a3") == CURATION_EN_A3
    assert derive_offline_recomputable("en_a3") == "holder_only"


def test_no_other_corpus_set_touches_a3() -> None:
    """射程写死：一次性臂若挂在别的编组上，跑那个编组就顺手把它花掉了。"""
    for name in CORPUS_SETS:
        if name == "en_a3":
            continue
        assert not any(p.corpus_subdir == A3 for p in curation_for(name)), (
            f"编组 {name!r} 里出现了 A3"
        )


def test_a3_and_a2_are_not_in_the_same_corpus_set() -> None:
    """🔴 两条 read-once 攻击臂同处一个编组 = 跑一条就花掉两条。"""
    for name in CORPUS_SETS:
        subs = {p.corpus_subdir for p in curation_for(name)}
        assert not ({A3, A2} <= subs), f"编组 {name!r} 同时含 A3 与 A2"


def test_the_real_a3_corpus_still_matches_its_frozen_labels() -> None:
    """🔴 真语料上的实跑。变量未设 ⇒ 声明式跳过，不是通过。"""
    root = os.environ.get(ARM_VOLUME_ENV[A3], "")
    if not root:
        pytest.skip(f"{ARM_VOLUME_ENV[A3]} 未设 ⇒ A3 未校验（不是通过）")
    d = Path(root) / A3
    if not d.is_dir():
        pytest.skip(f"{d} 不存在 ⇒ A3 未校验（不是通过）")
    assert label_sha256(label_map(d)) == FROZEN_LABEL_SHA[A3]
