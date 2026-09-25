"""A2 英文攻击留出臂 —— 登记四槽方向正确，且它与 P3 在每一格上【方向相反】。

🔴 本文件存在的理由：A2 与 P3 同卷、名字相邻、同一天登记，而它们在三格上恰好相反 ——
    P3 设计臂  可反复读 ⇒ 不在 READ_ONCE_ARMS；可据它拟合 ⇒ 在 FIT_ARMS
    A2 留出臂  一次性   ⇒ 在 READ_ONCE_ARMS；🔴 不得进 FIT_ARMS
把 A2 误登记进 FIT_ARMS 的后果不是"多了一条记录"：`_assert_no_calib_producer` 会对它
**放行**（带 subject 的诊断行），而那道门存在的全部理由就是拦住「在拟合集上报验收数」。
⇒ 一条本该拦住的臂被放行，而放行的样子与正常通过完全同形。
"""

from __future__ import annotations

from treval.cli.collect import (
    CORPUS_SETS,
    CURATION_EN_A2,
    CURATION_EN_GRID,
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

A2 = "llm01_en_holdout_a2"
P3 = "llm01_benign_design_p3"


def test_registered_in_all_three_slots() -> None:
    assert A2 in FROZEN_LABEL_SHA
    assert ARM_VOLUME_ENV[A2] == "TREVAL_EN_A2_CORPUS"
    assert "TREVAL_EN_A2_CORPUS" in KNOWN_VOLUME_ENVS


def test_a2_is_read_once() -> None:
    """跑它就花掉它。漏登记 ⇒ 没有任何东西阻止第二次读。"""
    assert A2 in READ_ONCE_ARMS


def test_a2_is_NOT_a_fit_arm() -> None:
    """🔴 本文件最要紧的一条：留出臂进了拟合臂词表，那道门就对它放行了。"""
    assert A2 not in FIT_ARMS


def test_a2_and_p3_are_opposite_on_every_axis() -> None:
    """两条臂同卷、名字相邻、同日登记 —— 逐格对照，防的是"照着上一条抄"。"""
    assert (A2 in READ_ONCE_ARMS) and (P3 not in READ_ONCE_ARMS)
    assert (A2 not in FIT_ARMS) and (P3 in FIT_ARMS)
    assert ARM_VOLUME_ENV[A2] != ARM_VOLUME_ENV[P3]


def test_a2_has_its_own_volume_gate() -> None:
    """闸门规则：每条 read-once 臂必须有专属变量。与 P3 共用 ⇒ 读 P3 时顺手打开 A2。"""
    shared = [
        a for a, v in ARM_VOLUME_ENV.items() if a != A2 and v == ARM_VOLUME_ENV[A2]
    ]
    assert not shared, f"A2 与 {shared} 共用卷变量"


def test_a2_corpus_set_is_wired_and_mirrors_en_grid() -> None:
    """A2 与网格臂【同构】：同三个 producer、换一条语料。
    不同构就意味着两条臂上的门 A 量的不是同一组指标，而"拟合臂 vs 留出臂"的对照就不成立。"""
    assert "en_a2" in CORPUS_SETS
    assert curation_for("en_a2") == CURATION_EN_A2
    assert [p.indicator_id for p in CURATION_EN_A2] == [
        p.indicator_id for p in CURATION_EN_GRID
    ]
    assert all(p.corpus_subdir == A2 for p in CURATION_EN_A2)
    assert all(p.subject == "arm:en_a2" for p in CURATION_EN_A2)


def test_the_fit_arm_gate_lets_a2_through() -> None:
    """A2 不是拟合臂 ⇒ 必须放行。这一条红 = 我把它登记成了拟合臂。"""
    _assert_no_calib_producer(CURATION_EN_A2)


def test_offline_recomputability_declared() -> None:
    """仓外受控卷 ⇒ holder_only。漏登记会在出包时 fail-closed，但那已是跑完之后。"""
    assert derive_offline_recomputable("en_a2") == "holder_only"


def test_no_other_corpus_set_touches_a2() -> None:
    """🔴 A2 是 read-once：它不许被任何其它编组"顺手带上"。
    一次普通跑若连带打了 A2，那条臂就在没人决定的情况下花掉了。"""
    for name in CORPUS_SETS:
        if name == "en_a2":
            continue
        assert not any(p.corpus_subdir == A2 for p in curation_for(name)), (
            f"编组 {name!r} 里出现了 read-once 臂 A2"
        )
