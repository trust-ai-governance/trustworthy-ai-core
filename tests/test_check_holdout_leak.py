"""留出臂外泄门。

🔴 每条先说【什么让它红】。本文件的第一条就是那次真实违规的复现 ——
   测的不是"门能不能工作"，是"门能不能抓住【已经发生过的那一次】"。
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tools.check_holdout_leak import holdout_bodies, leaks, main

_CASE = {
    "id": "synthetic.fixture.001",
    "owasp": "LLM01",
    "dimension": "robustness",
    "attack_class": "direct_prompt_injection",
    "success_when": "blocked_or_flagged",
    "severity": "info",
    "source": "core-authored",
    # 🔴 2026-09-25：原 fixture 的正文是【真 W6 件的开头】，逐字出现在留出臂语料里 ——
    # 而它就在这份为抓该违规而写的测试里。本仓那把量具（tools/check_holdout_leak.py）
    # 扫全仓时把它抓了出来。⇒ 换成一句【实测在任何语料里零命中】的合成句。
    # ⚠️ 合成不是自称的：换之前逐字扫过全部仓外语料，三个片段都 0 命中。
    "input": "zzq please reconcile the widget ledger before the quarterly freeze completes",
}


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    d = tmp_path / "holdout"
    d.mkdir()
    (d / "c.yaml").write_text(yaml.safe_dump(_CASE), encoding="utf-8")
    return d


def test_it_catches_the_violation_that_actually_happened(corpus: Path) -> None:
    """🔴 红条件：门放过一段逐字引了留出臂开头的话。

    这正是 2026-09-16 那次 —— 一段指名发给规则专家的话里带了三条 W6 件的开头。
    """
    msg = (
        "逐件看是一个作者习惯：zzq please reconcile the widget ledger — 这类开头占多数"
    )
    hits = leaks(msg, holdout_bodies([corpus]))
    assert [c for c, _ in hits] == ["synthetic.fixture.001"]


def test_aggregate_numbers_alone_do_not_trip_it(corpus: Path) -> None:
    """✅ 必须不红：只发聚合数 —— 那正是允许的发法，误红它等于废掉这条通道。"""
    assert not leaks(
        "留出臂的大写率 / 问号率 / 句长比（值在私有仓，🔴 纪律②不进公开仓）",
        holdout_bodies([corpus]),
    )


def test_newlines_and_indentation_cannot_smuggle_a_quote(corpus: Path) -> None:
    """🔴 红条件：只做朴素子串匹配 ⇒ 换行或缩进一插，逐字引用就逃掉了。"""
    msg = "开头是：\n\n    zzq please reconcile the\n    widget ledger — 后略"
    assert leaks(" ".join(msg.split()), holdout_bodies([corpus]))


def test_one_case_is_reported_once(corpus: Path) -> None:
    """红条件：同一件命中多个片段就报多条 —— 把一件事说 N 遍不会让它更清楚。"""
    msg = "zzq please reconcile the widget ledger before the quarterly freeze completes"
    assert len(leaks(msg, holdout_bodies([corpus]))) == 1


def test_no_corpus_is_an_empty_pass_and_exits_2(tmp_path: Path, capsys) -> None:
    """🔴 红条件：读不到语料时返回 0。

    一次【空过】长得和一次【通过】一样，是本仓反复栽的那个形状 ——
    所以它必须有自己的退出码，并且把"我什么也没查"说出来。
    """
    f = tmp_path / "msg.md"
    f.write_text("随便什么", encoding="utf-8")
    assert main([str(f), "--corpus", str(tmp_path / "nope")]) == 2
    assert "空过" in capsys.readouterr().err


def test_clean_file_exits_0_and_dirty_file_exits_1(
    tmp_path: Path, corpus: Path
) -> None:
    """红条件：退出码与结论脱节 —— CI 靠退出码，人靠文字，两者必须同向。"""
    clean = tmp_path / "clean.md"
    clean.write_text("留出臂的大写率（只发聚合数，不带值）", encoding="utf-8")
    assert main([str(clean), "--corpus", str(corpus)]) == 0
    dirty = tmp_path / "dirty.md"
    dirty.write_text("zzq please reconcile the widget ledger — 后略", encoding="utf-8")
    assert main([str(dirty), "--corpus", str(corpus)]) == 1


def test_span_is_a_declared_value_not_fitted_to_the_known_violation() -> None:
    """🔴 判据的判据：门槛不能是照着已知那三句调出来的。

    红条件：有人把 _SPAN 调到刚好抓住手头的样本 —— 那是"照着自己的测试集定义判据"，
    本仓已经栽过两次（近重复门 v1/v2）。这里只钉住它是个【声明值】且不依赖样本。
    """
    from tools.check_holdout_leak import _SPAN

    assert _SPAN == 24, "改动 _SPAN 要同时改掉注释里的理由，并说明新值是怎么来的"
