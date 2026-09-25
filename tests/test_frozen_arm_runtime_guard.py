"""跑时冻结校验 —— `assert_labels_frozen` 终于被生产路径调用了。

🔴 本文件的全部理由（PM 2026-09-17 核出）：那个函数定义得好好的、fail-closed、
docstring 逐字写着「只能在跑之前拦」，而它的【全部调用点都在测试里】——
它从来没有在跑之前拦过。一个只被自己的测试调用的 fail-closed 守卫，
与一个不存在的守卫，在生产路径上是同一个东西。
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from treval.active_eval import InjectionCatchRate
from treval.cli.collect import Producer, _assert_frozen_arms_unchanged
from treval.label_freeze import label_map, label_sha256

_ARM = "llm01_frozen_demo"
_CASE = {
    "id": "d.1",
    "owasp": "LLM01",
    "dimension": "robustness",
    "attack_class": "direct_prompt_injection",
    "input": "x",
    "success_when": "blocked_or_flagged",
    "severity": "info",
    "source": "core-authored",
}


def _arm(root: Path, **over) -> Path:
    d = root / _ARM
    d.mkdir(parents=True, exist_ok=True)
    (d / "a.yaml").write_text(
        yaml.safe_dump({**_CASE, **over}, allow_unicode=True), encoding="utf-8"
    )
    return d


def _prod() -> tuple[Producer, ...]:
    return (Producer("injection_catch_rate", InjectionCatchRate, _ARM),)


def test_a_drifted_label_stops_the_run(tmp_path: Path, monkeypatch) -> None:
    """🔴 必须红：标签漂了还照跑。

    docstring 逐字：一个标签漂了的批次，它的每一个数都在描述另一批件，
    而那件事【在跑完之后是看不出来的】。
    """
    d = _arm(tmp_path)
    frozen = label_sha256(label_map(d))
    monkeypatch.setattr(
        "treval.label_freeze.FROZEN_LABEL_SHA", {_ARM: frozen}, raising=False
    )
    _assert_frozen_arms_unchanged(_prod(), tmp_path)  # 没漂 ⇒ 静默通过
    _arm(tmp_path, success_when="not_leaked")  # 改一个标签
    with pytest.raises(Exception):
        _assert_frozen_arms_unchanged(_prod(), tmp_path)


def test_an_unregistered_arm_is_skipped_not_reddened(
    tmp_path: Path, monkeypatch
) -> None:
    """红条件：把"未登记"当成红。

    冻结是【自愿登记制】—— 未登记就判红，等于每一条新臂在登记之前都开不了工。
    """
    _arm(tmp_path)
    monkeypatch.setattr("treval.label_freeze.FROZEN_LABEL_SHA", {}, raising=False)
    _assert_frozen_arms_unchanged(_prod(), tmp_path)


def test_a_missing_dir_is_left_to_the_other_gate(tmp_path: Path, monkeypatch) -> None:
    """🔴 红条件：目录不在时由本门报错。

    那是 `MissingArmError` 的活。一道门替另一道门报错，会让人去修错的那一处。
    """
    monkeypatch.setattr(
        "treval.label_freeze.FROZEN_LABEL_SHA", {_ARM: "0" * 64}, raising=False
    )
    _assert_frozen_arms_unchanged(_prod(), tmp_path)  # 目录不存在 ⇒ 不由本门红


def test_the_guard_is_actually_wired_into_the_run_path() -> None:
    """🔴 判据的判据：证明它【真的在生产路径上被调用】，而不只是被这个文件调用。

    红条件：有人把那一行从 collect_measurements 里删掉 —— 而所有别的测试仍会绿，
    因为它们直接调这个函数。这正是 PM 数到的第六个"建了没接线"的形状。
    """
    import inspect

    from treval.cli.collect import collect_measurements

    src = inspect.getsource(collect_measurements)
    assert "_assert_frozen_arms_unchanged(" in src, (
        "跑时冻结校验没有接在 collect_measurements 上 —— 它又变回只被测试调用的那种守卫"
    )
