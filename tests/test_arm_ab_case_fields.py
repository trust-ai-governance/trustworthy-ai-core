"""臂 A / 臂 B 的三个新 case 字段：`payload_case_id` · `payload_msg_index` · `lang`。

🔴 三个都是【裁定的产物】，不是补全：
  payload_case_id    §八①「两者载荷字节相同」只有两件都指得出同一源件时才机械可核
  payload_msg_index  位置是臂 A 的自变量，推断出来的自变量 = 把"我以为"写成测量
  lang               Lead 2026-09-15「停止规则只读中文 120 的率」——在它落地前那条裁定执行不了

⚠️ 三个都 OPTIONAL：本轮之前的每一批语料都没有它们，缺省必须干净装载。
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from treval.active_eval.corpus import CorpusCase, CorpusError, load_corpus

_MIN = {
    "id": "x.1",
    "owasp": "LLM01",
    "dimension": "robustness",
    "attack_class": "direct_prompt_injection",
    "input": "hello",
    "success_when": "blocked_or_flagged",
    "severity": "info",
    "source": "core-authored",
}


def _write(tmp_path: Path, **extra) -> tuple[CorpusCase, ...]:
    (tmp_path / "c.yaml").write_text(
        yaml.safe_dump({**_MIN, **extra}, allow_unicode=True), encoding="utf-8"
    )
    return load_corpus(tmp_path)


def test_absent_fields_still_load_clean(tmp_path: Path) -> None:
    """红条件：把任一字段加进 `_REQUIRED` ⇒ 本轮之前的每一批语料当场装不进来。"""
    (c,) = _write(tmp_path)
    assert (c.payload_case_id, c.payload_msg_index, c.lang) == ("", -1, "")


def test_index_zero_survives_and_is_not_confused_with_absent(tmp_path: Path) -> None:
    """🔴 红条件：把缺省写成 0。

    0 是合法下标（臂 A 的 T 侧就在 0），所以缺省只能是 -1；
    缺省用 0 会让"没声明"和"载荷在第一条消息"变成同一个值。
    """
    (c,) = _write(tmp_path, payload_case_id="src.1", payload_msg_index=0)
    assert c.payload_msg_index == 0 and c.payload_case_id == "src.1"


def test_bool_is_refused_as_an_index(tmp_path: Path) -> None:
    """红条件：忘了 bool 是 int 的子类 ⇒ `payload_msg_index: true` 被静默收成 1。"""
    with pytest.raises(CorpusError, match="payload_msg_index"):
        _write(tmp_path, payload_case_id="src.1", payload_msg_index=True)


def test_negative_index_is_refused(tmp_path: Path) -> None:
    """红条件：允许显式写 -1 ⇒ "未声明"变成一个可以被手写的值，三态塌成两态。"""
    with pytest.raises(CorpusError, match="payload_msg_index"):
        _write(tmp_path, payload_case_id="src.1", payload_msg_index=-1)


@pytest.mark.parametrize(
    "extra", [{"payload_case_id": "src.1"}, {"payload_msg_index": 2}]
)
def test_the_two_arm_a_fields_must_come_as_a_pair(tmp_path: Path, extra: dict) -> None:
    """🔴 红条件：只带其一也放行。

    只有载荷 id 没有下标 ⇒ 指不出位置；只有下标没有载荷 id ⇒ 指不出载荷。
    两种都不是"少一点信息"，是自变量断了 —— 而断了的样子和填好的一模一样。
    """
    with pytest.raises(CorpusError, match="成对"):
        _write(tmp_path, **extra)


def test_empty_lang_is_refused_but_absent_lang_is_fine(tmp_path: Path) -> None:
    """红条件：把 `lang: ""` 当成合法值 ⇒ "写了但是空"与"没写"同形。"""
    with pytest.raises(CorpusError, match="lang"):
        _write(tmp_path, lang="")
    (c,) = _write(tmp_path)
    assert c.lang == ""


def test_stop_rule_can_slice_arm_b_by_language_mechanically() -> None:
    """🔴 Lead 2026-09-15「停止规则只读中文 120 的率」—— 本条证明那条裁定【可执行】。

    红条件：`lang` 没进 CorpusCase ⇒ loader 静默丢弃 ⇒ 分层只能靠 case id 前缀猜，
    而那是把命名约定当数据：改一次 id 规则，停止规则会静默换一个分母，没有门会红。
    """
    # 🔴 路径从环境变量取，不写字面量：本仓是 PUBLIC，而语料在仓外受控卷。
    # 未设即【声明式跳过】—— 现成写法见 tests/test_label_freeze.py:30。
    # ⚠️ 这一处是语料作者 2026-09-17 复核出来的，全仓唯一一处；而它能留到今天，
    #    是因为路径外泄这条规矩只有【一处点检】(test_w2_product_revisions.py:335 只查一个字符串常量)，
    #    没有仓级扫描 ⇒ 规矩在、门不在。门已补：test_no_corpus_path_literals_in_repo。
    root = os.environ.get("TREVAL_CN_CORPUS", "")
    if not root:
        pytest.skip("TREVAL_CN_CORPUS 未设 —— 中文语料在仓外受控卷，声明式跳过")
    d = Path(root) / "eval" / "llm01_grid_attack"
    if not d.is_dir():
        pytest.skip("臂 B 语料目录本机不可见")
    cases = load_corpus(d)
    by_lang: dict[str, int] = {}
    for c in cases:
        by_lang[c.lang] = by_lang.get(c.lang, 0) + 1
    assert "" not in by_lang, "有件没声明 lang ⇒ 停止规则的分母会缺一块"
    assert set(by_lang) == {"zh", "en"}, by_lang
    # 🔴 不写死 120/40:件数是语料侧的事,本测试要守的是【分得开】,不是分成几份。
    assert all(v > 0 for v in by_lang.values())


# --------------------------------------------------------------------------- #
# 七个分类字段（语料作者 2026-09-17 报：臂 B 盘上 17 个字段，7 个被静默丢弃）
# --------------------------------------------------------------------------- #
_CLASSIFIERS = ("family", "mechanism", "anchor", "evasion", "control_rule_anchor")


@pytest.mark.parametrize("key", _CLASSIFIERS)
def test_classifier_fields_survive_loading(tmp_path: Path, key: str) -> None:
    """🔴 红条件：字段没进 CorpusCase ⇒ loader 静默丢弃。

    判据与 `lang` 那次逐字相同：盘上写着而装载之后读不到，
    而「读不到」与「这批件没有这个字段」一模一样。
    """
    (c,) = _write(tmp_path, **{key: "v"})
    assert getattr(c, key) == "v"
    (c2,) = _write(tmp_path)
    assert getattr(c2, key) == "", "缺省必须干净装载 —— 本轮之前的语料都没有它们"


def test_grid_no_zero_is_not_absent(tmp_path: Path) -> None:
    """红条件：缺省写成 0 ⇒ "未声明"与"第 0 号格"同形。"""
    (c,) = _write(tmp_path, grid_no=0)
    assert c.grid_no == 0
    with pytest.raises(CorpusError, match="grid_no"):
        _write(tmp_path, grid_no=True)  # bool 是 int 子类
    with pytest.raises(CorpusError, match="grid_no"):
        _write(tmp_path, grid_no=-1)


def test_unknown_is_not_a_legal_derived_from_value(tmp_path: Path) -> None:
    """🔴 红条件：把 `unknown` 收进值域。

    语料作者逐字：一个叫 unknown 的合法值会让「没查过来源」和「查过但查不到」同形。
    老件走 `unknown_legacy` —— 它自陈是历史欠账，而 unknown 读起来像一个结论。
    """
    with pytest.raises(CorpusError, match="unknown"):
        _write(tmp_path, derived_from="unknown")
    (c,) = _write(tmp_path, derived_from="unknown_legacy")
    assert c.derived_from == "unknown_legacy"


def test_public_dataset_must_name_the_dataset_and_version(tmp_path: Path) -> None:
    """🔴 红条件：`public_dataset` 不带名字和版本也放行 —— 那等于没记来源。"""
    with pytest.raises(CorpusError, match="public_dataset"):
        _write(tmp_path, derived_from="public_dataset")
    (c,) = _write(tmp_path, derived_from="public_dataset:garak@0.9.1")
    assert c.derived_from.startswith("public_dataset:")


def test_authenticity_is_a_closed_three_state(tmp_path: Path) -> None:
    """红条件：值域开着 ⇒ 写件人的把握变成一个自由文本，数不出来也比不了。"""
    for v in ("confident", "unsure", "syntax_only"):
        (c,) = _write(tmp_path, authenticity=v)
        assert c.authenticity == v
    with pytest.raises(CorpusError, match="authenticity"):
        _write(tmp_path, authenticity="high")


def test_citation_form_is_deliberately_not_a_case_field() -> None:
    """🔴 红条件：有人把 `citation_form` 加进 CorpusCase。

    语料作者 2026-09-17 逐字：它是挂在【一个数】上的口径句，不是件的字段。
    加了它才是真错 —— 那会把一个类别错误固化进契约。
    """
    assert "citation_form" not in CorpusCase.__dataclass_fields__, (
        "citation_form 是出数时挂的口径，不是件的属性"
    )
