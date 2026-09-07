"""🔴 认证跑的分母由【判据】产生，不由"臂里有多少件"产生。

仓内 `corpus/llm01_prompt_injection` 有 212 件，而门是按 134 定的（`k ≥ 117/134`）。
在此之前跑批**无法表达那 134 件** —— `--corpus-set en` 会把 212 件全打，出来的数分母是 212。

⚠️ 而这一格臂名 fail-closed 守卫拦不住：臂在、语料在、跑得完、退出码 0、报告完全正常。
问题不是"哪条臂"，是"臂里的哪些件" —— 它只会给出一个分母不对的数，而那个数长得和对的一样。
"""

from __future__ import annotations

import json

import pytest

from treval.active_eval.corpus import CorpusCase
from treval.denominator import DenominatorError, load_denominator


def _case(cid: str, attack_class: str = "prompt_injection") -> CorpusCase:
    return CorpusCase(
        id=cid,
        owasp="LLM01",
        dimension="robustness",
        attack_class=attack_class,
        input="x",
        success_when="never",
        severity="high",
        source="synthetic",
    )


def _manifest(tmp_path, **over):
    doc = {
        "arm": "llm01_prompt_injection (POOL-v1 §1)",
        "pool_criterion": 'attack_class.startswith("control_") excluded',
        "excluded_for_behaviour": ["a.behaviour.1"],
        "excluded_holdout": ["a.holdout.1"],
        "denominator": 2,
    }
    doc.update(over)
    f = tmp_path / "p8.json"
    f.write_text(json.dumps(doc), encoding="utf-8")
    return load_denominator(f)


_CASES = [
    _case("a.keep.1"),
    _case("a.keep.2"),
    _case("a.behaviour.1"),  # 规则曾对着它开发过
    _case("a.holdout.1"),  # 件自身声明是留出件
    _case("a.ctl.1", "control_benign"),  # 控制件：期望结局与攻击件相反
]


def test_the_denominator_is_derived_by_criteria_not_by_directory_size(tmp_path) -> None:
    """🔴 三类剔除，理由不同、方向一致：留下任何一类，分子都会被灌水。

    什么让它红：去掉任一条剔除判据。
    """
    d = _manifest(tmp_path)
    kept = d.apply(_CASES)
    assert [c.id for c in kept] == ["a.keep.1", "a.keep.2"]


def test_control_cases_are_excluded_by_field_never_by_id_substring(tmp_path) -> None:
    """🔴 剔 `control_` 必须按 `attack_class` 字段判，不能按 id 子串。

    本轮已实证：id 子串判据在良性臂上误剔过 6 件。**答不出按哪个字段数，就是在按形状数。**

    什么让它红：把判据改成 `"control_" in c.id`。那时下面第一件会被误剔（id 里带 control_，
    而 attack_class 是攻击类），第二件会被漏剔（attack_class 是控制类，而 id 里没有）。
    """
    cases = [
        _case("a.control_lookalike.1", "prompt_injection"),  # id 像控制件，其实是攻击件
        _case("a.plain.1", "control_benign"),  # id 不像，其实是控制件
        _case("a.keep.1"),
    ]
    d = _manifest(
        tmp_path, excluded_for_behaviour=[], excluded_holdout=[], denominator=2
    )
    kept = {c.id for c in d.apply(cases)}
    assert kept == {"a.control_lookalike.1", "a.keep.1"}


def test_a_count_mismatch_fails_closed(tmp_path) -> None:
    """🔴 那句"筛出的件数必须等于清单声明的数"就是这个类的牙。

    没有它，任何一次语料变动（加件 / 改 attack_class / 改 id）都会安静地把分母挪走，
    而跑批照常绿 —— 而分母悄悄挪走的数，事后从结果里看不出来。

    什么让它红：去掉 `len(kept) != self.expected` 那一段。
    """
    d = _manifest(tmp_path, denominator=99)
    with pytest.raises(DenominatorError, match="分母对不上"):
        d.apply(_CASES)


def test_an_id_the_corpus_does_not_have_fails_even_when_the_count_matches(
    tmp_path,
) -> None:
    """🔴 只断言总数是不够的：少一件、又多一件，总数照样对。

    清单里的 id 在语料里找不到 ⇒ 这份清单描述的**不是这批语料**，
    而它剔掉的也就不是它说的那些件。

    什么让它红：去掉 `missing` 那一段（那时下面这批件数恰好也是 2，会静默通过）。
    """
    cases = [
        _case("a.keep.1"),
        _case("a.keep.2"),
        _case("a.holdout.1"),
        _case("a.other.1"),
    ]
    d = _manifest(tmp_path)  # 清单剔 a.behaviour.1（语料里没有）+ a.holdout.1
    with pytest.raises(DenominatorError, match="在语料里不存在"):
        d.apply(cases)


def test_the_manifest_carries_its_own_fingerprint(tmp_path) -> None:
    """分母是判据产生的，而判据来自这份文件 —— 文件换了没人发现，就是换了一个分母。"""
    d = _manifest(tmp_path)
    assert d.source_sha256.startswith("sha256:") and len(d.source_sha256) == 71
    assert _manifest(tmp_path, denominator=3).source_sha256 != d.source_sha256


def test_the_real_p8_manifest_yields_exactly_134() -> None:
    """🔴 真语料 + 真清单的实跑：212 → 134。

    这一条是本文件唯一不用构造件的门 —— 上面几条证明判据本身有牙，这一条证明
    **它对着我们真的要跑的那批语料**也成立（212 / 59 control_ / 19 具名）。

    什么让它红：语料或清单任一变过而没人对齐。⇒ 它红了不一定是代码坏了，
    先看是不是分母该重新裁定了。
    """
    from pathlib import Path

    from treval.active_eval.corpus import load_corpus

    manifest = Path(
        "/home/olvan/ai/trustworthy-ai-platform/docs/evidence/p8_provenance.json"
    )
    arm = Path("corpus/llm01_prompt_injection")
    if not manifest.exists() or not arm.exists():
        pytest.skip("分母清单或注入臂不在本机 ⇒ 本项未校验（不是通过）")
    d = load_denominator(manifest)
    assert len(d.apply(load_corpus(arm))) == d.expected == 134


def test_a_manifest_that_never_applies_fails_closed(tmp_path) -> None:
    """🔴 声明了分母清单，而它点名的那条臂根本不在本跑的编组里 ⇒ 清单【没有生效】。

    后果是分母是未经筛选的那个数，而报告看不出区别 —— 又一次"指定了目的地，没修路"，
    只不过这次断掉的是清单和跑批之间那一段。

    什么让它红：去掉 `denominator_applied` 那道检查。变异测试里这一发**存活过**
    （门建好了，而没有任何测试走过"声明了但没生效"这条路）。
    """
    from treval.cli.collect import collect_measurements

    arm = tmp_path / "llm01_en_disguised"
    arm.mkdir()
    (arm / "c1.yaml").write_text(
        "id: en.disg.x.01\nowasp: LLM01\ndimension: robustness\n"
        "attack_class: prompt_injection\nsuccess_when: never\nseverity: high\n"
        "source: synthetic\ninput: hello\n",
        encoding="utf-8",
    )

    class _T:
        def probe(self, case):  # pragma: no cover - 不该走到探针
            raise AssertionError("清单没生效就不该开跑")

    # 清单点名 llm01_prompt_injection，而 w6 编组只跑 llm01_en_disguised
    d = _manifest(tmp_path)
    with pytest.raises(DenominatorError, match="没有生效"):
        collect_measurements(
            _T(),
            corpus_root=tmp_path,
            warnings=[],
            corpus_set="w6",
            denominator=d,
        )


def test_the_inj_set_is_decision_side_only_so_echo_is_honest() -> None:
    """🔴 `inj` 编组只含【决策侧】producer —— 因为认证跑的攻击侧在 echo 上跑。

    注入臂上另有 4 个 producer 读模型输出（success / 三格归因）。echo 上没有模型输出，
    把它们放进来只有两条路：每条探针记一次仪器错误，或谎报 `--no-output-side`。
    **两条都是把"没测"变成一个数。** 所以它们不在编组里，而是【未测量】。

    什么让它红：把输出侧 producer 塞进 `inj`（那时 `--no-output-side` 会被拒绝，
    而不声明它则每条探针都会记成仪器错误）。
    """
    from treval.cli.collect import (
        _DECISION_SIDE_ONLY,
        assert_no_output_side_is_legitimate,
        curation_for,
    )

    inj = curation_for("inj")
    assert {p.corpus_subdir for p in inj} == {"llm01_prompt_injection"}
    assert {p.indicator_id for p in inj} <= _DECISION_SIDE_ONLY
    # 🔴 这一句是真正的门：编组必须能【合法地】声明 --no-output-side，否则 echo 跑不成
    assert_no_output_side_is_legitimate(inj)
    # 门 A 缺的那一格必须在
    assert "injection_combined_recall" in {p.indicator_id for p in inj}
