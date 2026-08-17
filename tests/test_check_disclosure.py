"""F8 disclosure gate (EV-COVERAGE-E3F §7B) — the pure scanner + exemptions. The git-diff wrapper
(added_lines) is integration; here we pin the three hit patterns and the exemption discipline."""

from __future__ import annotations

from tools.check_disclosure import _is_exempt, disclosure_hit


def test_pattern_1_k_over_n_with_percent_or_ci():
    """§7B.2 ① — k/n on a line that also has % or ci_ (a measured proportion in prose)."""
    assert (
        disclosure_hit("catch rate 25/28 = 89.3%") is not None
    )  # disclosure-ok: 构造性测试输入 —— 这些字面量【就是】被测判据的输入，证明门有牙
    assert (
        disclosure_hit("FPR 0/100, 95% CI [0, 3.7%]") is not None
    )  # disclosure-ok: 构造性测试输入 —— 这些字面量【就是】被测判据的输入，证明门有牙
    assert (
        disclosure_hit("we probed 25/28 cases") is None
    )  # k/n but no % / ci_ ⇒ not a disclosure


def test_pattern_2_ci_value_but_not_a_threshold():
    """§7B.2 ② — ci_low / ci_high followed by a literal decimal VALUE. 🔴 A THRESHOLD (`ci_low >= 0.80`,
    a satisfied_when criterion) is NOT a disclosure — it defines the gate, it reports no measurement."""
    assert (
        disclosure_hit("its ci_low is 0.728 at n=28") is not None
    )  # disclosure-ok: 构造性测试输入 —— 这些字面量【就是】被测判据的输入，证明门有牙
    assert (
        disclosure_hit("gate on ci_low >= 0.80 (a threshold)") is None
    )  # a CRITERION, not a value
    assert disclosure_hit("satisfied_when: ci_high <= 0.05") is None  # ditto
    assert disclosure_hit("ci_low is nullable, no interval") is None


def test_pattern_3_indicator_id_with_a_percentage():
    """§7B.2 ③ — an indicator id alongside a percentage."""
    assert (
        disclosure_hit("injection_catch_rate = 89%") is not None
    )  # disclosure-ok: 构造性测试输入 —— 这些字面量【就是】被测判据的输入，证明门有牙
    assert (
        disclosure_hit("chain_integrity 100.0% (census)") is not None
    )  # disclosure-ok: 构造性测试输入 —— 这些字面量【就是】被测判据的输入，证明门有牙
    assert (
        disclosure_hit("injection_catch_rate is the recall metric") is None
    )  # name, no %


def test_synthetic_marker_exempts_the_line():
    """§7B.2 — constructive/synthetic test data (incl. a math function's known-IO) must carry the
    marker; a marked line is exempt even if it holds a value shape."""
    assert (
        disclosure_hit(
            "assert binomial_ci(0.5, 100) == (0.40, 0.60)  # synthetic: Wilson IO"
        )
        is None
    )
    assert disclosure_hit("catch 3/4 = 75%  # synthetic: fixture input") is None


def test_path_exemptions_corpus_and_fixtures():
    """§7B.2 + §四 — corpus/ is INPUT and tests/fixtures/ is MACHINE-GENERATED; both exempt. Human
    prose (docs, registry, source comments) is NOT."""
    assert _is_exempt("corpus/llm01_prompt_injection/x.yaml") is True
    assert (
        _is_exempt("tests/fixtures/report/valid/rich.json") is True
    )  # §四 — regen'd artifact
    assert _is_exempt("docs/EVAL_ISSUES.md") is False
    assert _is_exempt("registry/dimensions/robustness.yaml") is False
    assert _is_exempt("treval/citability.py") is False
