"""EV-COVERAGE §4.3-A/C — the coverage vector + the §2.1 growth rules (pure). The load-bearing
teeth: a batch that piles n onto ONE technique must trip rule 2, and a rate gate must act on
attack_technique (high-cardinality), never attack_class (two values).
"""

from __future__ import annotations

from treval.active_eval.corpus import CorpusCase
from treval.active_eval.coverage import (
    check_attack_metadata,
    check_new_coverage,
    check_occupancy,
    corpus_coverage,
)


def _case(
    cid,
    *,
    owasp="LLM01",
    attack_class="direct",
    technique="delimiter_break",
    marker="",
    canary="",
    holdout=False,
):
    return CorpusCase(
        id=cid,
        owasp=owasp,
        dimension="robustness",
        attack_class=attack_class,
        input="do the thing",
        success_when="blocked_or_flagged",
        severity="high",
        source="core-authored",
        output_marker=marker,
        secret_canary=canary,
        attack_technique=technique,
        holdout=holdout,
    )


# --------------------------------------------------------------------------- #
# A — corpus_coverage: fixed shape, four axes, NO total %
# --------------------------------------------------------------------------- #


def test_coverage_shape_and_axes():
    by_dir = {
        "llm01": [
            _case("llm01.direct.a.1", technique="a", marker="ZZ"),
            _case("llm01.direct.b.2", technique="b"),
        ],
        "llm02": [
            _case("llm02.x.c.1", owasp="LLM02", technique="c", canary="SEK"),
            _case(
                "llm02.benign.1",
                owasp="LLM02",
                attack_class="benign_control",
                technique="",
            ),
        ],
    }
    cov = corpus_coverage(by_dir)
    assert cov["corpus_sha"].startswith("sha256:")
    assert cov["case_count"] == {"attack": 3, "benign": 1}
    # ① present/absent LISTS — never a 6/10 ratio
    assert cov["category_coverage"]["present"] == ["LLM01", "LLM02"]
    assert "LLM03" in cov["category_coverage"]["absent"]
    assert (
        "total_coverage" not in cov and "coverage_pct" not in cov
    )  # §1: no rolled-up %
    # ② distinct technique COUNT + names (benign 'c'? no — benign excluded, empty technique)
    assert cov["technique_coverage"]["count"] == 3
    assert cov["technique_coverage"]["names"] == ["a", "b", "c"]
    assert cov["technique_coverage"]["by_corpus"]["llm01"] == ["a", "b"]
    # ③ observable over ATTACK cases only
    assert cov["outcome_observable"]["observable"] == 2  # a (marker) + c (canary)
    assert cov["outcome_observable"]["total"] == 3
    assert cov["outcome_observable"]["by_corpus"]["llm02"] == [1, 1]
    # ④ hold-out over ALL cases
    assert cov["holdout"] == {"holdout": 0, "total": 4}


def test_technique_shared_across_corpora_counts_once_globally():
    """A technique with the SAME name in two corpora (same defence ⇒ one technique, §4.2.4) counts
    once in the global count and appears in BOTH by_corpus lists."""
    by_dir = {
        "llm01_prompt_injection": [
            _case("a.tool_result_poison.1", technique="tool_result_poison")
        ],
        "llm01_wire_indirect": [
            _case("b.tool_result_poison.2", technique="tool_result_poison")
        ],
    }
    cov = corpus_coverage(by_dir)
    assert cov["technique_coverage"]["count"] == 1
    assert cov["technique_coverage"]["names"] == ["tool_result_poison"]


def test_occupancy_is_per_corpus_technique_share():
    by_dir = {
        "d": [
            _case("d.a.1", technique="a"),
            _case("d.a.2", technique="a"),
            _case("d.b.3", technique="b"),
            _case("d.c.4", technique="c"),
        ]
    }
    occ = corpus_coverage(by_dir)["occupancy"]["d"]
    assert occ["a"] == 0.5 and occ["b"] == 0.25 and occ["c"] == 0.25


# --------------------------------------------------------------------------- #
# C rule 1 / 1b — single-technique domination (on attack_technique, not attack_class)
# --------------------------------------------------------------------------- #


def _n(dir_, count, technique, **kw):
    return [
        _case(f"{dir_}.{technique}.{i}", technique=technique, **kw)
        for i in range(count)
    ]


def test_rule1_share_above_20pct_fails():
    # 3 of 'x' out of 10 = 30% > 20% ⇒ rule1
    cases = _n("d", 3, "x") + _n("d", 7, "y")  # y appears 7× too → also >20%
    (viol) = check_occupancy({"d": cases})
    rules = {v.rule for v in viol}
    assert "rule1" in rules
    assert any("30%" in v.detail for v in viol if v.rule == "rule1")


def test_rule1_exactly_20pct_passes():
    # 2 of 'x' out of 10 = 20% (inclusive) — must PASS; every technique ≤ 2/10
    cases = (
        _n("d", 2, "a")
        + _n("d", 2, "b")
        + _n("d", 2, "c")
        + _n("d", 2, "e")
        + _n("d", 2, "f")
    )
    assert check_occupancy({"d": cases}) == []


def test_rule1b_small_corpus_uses_count_cap_not_share():
    # n=3 corpus: 1/3 = 33% would FAIL a share gate, but the small-corpus rule caps at ≤2 COUNT ⇒ pass
    assert (
        check_occupancy({"d": _n("d", 1, "a") + _n("d", 1, "b") + _n("d", 1, "c")})
        == []
    )
    # 3 of the same technique in a small corpus DOES violate the count cap
    viol = check_occupancy({"d": _n("d", 3, "a")})
    assert [v.rule for v in viol] == ["rule1b"]


# --------------------------------------------------------------------------- #
# C rule 2 — the headline teeth: new cases MUST bring new coverage
# --------------------------------------------------------------------------- #


def test_rule2_teeth_thirty_cases_one_technique_fails():
    """§7 带牙: a 30-case batch all on ONE technique ⇒ rule 2 FAIL, message says how short."""
    added = {"d": _n("d", 30, "same_old", marker="ZZ")}
    viol = check_new_coverage(added, old_techniques_by_dir={})
    rule2 = [v for v in viol if v.rule == "rule2"]
    assert rule2 and "need ≥ 10" in rule2[0].detail
    assert "30 new attack case(s) brought only 1 new technique" in rule2[0].detail


def test_rule2_thirty_cases_ten_new_techniques_passes():
    added = {"d": [c for i in range(10) for c in _n("d", 3, f"t{i}", marker="ZZ")]}
    assert [v for v in check_new_coverage(added, {}) if v.rule == "rule2"] == []


def test_rule2_technique_already_in_baseline_is_not_new():
    """A batch reusing an EXISTING technique earns no new-coverage credit — that is the point."""
    added = {"d": _n("d", 6, "t_old", marker="ZZ") + _n("d", 6, "t_new", marker="ZZ")}
    # only t_new is new (t_old is in the baseline) ⇒ 12 cases, 1 new technique ⇒ need ≥ 4 ⇒ FAIL
    viol = [v for v in check_new_coverage(added, {"d": {"t_old"}}) if v.rule == "rule2"]
    assert viol and "1 new technique" in viol[0].detail


# --------------------------------------------------------------------------- #
# C rule 3 — attack cases carry a technique; new cases are observable
# --------------------------------------------------------------------------- #


def test_rule3_empty_technique_on_attack_case_fails():
    cases = [
        _case("d.x.1", technique=""),
        _case("d.b.benign", attack_class="benign_x", technique=""),
    ]
    viol = check_attack_metadata({"d": cases})
    assert [v.rule for v in viol] == ["rule3-empty"]  # benign one is exempt
    assert "d.x.1" in viol[0].detail


def test_rule3_new_batch_below_80pct_observable_fails():
    # 10 new attack cases, only 5 observable = 50% < 80% ⇒ rule3-observable
    added = {
        "d": _n("d", 5, "a", marker="ZZ")
        + [_case(f"d.b.{i}", technique=f"b{i}") for i in range(5)]
    }
    viol = [v for v in check_new_coverage(added, {}) if v.rule == "rule3-observable"]
    assert viol and "50%" in viol[0].detail


def test_rule3_new_batch_all_observable_passes():
    added = {"d": [c for i in range(10) for c in _n("d", 1, f"t{i}", marker="ZZ")]}
    assert [
        v for v in check_new_coverage(added, {}) if v.rule == "rule3-observable"
    ] == []
