"""GATE-CONSISTENCY 件二 — the threshold-registry gate. The shipped table passes; the teeth: an empty
authoritative location FAILs (rule 1), a value shared with a blank scope WARNs (rule 2, the 'two
0.80s' trap), and a registry threshold missing from the table FAILs (rule 3, the '0.05 in prose' trap).
"""

from __future__ import annotations

import tools.check_thresholds as gate
from tools.check_thresholds import (
    Threshold,
    check_rule1_locations,
    check_rule2_shared_values,
    check_rule3_unregistered,
    parse_table,
)
from treval.registry import load_registry


def test_shipped_table_passes_clean():
    fails, warns = gate.run()
    assert fails == [] and warns == []  # 🔴 the real registry + table are consistent


def test_table_parses_the_expected_thresholds():
    regs = parse_table(gate._TABLE.read_text(encoding="utf-8"))
    names = {t.name for t in regs}
    assert {"τ_recall", "τ_fpr", "θ_benign_floor", "max_technique_share"} <= names
    assert next(t for t in regs if t.name == "τ_recall").value == 0.80


def test_rule1_teeth_empty_or_wrong_location_fails_naming_it():
    reg = load_registry()
    # 🔴 带牙一: the objective exists but its threshold ≠ the table value (someone edited one, not both)
    wrong = Threshold(
        "τ_recall", 0.99, "registry:rob.l2.injection_rule_detection", "recall"
    )
    (p,) = [x for x in check_rule1_locations([wrong], reg) if x[0] == "rule1"]
    assert "0.8" in p[2] and "0.99" in p[2]
    # a location pointing at a NON-existent objective = an empty location ⇒ FAIL
    gone = Threshold("τ_ghost", 0.5, "registry:rob.l2.does_not_exist", "x")
    assert any(
        "no measured satisfied_when" in why
        for _r, _n, why in check_rule1_locations([gone], reg)
    )
    # a const location whose value drifted ⇒ FAIL
    drift = Threshold(
        "max_technique_share",
        0.99,
        "const:treval.active_eval.coverage:MAX_TECHNIQUE_SHARE",
        "x",
    )
    assert any("0.99" in why for _r, _n, why in check_rule1_locations([drift], reg))


def test_rule1_correct_location_is_clean():
    reg = load_registry()
    ok = Threshold(
        "τ_recall", 0.80, "registry:rob.l2.injection_rule_detection", "recall"
    )
    assert check_rule1_locations([ok], reg) == []


def test_rule2_teeth_shared_value_with_blank_scope_warns_naming_both():
    # 🔴 带牙二: two names on one value, one scope BLANK ⇒ WARN naming both (the two-0.80s trap)
    a = Threshold("τ_recall", 0.80, "registry:x", "injection recall")
    b = Threshold("τ_mystery", 0.80, "const:m:N", "")  # blank scope
    (w,) = check_rule2_shared_values([a, b])
    assert w[0] == "rule2" and "τ_recall" in w[1] and "τ_mystery" in w[1]
    # both scopes filled ⇒ acknowledged, no warn (the shipped 0.8 trio is like this)
    b_named = Threshold("τ_mystery", 0.80, "const:m:N", "a different axis")
    assert check_rule2_shared_values([a, b_named]) == []


def test_rule3_teeth_unregistered_registry_threshold_fails():
    reg = load_registry()
    # a registry that carries 0.80/0.05/… but a table that registered NONE of them ⇒ every measured
    # quality/volume threshold is unregistered ⇒ rule 3 flags them, naming the objective.
    problems = check_rule3_unregistered([], reg)
    assert problems, "rule 3 must flag registry thresholds absent from the table"
    assert any(p[1] == "rob.l2.injection_rule_detection" for p in problems)
    assert all(p[0] == "rule3" for p in problems)


def test_rule3_registered_values_are_clean():
    reg = load_registry()
    regs = parse_table(gate._TABLE.read_text(encoding="utf-8"))
    assert (
        check_rule3_unregistered(regs, reg) == []
    )  # the shipped values are all registered
