"""EV-COVERAGE §4.3-C — the corpus-coverage GATE tool (git + IO wiring around the pure rule checkers).
The rule MATH is covered in test_coverage.py; here we prove the tool passes on the shipped corpus and
that a violation is reported in the disclosure-gate shape (corpus / rule / detail) with exit 1."""

from __future__ import annotations

import tools.check_corpus_coverage as gate
from treval.active_eval.coverage import Violation


def test_gate_passes_on_shipped_corpus_structural_rules(monkeypatch):
    """§4.4: after the E0 backfill, llm01's single-technique share is 3.6% ⇒ the structural rules
    (1/1b/3-empty) pass on the shipped corpus. We stub the git baseline to empty so this asserts the
    corpus content, not the working tree's uncommitted additions."""
    monkeypatch.setattr(gate, "_added_case_paths", lambda base: set())
    assert gate.collect_violations("HEAD") == []


def test_gate_reports_violation_and_exits_1(monkeypatch, capsys):
    """The tool's output contract: FAIL banner + `[rule] corpus/<dir>: why` + detail, exit 1 — the
    same shape as tools/check_doc_disclosure.py so one mental model covers both gates."""
    fake = Violation(
        "rule2", "llm01_prompt_injection", "new techniques ≥ new cases ÷ 3", "30 → 1"
    )
    monkeypatch.setattr(gate, "collect_violations", lambda base: [fake])
    rc = gate.main([])
    assert rc == 1
    err = capsys.readouterr().err
    assert "FAIL" in err
    assert "[rule2] corpus/llm01_prompt_injection:" in err and "30 → 1" in err


def test_gate_passes_when_no_violations(monkeypatch, capsys):
    monkeypatch.setattr(gate, "collect_violations", lambda base: [])
    assert gate.main([]) == 0
    assert "PASS" in capsys.readouterr().out
