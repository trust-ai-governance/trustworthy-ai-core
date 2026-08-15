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


def test_full_scan_benign_pii_wired_and_shipped_corpus_clean(monkeypatch):
    """E3 wiring + SCOPING: with NO git-added cases, collect_violations is empty — which means the
    benign-PII rule (§2.2.1, FULL scan) found the shipped benign corpus PII-free (zero legacy debt),
    AND the new-batch rules (source diversity §5.2, benign scene §5.3) are no-ops ⇒ no day-one red."""
    monkeypatch.setattr(gate, "_added_case_paths", lambda base: set())
    assert gate.collect_violations("HEAD") == []


def test_new_batch_wiring_source_diversity_and_benign_scene(monkeypatch):
    """Wiring + SCOPING proof: mark one existing attack case and one existing benign case as git-ADDED.
    The pooled attack batch is then single-source core-authored ⇒ source-external-native reds; the
    added benign case has no `scene` ⇒ benign-scene reds. The SAME cases red nothing when they are not
    git-added (previous test) — that scoping is exactly what avoids a day-one red on the legacy corpus."""
    by_dir, path_by_id = gate._load_tree()
    attack_id = next(
        c.id
        for cases in by_dir.values()
        for c in cases
        if not gate.is_benign(c) and c.attack_technique
    )
    benign_id = next(
        c.id
        for cases in by_dir.values()
        for c in cases
        if gate.is_benign(c)
        and not c.scene  # a scene-LESS benign ⇒ benign-scene reds when git-added
    )
    added = {
        path_by_id[attack_id].relative_to(gate._ROOT).as_posix(),
        path_by_id[benign_id].relative_to(gate._ROOT).as_posix(),
    }
    monkeypatch.setattr(gate, "_added_case_paths", lambda base: added)
    rules = {v.rule for v in gate.collect_violations("HEAD")}
    assert (
        "source-external-native" in rules
    )  # single-source added attack batch, none external
    assert "benign-scene" in rules  # the added benign case declares no scene


# --------------------------------------------------------------------------- #
# E3-j — the three FULL-scan standing doors + green-day-one on the shipped corpus
# --------------------------------------------------------------------------- #

from treval.active_eval.corpus import CorpusCase  # noqa: E402 — test helper import


def _mini(cid, **kw):
    base = dict(
        id=cid,
        owasp="LLM01",
        dimension="robustness",
        attack_class="direct",
        input="hello",
        success_when="blocked_or_flagged",
        severity="high",
        source="core-authored",
        attack_technique="t_" + cid,
    )
    base.update(kw)
    return CorpusCase(**base)


def test_e3j_full_scan_doors_are_wired(monkeypatch):
    """The three E3-j FULL-scan doors are wired into collect_violations. RED inputs, one per door: a
    reject-source (advbench) case, a payload-neutralized case with no pre-swap hash, and a case with
    real (non-placeholder) PII. `_load_tree` is stubbed with a crafted tree; git-added is empty."""
    tree = {
        "d": [
            _mini("a1", source="advbench:hb-001"),
            _mini("a2", source="promptfoo:p@v1 (payload-neutralized)"),
            _mini("a3", input="reach me at real.person@gmail.com"),
        ]
    }
    path_by_id = {
        c.id: gate._ROOT / "corpus" / "d" / f"{c.id}.yaml"
        for cs in tree.values()
        for c in cs
    }
    monkeypatch.setattr(gate, "_load_tree", lambda: (tree, path_by_id))
    monkeypatch.setattr(gate, "_added_case_paths", lambda base: set())
    rules = {v.rule for v in gate.collect_violations("HEAD")}
    assert {"reject-source", "payload-neutralized-hash", "corpus-pii-egress"} <= rules


def test_e3j_standing_doors_green_on_shipped_corpus(monkeypatch):
    """🔴 Green-day-one: on the real corpus (all core-authored; the only PII is the RFC-2606 placeholder
    attacker@evil.example) the four E3-j doors fire NOTHING — if any did, the door would get turned off.
    This is the standing-door contract: green until the relevant case actually arrives."""
    monkeypatch.setattr(gate, "_added_case_paths", lambda base: set())
    rules = {v.rule for v in gate.collect_violations("HEAD")}
    assert not (
        rules
        & {
            "reject-source",
            "payload-neutralized-hash",
            "payload-neutralized-ratio",
            "corpus-pii-egress",
        }
    )
