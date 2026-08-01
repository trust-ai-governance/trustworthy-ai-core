"""EV-COVERAGE §4.3-B — the `coverage` CLI: json is corpus_coverage() verbatim; human frames the
four axes with corpus_sha at the top and lists what is ABSENT (never a single rolled-up score)."""

from __future__ import annotations

import json

from treval.cli.main import main


def test_coverage_json_is_the_vector_with_corpus_sha(capsys):
    rc = main(["coverage", "--format", "json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["corpus_sha"].startswith("sha256:")
    # the four axes are all present and framed with the sha (§1 disclosure discipline)
    for axis in (
        "category_coverage",
        "technique_coverage",
        "outcome_observable",
        "holdout",
    ):
        assert axis in doc
    assert doc["category_coverage"]["present"] and doc["category_coverage"]["absent"]
    # 🔴 no rolled-up total-coverage percentage (§1)
    assert "total_coverage" not in doc and "coverage_pct" not in doc


def test_coverage_human_lists_absent_and_frames_sha(capsys):
    rc = main(["coverage"])  # human is the default
    assert rc == 0
    out = capsys.readouterr().out
    assert "corpus_sha sha256:" in out.splitlines()[0]  # sha at the TOP
    assert "① category coverage" in out and "absent" in out
    assert "② technique coverage" in out and "NOT a %" in out
    assert "③ outcome-observable" in out and "④ hold-out" in out
