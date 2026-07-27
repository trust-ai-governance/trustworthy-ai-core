"""I3 file-grouped verdict intake — the real-corpus shape (I3-MULTIFILE-INTAKE §7).

One verdict file per group; benign-vs-violating rides FILE MEMBERSHIP, case ids are namespaced
`{group}:{line}`, and the repeat transpose (hence the warmup drop) is preserved. Runs against
`tests/fixtures/i3/groups/` — real recorded judge scores, anonymized classes, repeats numbered
from 1 (see that directory's README for exactly what was re-arranged).
"""

from __future__ import annotations

import json
import os

import pytest

from treval.active_eval import (
    VerdictError,
    first_vendor_label_score,
    load_verdict_groups,
    preflight_verdict_groups,
    roc_curve,
    score_stability,
)
from treval.active_eval.corpus import CorpusCase
from treval.active_eval.i3_run import main as i3_main

_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "i3", "groups")
_GROUPS = {
    "violating": os.path.join(_DIR, "violating.jsonl"),
    "benign": os.path.join(_DIR, "benign.jsonl"),
    "benign_meta": os.path.join(_DIR, "benign_meta.jsonl"),
}
_REPEATS = 7  # each line is recorded 7 times (numbered 1..7)


def _case(cid: str, content_class: str) -> CorpusCase:
    return CorpusCase(
        id=cid,
        owasp="LLM01",
        dimension="robustness",
        attack_class="content",
        input="",
        success_when="blocked_or_flagged",
        severity="high",
        source="i3-verdicts",
        content_class=content_class,
    )


def _write(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return str(path)


def _row(line, repeat, score, *, contract="violate", content_class="topic_A"):
    return {
        "score": score,
        "content_class": content_class,
        "contract": contract,
        "model": "m",
        "quant": "Q",
        "load_duration_ns": 1,
        "reload_contaminated": False,
        "line": line,
        "repeat": repeat,
    }


# --- §7-1: grouping, namespacing, sides, per-case content_class ------------------------ #


def test_groups_load_with_namespaced_case_ids_and_union_benign_side():
    runs, sides, cc = load_verdict_groups(_GROUPS)

    # case ids are group-namespaced — note line 1 exists in ALL THREE files and must not collide
    assert sides["violating"] == ["violating:1"]
    assert sides["benign"] == ["benign:1", "benign:2", "benign_meta:1"]  # benign ∪ meta
    assert len(set(sides["benign"]) & set(sides["violating"])) == 0

    # every case carries its own content_class
    assert cc == {
        "violating:1": "topic_A",
        "benign:1": "topic_A",
        "benign:2": "topic_B",
        "benign_meta:1": "topic_B",
    }
    # 4 cases × 7 repeats, transposed into 7 passes of 4
    assert len(runs) == _REPEATS
    assert [len(r) for r in runs] == [4] * _REPEATS


def test_line_numbers_collide_across_files_but_cases_do_not():
    # The concrete collision the namespace exists for: "1" is a line in all three groups.
    _runs, sides, _cc = load_verdict_groups(_GROUPS)
    all_ids = sides["benign"] + sides["violating"]
    assert len(all_ids) == len(set(all_ids)) == 4
    assert {"benign:1", "benign_meta:1", "violating:1"} <= set(all_ids)


# --- §7-2 / §7-6: transpose preserved ⇒ warmup drop still load-bearing ----------------- #


def test_transpose_preserved_and_warmup_drop_is_load_bearing():
    runs, _sides, _cc = load_verdict_groups(_GROUPS)
    rep = score_stability(runs, score_of=first_vendor_label_score)
    assert rep.deterministic_fraction == 1.0
    assert rep.max_variance == 0.0
    assert rep.curve_eligible is True
    assert rep.warmup_dropped == 4  # the whole first pass = one sample per case

    # §7-6 sample budget: n_used == repeats − 1, with repeats numbered from 1
    for cs in rep.per_case.values():
        assert len(cs.scores) == _REPEATS - 1 == 6

    # teeth: KEEP the first pass and the run reads as non-deterministic (the violating case's
    # real cold repeat differs from its warm ones by ~1e-8).
    kept = score_stability([runs[0]] + runs, score_of=first_vendor_label_score)
    assert kept.deterministic_fraction < 1.0
    assert kept.curve_eligible is False


def test_runs_zero_is_the_lowest_repeat_of_every_group():
    runs, _sides, _cc = load_verdict_groups(_GROUPS)
    # repeats are numbered 1..7 here; runs[0] is the lowest (1) for EVERY case, not one file's
    assert {pr.request_id.rsplit("R", 1)[1] for pr in runs[0]} == {"1"}
    assert {pr.case_id for pr in runs[0]} == {
        "violating:1",
        "benign:1",
        "benign:2",
        "benign_meta:1",
    }


# --- §7-3: the two-sided curve split comes from file membership ------------------------ #


def test_roc_curve_split_uses_groups_and_excludes_one_sided_class():
    runs, sides, cc = load_verdict_groups(_GROUPS)
    stability = score_stability(runs, score_of=first_vendor_label_score)
    benign = [_case(c, cc[c]) for c in sides["benign"]]
    violating = [_case(c, cc[c]) for c in sides["violating"]]
    curve = roc_curve(
        benign, violating, runs[1], stability, score_of=first_vendor_label_score
    )

    assert curve.points is not None  # curve_eligible ⇒ curve emitted
    # topic_A has both sides (violating:1 + benign:1) ⇒ a curve.
    # topic_B is benign-only (benign:2 + benign_meta:1) ⇒ NO curve (would be a fake 0% FPR),
    # but it still surfaces in the measurable counts.
    assert set(curve.by_class) == {"topic_A"}
    assert curve.measurable["topic_B"] == (0, 2)  # 0 violating, 2 benign
    assert curve.measurable["topic_A"] == (1, 1)
    # clean separation on the real scores ⇒ full recall at a matched FPR
    assert curve.recall_at_fpr(0.05) == (1.0, 1.0, 1.0)


# --- §7-5: one contract per load — fail loud, never fake non-determinism --------------- #


def test_mixed_contract_under_one_case_raises(tmp_path):
    mixed = _write(
        tmp_path / "violating.jsonl",
        [
            _row(1, r, 0.9, contract="violate" if r <= 3 else "safe")
            for r in range(1, 7)
        ],
    )
    with pytest.raises(VerdictError, match="more than one contract"):
        load_verdict_groups({"violating": mixed})


def test_mixed_contract_would_otherwise_read_as_fake_non_determinism(tmp_path):
    # Teeth for the guard above: the SAME rows, loaded as two separate single-contract files,
    # are each deterministic — but concatenated under one case id they span two distributions
    # and would silently report deterministic_fraction=0.0 / curve_eligible=False. The guard
    # must raise instead of letting that fake number out.
    a = _write(
        tmp_path / "violate.jsonl",
        [_row(1, r, 0.90, contract="violate") for r in range(1, 8)],
    )
    b = _write(
        tmp_path / "safe.jsonl",
        [_row(1, r, 0.20, contract="safe") for r in range(1, 8)],
    )
    for path in (a, b):
        runs, _s, _c = load_verdict_groups({"violating": path})
        assert score_stability(runs, score_of=first_vendor_label_score).curve_eligible

    merged_rows = [json.loads(x) for x in open(a, encoding="utf-8")]
    merged_rows += [json.loads(x) for x in open(b, encoding="utf-8")]
    merged = _write(tmp_path / "merged.jsonl", merged_rows)
    with pytest.raises(VerdictError, match="more than one contract"):
        load_verdict_groups({"violating": merged})


# --- fail-loud on the other ways the drop/sides would go silently wrong ---------------- #


def test_groups_starting_at_different_repeat_numbers_raise(tmp_path):
    # The drop is by POSITION, so a group starting at 1 while another starts at 0 would keep
    # its own cold pass while the other's is dropped — a non-uniform warmup drop.
    v = _write(tmp_path / "v.jsonl", [_row(1, r, 0.9) for r in range(0, 7)])
    b = _write(tmp_path / "b.jsonl", [_row(1, r, 0.1) for r in range(1, 8)])
    with pytest.raises(VerdictError, match="different repeat numbers"):
        load_verdict_groups({"violating": v, "benign": b})


def test_unknown_group_name_raises(tmp_path):
    p = _write(tmp_path / "x.jsonl", [_row(1, 1, 0.5)])
    with pytest.raises(VerdictError, match="unknown verdict group"):
        load_verdict_groups(
            {"bening": p}
        )  # typo — must not silently vanish from a side


def test_malformed_row_is_fatal(tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"line": 1, "repeat": 1}\nnot json\n', encoding="utf-8")
    with pytest.raises(VerdictError, match="not valid JSON"):
        load_verdict_groups({"benign": str(p)})


# --- §7-4: --dry-run is verdict-level only, no scoring --------------------------------- #


def test_preflight_reports_counts_repeats_classes_and_parse_errors(tmp_path):
    report = preflight_verdict_groups(_GROUPS)
    assert report["benign"]["rows"] == 14 and report["benign"]["cases"] == 2
    assert report["benign"]["repeats_by_line"] == {"1": _REPEATS, "2": _REPEATS}
    assert report["benign"]["content_classes"] == {"topic_A": 7, "topic_B": 7}
    assert report["benign"]["contracts"] == ["violate"]
    assert report["benign_meta"]["side"] == "benign"  # meta feeds the benign side
    assert all(not r["parse_errors"] for r in report.values())

    # parse errors are COLLECTED (a pre-check reports what is wrong; it does not abort)
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"line":1,"repeat":1}\nnope\n', encoding="utf-8")
    rep = preflight_verdict_groups({"benign": str(bad)})["benign"]
    assert len(rep["parse_errors"]) == 1 and rep["rows"] == 2


# --- CLI: grouped mode, dry-run, and the single-file form still works ------------------ #


def test_cli_grouped_mode(capsys):
    rc = i3_main(
        [
            "--violating",
            _GROUPS["violating"],
            "--benign",
            _GROUPS["benign"],
            "--benign-meta",
            _GROUPS["benign_meta"],
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "curve_eligible = True" in out
    assert "roc_curve" in out and "recall@FPR" in out


def test_cli_dry_run_does_not_score(capsys):
    rc = i3_main(["--violating", _GROUPS["violating"], "--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "dry-run" in out and "repeats per line" in out
    assert "curve_eligible" not in out  # no metrics were run


def test_cli_single_file_form_still_works(capsys):
    smoke = os.path.join(os.path.dirname(_DIR), "verdicts_smoke.jsonl")
    rc = i3_main(["--verdicts", smoke, "--benign", "1,2", "--violating", "3"])
    out = capsys.readouterr().out
    assert rc == 0 and "curve_eligible = True" in out


def test_cli_requires_some_input(capsys):
    rc = i3_main([])
    assert rc == 3
    assert "error:" in capsys.readouterr().err


def test_cli_reports_verdict_errors_cleanly(tmp_path, capsys):
    p = _write(
        tmp_path / "v.jsonl",
        [
            _row(1, r, 0.9, contract="violate" if r <= 2 else "safe")
            for r in range(1, 5)
        ],
    )
    rc = i3_main(["--violating", p])
    assert rc == 3
    assert "more than one contract" in capsys.readouterr().err


def test_cross_group_contract_mix_raises(tmp_path):
    # Per-case guards do not catch this: two groups can each be internally consistent yet carry
    # different contracts (the real hazard is `verdicts_meta_violate.jsonl` vs
    # `verdicts_meta_safe.jsonl` — one word apart). Pairing a recall read on one contract's
    # scale with an FPR read on another's produces a normal-looking, meaningless curve.
    v = _write(
        tmp_path / "violating.jsonl",
        [_row(1, r, 0.9, contract="violate") for r in range(1, 8)],
    )
    meta_safe = _write(
        tmp_path / "meta_safe.jsonl",
        [_row(1, r, 0.2, contract="safe") for r in range(1, 8)],
    )
    with pytest.raises(VerdictError, match="mixes more than one contract"):
        load_verdict_groups({"violating": v, "benign_meta": meta_safe})


def test_same_contract_across_groups_is_fine(tmp_path):
    v = _write(tmp_path / "v.jsonl", [_row(1, r, 0.9) for r in range(1, 8)])
    b = _write(tmp_path / "b.jsonl", [_row(1, r, 0.1) for r in range(1, 8)])
    runs, sides, _cc = load_verdict_groups({"violating": v, "benign": b})
    assert len(runs) == 7 and sides["violating"] == ["violating:1"]
