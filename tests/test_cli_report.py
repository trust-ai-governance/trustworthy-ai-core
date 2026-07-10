"""EV-8 — the pure `report` path: json/human/csv rendering, determinism, honest
partial-bundle handling, and exit codes."""

from __future__ import annotations

import json
from pathlib import Path

from treval.cli.main import EXIT_GRADING, EXIT_IO, EXIT_OK, main, run_report

_ROOT = Path(__file__).resolve().parents[1]
_POSTURE_SAMPLE = _ROOT / "docs" / "posture.sample.yaml"


def _bundle_doc(measurements, *, tenant_id="__eval__", window=(1000, 2000)):
    return {
        "schema_version": 1,
        "tenant_id": tenant_id,
        "window": list(window),
        "mode": "active",
        "measurements": measurements,
    }


def _measurement(
    indicator_id, dimension, value, *, sample_size=10, integrity="verified"
):
    return {
        "indicator_id": indicator_id,
        "dimension": dimension,
        "value": value,
        "unit": "ratio",
        "sample_size": sample_size,
        "subject": "",
        "notes": "",
        "integrity": integrity,
        "evidence_refs": [],
    }


def _write(tmp_path, doc, name="bundle.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def _injection_met_bundle(tmp_path):
    doc = _bundle_doc(
        [_measurement("injection_catch_rate", "robustness", 0.9, sample_size=34)]
    )
    return _write(tmp_path, doc)


# --------------------------------------------------------------------------- #
# json — schema + determinism + the min gate
# --------------------------------------------------------------------------- #


def test_report_json_is_valid_and_min_gated(tmp_path):
    bundle = _injection_met_bundle(tmp_path)
    text, _ = run_report(bundle, _POSTURE_SAMPLE, "json")
    doc = json.loads(text)
    assert doc["schema_version"] == 1
    rob = next(d for d in doc["report"]["dimensions"] if d["dimension"] == "robustness")
    # injection met → measured L2; posture sample attests robustness L3 → gap at L3, awarded L2.
    assert rob["measured_ceiling"] == "L2"
    assert rob["attested_ceiling"] == "L3"
    assert rob["awarded_level"] == "L2"
    assert "rob.l3.standardized_suite" in rob["gaps"]


def test_report_json_is_byte_identical(tmp_path):
    bundle = _injection_met_bundle(tmp_path)
    a, _ = run_report(bundle, _POSTURE_SAMPLE, "json")
    b, _ = run_report(bundle, _POSTURE_SAMPLE, "json")
    assert a == b


# --------------------------------------------------------------------------- #
# human — the four sections, grid-first
# --------------------------------------------------------------------------- #


def test_report_human_has_grid_gap_detail_appendix(tmp_path):
    bundle = _injection_met_bundle(tmp_path)
    text, _ = run_report(bundle, _POSTURE_SAMPLE, "human", color=False)
    assert "maturity grid" in text
    assert "legend:" in text
    assert "over-claim gaps" in text
    assert "dimension detail" in text
    assert "appendix" in text
    # the flagship over-claim is named; a NotMeasured dimension is tagged
    assert "rob.l3.standardized_suite" in text
    assert "(NotMeasured)" in text  # e.g. transparency has zero collected measured data
    # the measured value is shown in the detail
    assert "injection_catch_rate=0.90" in text


def test_report_human_no_ansi_when_color_false(tmp_path):
    bundle = _injection_met_bundle(tmp_path)
    text, _ = run_report(bundle, _POSTURE_SAMPLE, "human", color=False)
    assert "\033[" not in text  # no escape codes in the non-TTY / piped form


# --------------------------------------------------------------------------- #
# csv — flat per-objective rows
# --------------------------------------------------------------------------- #


def test_report_csv_header_and_rows(tmp_path):
    bundle = _injection_met_bundle(tmp_path)
    text, _ = run_report(bundle, _POSTURE_SAMPLE, "csv")
    lines = text.splitlines()
    assert (
        lines[0]
        == "dimension,level,objective_id,kind,status,indicator_id,value,integrity"
    )
    row = next(r for r in lines if "rob.l2.injection_rule_detection" in r)
    assert (
        "measured" in row
        and "met" in row
        and "injection_catch_rate" in row
        and "verified" in row
    )


# --------------------------------------------------------------------------- #
# §5 — partial / empty bundle renders honestly, never crashes
# --------------------------------------------------------------------------- #


def test_empty_bundle_renders_all_not_measured(tmp_path):
    bundle = _write(tmp_path, _bundle_doc([]))
    text, warnings = run_report(bundle, _POSTURE_SAMPLE, "json")
    doc = json.loads(text)
    for dim in doc["report"]["dimensions"]:
        assert dim["measured_ceiling"] is None  # nothing measured anywhere
    assert any("no measurements" in w for w in warnings)


def test_no_posture_warns_and_grades(tmp_path):
    bundle = _injection_met_bundle(tmp_path)
    text, warnings = run_report(bundle, None, "json")
    doc = json.loads(text)
    rob = next(d for d in doc["report"]["dimensions"] if d["dimension"] == "robustness")
    assert rob["attested_ceiling"] is None  # no posture → attested all unmet
    assert any("no --posture" in w for w in warnings)


# --------------------------------------------------------------------------- #
# main() argv wiring + exit codes (mirrors wal_verify: 0 / 2 / 3)
# --------------------------------------------------------------------------- #


def test_main_report_ok(tmp_path, capsys):
    bundle = _injection_met_bundle(tmp_path)
    rc = main(["report", "--measurement-bundle", str(bundle), "--format", "json"])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert json.loads(out)["schema_version"] == 1


def test_main_bad_bundle_path_is_io_error(capsys):
    rc = main(
        ["report", "--measurement-bundle", "/no/such/bundle.json", "--format", "json"]
    )
    assert rc == EXIT_IO
    assert "error:" in capsys.readouterr().err


def test_main_duplicate_aggregate_id_is_grading_error(tmp_path, capsys):
    doc = _bundle_doc(
        [
            _measurement("injection_catch_rate", "robustness", 0.9),
            _measurement("injection_catch_rate", "robustness", 0.1),  # dup aggregate id
        ]
    )
    bundle = _write(tmp_path, doc)
    rc = main(["report", "--measurement-bundle", str(bundle), "--format", "json"])
    assert rc == EXIT_GRADING
    assert "ambiguous" in capsys.readouterr().err


def test_main_writes_out_file(tmp_path, capsys):
    bundle = _injection_met_bundle(tmp_path)
    out = tmp_path / "report.json"
    rc = main(
        [
            "report",
            "--measurement-bundle",
            str(bundle),
            "--format",
            "json",
            "--out",
            str(out),
        ]
    )
    assert rc == EXIT_OK
    assert json.loads(out.read_text())["schema_version"] == 1
