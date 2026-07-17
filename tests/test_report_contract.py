"""EV-R1 — the report JSON contract: a drift-guard (fixtures ↔ the real serializer) + the
formal draft-07 schema (every valid/ fixture passes, every invalid/ fixture fails).

A change to MaturityReport/Measurement/the serializer/the shipped registry that would break
the UI contract fails the drift-guard here. Regenerate a PLANNED change with UPDATE_FIXTURES=1.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from _report_fixtures import generate

_ROOT = Path(__file__).resolve().parents[1]
_VALID = _ROOT / "tests" / "fixtures" / "report" / "valid"
_INVALID = _ROOT / "tests" / "fixtures" / "report" / "invalid"
_SCHEMA_PATH = _ROOT / "docs" / "report.schema.json"


def _schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Drift-guard (D2): committed fixtures are byte-identical to the serializer output.
# --------------------------------------------------------------------------- #


def test_valid_fixtures_match_the_real_serializer():
    generated = generate()
    if os.environ.get("UPDATE_FIXTURES") == "1":
        _VALID.mkdir(parents=True, exist_ok=True)
        for name, js in generated.items():
            (_VALID / f"{name}.json").write_text(js, encoding="utf-8")

    committed = {p.stem: p.read_text(encoding="utf-8") for p in _VALID.glob("*.json")}
    assert set(committed) == set(generated), (
        "fixture set drifted (a scenario was added/removed) — "
        "regenerate with UPDATE_FIXTURES=1"
    )
    for name, expected in generated.items():
        assert committed[name] == expected, (
            f"fixture {name}.json drifted from the serializer — the UI contract changed; "
            "regenerate with UPDATE_FIXTURES=1 and review the diff"
        )


def test_expected_scenarios_present():
    assert set(generate()) == {
        "rich",
        "all_not_measured",
        "over_claim_gaps",
        "insufficient_data",
        "verification_basis",
        "per_subject",
    }


# --------------------------------------------------------------------------- #
# Schema (D4): the formal contract enforces both directions.
# --------------------------------------------------------------------------- #


def test_schema_is_valid_draft07():
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.Draft7Validator.check_schema(_schema())


@pytest.mark.parametrize("path", sorted(_VALID.glob("*.json")), ids=lambda p: p.name)
def test_valid_fixture_passes_schema(path):
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.validate(json.loads(path.read_text(encoding="utf-8")), _schema())


@pytest.mark.parametrize("path", sorted(_INVALID.glob("*.json")), ids=lambda p: p.name)
def test_invalid_fixture_fails_schema(path):
    jsonschema = pytest.importorskip("jsonschema")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(json.loads(path.read_text(encoding="utf-8")), _schema())


def test_fixtures_are_non_empty():
    # guards against the parametrized schema tests silently collecting zero cases.
    assert len(list(_VALID.glob("*.json"))) == 6
    assert len(list(_INVALID.glob("*.json"))) >= 2


# --------------------------------------------------------------------------- #
# The join rule (D1) is renderable from the bundle alone: objective_id →
# registry indicator_id → measurement value (what the UI does, no live engine).
# --------------------------------------------------------------------------- #


def test_registry_fingerprint_matches_the_inlined_bundle():
    # EV-W1 recomputes registry_fingerprint(loaded_registry) and compares to the bundle's
    # field; the standalone helper MUST agree with the value the bundle inlines.
    from treval import load_registry, registry_fingerprint

    bundle = json.loads((_VALID / "rich.json").read_text(encoding="utf-8"))
    fp = registry_fingerprint(load_registry())
    assert fp.startswith("sha256:") and len(fp) == len("sha256:") + 64
    assert fp == bundle["registry_fingerprint"]


def test_value_join_works_from_the_bundle_alone():
    bundle = json.loads((_VALID / "rich.json").read_text(encoding="utf-8"))
    # objective_id → indicator_id, from the inlined registry
    obj_to_indicator = {
        o["id"]: o["indicator_id"]
        for dim in bundle["registry"]["dimensions"]
        for objs in dim["levels"].values()
        for o in objs
    }
    # indicator_id → aggregate measurement value
    agg = {
        m["indicator_id"]: m["value"]
        for m in bundle["measurements"]
        if m["subject"] == ""
    }
    ind = obj_to_indicator["rob.l2.injection_rule_detection"]
    assert ind == "injection_catch_rate"
    assert agg[ind] == 0.92  # the grid's value column resolves from the file alone
