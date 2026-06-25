"""Tests for the DimensionRegistry loader + validation (EV-6)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from treval import (
    DimensionRegistry,
    RegistryError,
    load_registry,
    validate_against,
)
from treval.registry.models import (
    ControlObjective,
    Dimension,
    DimensionRegistry as _Reg,
    Evidence,
)

_SAMPLE = Path(__file__).resolve().parents[1] / "docs" / "web" / "registry.sample.json"

# The planned indicator-id set (EVAL_ARCHITECTURE §5 / EV-5 / EV-9 / EV-6 §6).
KNOWN_INDICATOR_IDS = {
    "block_rate",
    "scope_deny_rate",
    "token_cost_per_agent",
    "error_rate",
    "terminal_error_ratio",
    "duration_p99",
    "unclosed_loop_rate",
    "chain_integrity",
    "hint_emission_rate",
    "injection_rule_hit_ratio",
    "boundary_breach_rate",
    "drift_alert_count",
    "redaction_hit_ratio",
    "pii_exposure_surface",
}

_EXPECTED = {
    "robustness",
    "efficient_reliability",
    "security_alignment",
    "transparency_accountability",
    "privacy_data_protection",
}
_LEVELS = ("L1", "L2", "L3", "L4", "L5")


# --------------------------------------------------------------------------- #
# Fixture builders for the malformed-input tests.
# --------------------------------------------------------------------------- #


def _attested_obj(oid):
    return {
        "id": oid,
        "statement_zh": "s",
        "evidence": {"kind": "attested", "posture_key": f"d.{oid}"},
    }


def _dim_doc(dimension="robustness", l2=None):
    return {
        "dimension": dimension,
        "title_en": "T",
        "title_zh": "标题",
        "levels": {
            "L1": {"control_objectives": []},
            "L2": {
                "control_objectives": l2 if l2 is not None else [_attested_obj("a")]
            },
            "L3": {"control_objectives": []},
            "L4": {"control_objectives": []},
            "L5": {"control_objectives": []},
        },
    }


def _write(tmp_path, doc):
    p = tmp_path / f"{doc['dimension']}.yaml"
    p.write_text(yaml.safe_dump(doc, allow_unicode=True), encoding="utf-8")
    return tmp_path


# --------------------------------------------------------------------------- #
# 1 + 4. The shipped 5 YAMLs round-trip; completeness holds.
# --------------------------------------------------------------------------- #


def test_shipped_registry_loads_and_is_complete():
    reg = load_registry()
    assert isinstance(reg, DimensionRegistry)
    assert set(reg.dimensions) == _EXPECTED
    for dim in reg.dimensions.values():
        assert set(dim.levels) == set(_LEVELS)
        assert dim.levels["L1"] == ()  # L1 is explicit N/A everywhere


# --------------------------------------------------------------------------- #
# 5. Cross-reference: shipped YAMLs reference only known indicator ids.
# --------------------------------------------------------------------------- #


def test_shipped_registry_has_no_indicator_typos():
    reg = load_registry()
    assert validate_against(reg, indicator_ids=KNOWN_INDICATOR_IDS) == []


def test_registry_matches_w0_sample():
    """The live registry must agree with the EV-W0 frontend sample on every
    objective's id/statement_zh/kind/indicator_id/posture_key — otherwise the UI
    renders different text than the real GET /api/registry endpoint (F1)."""
    sample = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    sample_by_id = {
        o["id"]: (
            o["statement_zh"],
            o["kind"],
            o.get("indicator_id"),
            o.get("posture_key"),
        )
        for dim in sample["dimensions"]
        for objs in dim["levels"].values()
        for o in objs
    }

    reg = load_registry()
    live_by_id = {
        obj.id: (
            obj.statement_zh,
            obj.evidence.kind,
            obj.evidence.indicator_id,
            obj.evidence.posture_key,
        )
        for dim in reg.dimensions.values()
        for level in _LEVELS
        for obj in dim.levels[level]
    }
    assert live_by_id == sample_by_id


def test_validate_against_catches_indicator_typo():
    reg = _Reg(
        dimensions={
            "robustness": Dimension(
                "robustness",
                "T",
                "t",
                {
                    "L1": (),
                    "L2": (
                        ControlObjective(
                            "x",
                            "s",
                            Evidence("measured", "bogus_indicator", None, "value >= 0"),
                        ),
                    ),
                    "L3": (),
                    "L4": (),
                    "L5": (),
                },
            )
        }
    )
    problems = validate_against(reg, indicator_ids={"block_rate"})
    assert any("bogus_indicator" in p for p in problems)
    # posture_keys check is opt-in.
    assert (
        validate_against(reg, indicator_ids={"bogus_indicator"}, posture_keys=set())
        == []
    )


def test_validate_against_catches_posture_typo():
    reg = _Reg(
        dimensions={
            "robustness": Dimension(
                "robustness",
                "T",
                "t",
                {
                    "L1": (),
                    "L2": (
                        ControlObjective(
                            "x",
                            "s",
                            Evidence("attested", None, "robustness.bogus_key", None),
                        ),
                    ),
                    "L3": (),
                    "L4": (),
                    "L5": (),
                },
            )
        }
    )
    problems = validate_against(
        reg, indicator_ids=set(), posture_keys={"robustness.known"}
    )
    assert any("bogus_key" in p for p in problems)


# --------------------------------------------------------------------------- #
# 2. Structural validation — each a clear RegistryError.
# --------------------------------------------------------------------------- #


def test_unknown_kind(tmp_path):
    obj = _attested_obj("a")
    obj["evidence"]["kind"] = "guessed"
    with pytest.raises(RegistryError, match="kind"):
        load_registry(_write(tmp_path, _dim_doc(l2=[obj])))


def test_both_indicator_and_posture(tmp_path):
    obj = {
        "id": "a",
        "statement_zh": "s",
        "evidence": {
            "kind": "measured",
            "indicator_id": "block_rate",
            "posture_key": "d.a",
            "satisfied_when": "value >= 0",
        },
    }
    with pytest.raises(RegistryError, match="no posture_key"):
        load_registry(_write(tmp_path, _dim_doc(l2=[obj])))


def test_neither_indicator_nor_posture(tmp_path):
    obj = {"id": "a", "statement_zh": "s", "evidence": {"kind": "attested"}}
    with pytest.raises(RegistryError, match="posture_key"):
        load_registry(_write(tmp_path, _dim_doc(l2=[obj])))


def test_measured_missing_satisfied_when(tmp_path):
    obj = {
        "id": "a",
        "statement_zh": "s",
        "evidence": {"kind": "measured", "indicator_id": "block_rate"},
    }
    with pytest.raises(RegistryError, match="satisfied_when"):
        load_registry(_write(tmp_path, _dim_doc(l2=[obj])))


def test_measured_bad_satisfied_when(tmp_path):
    obj = {
        "id": "a",
        "statement_zh": "s",
        "evidence": {
            "kind": "measured",
            "indicator_id": "block_rate",
            "satisfied_when": "value; os.system('x')",
        },
    }
    with pytest.raises(RegistryError, match="satisfied_when|invalid"):
        load_registry(_write(tmp_path, _dim_doc(l2=[obj])))


def test_attested_must_not_have_satisfied_when(tmp_path):
    obj = {
        "id": "a",
        "statement_zh": "s",
        "evidence": {
            "kind": "attested",
            "posture_key": "d.a",
            "satisfied_when": "value >= 0",
        },
    }
    with pytest.raises(RegistryError, match="satisfied_when"):
        load_registry(_write(tmp_path, _dim_doc(l2=[obj])))


# --------------------------------------------------------------------------- #
# Completeness + structural shape errors.
# --------------------------------------------------------------------------- #


def test_missing_level_key(tmp_path):
    doc = _dim_doc()
    del doc["levels"]["L5"]
    with pytest.raises(RegistryError, match="levels must be exactly"):
        load_registry(_write(tmp_path, doc))


def test_empty_level_must_be_explicit(tmp_path):
    doc = _dim_doc()
    doc["levels"]["L3"] = None  # not an explicit control_objectives: []
    with pytest.raises(RegistryError, match="control_objectives"):
        load_registry(_write(tmp_path, doc))


def test_missing_dimension_fails_completeness(tmp_path):
    # One valid dimension file -> structurally fine, but the 5-dim set is incomplete.
    with pytest.raises(RegistryError, match="exactly the 5 dimensions"):
        load_registry(_write(tmp_path, _dim_doc()))


def test_evidence_not_a_mapping(tmp_path):
    obj = {"id": "a", "statement_zh": "s", "evidence": "not-a-mapping"}
    with pytest.raises(RegistryError, match="evidence must be a mapping"):
        load_registry(_write(tmp_path, _dim_doc(l2=[obj])))


def test_missing_dir(tmp_path):
    with pytest.raises(RegistryError, match="not found"):
        load_registry(tmp_path / "nope")
