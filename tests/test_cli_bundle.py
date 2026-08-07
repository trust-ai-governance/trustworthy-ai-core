"""EV-8 — Measurement-bundle I/O: round-trip + fail-closed parsing + soft warnings."""

from __future__ import annotations

import json

import pytest

from treval.cli.bundle import BundleError, build_bundle, load_bundle
from treval.models import (
    INTERVAL_CENSUS,
    INTERVAL_TOTAL_FUNCTION,
    EvidenceRef,
    IntegrityStatus,
    Measurement,
)


def _m(indicator_id, dimension, value, **kw):
    return Measurement(
        indicator_id=indicator_id,
        dimension=dimension,
        value=value,
        unit="ratio",
        sample_size=kw.get("sample_size", 10),
        evidence_refs=kw.get(
            "refs", (EvidenceRef(source="eval:x", seq=3, request_id="r"),)
        ),
        subject=kw.get("subject", ""),
        integrity=kw.get("integrity", IntegrityStatus.VERIFIED),
    )


def _write(tmp_path, doc):
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_interval_basis_survives_the_round_trip(tmp_path):
    """🔴 EV-CITE 件一 (review): the interval MECHANISM must ride WITH the product through the
    collect→report round-trip — else citation_form loses it on the user's actual path and falls back.
    A census stays census, a total function stays total_function."""
    measurements = (
        Measurement(
            "chain_integrity",
            "transparency_accountability",
            1.0,
            "ratio",
            867,
            (EvidenceRef(source="wal:x", seq=1),),
            interval_basis=INTERVAL_CENSUS,
        ),
        Measurement(
            "tool_scope_violation_rate",
            "security_alignment",
            0.0,
            "ratio",
            12,
            (EvidenceRef(source="wal:x", seq=2),),
            interval_basis=INTERVAL_TOTAL_FUNCTION,
        ),
    )
    loaded = load_bundle(
        _write(
            tmp_path,
            build_bundle(measurements, tenant_id="t", window=(1, 2), mode="active"),
        )
    )
    by_id = {m.indicator_id: m.interval_basis for m in loaded.measurements}
    assert by_id["chain_integrity"] == INTERVAL_CENSUS
    assert by_id["tool_scope_violation_rate"] == INTERVAL_TOTAL_FUNCTION


def test_build_then_load_round_trips(tmp_path):
    measurements = (
        _m("injection_catch_rate", "robustness", 0.9),
        _m("tool_scope_violation_rate", "security_alignment", 0.0, refs=()),
        _m(
            "x",
            "robustness",
            0.5,
            integrity=IntegrityStatus.UNVERIFIED,
            subject="agent-1",
        ),
    )
    doc = build_bundle(measurements, tenant_id="t", window=(1, 2), mode="active")
    loaded = load_bundle(_write(tmp_path, doc))
    assert loaded.tenant_id == "t"
    assert loaded.window == (1, 2)
    assert (
        loaded.schema_version == 6
    )  # EV-CITE: collect bundle v6 (measurements gain interval_basis)
    assert loaded.target_kind == "gateway"  # R1: default, round-trips
    # same measurements (order-independent: compare as sets of key fields)
    got = {
        (m.indicator_id, m.subject, m.value, m.integrity) for m in loaded.measurements
    }
    want = {(m.indicator_id, m.subject, m.value, m.integrity) for m in measurements}
    assert got == want
    # evidence_refs survive
    inj = next(
        m for m in loaded.measurements if m.indicator_id == "injection_catch_rate"
    )
    assert inj.evidence_refs == (EvidenceRef(source="eval:x", seq=3, request_id="r"),)


def test_missing_tenant_and_window_warn_and_default(tmp_path):
    doc = {"schema_version": 2, "measurements": []}
    loaded = load_bundle(_write(tmp_path, doc))
    assert loaded.tenant_id == "unknown"
    assert loaded.window == (0, 0)
    joined = " ".join(loaded.warnings)
    assert "tenant_id" in joined and "window" in joined and "no measurements" in joined


def test_wrong_schema_version_warns_but_loads(tmp_path):
    doc = {"schema_version": 99, "tenant_id": "t", "window": [1, 2], "measurements": []}
    loaded = load_bundle(_write(tmp_path, doc))
    assert any("schema_version" in w for w in loaded.warnings)


def test_bad_json_is_fatal(tmp_path):
    p = tmp_path / "bundle.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(BundleError, match="not valid JSON"):
        load_bundle(p)


def test_top_level_not_object_is_fatal(tmp_path):
    with pytest.raises(BundleError, match="top level"):
        load_bundle(_write(tmp_path, [1, 2, 3]))


def test_measurements_not_array_is_fatal(tmp_path):
    with pytest.raises(BundleError, match="'measurements' must be an array"):
        load_bundle(_write(tmp_path, {"schema_version": 1, "measurements": {}}))


def test_measurement_missing_field_is_fatal(tmp_path):
    doc = {
        "schema_version": 1,
        "measurements": [{"indicator_id": "x", "dimension": "robustness"}],
    }
    with pytest.raises(BundleError, match="missing required field"):
        load_bundle(_write(tmp_path, doc))


def test_unknown_integrity_is_fatal(tmp_path):
    doc = {
        "schema_version": 1,
        "measurements": [
            {
                "indicator_id": "x",
                "dimension": "robustness",
                "value": 0.5,
                "unit": "ratio",
                "sample_size": 3,
                "integrity": "sort-of-verified",
            }
        ],
    }
    with pytest.raises(BundleError, match="integrity must be one of"):
        load_bundle(_write(tmp_path, doc))


def test_non_numeric_value_is_fatal(tmp_path):
    doc = {
        "schema_version": 1,
        "measurements": [
            {
                "indicator_id": "x",
                "dimension": "robustness",
                "value": "high",
                "unit": "ratio",
                "sample_size": 3,
            }
        ],
    }
    with pytest.raises(BundleError, match="value must be a number"):
        load_bundle(_write(tmp_path, doc))


def test_bool_is_not_a_valid_sample_size(tmp_path):
    doc = {
        "schema_version": 1,
        "measurements": [
            {
                "indicator_id": "x",
                "dimension": "robustness",
                "value": 0.5,
                "unit": "ratio",
                "sample_size": True,
            }
        ],
    }
    with pytest.raises(BundleError, match="sample_size must be an int"):
        load_bundle(_write(tmp_path, doc))
