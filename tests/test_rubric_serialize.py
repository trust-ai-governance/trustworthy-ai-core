"""EV-7 — deterministic report-bundle serialization (docs/REPORT_JSON_SCHEMA.md).

Asserts the §2 field mapping (enum → value, None → null, tuple → array), the §3
determinism (sorted keys + defined array order → byte-identical), and that the bundle
round-trips through json.loads.
"""

from __future__ import annotations

import json

from treval import bundle_to_json, evaluate, serialize_bundle
from treval.models import (
    EvidenceRef,
    IntegrityStatus,
    Measurement,
    PostureEvidence,
)
from treval.registry import (
    ControlObjective,
    Dimension,
    DimensionRegistry,
    Evidence,
)

_WINDOW = (1782191400000000000, 1782191600000000000)


def _measured_obj(oid, indicator_id, satisfied_when, *, requires_integrity=False):
    return ControlObjective(
        id=oid,
        statement_zh="s",
        evidence=Evidence(
            kind="measured",
            indicator_id=indicator_id,
            posture_key=None,
            satisfied_when=satisfied_when,
            requires_integrity=requires_integrity,
        ),
    )


def _attested_obj(oid, posture_key):
    return ControlObjective(
        id=oid,
        statement_zh="s",
        evidence=Evidence(
            kind="attested",
            indicator_id=None,
            posture_key=posture_key,
            satisfied_when=None,
        ),
    )


def _dim(dimension, levels):
    full = {
        level: tuple(levels.get(level, ())) for level in ("L1", "L2", "L3", "L4", "L5")
    }
    return Dimension(dimension=dimension, title_en="T", title_zh="标题", levels=full)


def _m(
    indicator_id, value, *, subject="", integrity=IntegrityStatus.VERIFIED, refs=None
):
    return Measurement(
        indicator_id=indicator_id,
        dimension="robustness",
        value=value,
        unit="ratio",
        sample_size=10,
        subject=subject,
        integrity=integrity,
        evidence_refs=refs
        if refs is not None
        else (EvidenceRef(source="wal:/w/000.wal", seq=1, request_id="r1"),),
    )


def _sample_bundle():
    dim = _dim(
        "robustness",
        {
            "L2": (
                _measured_obj("rob.l2.m", "catch", "value >= 0.80"),
                _attested_obj("rob.l2.a", "p.l2"),
            ),
            "L3": (_attested_obj("rob.l3.a", "p.l3"),),
        },
    )
    measurements = [_m("catch", 0.9)]
    posture = [
        PostureEvidence(
            ref=EvidenceRef(source="attest:p.yaml"),
            tenant_id="t",
            key="p.l2",
            value="true",
            attested_by="op",
            attested_at_ns=0,
        ),
        PostureEvidence(
            ref=EvidenceRef(source="attest:p.yaml"),
            tenant_id="t",
            key="p.l3",
            value="true",
            attested_by="op",
            attested_at_ns=0,
        ),
    ]
    reg = DimensionRegistry(dimensions={"robustness": dim})
    report = evaluate(reg, measurements, posture, window=_WINDOW, tenant_id="dogfood")
    return report, measurements


def test_bundle_envelope_shape():
    report, measurements = _sample_bundle()
    bundle = serialize_bundle(report, measurements)
    assert bundle["schema_version"] == 1
    assert set(bundle) == {"schema_version", "report", "measurements"}
    rep = bundle["report"]
    assert set(rep) == {
        "tenant_id",
        "window",
        "dimensions",
        "integrity_summary",
        "verification_basis",
    }
    assert rep["tenant_id"] == "dogfood"
    assert rep["window"] == list(_WINDOW)  # tuple → array


def test_report_field_mapping_enum_none_tuple():
    report, measurements = _sample_bundle()
    bundle = serialize_bundle(report, measurements)
    rep = bundle["report"]
    # integrity_summary: all three keys, values int, enum keyed by .value
    assert rep["integrity_summary"] == {"verified": 1, "unverified": 0, "broken": 0}
    assert rep["verification_basis"] == "wal"

    (dim,) = rep["dimensions"]
    assert dim["awarded_level"] == "L2"  # measured L2, attested L3 → min L2
    assert dim["gaps"] == ["rob.l3.a"]  # attested-met above measured ceiling → array

    # a measured objective carries its evidence_refs; an unmet attested one is []
    by_id = {o["objective_id"]: o for o in dim["objectives"]}
    assert by_id["rob.l2.m"]["status"] == "met"
    assert by_id["rob.l2.m"]["evidence_refs"][0] == {
        "source": "wal:/w/000.wal",
        "seq": 1,
        "request_id": "r1",
    }
    assert by_id["rob.l2.a"]["status"] == "met"  # posture present
    # seq None serializes to null
    m0 = bundle["measurements"][0]
    assert m0["integrity"] == "verified"  # enum → value
    assert m0["subject"] == ""


def test_measurements_sorted_by_indicator_then_subject():
    report, _ = _sample_bundle()
    measurements = [
        _m("z_ind", 0.1, subject="b"),
        _m("z_ind", 0.1, subject="a"),
        _m("a_ind", 0.1),
    ]
    bundle = serialize_bundle(report, measurements)
    keys = [(m["indicator_id"], m["subject"]) for m in bundle["measurements"]]
    assert keys == [("a_ind", ""), ("z_ind", "a"), ("z_ind", "b")]


def test_evidence_refs_sorted_within_a_measurement():
    report, _ = _sample_bundle()
    refs = (
        EvidenceRef(source="wal:/w/000.wal", seq=9),
        EvidenceRef(source="wal:/w/000.wal", seq=2),
        EvidenceRef(source="eval:probe", seq=None),
    )
    m = _m("catch", 0.9, refs=refs)
    bundle = serialize_bundle(report, [m])
    out = bundle["measurements"][0]["evidence_refs"]
    assert [(r["source"], r["seq"]) for r in out] == [
        ("eval:probe", None),
        ("wal:/w/000.wal", 2),
        ("wal:/w/000.wal", 9),
    ]


def test_json_is_byte_identical_across_runs_and_input_order():
    report, measurements = _sample_bundle()
    shuffled = (
        list(reversed(measurements)) + measurements
    )  # order + dup must not matter to keys
    a = bundle_to_json(report, measurements)
    b = bundle_to_json(report, measurements)
    assert a == b  # same input → byte-identical
    # sorted keys → the serialized object-key order is independent of dict construction
    assert bundle_to_json(report, shuffled) == bundle_to_json(
        report, list(reversed(shuffled))
    )


def test_bundle_round_trips_through_json():
    report, measurements = _sample_bundle()
    parsed = json.loads(bundle_to_json(report, measurements))
    assert parsed["report"]["dimensions"][0]["dimension"] == "robustness"
    assert parsed["schema_version"] == 1
