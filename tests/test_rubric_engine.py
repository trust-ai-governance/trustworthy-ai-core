"""EV-7 acceptance — the MaturityRubricEngine (`treval.rubric.evaluate`).

Covers §4: the min award gate, the over-claim gap list, the status distinctions
(insufficient_data vs unverified_evidence vs unmet), the D2 integrity gate
(UNVERIFIED satisfies an aggregate rate but not a `requires_integrity` objective),
source-agnosticism, NotMeasured, and byte-identical determinism.

Registries are built directly (not via the loader) so each test is a tiny, hand-
computable fixture — the engine only iterates `registry.dimensions`, it never calls
the loader's 5-dimension completeness check.
"""

from __future__ import annotations

import pytest

from treval import DuplicateIndicatorError, evaluate
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

_WINDOW = (1000, 2000)


# --------------------------------------------------------------------------- #
# Fixture builders
# --------------------------------------------------------------------------- #


def _measured(oid, indicator_id, satisfied_when, *, requires_integrity=False):
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


def _attested(oid, posture_key):
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
    """levels = {"L2": (obj, ...), ...}; unspecified levels default to empty ()."""
    full = {
        level: tuple(levels.get(level, ())) for level in ("L1", "L2", "L3", "L4", "L5")
    }
    return Dimension(dimension=dimension, title_en="T", title_zh="标题", levels=full)


def _reg(*dims):
    return DimensionRegistry(dimensions={d.dimension: d for d in dims})


def _m(
    indicator_id,
    dimension,
    value,
    *,
    sample_size=10,
    integrity=IntegrityStatus.VERIFIED,
):
    return Measurement(
        indicator_id=indicator_id,
        dimension=dimension,
        value=value,
        unit="ratio",
        sample_size=sample_size,
        evidence_refs=(EvidenceRef(source="wal:/w/000.wal", seq=1, request_id="r1"),),
        integrity=integrity,
    )


def _posture(key):
    return PostureEvidence(
        ref=EvidenceRef(source="attest:posture.yaml"),
        tenant_id="t",
        key=key,
        value="true",
        attested_by="operator@corp",
        attested_at_ns=0,
    )


def _dimreport(report, dimension):
    return next(d for d in report.dimensions if d.dimension == dimension)


# --------------------------------------------------------------------------- #
# §4 — the min award gate (short board decides)
# --------------------------------------------------------------------------- #


def test_award_is_min_of_measured_and_attested_ceilings():
    """measured supports L3, attestation only reaches L2 → awarded L2."""
    dim = _dim(
        "robustness",
        {
            "L2": (
                _measured("rob.l2.m", "catch", "value >= 0.80"),
                _attested("rob.l2.a", "p.l2"),
            ),
            "L3": (
                _measured("rob.l3.m", "leak", "value <= 0.05"),
                _attested("rob.l3.a", "p.l3"),
            ),
        },
    )
    measurements = [
        _m("catch", "robustness", 0.9),  # >= 0.80 → met
        _m("leak", "robustness", 0.01),  # <= 0.05 → met
    ]
    posture = [_posture("p.l2")]  # L3 attestation is absent → attested ceiling L2

    report = evaluate(_reg(dim), measurements, posture, window=_WINDOW, tenant_id="t")
    r = _dimreport(report, "robustness")
    assert r.measured_ceiling == "L3"
    assert r.attested_ceiling == "L2"
    assert r.awarded_level == "L2"  # min gate


def test_award_min_gate_symmetric_measured_is_the_short_board():
    """attestation reaches L3 but measurement only backs L2 → awarded L2 (+ a gap)."""
    dim = _dim(
        "robustness",
        {
            "L2": (_measured("rob.l2.m", "catch", "value >= 0.80"),),
            "L3": (_attested("rob.l3.a", "p.l3"),),
        },
    )
    measurements = [_m("catch", "robustness", 0.95)]  # met → measured ceiling L2
    posture = [_posture("p.l3")]  # attested L3

    report = evaluate(_reg(dim), measurements, posture, window=_WINDOW, tenant_id="t")
    r = _dimreport(report, "robustness")
    assert r.measured_ceiling == "L2"
    assert r.attested_ceiling == "L3"
    assert r.awarded_level == "L2"


# --------------------------------------------------------------------------- #
# §4 — over-claim gap (the product headline)
# --------------------------------------------------------------------------- #


def test_overclaim_gaps_list_attested_met_above_measured_ceiling():
    """Attested-met at L3/L4 while measurement backs only L2 → those ids are gaps."""
    dim = _dim(
        "security_alignment",
        {
            "L2": (_measured("sec.l2.m", "block", "value >= 0.50"),),
            "L3": (_attested("sec.l3.a", "p.l3"),),
            "L4": (
                _attested("sec.l4.a", "p.l4"),
                _attested("sec.l4.b", "p.l4b"),
            ),
        },
    )
    measurements = [_m("block", "security_alignment", 0.6)]  # met → measured ceiling L2
    posture = [_posture("p.l3"), _posture("p.l4"), _posture("p.l4b")]

    report = evaluate(_reg(dim), measurements, posture, window=_WINDOW, tenant_id="t")
    r = _dimreport(report, "security_alignment")
    assert r.measured_ceiling == "L2"
    assert r.awarded_level == "L2"
    # sorted, deterministic; every attested-met objective above L2
    assert r.gaps == ("sec.l3.a", "sec.l4.a", "sec.l4.b")


def test_no_gap_when_attestation_within_measured_ceiling():
    dim = _dim(
        "robustness",
        {
            "L2": (
                _measured("rob.l2.m", "catch", "value >= 0.80"),
                _attested("rob.l2.a", "p.l2"),
            ),
            "L3": (_measured("rob.l3.m", "catch3", "value >= 0.80"),),
        },
    )
    measurements = [_m("catch", "robustness", 0.9), _m("catch3", "robustness", 0.9)]
    report = evaluate(
        _reg(dim), measurements, [_posture("p.l2")], window=_WINDOW, tenant_id="t"
    )
    r = _dimreport(report, "robustness")
    assert r.measured_ceiling == "L3"
    assert r.gaps == ()  # attested L2 is at/below the measured ceiling


# --------------------------------------------------------------------------- #
# §4 — status distinctions
# --------------------------------------------------------------------------- #


def test_missing_measurement_is_insufficient_data_not_unmet():
    dim = _dim("robustness", {"L2": (_measured("rob.l2.m", "catch", "value >= 0.80"),)})
    report = evaluate(_reg(dim), [], [], window=_WINDOW, tenant_id="t")
    r = _dimreport(report, "robustness")
    (obj,) = [o for o in r.objectives if o.objective_id == "rob.l2.m"]
    assert obj.status == "insufficient_data"
    assert r.measured_ceiling is None


def test_measured_objective_without_indicator_id_fails_closed():
    """A hand-built (non-loader) registry with a measured objective missing its
    indicator_id can't be measured → insufficient_data, never a vacuous met."""
    malformed = ControlObjective(
        id="rob.l2.bad",
        statement_zh="s",
        evidence=Evidence(
            kind="measured", indicator_id=None, posture_key=None, satisfied_when=None
        ),
    )
    dim = _dim("robustness", {"L2": (malformed,)})
    report = evaluate(_reg(dim), [], [], window=_WINDOW, tenant_id="t")
    (obj,) = _dimreport(report, "robustness").objectives
    assert obj.status == "insufficient_data"


def test_zero_sample_short_circuits_before_threshold():
    """sample_size 0 with value 0.0 must NOT satisfy `value <= 0.05` — the empty-sample
    short-circuit runs first (§1)."""
    dim = _dim(
        "privacy_data_protection",
        {"L2": (_measured("prv.l2.m", "leak", "value <= 0.05"),)},
    )
    measurements = [_m("leak", "privacy_data_protection", 0.0, sample_size=0)]
    report = evaluate(_reg(dim), measurements, [], window=_WINDOW, tenant_id="t")
    (obj,) = _dimreport(report, "privacy_data_protection").objectives
    assert obj.status == "insufficient_data"  # not "met"


def test_failed_sample_size_gate_is_insufficient_data_not_unmet():
    """A `sample_size >= N` gate at sample_size<N = NOT ENOUGH DATA (insufficient_data), not a
    quality failure (unmet). A failed `value` gate on the same dimension stays unmet."""
    dim = _dim(
        "efficient_reliability",
        {
            "L4": (
                _measured("rel.l4.lat", "duration_p99", "sample_size >= 100"),
                _measured("rel.l4.qual", "catch", "value >= 0.80"),
            )
        },
    )
    measurements = [
        _m("duration_p99", "efficient_reliability", 120.0, sample_size=15),  # 15 < 100
        _m("catch", "efficient_reliability", 0.5, sample_size=200),  # value gate fails
    ]
    report = evaluate(_reg(dim), measurements, [], window=_WINDOW, tenant_id="t")
    by = {
        o.objective_id: o.status
        for o in _dimreport(report, "efficient_reliability").objectives
    }
    assert (
        by["rel.l4.lat"] == "insufficient_data"
    )  # sample-count gate → not enough data
    assert by["rel.l4.qual"] == "unmet"  # value gate → a real quality verdict


def test_broken_evidence_is_unverified_evidence():
    dim = _dim("robustness", {"L2": (_measured("rob.l2.m", "catch", "value >= 0.80"),)})
    measurements = [_m("catch", "robustness", 0.99, integrity=IntegrityStatus.BROKEN)]
    report = evaluate(_reg(dim), measurements, [], window=_WINDOW, tenant_id="t")
    r = _dimreport(report, "robustness")
    (obj,) = r.objectives
    assert (
        obj.status == "unverified_evidence"
    )  # BROKEN never grades, even at value 0.99
    assert r.measured_ceiling is None


def test_attested_never_insufficient_or_unverified():
    dim = _dim("robustness", {"L2": (_attested("rob.l2.a", "p.l2"),)})
    report = evaluate(_reg(dim), [], [], window=_WINDOW, tenant_id="t")
    (obj,) = _dimreport(report, "robustness").objectives
    assert obj.status == "unmet"  # a declaration is simply present or absent


# --------------------------------------------------------------------------- #
# §4 — D2 integrity gate (VERIFIED vs UNVERIFIED)
# --------------------------------------------------------------------------- #


def test_unverified_satisfies_aggregate_but_not_requires_integrity():
    """Same all-UNVERIFIED (Postgres index) input: an ordinary aggregate rate can be met,
    but a `requires_integrity` transparency objective resolves unverified_evidence — the
    Postgres path cannot claim the chain moat (D2). verification_basis becomes 'index'."""
    dim = _dim(
        "transparency_accountability",
        {
            "L3": (
                _measured(
                    "trn.l3.rate", "unclosed_loop_rate", "value <= 0"
                ),  # aggregate
                _measured(
                    "trn.l3.chain",
                    "chain_integrity",
                    "value >= 1",
                    requires_integrity=True,
                ),
            ),
        },
    )
    measurements = [
        _m(
            "unclosed_loop_rate",
            "transparency_accountability",
            0.0,
            integrity=IntegrityStatus.UNVERIFIED,
        ),
        _m(
            "chain_integrity",
            "transparency_accountability",
            1.0,
            integrity=IntegrityStatus.UNVERIFIED,
        ),
    ]
    report = evaluate(_reg(dim), measurements, [], window=_WINDOW, tenant_id="t")
    r = _dimreport(report, "transparency_accountability")
    by_id = {o.objective_id: o.status for o in r.objectives}
    assert by_id["trn.l3.rate"] == "met"  # aggregate rate is fine from an index
    assert by_id["trn.l3.chain"] == "unverified_evidence"  # integrity moat is not
    assert report.verification_basis == "index"


def test_same_data_verified_meets_the_integrity_objective():
    """The SAME shape but VERIFIED (WAL) → the requires_integrity objective is met and
    verification_basis is 'wal' (§4 the two-sided proof)."""
    dim = _dim(
        "transparency_accountability",
        {
            "L3": (
                _measured(
                    "trn.l3.chain",
                    "chain_integrity",
                    "value >= 1",
                    requires_integrity=True,
                ),
            )
        },
    )
    measurements = [
        _m("chain_integrity", "transparency_accountability", 1.0)
    ]  # VERIFIED default
    report = evaluate(_reg(dim), measurements, [], window=_WINDOW, tenant_id="t")
    (obj,) = _dimreport(report, "transparency_accountability").objectives
    assert obj.status == "met"
    assert report.verification_basis == "wal"


def test_mixed_integrity_is_hybrid():
    dim = _dim(
        "robustness",
        {
            "L2": (_measured("rob.l2.m", "catch", "value >= 0.80"),),
            "L3": (_measured("rob.l3.m", "catch3", "value >= 0.80"),),
        },
    )
    measurements = [
        _m("catch", "robustness", 0.9, integrity=IntegrityStatus.VERIFIED),
        _m("catch3", "robustness", 0.9, integrity=IntegrityStatus.UNVERIFIED),
    ]
    report = evaluate(_reg(dim), measurements, [], window=_WINDOW, tenant_id="t")
    assert report.verification_basis == "hybrid"


# --------------------------------------------------------------------------- #
# §4 — source-agnosticism + integrity_summary
# --------------------------------------------------------------------------- #


def test_source_agnostic_same_measurement_grades_identically():
    """A Measurement's provenance (active ProbeResult vs passive WAL-tag) is invisible to
    the engine — only its fields matter. Two runs with an identical Measurement but
    different evidence-ref sources award the same level."""
    dim = _dim(
        "robustness",
        {
            "L2": (
                _measured("rob.l2.m", "catch", "value >= 0.80"),
                _attested("rob.l2.a", "p.l2"),
            )
        },
    )
    posture = [_posture("p.l2")]

    active = Measurement(
        indicator_id="catch",
        dimension="robustness",
        value=0.9,
        unit="ratio",
        sample_size=10,
        evidence_refs=(EvidenceRef(source="eval:probe-1"),),
    )
    passive = Measurement(
        indicator_id="catch",
        dimension="robustness",
        value=0.9,
        unit="ratio",
        sample_size=10,
        evidence_refs=(EvidenceRef(source="wal:/w/000.wal", seq=7),),
    )
    ra = _dimreport(
        evaluate(_reg(dim), [active], posture, window=_WINDOW, tenant_id="t"),
        "robustness",
    )
    rp = _dimreport(
        evaluate(_reg(dim), [passive], posture, window=_WINDOW, tenant_id="t"),
        "robustness",
    )
    # Provenance differs (eval:probe vs wal:...) but the grade is identical.
    assert ra.awarded_level == rp.awarded_level == "L2"
    assert ra.measured_ceiling == rp.measured_ceiling == "L2"


def test_integrity_summary_counts_all_three_keys():
    dim = _dim("robustness", {"L2": (_measured("rob.l2.m", "catch", "value >= 0.80"),)})
    measurements = [
        _m("catch", "robustness", 0.9, integrity=IntegrityStatus.VERIFIED),
        _m("x", "robustness", 0.1, integrity=IntegrityStatus.UNVERIFIED),
        _m("y", "robustness", 0.1, integrity=IntegrityStatus.BROKEN),
    ]
    report = evaluate(_reg(dim), measurements, [], window=_WINDOW, tenant_id="t")
    assert report.integrity_summary == {"verified": 1, "unverified": 1, "broken": 1}


# --------------------------------------------------------------------------- #
# §0 — NotMeasured + ceiling shape
# --------------------------------------------------------------------------- #


def test_not_measured_dimension_does_not_vacuously_grade_high():
    """A dimension with ZERO measured objectives must not let attestation prop up a
    'verified' level: measured_ceiling is None and awarded is gated to None."""
    dim = _dim(
        "efficient_reliability",
        {
            "L2": (_attested("rel.l2.a", "p.l2"),),
            "L3": (_attested("rel.l3.a", "p.l3"),),
        },
    )
    posture = [_posture("p.l2"), _posture("p.l3")]
    report = evaluate(_reg(dim), [], posture, window=_WINDOW, tenant_id="t")
    r = _dimreport(report, "efficient_reliability")
    assert r.measured_ceiling is None  # NotMeasured (no measured objective)
    assert r.attested_ceiling == "L3"
    assert r.awarded_level is None  # attestation alone cannot raise a verified level


def test_ceiling_climbs_empty_intermediate_but_not_empty_top():
    """measured met at L2 and L4, empty measured at L3 (climbed); no measured at L5
    (does not inflate) → measured_ceiling L4."""
    dim = _dim(
        "robustness",
        {
            "L2": (_measured("rob.l2.m", "a", "value >= 0.80"),),
            "L3": (_attested("rob.l3.a", "p.l3"),),  # no measured obj here
            "L4": (_measured("rob.l4.m", "b", "value >= 0.80"),),
            "L5": (_attested("rob.l5.a", "p.l5"),),  # empty top on measured axis
        },
    )
    measurements = [_m("a", "robustness", 0.9), _m("b", "robustness", 0.9)]
    posture = [_posture("p.l3"), _posture("p.l5")]
    report = evaluate(_reg(dim), measurements, posture, window=_WINDOW, tenant_id="t")
    assert _dimreport(report, "robustness").measured_ceiling == "L4"


def test_lower_level_unmet_caps_ceiling_below_a_higher_met_level():
    """An unmet measured objective at L2 caps the ceiling below L2 even if L3's measured
    objective is met (monotonic L1..N gate)."""
    dim = _dim(
        "robustness",
        {
            "L2": (_measured("rob.l2.m", "a", "value >= 0.80"),),
            "L3": (_measured("rob.l3.m", "b", "value >= 0.80"),),
        },
    )
    measurements = [_m("a", "robustness", 0.5), _m("b", "robustness", 0.99)]  # L2 unmet
    report = evaluate(_reg(dim), measurements, [], window=_WINDOW, tenant_id="t")
    assert _dimreport(report, "robustness").measured_ceiling is None


# --------------------------------------------------------------------------- #
# §4 — determinism (byte-identical) + dimension/objective ordering
# --------------------------------------------------------------------------- #


def test_report_is_deterministic_across_runs():
    dim = _dim(
        "robustness",
        {
            "L2": (
                _measured("rob.l2.m", "catch", "value >= 0.80"),
                _attested("rob.l2.a", "p.l2"),
            ),
            "L3": (_attested("rob.l3.a", "p.l3"),),
        },
    )
    measurements = [_m("catch", "robustness", 0.9)]
    posture = [_posture("p.l2"), _posture("p.l3")]
    r1 = evaluate(_reg(dim), measurements, posture, window=_WINDOW, tenant_id="t")
    r2 = evaluate(
        _reg(dim),
        list(reversed(measurements)),
        list(reversed(posture)),
        window=_WINDOW,
        tenant_id="t",
    )
    assert r1 == r2  # frozen dataclasses compare by value; input order is irrelevant


def test_dimension_order_follows_registry_key_order():
    d_a = _dim("robustness", {"L2": (_attested("a", "p"),)})
    d_b = _dim("security_alignment", {"L2": (_attested("b", "p"),)})
    reg = DimensionRegistry(dimensions={"robustness": d_a, "security_alignment": d_b})
    report = evaluate(reg, [], [], window=_WINDOW, tenant_id="t")
    assert [d.dimension for d in report.dimensions] == [
        "robustness",
        "security_alignment",
    ]


def test_duplicate_aggregate_id_raises_not_silent_pick():
    """A duplicate aggregate id is an ambiguous binding → fail LOUD (EV-7 D3), never a
    silent first-wins that could emit a plausible-but-wrong grade."""
    dim = _dim("robustness", {"L2": (_measured("rob.l2.m", "catch", "value >= 0.80"),)})
    measurements = [
        _m("catch", "robustness", 0.9),
        _m("catch", "robustness", 0.1),  # same aggregate id → ambiguous
    ]
    with pytest.raises(DuplicateIndicatorError) as exc:
        evaluate(_reg(dim), measurements, [], window=_WINDOW, tenant_id="t")
    assert exc.value.indicator_id == "catch"
    assert (
        len(exc.value.conflicting) == 2
    )  # both offenders exposed for a driver-side merge
    assert "catch" in str(exc.value)


def test_per_subject_measurement_ignored_for_aggregate_binding():
    """The engine binds only aggregate (subject == '') measurements; a per-subject row
    with the same id does not satisfy an objective."""
    dim = _dim("robustness", {"L2": (_measured("rob.l2.m", "catch", "value >= 0.80"),)})
    per_subject = Measurement(
        indicator_id="catch",
        dimension="robustness",
        value=0.99,
        unit="ratio",
        sample_size=10,
        evidence_refs=(EvidenceRef(source="eval:x"),),
        subject="agent-1",
    )
    report = evaluate(_reg(dim), [per_subject], [], window=_WINDOW, tenant_id="t")
    (obj,) = _dimreport(report, "robustness").objectives
    assert obj.status == "insufficient_data"  # no aggregate matched


# --------------------------------------------------------------------------- #
# End-to-end against the SHIPPED registry (proves the loader + engine compose)
# --------------------------------------------------------------------------- #


def test_shipped_registry_grades_without_error():
    from treval import load_registry

    reg = load_registry()
    # One aggregate for each active indicator now bound by table A + a chain measurement.
    measurements = [
        _m("injection_catch_rate", "robustness", 0.9),
        _m("tool_scope_violation_rate", "security_alignment", 0.0),
    ]
    report = evaluate(reg, measurements, [], window=_WINDOW, tenant_id="dogfood")
    assert report.tenant_id == "dogfood"
    assert {d.dimension for d in report.dimensions} == set(reg.dimensions)
    rob = _dimreport(report, "robustness")
    (inj,) = [
        o for o in rob.objectives if o.objective_id == "rob.l2.injection_rule_detection"
    ]
    assert inj.status == "met"  # 0.9 >= 0.80
