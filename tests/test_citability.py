"""EV-CITE 件一 — the report-level citability gate (acceptance 1-6).

The gate is pure (`treval.citability.report_citability`), so most of this drives it directly with
crafted provenance; two tests go through the real serializer to prove the fields land on the
delivery bundle with the pairing-path shape and that NO dimension grows its own citable.
"""

from __future__ import annotations

from dataclasses import replace

from treval import load_registry
from treval.citability import (
    OBSERVABLE_BIAS_NOTE,
    citation_form,
    report_citability,
)
from treval.models import (
    INTERVAL_CENSUS,
    INTERVAL_NO_CI_BASES,
    INTERVAL_TOTAL_FUNCTION,
    EvidenceRef,
    IntegrityStatus,
    Measurement,
)
from treval.rubric.engine import evaluate
from treval.rubric.serialize import serialize_self_contained_bundle
from treval.stats import wilson_interval

_REG = load_registry()
_ROB = "robustness"
_PINNED = {"pinned": True, "wal_segments": {"sha256": "sha256:" + "a" * 64}}


def _m(indicator: str, value: float, n: int) -> Measurement:
    lo, _p, hi = wilson_interval(round(value * n), n) if n else (None, None, None)
    return Measurement(
        indicator_id=indicator,
        dimension=_ROB,
        value=value,
        unit="ratio",
        sample_size=n,
        evidence_refs=(EvidenceRef(source="wal:test", seq=1),),
        integrity=IntegrityStatus.VERIFIED,
        ci_low=lo,
        ci_high=hi,
    )


def _bundle(provenance, *, evidence_basis="wal_anchored", broken=0):
    return {
        "evidence_basis": evidence_basis,
        "provenance": provenance,
        "report": {
            "integrity_summary": {"verified": 5, "unverified": 0, "broken": broken}
        },
    }


# --------------------------------------------------------------------------- #
# 1 — shape matches the pairing path, and lands on the delivery bundle
# --------------------------------------------------------------------------- #


def test_fields_have_the_pairing_shape_on_the_delivery_bundle():
    """🔴 acceptance 1: the SELF-CONTAINED bundle top-level carries `citable` (bool) +
    `citable_blockers` (list[str]) — the exact pairing-path names, not a new `quotable`/`publishable`."""
    report = evaluate(
        _REG,
        [_m("injection_catch_rate", 25 / 28, 28)],
        [],
        window=(0, 1),
        tenant_id="t",
    )
    bundle = serialize_self_contained_bundle(report, [], _REG, _PINNED)
    assert isinstance(bundle["citable"], bool)
    assert isinstance(bundle["citable_blockers"], list)
    assert all(isinstance(b, str) for b in bundle["citable_blockers"])
    assert bundle["citable"] == (
        bundle["citable_blockers"] == []
    )  # citable ⇔ no blockers


# --------------------------------------------------------------------------- #
# 2 — unpinned ⇒ not citable, and the blocker NAMES the fix
# --------------------------------------------------------------------------- #


def test_unpinned_is_not_citable_and_the_blocker_names_the_fix():
    """🔴 acceptance 2: `provenance.pinned=false` ⇒ citable=false, and the blocker contains the
    actual remedy `--window-from-ns` — a bare "unpinned" with no fix would red this."""
    citable, blockers = report_citability(
        _bundle({"pinned": False, "wal_segments": {"sha256": "x"}})
    )
    assert citable is False
    assert any("--window-from-ns" in b for b in blockers)


# --------------------------------------------------------------------------- #
# 3 — 🔴 the easy-to-get-backwards one: "unmet" is still CITABLE
# --------------------------------------------------------------------------- #


def test_below_threshold_is_still_citable():
    """🔴 acceptance 3: a fully pinned / wal_anchored / intact report whose injection objective is
    `unmet` is STILL citable — an honest "we measured, it's below the line" is the measured>attested
    selling point, never a blocker (§0). This is the single most invertible rule in the ticket."""
    report = evaluate(
        _REG,
        [_m("injection_catch_rate", 25 / 28, 28), _m("false_positive_rate", 0.0, 19)],
        [],
        window=(0, 1),
        tenant_id="t",
    )
    rob = next(d for d in report.dimensions if d.dimension == _ROB)
    assert rob.measured_state == "below_floor"  # it really is measured-but-low…
    bundle = serialize_self_contained_bundle(report, [], _REG, _PINNED)
    assert (
        bundle["citable"] is True and bundle["citable_blockers"] == []
    )  # …yet citable


# --------------------------------------------------------------------------- #
# 4 — no dimension-level citable (C7), backend OR front-end
# --------------------------------------------------------------------------- #


def test_no_dimension_level_citable_anywhere():
    """🔴 acceptance 4 (C7): citability is report-level ONLY — no dimension carries `citable` /
    `citable_blockers` (a forever-true dimension badge would read as an endorsement). The Web layer
    derives none either."""
    report = evaluate(
        _REG,
        [_m("injection_catch_rate", 25 / 28, 28)],
        [],
        window=(0, 1),
        tenant_id="t",
    )
    bundle = serialize_self_contained_bundle(report, [], _REG, _PINNED)
    for d in bundle["report"]["dimensions"]:
        assert "citable" not in d and "citable_blockers" not in d
    # the Web row builder produces no per-dimension citable field either
    import pytest

    pytest.importorskip("fastapi")
    from treval.web.view import maturity_rows

    for row in maturity_rows(bundle["report"], {}):
        assert "citable" not in row


# --------------------------------------------------------------------------- #
# 5 — a real-shaped report (has insufficient_data) is citable once pinned (C6)
# --------------------------------------------------------------------------- #


def test_insufficient_data_present_but_pinned_is_citable():
    """🔴 acceptance 5 (C6): `insufficient_data` is NOT a citability blocker — a pinned, intact
    report is citable even though some indicator did not produce this run (every real report has
    that). Mirrors the stored __eval__ report (drift_alerting / guardrail_blocking insufficient)."""
    # injection_catch_rate present (unmet), but no false_positive_rate ⇒ that objective is
    # insufficient_data — a real "some indicator didn't produce" report.
    report = evaluate(
        _REG,
        [_m("injection_catch_rate", 25 / 28, 28)],
        [],
        window=(0, 1),
        tenant_id="t",
    )
    rob = next(d for d in report.dimensions if d.dimension == _ROB)
    assert any(
        o.status == "insufficient_data" for o in rob.objectives
    )  # it's in there…
    bundle = serialize_self_contained_bundle(report, [], _REG, _PINNED)
    assert bundle["citable"] is True  # …and it does NOT block citation


# --------------------------------------------------------------------------- #
# 6 — a broken chain is fatal AND its blocker is first
# --------------------------------------------------------------------------- #


def test_broken_chain_is_not_citable_and_ranks_first():
    """🔴 acceptance 6: integrity_summary.broken>0 ⇒ not citable, and the integrity blocker is the
    FIRST entry (it voids everything beneath it) even when the run is also unpinned."""
    citable, blockers = report_citability(
        _bundle({"pinned": False, "wal_segments": {}}, broken=2)
    )
    assert citable is False
    assert (
        "完整性破损" in blockers[0]
    )  # first, ahead of the unpinned / segment-hash blockers
    assert len(blockers) >= 2  # the other failures are still listed, just after


# --------------------------------------------------------------------------- #
# 21 — C12: a pin over an EMPTY window anchors nothing, and the fix window is printed
# --------------------------------------------------------------------------- #


def test_pinned_but_empty_window_is_not_citable_and_prints_the_observed_window():
    """🔴 C12 / acceptance 21: `pinned && record_count==0` ⇒ citable=false — a fixed window with no
    records anchors nothing. The blocker prints the ACTUAL observed window [X, Y) so the operator
    re-pins by COPYING, never by computing nanoseconds. Saying only "空窗口" without the numbers ⇒ red."""
    x, y = 1737000000000000000, 1737000005000000000
    citable, blockers = report_citability(
        {
            "evidence_basis": "wal_anchored",
            "provenance": {
                "pinned": True,
                "record_count": 0,
                "observed_window": [x, y],
                "wal_segments": {"sha256": "sha256:" + "a" * 64},
            },
            "report": {"integrity_summary": {"broken": 0}},
        }
    )
    assert citable is False
    blk = next(b for b in blockers if "锚不住" in b)
    assert (
        str(x) in blk and str(y) in blk
    )  # 🔴 the actual ns, copyable — not just "空窗口"

    # a pinned run WITH records is untouched (no false positive)
    ok, _b = report_citability(
        {
            "evidence_basis": "wal_anchored",
            "provenance": {
                "pinned": True,
                "record_count": 867,
                "wal_segments": {"sha256": "sha256:" + "a" * 64},
            },
            "report": {"integrity_summary": {"broken": 0}},
        }
    )
    assert ok is True


# --------------------------------------------------------------------------- #
# 7 / 8 / 9 — citation_form: interval BY MECHANISM, and never blank when not citable
# --------------------------------------------------------------------------- #


def _no_ci(indicator: str, value: float, n: int, basis: str) -> Measurement:
    return Measurement(
        indicator_id=indicator,
        dimension="transparency_accountability",
        value=value,
        unit="ratio",
        sample_size=n,
        evidence_refs=(EvidenceRef(source="wal:test", seq=1),),
        integrity=IntegrityStatus.VERIFIED,
        ci_low=None,  # no interval — the mechanism (census / total_function) is DECLARED, not proxied
        ci_high=None,
        interval_basis=basis,
    )


def _census(indicator: str, value: float, n: int) -> Measurement:
    return _no_ci(indicator, value, n, INTERVAL_CENSUS)


def _cite(m: Measurement, *, citable=True) -> str:
    return citation_form(
        m,
        pinned=True,
        window=[1, 2],
        evidence_basis="wal_anchored",
        citable=citable,
        first_blocker=None,
        satisfied_when=None,
    )


def _pinned_bundle(measurements):
    report = evaluate(_REG, measurements, [], window=(100, 200), tenant_id="t")
    prov = {
        "pinned": True,
        "window": [100, 200],
        "wal_segments": {"sha256": "sha256:" + "a" * 64},
    }
    return serialize_self_contained_bundle(report, measurements, _REG, prov)


def test_citation_form_rate_carries_n_and_interval():
    """🔴 acceptance 7: a binomial rate's citation_form carries BOTH its n and its 95% interval —
    dropping either would let the bare percentage travel alone (the recurring miss)."""
    ms = [_m("injection_catch_rate", 25 / 28, 28), _m("false_positive_rate", 0.0, 19)]
    bundle = _pinned_bundle(ms)
    for row in bundle["measurements"]:
        if row["ci_low"] is not None:  # a rate
            form = row["citation_form"]
            assert f"/{row['sample_size']}" in form and "95% CI [" in form


def test_citation_form_census_has_no_interval_says_普查():
    """🔴 acceptance 8: a census (chain_integrity, ci None) gets NO fake interval — it reads "普查
    n/n". The count is the measurement's own sample_size (live), never a hardcoded 173/867."""
    bundle = _pinned_bundle([_census("chain_integrity", 1.0, 867)])
    form = next(
        r["citation_form"]
        for r in bundle["measurements"]
        if r["indicator_id"] == "chain_integrity"
    )
    assert "普查 867/867" in form and "95% CI" not in form and "CI [" not in form


def test_citation_form_not_citable_is_prefixed_never_blank():
    """🔴 acceptance 9: in a NOT-citable bundle every citation_form is non-empty and starts with
    "🔴 NOT CITABLE" — a blank would send the reader back to quoting the naked number."""
    report = evaluate(
        _REG,
        [_m("injection_catch_rate", 25 / 28, 28)],
        [],
        window=(0, 1),
        tenant_id="t",
    )
    bundle = serialize_self_contained_bundle(
        report, [_m("injection_catch_rate", 25 / 28, 28)], _REG, None
    )
    assert bundle["citable"] is False
    for row in bundle["measurements"]:
        assert row["citation_form"].startswith("🔴 NOT CITABLE")


# --------------------------------------------------------------------------- #
# 🔴 review fix — the THREE-way (not two): a total function is NOT a census; the class is DECLARED,
# never derived from `ci is None`.
# --------------------------------------------------------------------------- #


def test_total_function_is_not_labelled_a_census():
    """🔴 the merge bug: tool_scope_violation_rate (n=12, default-deny) must NOT read "普查 12/12"
    (which claims we exhausted the population). It gets the total-function口径 — no interval because
    the residual is a hole in the allow-list, not a rate."""
    form = _cite(_no_ci("tool_scope_violation_rate", 0.0, 12, INTERVAL_TOTAL_FUNCTION))
    assert "普查" not in form  # the whole point
    assert "默认拒绝" in form and "区间不适用" in form and "残余在覆盖面" in form
    assert "12/12 条探针未见失效" in form and "95% CI" not in form


def test_census_and_total_function_are_distinct_wordings():
    """The two no-CI classes read differently — a census DOES claim full enumeration ("普查"), a total
    function explicitly does NOT (its uncertainty is in coverage)."""
    census = _cite(_census("chain_integrity", 1.0, 867))
    total = _cite(_no_ci("tool_scope_violation_rate", 0.0, 12, INTERVAL_TOTAL_FUNCTION))
    assert "普查 867/867" in census and "残余在覆盖面" not in census
    assert "普查" not in total and "残余在覆盖面" in total


def test_ci_none_ratio_without_a_declaration_never_claims_census():
    """🔴 the proxy is dead: a ci-None rate that declared NO mechanism must NOT fall through to "普查"
    — it says its interval-applicability is undeclared (honest), so a forgotten new indicator can
    never silently claim an exhausted census."""
    form = _cite(_no_ci("some_new_rate", 0.3, 50, ""))
    assert "普查" not in form and "区间适用性未声明" in form


def _all_indicator_classes():
    """The indicator registry, discovered — NOT a hardcoded list. Every class in the treval.indicators
    package plus the active CURATION factories. A new indicator file / producer is picked up
    automatically, so the gate below cannot be out-run by adding one."""
    import importlib
    import inspect
    import pkgutil

    import treval.indicators as pkg
    from treval.cli.collect import CURATION

    classes = {p.factory for p in CURATION}
    for mod_info in pkgutil.iter_modules(pkg.__path__):
        mod = importlib.import_module(f"treval.indicators.{mod_info.name}")
        for _name, obj in inspect.getmembers(mod, inspect.isclass):
            if (
                obj.__module__ == mod.__name__
                and getattr(obj, "indicator_id", None)
                and hasattr(obj, "measure")
            ):
                classes.add(obj)
    return classes


def _observable_stratum() -> Measurement:
    lo, _p, hi = wilson_interval(8, 8)  # 8/8 = 100%, but ci_low 0.676 (small n)
    return Measurement(
        "injection_catch_rate",
        "robustness",
        1.0,
        "ratio",
        8,
        (EvidenceRef(source="wal:t", seq=1),),
        subject="outcome_observable",
        integrity=IntegrityStatus.VERIFIED,
        ci_low=lo,
        ci_high=hi,
    )


def test_stratified_measurement_names_its_stratum():
    """🔴 review fix: a subject != "" measurement MUST name its stratum (@subject) — else the
    paste-whole string for injection_catch_rate@outcome_observable (100% on the marker subset) reads
    as "injection catch rate = 100%". Teeth: drop the subject and the @stratum vanishes."""
    m = _observable_stratum()
    assert "injection_catch_rate@outcome_observable" in _cite(m)
    assert "injection_catch_rate@" not in _cite(
        replace(m, subject="")
    )  # aggregate: no @stratum


def test_observable_subset_stratum_carries_the_ONE_shared_bias_note():
    """🔴 review fix (EV-R2 §9.7): the @outcome_observable stratum rides WITH the observable-subset
    caveat, and it is the SAME object the pairing path uses — ONE note, never a second copy."""
    from treval.cli.pair import OBSERVABLE_BIAS_NOTE as PAIR_NOTE

    assert PAIR_NOTE is OBSERVABLE_BIAS_NOTE  # literally one source of truth
    form = _cite(_observable_stratum())
    assert OBSERVABLE_BIAS_NOTE in form and "OPTIMISTICALLY biased" in form
    # the all-decided AGGREGATE (subject="") is NOT observable-biased → no caveat
    assert OBSERVABLE_BIAS_NOTE not in _cite(replace(_observable_stratum(), subject=""))


def test_every_ci_none_ratio_indicator_declares_its_mechanism():
    """🔴 GATE-CONSISTENCY 件二 — a real gate, not a name list. It ENUMERATES the indicator registry
    and, for any indicator that emits a ratio WITHOUT attaching a CI (source has `unit="ratio"` and
    no `ci_low=`), asserts it declares a valid `interval_basis`. 🔴 Teeth: add a new ci-None ratio
    indicator without declaring, and this turns RED (it is discovered, then fails the assertion) —
    exactly what the old hard-coded list could not do."""
    import inspect

    discovered = []
    for cls in sorted(_all_indicator_classes(), key=lambda c: c.__name__):
        src = inspect.getsource(cls)
        produces_ratio = 'unit="ratio"' in src
        attaches_ci = (
            "ci_low=" in src
        )  # a detector fills the Wilson interval; census/total do not
        if produces_ratio and not attaches_ci:
            discovered.append(cls.__name__)
            assert getattr(cls, "interval_basis", "") in INTERVAL_NO_CI_BASES, (
                f"{cls.__name__} emits a ci-None ratio but declares no interval_basis "
                f"(got {getattr(cls, 'interval_basis', None)!r}) — declare census / total_function"
            )
    # non-vacuous: the known no-CI ratio indicators were actually reached by the discovery
    assert {"ChainIntegrity", "ToolScopeViolationRate", "BlockRate"} <= set(
        discovered
    ), discovered
