"""EV-CITE 件一 — the report-level citability gate (acceptance 1-6).

The gate is pure (`treval.citability.report_citability`), so most of this drives it directly with
crafted provenance; two tests go through the real serializer to prove the fields land on the
delivery bundle with the pairing-path shape and that NO dimension grows its own citable.
"""

from __future__ import annotations

from dataclasses import replace

from treval import load_registry
from treval.citability import (
    CRITERIA_BLOCKERS,
    CRITERIA_VERSION,
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
# E3-h/E3-m: the freeze-pack scope a citable run must declare — language_scope (the #1 axis) +
# tested version / detect config / exec mode.
_CONFIG = {
    "language_scope": "英文为主 · 含跨语言手法件 · 中文金融流量未测",
    "tested_version": "deepseek-v4-flash@2026-01-30",
    "detect_config": "encode_decode=off",
    "exec_mode": "block",
    # E3-n ③: the detection-layer status + the tested party's declared upstream timeout fold into
    # the SAME missing_run_config criterion — a citable run must declare all six.
    "detection_layer_status": "tier1_only (tier2 shadow off)",
    "upstream_timeout_s": 60.0,
}
# A PROPERLY pinned run: a WAL source declared (wal_dir), a closure stamp (generated_at_ns), a segment
# hash, AND the E3-h freeze-pack config. C14 keys the window-family blockers on wal_dir; C15 requires
# generated_at_ns; E3-h requires the config trio — so a citable fixture must carry all of them.
_PINNED = {
    "pinned": True,
    "wal_dir": "/wal",
    "generated_at_ns": 10,
    "wal_segments": {"sha256": "sha256:" + "a" * 64},
    **_CONFIG,
}


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
        _bundle({"pinned": False, "wal_dir": "/w", "wal_segments": {"sha256": "x"}})
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
        _bundle({"pinned": False, "wal_dir": "/w", "wal_segments": {}}, broken=2)
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
                "wal_dir": "/w",
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

    # a pinned run WITH records AND a closure stamp + config is untouched (no false positive)
    ok, _b = report_citability(
        {
            "evidence_basis": "wal_anchored",
            "provenance": {
                "pinned": True,
                "wal_dir": "/w",
                "record_count": 867,
                "generated_at_ns": y,
                "wal_segments": {"sha256": "sha256:" + "a" * 64},
                **_CONFIG,
            },
            "report": {"integrity_summary": {"broken": 0}},
        }
    )
    assert ok is True


# --------------------------------------------------------------------------- #
# 23 / 27 — C15: an unclosed (future-upper-bound) pin is not a pin
# --------------------------------------------------------------------------- #


def test_future_upper_bound_is_not_citable_C15():
    """🔴 C15 / acceptance 23: a pinned window whose UPPER bound is in the future (relative to the
    product's OWN generated_at_ns) is not frozen — re-reading the same WAL later returns MORE records
    and the number moves. citable=false. 🔴 The verdict reads generated_at_ns from INSIDE the bundle,
    never the wall clock. RED input: before C15 this exact bundle returned (True, [])."""
    gen = 1786019882041459593
    citable, blockers = report_citability(
        {
            "evidence_basis": "wal_anchored",
            "provenance": {
                "pinned": True,
                "wal_dir": "/w",
                "record_count": 867,
                "window": [gen - 1000, 9999999999999999999],  # upper ≈ year 2286
                "generated_at_ns": gen,
                "wal_segments": {"sha256": "sha256:" + "a" * 64},
            },
            "report": {"integrity_summary": {"broken": 0}},
        }
    )
    assert citable is False
    assert any(
        "未来" in b for b in blockers
    )  # the blocker names the unclosed-window fix

    # the SAME window with a stamp AT/after its upper bound is CLOSED (window[1] > gen is false) ⇒
    # citable. Proves C15 keys on the product's own datum, not on the window being small.
    closed = 9999999999999999999
    ok, blk = report_citability(
        {
            "evidence_basis": "wal_anchored",
            "provenance": {
                "pinned": True,
                "wal_dir": "/w",
                "record_count": 867,
                "window": [0, closed],
                "generated_at_ns": closed,
                "wal_segments": {"sha256": "sha256:" + "a" * 64},
                **_CONFIG,
            },
            "report": {"integrity_summary": {"broken": 0}},
        }
    )
    assert ok is True and not any("未来" in b for b in blk)


def test_C12_message_warns_not_to_widen_into_the_future_C15():
    """🔴 C15 / acceptance 27: the C12 empty-window blocker must ALSO tell the operator not to widen
    the upper bound into the future — else the report itself teaches the hole (the natural reaction
    to '空窗口' is to widen the window; widening into the future turns the gate falsely green). RED
    input: a C12 blocker that hands over the observed window but omits the anti-widen clause."""
    x, y = 1737000000000000000, 1737000005000000000
    _c, blockers = report_citability(
        {
            "evidence_basis": "wal_anchored",
            "provenance": {
                "pinned": True,
                "wal_dir": "/w",
                "record_count": 0,
                "observed_window": [x, y],
                "wal_segments": {"sha256": "sha256:" + "a" * 64},
            },
            "report": {"integrity_summary": {"broken": 0}},
        }
    )
    blk = next(b for b in blockers if "锚不住" in b)
    assert (
        "不要把上界放宽到未来" in blk
    )  # the explicit anti-踩洞 clause (acceptance 27)
    assert (
        str(x) in blk and str(y) in blk
    )  # AND still hands over the copyable window (C12)


# --------------------------------------------------------------------------- #
# C14 — the window-family blockers apply only when a WAL source was DECLARED (wal_dir)
# --------------------------------------------------------------------------- #


def test_window_family_blockers_gate_on_wal_dir_not_a_result_C14():
    """🔴 C14: the window-family blockers apply only when this run DECLARED a WAL evidence source
    (provenance.wal_dir). A no-WAL bundle (a raw_model run, or a gateway run given no --wal) is
    anchored by corpus_sha + evidence_refs, NOT a window — so unpinned / empty-window / seghash must
    NOT fire. 🔴 The gate keys on INTENT (wal_dir), NOT a RESULT (mode / record_count): a run that
    NAMED --wal but read 0 records still has wal_dir set ⇒ C12 fires (the gate must not re-open C12)."""
    # no wal_dir ⇒ exempt: an unpinned no-WAL bundle is citable
    no_wal = {
        "evidence_basis": "wal_anchored",
        "provenance": {"pinned": False, "wal_segments": {}},
        "report": {"integrity_summary": {"broken": 0}},
    }
    citable, blockers = report_citability(no_wal)
    assert citable is True and blockers == []  # unpinned does NOT block a no-WAL bundle

    # a broken chain is NOT window-family — it still voids a no-WAL bundle
    broken = {**no_wal, "report": {"integrity_summary": {"broken": 1}}}
    c2, b2 = report_citability(broken)
    assert c2 is False and any("完整性破损" in b for b in b2)

    # 🔴 teeth (the C14-re-opens-C12 regression): a run that DECLARED --wal but read 0 records has
    # wal_dir SET ⇒ NOT exempt ⇒ the empty-window (C12) blocker fires. `mode: "active"` is exactly
    # what the pre-fix collect stamped for a 0-record run (record_count==0 ⇒ passive empty ⇒ mode
    # "active"), and the OLD `if mode != "active"` gate then EXEMPTED it from the very C12 blocker
    # built to catch it (returned (True, [])). The new gate ignores `mode` and keys on wal_dir, so
    # this now correctly blocks — RED before the fix, green after.
    declared_wal_empty = {
        "mode": "active",  # the pre-fix symptom; the new gate ignores it
        "evidence_basis": "wal_anchored",
        "provenance": {
            "pinned": True,
            "wal_dir": "/w",
            "record_count": 0,
            "observed_window": [100, 200],
            "generated_at_ns": 300,
            "wal_segments": {"sha256": "sha256:" + "a" * 64},
        },
        "report": {"integrity_summary": {"broken": 0}},
    }
    c3, b3 = report_citability(declared_wal_empty)
    assert c3 is False and any("锚不住" in b for b in b3)  # C12 fired despite wal_dir


def test_missing_generated_at_ns_on_pinned_run_is_not_citable_C15():
    """🔴 C15 fail-CLOSED (I-rule): a PINNED run that declared a WAL source (wal_dir) but carries NO
    generated_at_ns cannot prove its window is closed, so it BLOCKS — same repo posture as C12 (an
    unverifiable claim ⇒ refuse). 🔴 口径: every pre-C15 pinned bundle lacks this collect-time stamp,
    so they all become NOT citable until regenerated (intended). RED input: pinned + wal_dir +
    generated_at_ns absent — before this ruling C15 skipped silently ⇒ (True, [])."""
    citable, blockers = report_citability(
        {
            "evidence_basis": "wal_anchored",
            "provenance": {
                "pinned": True,
                "wal_dir": "/w",
                "record_count": 867,
                "window": [
                    1000,
                    2000,
                ],  # window present, but no stamp to check it against
                "wal_segments": {"sha256": "sha256:" + "a" * 64},
            },
            "report": {"integrity_summary": {"broken": 0}},
        }
    )
    assert citable is False
    assert any("generated_at_ns" in b and "重新采集" in b for b in blockers)

    # the SAME bundle WITH a valid stamp (>= window[1]) AND config is citable — the ruling blocks only
    # the unverifiable claim, it does not make every pinned run un-citable.
    ok, _b = report_citability(
        {
            "evidence_basis": "wal_anchored",
            "provenance": {
                "pinned": True,
                "wal_dir": "/w",
                "record_count": 867,
                "window": [1000, 2000],
                "generated_at_ns": 2000,
                "wal_segments": {"sha256": "sha256:" + "a" * 64},
                **_CONFIG,
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
    # a properly pinned run: wal_dir declared, window closed (generated_at_ns >= window[1]), and the
    # E3-h freeze-pack config declared ⇒ citable
    prov = {
        "pinned": True,
        "wal_dir": "/wal",
        "window": [100, 200],
        "generated_at_ns": 200,
        "wal_segments": {"sha256": "sha256:" + "a" * 64},
        **_CONFIG,
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
    # a run that declared a WAL source but is unpinned ⇒ not citable (window-family applies)
    bundle = serialize_self_contained_bundle(
        report,
        [_m("injection_catch_rate", 25 / 28, 28)],
        _REG,
        {"pinned": False, "wal_dir": "/w", "wal_segments": {}},
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


# --------------------------------------------------------------------------- #
# C16 — the citability verdict is versioned, so it is falsifiable
# --------------------------------------------------------------------------- #


def test_citability_criteria_version_is_serialized_with_the_verdict_C16():
    """🔴 C16 teeth ①: a citability verdict can NEVER be serialized without its criteria version —
    the self-contained bundle carries top-level `citability_criteria` next to citable/citable_blockers,
    and the report schema REQUIRES it. RED input: delete the serialize line, or the schema `required`
    entry — either makes this red."""
    import json
    from pathlib import Path

    report = evaluate(
        _REG,
        [_m("injection_catch_rate", 25 / 28, 28)],
        [],
        window=(0, 1),
        tenant_id="t",
    )
    bundle = serialize_self_contained_bundle(report, [], _REG, _PINNED)
    assert bundle["citability_criteria"] == CRITERIA_VERSION

    schema = json.loads(
        (Path(__file__).resolve().parents[1] / "docs" / "report.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert "citability_criteria" in schema["required"]
    assert "citability_criteria" in schema["properties"]


def test_criteria_version_is_bound_to_the_blocker_identity_set_C16():
    """🔴 C16 teeth ②: the version is pinned to the IDENTITY set of blockers this gate can emit.
    Changing CRITERIA_BLOCKERS (add / remove / repurpose a key) WITHOUT bumping CRITERIA_VERSION ⇒
    red. A wording-only edit to a `_*_FIX` string leaves CRITERIA_BLOCKERS untouched ⇒ this stays
    green (proving 文案改动 does not bump the version)."""
    assert (
        (CRITERIA_VERSION, CRITERIA_BLOCKERS)
        == (
            2,  # 1→2: E3-h added missing_run_config; E3-m + E3-n ③ FOLD into it (no re-bump); E3-n ④
            # adds build_fingerprint_changed — all folded into the SAME uncommitted v2, so VERSION stays 2.
            frozenset(
                {
                    "integrity_broken",
                    "pinned_empty_window",
                    "future_upper_bound",
                    "no_generated_at_ns",
                    "unpinned",
                    "missing_segment_hash",
                    "not_wal_anchored",
                    "missing_run_config",
                    "build_fingerprint_changed",  # E3-n ④ — the one new identity
                }
            ),
        )
    )


def test_criteria_blockers_count_matches_the_code_append_sites_C16():
    """🔴 C16 honesty: the number of blocker-append sites in report_citability's SOURCE must equal
    len(CRITERIA_BLOCKERS). Add a code blocker but forget its identity key (or vice versa) ⇒ counts
    diverge ⇒ red — closing the "added a code blocker but forgot the key set" gap. Uses source
    introspection (like the existing indicator-mechanism gate), NOT message matching, so a pure 文案
    edit to a `_*_FIX` string never trips it."""
    import inspect

    from treval import citability

    append_sites = inspect.getsource(citability.report_citability).count(
        "blockers.append("
    )
    assert append_sites == len(citability.CRITERIA_BLOCKERS), (
        f"{append_sites} blocker-append site(s) vs {len(citability.CRITERIA_BLOCKERS)} declared "
        "key(s) — add/remove a blocker ⇒ update CRITERIA_BLOCKERS (and bump CRITERIA_VERSION)"
    )


# --------------------------------------------------------------------------- #
# E3-h — the freeze pack must carry version + config + exec-mode (§3.1, acceptance 13)
# --------------------------------------------------------------------------- #


def _wal_run(**config):
    """A pinned, closed, wal_anchored run — citable EXCEPT for whatever config is missing."""
    prov = {
        "pinned": True,
        "wal_dir": "/w",
        "record_count": 5,
        "generated_at_ns": 20,
        "window": [1, 2],
        "wal_segments": {"sha256": "sha256:" + "a" * 64},
    }
    prov.update(config)
    return {
        "evidence_basis": "wal_anchored",
        "provenance": prov,
        "report": {"integrity_summary": {"broken": 0}},
    }


def test_missing_run_config_blocks_citation_acceptance13():
    """🔴 acceptance 13/22 (§3.1/§5): a wal_anchored run whose freeze pack lacks language_scope /
    version / config / exec-mode is NOT citable — "89%" without them is unscoped. Declaring all FOUR ⇒
    citable. RED input: a pinned+closed+wal_anchored run with any one scope key empty returned (True,
    [])."""
    # declared in full (all four scope fields) ⇒ citable
    ok, blk = report_citability(_wal_run(**_CONFIG))
    assert ok is True and blk == []
    # any one of the FOUR missing ⇒ NOT citable (language_scope included — E3-m)
    for missing in _CONFIG:
        full = dict(_CONFIG)
        full[missing] = ""  # present-but-empty
        citable, _b = report_citability(_wal_run(**full))
        assert citable is False, f"a run missing {missing} must not be citable"


def test_missing_config_two_messages_absent_vs_empty_E3h():
    """🔴 E3-h two-message teeth (timing-independent, absent-vs-empty):
    - keys PRESENT but EMPTY (a v2 run that didn't declare) ⇒ "补声明重跑" (--tested-version/...);
    - keys ABSENT entirely (a pre-E3 bundle) ⇒ diagnosed as DRIFT, "旧判据 … 重跑即可引", NOT a defect.
    🔴 RED input each: an empty-keys run must not read as a pre-E3 drift, and vice versa."""
    # present-but-empty (all four scope keys present, empty) ⇒ the "declare it and re-run" message
    _c, empty_blk = report_citability(_wal_run(**{k: "" for k in _CONFIG}))
    empty_msg = next(b for b in empty_blk if "版本" in b and "执行模式" in b)
    assert "补声明重跑" in empty_msg and "--tested-version" in empty_msg
    assert "旧判据" not in empty_msg  # NOT the pre-E3 drift diagnosis

    # keys absent entirely ⇒ the pre-E3 DRIFT diagnosis (mirrors C16's stored-vs-recompute face)
    _c2, absent_blk = report_citability(_wal_run())  # no config keys at all
    absent_msg = next(b for b in absent_blk if "版本" in b and "执行模式" in b)
    assert "旧判据" in absent_msg and "重新采集" in absent_msg
    assert "不是坏了" in absent_msg  # drift, not a defect
    assert "补声明重跑" not in absent_msg  # NOT the didn't-declare message


def test_missing_run_config_is_one_identity_scoped_to_wal_anchored_E3h():
    """🔴 the config blocker is ONE identity (missing_run_config) and, like C12/C15, is wal_anchored/
    wal_dir-scoped: a pure-active run (present provenance, no wal_dir) is NOT blocked for missing
    config (a window/config pins nothing there)."""
    pure_active = {
        "evidence_basis": "wal_anchored",
        "provenance": {
            "pinned": False,
            "wal_segments": {},
        },  # present, no wal_dir ⇒ exempt
        "report": {"integrity_summary": {"broken": 0}},
    }
    ok, blk = report_citability(pure_active)
    assert ok is True and blk == []  # no config blocker for a no-WAL run


def test_citation_form_carries_the_run_config_acceptance13():
    """🔴 acceptance 13: a quoted number states which version / config / exec-mode it was measured
    under — the delivery bundle's citation_form contains all three. RED input: a citation_form built
    from a declared run that DROPS any of them (before E3-h citation_form had no config clause)."""
    ms = [_m("injection_catch_rate", 25 / 28, 28)]
    report = evaluate(_REG, ms, [], window=(100, 200), tenant_id="t")
    prov = {
        "pinned": True,
        "wal_dir": "/wal",
        "generated_at_ns": 200,
        "window": [100, 200],
        "wal_segments": {"sha256": "sha256:" + "a" * 64},
        **_CONFIG,
    }
    bundle = serialize_self_contained_bundle(report, ms, _REG, prov)
    assert bundle["citable"] is True
    form = bundle["measurements"][0]["citation_form"]
    assert "deepseek-v4-flash@2026-01-30" in form  # version
    assert "encode_decode=off" in form  # detection config
    assert "拦截" in form  # exec mode (block → 拦截(命中即拒))
    assert "被测方" in form and "检测配置" in form and "执行模式" in form
    # E3-m: language_scope is the #1 axis — present AND leads (before 被测方 / version)
    assert _CONFIG["language_scope"] in form and "作用域" in form
    assert form.index("作用域") < form.index("被测方")


# --------------------------------------------------------------------------- #
# E3-m — language_scope folds into the SAME missing_run_config criterion (§5, acceptance 22)
# --------------------------------------------------------------------------- #


def test_language_scope_missing_blocks_citation_acceptance22():
    """🔴 acceptance 22 (§5): language_scope is the #1 scope axis and folds into the SAME
    missing_run_config criterion — a run declaring version/config/exec-mode but NOT language_scope is
    NOT citable. Same two-message split as E3-h: present-but-empty ⇒ "补声明重跑"; absent ⇒ drift.
    RED input: the three config keys declared but language_scope empty/absent returned citable before E3-m."""
    others = {
        "tested_version": "v4@2026-01-30",
        "detect_config": "encode_decode=off",
        "exec_mode": "block",
        # E3-n ③: the other two required config fields, so only language_scope is under test here
        "detection_layer_status": "tier1_only",
        "upstream_timeout_s": 60.0,
    }
    # language_scope present-but-empty ⇒ not citable, "补声明重跑"
    _c, empty_blk = report_citability(_wal_run(language_scope="", **others))
    assert _c is False
    assert any("补声明重跑" in b for b in empty_blk)
    # language_scope absent (others declared) ⇒ not citable, DRIFT (a criterion field is missing entirely)
    _c2, absent_blk = report_citability(_wal_run(**others))
    assert _c2 is False
    assert any("旧判据" in b and "不是坏了" in b for b in absent_blk)
    # all four declared ⇒ citable
    ok, blk = report_citability(_wal_run(language_scope="英文为主", **others))
    assert ok is True and blk == []


def test_language_scope_is_declared_never_derived_from_case_content_acceptance22():
    """🔴 acceptance 22 (§5) REVERSE: language_scope is an operator DECLARATION (the --language-scope
    flag → provenance), NEVER inferred by scanning case/measurement content. This batch is
    English-majority but CONTAINS cross-language cases, so a "scan the cases and guess the language"
    implementation would mislabel it — this test REDs such an implementation.
    - an EMPTY language_scope is NOT rescued by rich measurement content (no inference makes it citable);
    - the declared scope rides into citation_form VERBATIM, UNCHANGED by measurement content;
    - run_config_note takes ONLY provenance — it structurally cannot scan cases."""
    base_prov = {
        "pinned": True,
        "wal_dir": "/wal",
        "generated_at_ns": 200,
        "window": [100, 200],
        "wal_segments": {"sha256": "sha256:" + "a" * 64},
        "tested_version": "v4@2026-01-30",
        "detect_config": "encode_decode=off",
        "exec_mode": "block",
        # E3-n ③: the other two required config fields (so a declared language_scope makes it citable)
        "detection_layer_status": "tier1_only",
        "upstream_timeout_s": 60.0,
    }
    ms = [_m("injection_catch_rate", 25 / 28, 28)]
    report = evaluate(_REG, ms, [], window=(100, 200), tenant_id="t")

    # ① empty language_scope + real measurements ⇒ still NOT citable (nothing inferred from content)
    b0 = serialize_self_contained_bundle(
        report, ms, _REG, {**base_prov, "language_scope": ""}
    )
    assert (
        b0["citable"] is False
    )  # scanning ms does NOT rescue an undeclared language_scope

    # ② declared scope rides VERBATIM and does not depend on measurement content
    declared = "英文为主 · 含跨语言手法件 · 中文金融流量未测"
    prov = {**base_prov, "language_scope": declared}
    ms_b = [_m("injection_catch_rate", 0.40, 40)]  # different content
    rep_b = evaluate(_REG, ms_b, [], window=(100, 200), tenant_id="t")
    form_a = serialize_self_contained_bundle(report, ms, _REG, prov)["measurements"][0][
        "citation_form"
    ]
    form_b = serialize_self_contained_bundle(rep_b, ms_b, _REG, prov)["measurements"][
        0
    ]["citation_form"]
    assert (
        declared in form_a and declared in form_b
    )  # verbatim from provenance, not derived
    # the scope clause is byte-identical across the two different-content runs
    scope_a = form_a[form_a.index("作用域") : form_a.index("· 被测方")]
    scope_b = form_b[form_b.index("作用域") : form_b.index("· 被测方")]
    assert scope_a == scope_b

    # ③ run_config_note takes ONLY provenance — structurally cannot scan cases/measurements
    import inspect

    from treval.citability import run_config_note

    assert list(inspect.signature(run_config_note).parameters) == ["provenance"]
