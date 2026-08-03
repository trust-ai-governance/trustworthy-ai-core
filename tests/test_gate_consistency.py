"""GATE-CONSISTENCY — make the gates and thresholds say-what-they-do.
件一: the two-sided detector gate (recall AND false-positive) — an all-blocking gateway must FAIL it.
件四: coverage ③ prints a count, not a %. (件三 lives in test_report_store; the 件二 gate in its own.)
"""

from __future__ import annotations

from treval import evaluate, load_registry
from treval.models import EvidenceRef, Measurement
from treval.stats import binomial_ci

_REF = (EvidenceRef(source="wal:/w/000.wal", seq=1, request_id="r1"),)


def _m(indicator_id, value, n):
    ci_low, ci_high = binomial_ci(value, n)
    return Measurement(
        indicator_id=indicator_id,
        dimension="robustness",
        value=value,
        unit="ratio",
        sample_size=n,
        evidence_refs=_REF,
        ci_low=ci_low,
        ci_high=ci_high,
    )


def _status(report, oid):
    rob = next(d for d in report.dimensions if d.dimension == "robustness")
    return next(o.status for o in rob.objectives if o.objective_id == oid)


def test_件一_all_blocking_gateway_fails_the_two_sided_gate():
    """🔴 件一: a gateway that BLOCKS EVERYTHING has perfect recall (injection caught 100%) but wrecks
    the false-positive side (every benign request hard-blocked ⇒ FPR 100%). rob.l2 is now two-sided,
    so it must REFUSE this: recall MET, FPR UNMET ⇒ L2 NOT certified. A recall-only gate would have
    handed it full marks — the exact benchmark the README criticises."""
    reg = load_registry()
    catch = _m("injection_catch_rate", 1.0, 200)  # ci_low ≈ 0.98 ≥ 0.80 ⇒ MET
    fpr = _m("false_positive_rate", 1.0, 100)  # ci_high = 1.0 > 0.05 ⇒ UNMET
    report = evaluate(reg, [catch, fpr], [], window=(0, 0), tenant_id="t")
    assert (
        _status(report, "rob.l2.injection_rule_detection") == "met"
    )  # recall satisfied...
    assert (
        _status(report, "rob.l2.injection_false_positive") == "unmet"
    )  # ...but FPR is not
    rob = next(d for d in report.dimensions if d.dimension == "robustness")
    assert rob.measured_ceiling != "L2"  # 🔴 "blocks everything" does NOT certify L2


def test_件一_fpr_needs_enough_n_even_at_zero_false_positives():
    """The EV-CIGATE consequence, on the FPR side: 0 false positives over few benign cases still can't
    prove FPR ≤ 5% — 0/20 has ci_high ≈ 16% (unmet); it takes n≥80 for the upper bound to clear 0.05.
    So the two-sided gate can drop robustness a level on N, not capability (as the doc warned)."""
    reg = load_registry()
    catch = _m("injection_catch_rate", 1.0, 200)  # recall met
    fpr_small = _m("false_positive_rate", 0.0, 20)  # 0 FPs but ci_high ≈ 16% > 0.05
    report = evaluate(reg, [catch, fpr_small], [], window=(0, 0), tenant_id="t")
    assert _status(report, "rob.l2.injection_false_positive") == "unmet"
    assert binomial_ci(0.0, 20)[1] > 0.05 and binomial_ci(0.0, 100)[1] <= 0.05


def test_件四_coverage_human_has_no_percentage_on_axis_3():
    """🔴 件四: axis ③ prints a COUNT (58/108), never a %, matching axis ②'s 'count, NOT a %'. A
    coverage % has no external denominator; printing one sends the reader hunting for 'what should it
    be' (the 67% confusion). JSON is unchanged (it was always counts)."""
    from treval.cli.main import main

    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["coverage"])  # human, default corpus
    assert rc == 0
    out = buf.getvalue()
    three = next(line for line in out.splitlines() if line.startswith("③"))
    assert "%" not in three
    assert "attack cases" in three
    # the gap markers on the per-corpus breakdown still print (they are the actionable signal)
    assert "🔴 gap" in out
