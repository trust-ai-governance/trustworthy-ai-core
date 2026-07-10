"""EV-8 — the operator `collect` logic, exercised WITHOUT a gateway via a fake Target.

Proves the D3 curation contract (§3/§7): every bound id yields exactly one aggregate
Measurement, so the bundle feeds `report` with no DuplicateIndicatorError; and that a
failing producer aggregates to a warning instead of crashing the run (§5)."""

from __future__ import annotations

from pathlib import Path

from treval.active_eval.target import ProbeResult
from treval.cli.bundle import build_bundle, load_bundle
from treval.cli.collect import CURATION, collect_measurements
from treval.rubric import evaluate
from treval.registry import load_registry

_CORPUS = Path(__file__).resolve().parents[1] / "corpus"


class _FakeTarget:
    """Returns a canned governed ProbeResult — enough for the indicators to produce a
    (possibly zero-sample) aggregate Measurement, no network."""

    target_id = "fake"

    def probe(self, case):
        return ProbeResult(
            case_id=case.id,
            request_id="req-x",
            decision="BLOCK",
            response_text="",
            evidence=None,
        )


def test_collect_yields_one_aggregate_per_bound_id():
    warnings: list[str] = []
    measurements = collect_measurements(
        _FakeTarget(), corpus_root=_CORPUS, warnings=warnings
    )
    assert warnings == []
    ids = [m.indicator_id for m in measurements]
    assert ids == [p.indicator_id for p in CURATION]  # one per curated producer
    # every produced Measurement is an aggregate (binds to a rubric objective)
    assert all(m.subject == "" for m in measurements)


def test_collected_bundle_feeds_report_without_duplicate_error():
    warnings: list[str] = []
    measurements = collect_measurements(
        _FakeTarget(), corpus_root=_CORPUS, warnings=warnings
    )
    doc = build_bundle(measurements, tenant_id="__eval__", window=(0, 0), mode="active")
    # round-trip through the bundle, then grade — the §7 acceptance (no DuplicateIndicatorError)
    import json
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "bundle.json"
        p.write_text(json.dumps(doc), encoding="utf-8")
        loaded = load_bundle(p)
    report = evaluate(
        load_registry(),
        loaded.measurements,
        [],
        window=loaded.window,
        tenant_id=loaded.tenant_id,
    )
    # robustness has the injection measurement bound; grading completes cleanly.
    assert {d.dimension for d in report.dimensions} == set(load_registry().dimensions)


def test_failing_producer_aggregates_to_warning(tmp_path):
    """A corpus root missing the curated subdirs → every producer fails → warnings, no
    raise, empty measurement set (report will render insufficient_data)."""
    warnings: list[str] = []
    measurements = collect_measurements(
        _FakeTarget(), corpus_root=tmp_path, warnings=warnings
    )
    assert measurements == ()
    assert len(warnings) == len(CURATION)
    assert all("failed" in w for w in warnings)
