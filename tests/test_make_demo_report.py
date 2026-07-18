"""The synthetic demo report for the public whitepaper (PM pre-sales option B).

The demo MUST be a genuine engine output over 100% synthetic data — never a real tenant —
and it must actually demonstrate the two claims (an over-claim the engine catches, and no
total score). These tests pin all of that so the whitepaper figure can't silently rot.
"""

from __future__ import annotations

import json

from tools.make_demo_report import MEASUREMENTS, POSTURE, TENANT, main
from treval.registry import load_registry, serialize_registry
from treval.report_store import ReportStore


def _generate(tmp_path):
    assert main(["--out-dir", str(tmp_path)]) == 0
    store = ReportStore(tmp_path)
    entry = store.list()[0]
    return json.loads(store.read_bytes(entry)), entry


def test_demo_tenant_is_synthetic_never_a_real_one(tmp_path):
    """Hard constraint: the demo data is fabricated, never a live tenant."""
    bundle, entry = _generate(tmp_path)
    assert TENANT == "demo-fintech"
    assert entry.tenant_id == "demo-fintech"
    assert entry.tenant_id not in {"acme", "__eval__", "dogfood"}
    assert bundle["report"]["tenant_id"] == "demo-fintech"


def test_engine_catches_a_fabricated_over_claim(tmp_path):
    """The over-claim is COMPUTED by evaluate(), not written by us: robustness is attested to
    L3 while the only measured evidence backs L2, so the engine flags the gap itself."""
    bundle, _ = _generate(tmp_path)
    dims = {d["dimension"]: d for d in bundle["report"]["dimensions"]}
    rob = dims["robustness"]
    assert rob["measured_ceiling"] == "L2"
    assert rob["attested_ceiling"] == "L3"
    assert (
        rob["awarded_level"] == "L2"
    )  # min(measured, attested) — the claim can't lift it
    assert len(rob["gaps"]) >= 1, "engine did not flag the fabricated over-claim"


def test_demo_flags_the_real_gap_not_everything(tmp_path):
    """A demo where every dimension is flagged proves nothing. Exactly the over-claimed
    dimension carries gaps; the consistent ones do not."""
    bundle, _ = _generate(tmp_path)
    gapped = {d["dimension"] for d in bundle["report"]["dimensions"] if d["gaps"]}
    assert gapped == {"robustness"}, gapped


def test_demo_emits_no_total_score(tmp_path):
    """The report is per-dimension; there is no overall level anywhere in it."""
    bundle, _ = _generate(tmp_path)
    report = bundle["report"]
    assert "overall_level" not in report and "total_score" not in report
    # every graded fact is scoped to a dimension
    assert {d["dimension"] for d in report["dimensions"]} == {
        "efficient_reliability",
        "privacy_data_protection",
        "robustness",
        "security_alignment",
        "transparency_accountability",
    }


def test_demo_is_deterministic(tmp_path):
    """Fixed window + generated_at → same bytes → same content digest → idempotent store."""
    b1, e1 = _generate(tmp_path / "a")
    b2, e2 = _generate(tmp_path / "b")
    assert e1.file == e2.file  # content-addressed: identical digest


def test_demo_posture_keys_all_exist_in_the_registry(tmp_path):
    """A typo'd posture key attests nothing — the demo would silently under-claim."""
    reg = serialize_registry(load_registry())
    keys = {
        o["posture_key"]
        for d in reg["dimensions"]
        for objs in d["levels"].values()
        for o in objs
        if o["kind"] == "attested"
    }
    bad = [p.key for p in POSTURE if p.key not in keys]
    assert not bad, f"posture keys not in registry: {bad}"
    # and the synthetic measurements name real indicators
    assert all(m.indicator_id for m in MEASUREMENTS)
