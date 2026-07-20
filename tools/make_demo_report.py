"""Generate the SYNTHETIC demo report for the public whitepaper (pre-sales option B).

Hard constraint (PM): the data must be 100% synthetic — never a real tenant (not `acme`, not
`__eval__`, not any live traffic). A generator with hard-coded values satisfies that provably:
every number below is auditably fabricated, right here in the source.

What it demonstrates — and why it is a GENUINE engine output, not a hand-drawn picture:
the synthetic measurements + posture go through the real `evaluate()`. The engine itself
- catches a **fabricated over-claim**: robustness is self-attested to L3, but the only measured
  evidence (injection_catch_rate) supports L2 — no boundary_breach_rate, so L3 can't be earned.
  The gap is computed by the engine, not written by us.
- refuses a **total score**: `MaturityReport` has no overall level; we don't add one.
The other four dimensions are made consistent (measured supports what's attested) so the demo
shows the engine flags the real over-claim, not everything.

    python -m tools.make_demo_report --out-dir reports/store
"""

from __future__ import annotations

import argparse
import sys

from treval.models import (
    EvidenceRef,
    IntegrityStatus,
    Measurement,
    PostureEvidence,
)
from treval.registry import load_registry
from treval.report_store import write_bundle
from treval.rubric import evaluate, self_contained_bundle_to_json

TENANT = "demo-fintech"  # a fictional fintech — obviously not a real customer
# Fixed synthetic window + generated_at so the demo is reproducible (same bytes → same digest,
# idempotent in the store). 2026-01-01 00:00–00:10 UTC, in ns.
WINDOW = (1767225600_000000000, 1767226200_000000000)
GENERATED_AT_NS = 1767226200_000000000

_REF = EvidenceRef(source="wal:/demo/synthetic.wal", seq=1, request_id="demo-000001")

# The report must declare itself synthetic ON THE PAGE, not only in this file's header. The
# SYNTHETIC banner above is read by us; a screenshot is read by everyone else — and that is
# the exact path by which this generator's fabricated `chain_integrity n=520` reached an
# external document (PROV §5). `pinned:false` is not a slip: pinning is meaningless for data
# that was never measured, and claiming it would be the same lie in a smaller font.
PROVENANCE = {
    "data_source": "synthetic_demo",
    "pinned": False,
    "tenant_id": TENANT,
    "window": list(WINDOW),
    "wal_dir": None,
    "wal_segments": None,
    "record_count": 0,
}


def _m(indicator: str, dimension: str, value: float, unit: str, n: int) -> Measurement:
    """One synthetic aggregate measurement. All VERIFIED (a clean demo); refs are synthetic."""
    return Measurement(
        indicator_id=indicator,
        dimension=dimension,
        value=value,
        unit=unit,
        sample_size=n,
        evidence_refs=tuple(_REF for _ in range(n)),
        subject="",
        integrity=IntegrityStatus.VERIFIED,
    )


# --- synthetic measurements (auditably fake) ---------------------------------------------
MEASUREMENTS = (
    # robustness: injection backs L2; NO boundary_breach_rate → L3 measured stays unearned.
    _m("injection_catch_rate", "robustness", 0.91, "ratio", 240),
    # efficient_reliability: a HEALTHY latency baseline — 780 ms, not 60 s (good demo optics).
    _m("duration_p99", "efficient_reliability", 780.0, "ms", 240),
    _m("terminal_error_ratio", "efficient_reliability", 0.008, "ratio", 240),
    # security_alignment: L3 measured both pass.
    _m("tool_scope_violation_rate", "security_alignment", 0.0, "ratio", 200),
    _m("block_rate", "security_alignment", 0.42, "ratio", 200),
    # transparency_accountability: L3 + L4 baseline.
    _m("unclosed_loop_rate", "transparency_accountability", 0.0, "ratio", 240),
    _m("chain_integrity", "transparency_accountability", 1.0, "ratio", 520),
    # privacy_data_protection: L2 redaction + L4 baseline; clean.
    _m("redaction_hit_ratio", "privacy_data_protection", 0.97, "ratio", 240),
    _m("pii_exposure_surface", "privacy_data_protection", 0.0, "count", 240),
)


def _p(key: str) -> PostureEvidence:
    return PostureEvidence(
        ref=_REF,
        tenant_id=TENANT,
        key=key,
        value="true",
        attested_by="demo-ciso@demo-fintech",
        attested_at_ns=GENERATED_AT_NS,
    )


# --- synthetic posture: self-attested HIGH. robustness→L3 is the fabricated over-claim. ---
POSTURE = tuple(
    _p(k)
    for k in (
        # robustness L2 + L3 (measured only backs L2 → the engine flags L3 as over-claim)
        "robustness.adversarial_test_ledger",
        "robustness.model_version_freeze",
        "robustness.adversarial_suite_standardized",
        "robustness.change_triggers_regression",
        # efficient_reliability L2 + L3 (all-attested; L4 measured backs the baseline)
        "efficient_reliability.capacity_monitoring",
        "efficient_reliability.recovery_runbook",
        "efficient_reliability.train_infer_logical_isolation",
        "efficient_reliability.lb_failover_healthcheck",
        "efficient_reliability.sla_99_5",
        "efficient_reliability.iac_provisioned",
        "efficient_reliability.train_infer_network_isolation",
        # security_alignment L2 + L3
        "security_alignment.sso_mfa",
        "security_alignment.independent_nhi",
        "security_alignment.initial_risk_assessment",
        "security_alignment.ai_incident_response",
        "security_alignment.acceptable_use_policy",
        "security_alignment.dual_identity_chain",
        "security_alignment.actions_to_siem",
        "security_alignment.supply_chain_inventory",
        "security_alignment.cicd_security_checks",
        # transparency_accountability L2 + L3
        "transparency_accountability.ai_asset_inventory",
        "transparency_accountability.min_logging_retention",
        "transparency_accountability.approval_owner_documented",
        "transparency_accountability.deployment_registry",
        "transparency_accountability.ai_council",
        "transparency_accountability.role_based_training",
        # privacy_data_protection L2
        "privacy_data_protection.retention_deletion_process",
        "privacy_data_protection.pia_trigger_conditions",
    )
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="make_demo_report", description=__doc__)
    ap.add_argument("--out-dir", required=True, help="report store directory")
    args = ap.parse_args(argv)

    registry = load_registry()
    report = evaluate(
        registry,
        MEASUREMENTS,
        POSTURE,
        window=WINDOW,
        tenant_id=TENANT,
    )
    entry = write_bundle(
        args.out_dir,
        self_contained_bundle_to_json(report, MEASUREMENTS, registry, PROVENANCE),
        generated_at_ns=GENERATED_AT_NS,
    )

    gaps = sum(len(d.gaps) for d in report.dimensions)
    print(f"stored {entry.file}  tenant={TENANT}  window={entry.window}")
    for d in report.dimensions:
        print(
            f"  {d.dimension:28} 实测 {str(d.measured_ceiling or '—'):5} "
            f"声明 {str(d.attested_ceiling or '—'):5} 授级 {str(d.awarded_level or '—'):5} "
            f"gaps {len(d.gaps)}"
        )
    print(f"  total over-claim gaps the engine caught: {gaps}")
    print(
        "  overall score the engine emitted: (none — MaturityReport has no total level)"
    )
    if gaps == 0:
        print(
            "WARNING: demo shows no over-claim — not a compelling demo", file=sys.stderr
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
