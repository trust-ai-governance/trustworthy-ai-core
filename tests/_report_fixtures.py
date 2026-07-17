"""EV-R1 — the golden self-contained report bundles, GENERATED from the real serializer.

Both the committed `tests/fixtures/report/valid/*.json` and the drift-guard test call
`generate()`. Any change to the engine / serializer / shipped registry that would alter the
UI contract changes this output and fails the drift-guard (regenerate with UPDATE_FIXTURES=1).
Deterministic: fixed inputs + the byte-stable `self_contained_bundle_to_json`.
"""

from __future__ import annotations

from treval import evaluate, load_registry, self_contained_bundle_to_json
from treval.models import EvidenceRef, IntegrityStatus, Measurement, PostureEvidence

_WINDOW = (1782000000000000000, 1782000600000000000)
_TENANT = "dogfood"
_V = IntegrityStatus.VERIFIED
_U = IntegrityStatus.UNVERIFIED
_B = IntegrityStatus.BROKEN
_REF = (EvidenceRef(source="wal:/wal/000..018.wal", seq=7, request_id="req-000007"),)


def _m(
    indicator_id,
    dimension,
    value,
    *,
    sample_size=50,
    subject="",
    integrity=_V,
    unit="ratio",
):
    return Measurement(
        indicator_id=indicator_id,
        dimension=dimension,
        value=value,
        unit=unit,
        sample_size=sample_size,
        subject=subject,
        integrity=integrity,
        evidence_refs=_REF,
        notes="",
    )


def _posture(key):
    return PostureEvidence(
        ref=EvidenceRef(source="attest:posture.yaml"),
        tenant_id=_TENANT,
        key=key,
        value="true",
        attested_by="ciso@corp",
        attested_at_ns=0,
    )


# Real registry posture_keys — robustness attested to L3, security to L3.
_ROBUSTNESS_L3 = [
    _posture(k)
    for k in (
        "robustness.adversarial_test_ledger",
        "robustness.model_version_freeze",
        "robustness.adversarial_suite_standardized",
        "robustness.change_triggers_regression",
    )
]
_SECURITY_L3 = [
    _posture(k)
    for k in (
        "security_alignment.sso_mfa",
        "security_alignment.independent_nhi",
        "security_alignment.initial_risk_assessment",
        "security_alignment.ai_incident_response",
        "security_alignment.acceptable_use_policy",
        "security_alignment.dual_identity_chain",
        "security_alignment.actions_to_siem",
        "security_alignment.supply_chain_inventory",
        "security_alignment.cicd_security_checks",
    )
]


def _inputs():
    """name → (measurements, posture). One self-contained bundle is generated per entry."""
    return {
        # 1. rich — measured + attested mix across dimensions, non-empty gaps.
        "rich": (
            [
                _m("injection_catch_rate", "robustness", 0.92, sample_size=34),
                _m(
                    "chain_integrity",
                    "transparency_accountability",
                    1.0,
                    sample_size=120,
                ),
                _m(
                    "tool_scope_violation_rate",
                    "security_alignment",
                    0.0,
                    sample_size=12,
                ),
                _m("block_rate", "security_alignment", 0.25, sample_size=40),
            ],
            _ROBUSTNESS_L3 + _SECURITY_L3,
        ),
        # 2. all_not_measured — no measurements → every measured objective insufficient_data.
        "all_not_measured": ([], []),
        # 3. over_claim_gaps — attested L3 but measurement backs only L2 → gaps[].
        "over_claim_gaps": (
            [_m("injection_catch_rate", "robustness", 0.9, sample_size=34)],
            _ROBUSTNESS_L3,
        ),
        # 4. insufficient_data — sample_size 0 → insufficient_data (not unmet).
        "insufficient_data": (
            [_m("injection_catch_rate", "robustness", 0.0, sample_size=0)],
            [],
        ),
        # 5. verification_basis — VERIFIED + UNVERIFIED + BROKEN → hybrid; all 3 summary keys.
        "verification_basis": (
            [
                _m(
                    "injection_catch_rate",
                    "robustness",
                    0.9,
                    sample_size=34,
                    integrity=_V,
                ),
                _m(
                    "chain_integrity",
                    "transparency_accountability",
                    1.0,
                    sample_size=120,
                    integrity=_U,
                ),
                _m(
                    "boundary_breach_rate",
                    "robustness",
                    0.1,
                    sample_size=50,
                    integrity=_B,
                ),
            ],
            [],
        ),
        # 6. per_subject — measurements with subject != "" (per-entity breakdown).
        "per_subject": (
            [
                _m("injection_catch_rate", "robustness", 0.9, sample_size=34),
                _m(
                    "token_cost_per_agent",
                    "efficient_reliability",
                    1820.0,
                    sample_size=12,
                    subject="agent-1",
                    unit="tokens",
                ),
                _m(
                    "token_cost_per_agent",
                    "efficient_reliability",
                    640.0,
                    sample_size=5,
                    subject="agent-2",
                    unit="tokens",
                ),
            ],
            [],
        ),
    }


def generate() -> dict[str, str]:
    """name → self-contained bundle JSON (byte-deterministic)."""
    registry = load_registry()
    out: dict[str, str] = {}
    for name, (measurements, posture) in _inputs().items():
        report = evaluate(
            registry, measurements, posture, window=_WINDOW, tenant_id=_TENANT
        )
        out[name] = self_contained_bundle_to_json(report, measurements, registry)
    return out
