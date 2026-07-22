"""Deterministic JSON serialization of a MaturityReport bundle (EV-7 §1 / EV-R1).

Emits the report-bundle envelope defined in `docs/REPORT_JSON_SCHEMA.md`: the rubric
verdict PLUS the measurements that fed it (the report stores only pass/fail, the UI wants
both). Pure — `json`/`hashlib` + the frozen dataclasses + the canonical registry serializer
(`treval.registry.serialize`). The engine NEVER imports the web layer (tests/test_layering.py).

Determinism (the EV-7 byte-identical requirement): object keys sorted, and every array
has a DEFINED order independent of insertion — `dimensions`/`objectives` in the engine's
(registry) order, `measurements` by `(indicator_id, subject)`, `evidence_refs` by
`(source, seq)`, `gaps` already sorted by the engine.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from treval.models import (
    DimensionReport,
    EvidenceRef,
    MaturityReport,
    Measurement,
    ObjectiveResult,
)
from treval.registry import DimensionRegistry, serialize_registry

SCHEMA_VERSION = 2  # R1: bundle top level gains target_kind + derived evidence_basis

# --- R1 — target_kind (report-level) + evidence_basis (DERIVED, single source of truth) ---
# target_kind names WHAT was evaluated; evidence_basis is its evidence strength and is NEVER
# stored independently — it is computed from target_kind here (R1 裁定 A). A new target_kind is
# ONE row below; do NOT invent an evidence_basis input. (`availability`/`evidence_requirement`
# are EV-FWD, not R1 — see R1 §1.5-A.)
TARGET_KINDS = ("raw_model", "gateway", "moderation_api")
DEFAULT_TARGET_KIND = "gateway"  # every current report is a gateway run (R1 §1.5-B)

_EVIDENCE_BASIS = {
    "gateway": "wal_anchored",  # WAL 锚定 · 可复算 · 最强
    "raw_model": "harness_observed",  # harness 自观测 · 中
    "moderation_api": "self_reported",  # 厂商自报 · 最弱 · 不可复算
}


def derive_evidence_basis(target_kind: str) -> str:
    """The evidence strength implied by a target_kind — the single source of truth for
    evidence_basis (R1 裁定 A). Fail-closed on an unknown target_kind so a typo cannot
    silently ship a bundle with no evidence tier."""
    try:
        return _EVIDENCE_BASIS[target_kind]
    except KeyError:
        raise ValueError(
            f"unknown target_kind {target_kind!r}; expected one of {TARGET_KINDS}"
        ) from None


def assert_evidence_basis_derived(target_kind: str, evidence_basis: str) -> None:
    """Machine gate (R1 §2): a bundle's evidence_basis MUST equal derive(target_kind). The
    serializers always compute it that way; this guards a future regression that reintroduces
    independent setting (a param / a stored field) — such a bundle FAILS here instead of
    silently shipping a mislabelled evidence tier. 靠门不靠人。"""
    expected = derive_evidence_basis(target_kind)
    if evidence_basis != expected:
        raise ValueError(
            f"evidence_basis {evidence_basis!r} != derive({target_kind!r})={expected!r} "
            "— evidence_basis is derived from target_kind, never stored independently "
            "(R1 裁定 A)"
        )


def _ref_sort_key(ref: EvidenceRef) -> tuple[str, bool, int, str]:
    """Total order over refs (seq may be None → sorts last within a source)."""
    return (ref.source, ref.seq is None, ref.seq or 0, ref.request_id or "")


def _serialize_ref(ref: EvidenceRef) -> dict[str, Any]:
    return {"source": ref.source, "seq": ref.seq, "request_id": ref.request_id}


def _serialize_refs(refs: tuple[EvidenceRef, ...]) -> list[dict[str, Any]]:
    return [_serialize_ref(r) for r in sorted(refs, key=_ref_sort_key)]


def _serialize_objective(obj: ObjectiveResult) -> dict[str, Any]:
    return {
        "objective_id": obj.objective_id,
        "kind": obj.kind,
        "status": obj.status,
        "evidence_refs": _serialize_refs(obj.evidence_refs),
    }


def _serialize_dimension(dim: DimensionReport) -> dict[str, Any]:
    return {
        "dimension": dim.dimension,
        "measured_ceiling": dim.measured_ceiling,
        "attested_ceiling": dim.attested_ceiling,
        "awarded_level": dim.awarded_level,
        "objectives": [_serialize_objective(o) for o in dim.objectives],
        "gaps": list(dim.gaps),
    }


def serialize_report(report: MaturityReport) -> dict[str, Any]:
    """The `report` half of the bundle (REPORT_JSON_SCHEMA §2)."""
    return {
        "tenant_id": report.tenant_id,
        "window": list(report.window),
        "dimensions": [_serialize_dimension(d) for d in report.dimensions],
        "integrity_summary": dict(report.integrity_summary),
        "verification_basis": report.verification_basis,
    }


def serialize_measurement(m: Measurement) -> dict[str, Any]:
    """A `measurements[]` entry. `integrity` (EV-7 D1) rides along so the UI can show the
    trust basis of each value without a live call."""
    return {
        "indicator_id": m.indicator_id,
        "dimension": m.dimension,
        "value": m.value,
        "unit": m.unit,
        "sample_size": m.sample_size,
        "subject": m.subject,
        "notes": m.notes,
        "integrity": m.integrity.value,
        "evidence_refs": _serialize_refs(m.evidence_refs),
    }


def serialize_bundle(
    report: MaturityReport,
    measurements: Iterable[Measurement],
    *,
    target_kind: str = DEFAULT_TARGET_KIND,
) -> dict[str, Any]:
    """The full report bundle: `{schema_version, target_kind, evidence_basis, report,
    measurements}`. `target_kind` (report-level, R1) names what was evaluated; `evidence_basis`
    is DERIVED from it, never an input. Measurements are sorted by `(indicator_id, subject)`
    for a stable array order (REPORT_JSON_SCHEMA §3)."""
    ordered = sorted(measurements, key=lambda m: (m.indicator_id, m.subject))
    evidence_basis = derive_evidence_basis(target_kind)
    assert_evidence_basis_derived(target_kind, evidence_basis)  # single source of truth
    return {
        "schema_version": SCHEMA_VERSION,
        "target_kind": target_kind,
        "evidence_basis": evidence_basis,
        "report": serialize_report(report),
        "measurements": [serialize_measurement(m) for m in ordered],
    }


def bundle_to_json(
    report: MaturityReport,
    measurements: Iterable[Measurement],
    *,
    target_kind: str = DEFAULT_TARGET_KIND,
) -> str:
    """Byte-identical (up to encoding) JSON for the bundle: sorted keys + compact, stable
    separators. `ensure_ascii=False` keeps the Chinese statements readable; UTF-8 encode
    for on-disk bytes."""
    return json.dumps(
        serialize_bundle(report, measurements, target_kind=target_kind),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


# --------------------------------------------------------------------------- #
# EV-R1 — the self-contained DELIVERY bundle: report + inline registry +
# measurements + a registry fingerprint, so the UI renders the 5×5 grid AND the
# value column (the objective→value join runs through the registry) from ONE file.
# Assembly at serialize time only — the engine dataclasses are unchanged.
# --------------------------------------------------------------------------- #


def _fingerprint_of(registry_dict: dict[str, Any]) -> str:
    """sha256 over a registry's canonical (sorted-key, compact) serialization — the
    mismatch-detection handle the decoupled path uses (EV-R1 §1)."""
    canonical = json.dumps(
        registry_dict, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def registry_fingerprint(registry: DimensionRegistry) -> str:
    """The `registry_fingerprint` for a loaded registry (EV-R1 §1). EV-W1 compares this to
    the registry it loaded and warns on mismatch; within a self-contained bundle it is
    redundant (the registry is inlined) but kept for the future decoupled path."""
    return _fingerprint_of(serialize_registry(registry))


def serialize_self_contained_bundle(
    report: MaturityReport,
    measurements: Iterable[Measurement],
    registry: DimensionRegistry,
    provenance: dict[str, Any] | None = None,
    *,
    target_kind: str = DEFAULT_TARGET_KIND,
) -> dict[str, Any]:
    """The EV-R1 delivery envelope `{schema_version, target_kind, evidence_basis,
    registry_fingerprint, provenance, report, registry, measurements}`
    (docs/REPORT_JSON_SCHEMA.md §1a). `target_kind`/`evidence_basis` (R1) ride the SAME
    derivation as `serialize_bundle` (one source of truth). The registry is inlined via the
    EV-W0 serializer so the UI loads one file and never mis-pairs parts. `report`/`measurements`
    are the EV-7 shapes, unchanged."""
    registry_dict = serialize_registry(registry)
    base = serialize_bundle(report, measurements, target_kind=target_kind)
    return {
        "schema_version": base["schema_version"],
        "target_kind": base["target_kind"],
        "evidence_basis": base["evidence_basis"],
        "registry_fingerprint": _fingerprint_of(registry_dict),
        # EV-PIN §1.5-1: the pin stamp must reach the DELIVERY artifact, not stop at the
        # collect bundle. Without it a `window=0-0` snapshot is indistinguishable from a
        # pinned run on the wire, and §1.4's "don't cite unpinned" has nothing to check.
        # `None` is honest — a pre-EV-PIN bundle genuinely has no provenance; never invent
        # a window or sha to fill the hole.
        "provenance": provenance,
        "report": base["report"],
        "registry": registry_dict,
        "measurements": base["measurements"],
    }


def self_contained_bundle_to_json(
    report: MaturityReport,
    measurements: Iterable[Measurement],
    registry: DimensionRegistry,
    provenance: dict[str, Any] | None = None,
    *,
    target_kind: str = DEFAULT_TARGET_KIND,
) -> str:
    """Byte-deterministic JSON for the self-contained bundle (sorted keys + compact
    separators + ensure_ascii=False). This is the golden-fixture / delivery form."""
    return json.dumps(
        serialize_self_contained_bundle(
            report, measurements, registry, provenance, target_kind=target_kind
        ),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
