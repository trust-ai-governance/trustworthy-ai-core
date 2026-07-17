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

SCHEMA_VERSION = 1


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
    report: MaturityReport, measurements: Iterable[Measurement]
) -> dict[str, Any]:
    """The full report bundle: `{schema_version, report, measurements}`. Measurements are
    sorted by `(indicator_id, subject)` for a stable array order (REPORT_JSON_SCHEMA §3)."""
    ordered = sorted(measurements, key=lambda m: (m.indicator_id, m.subject))
    return {
        "schema_version": SCHEMA_VERSION,
        "report": serialize_report(report),
        "measurements": [serialize_measurement(m) for m in ordered],
    }


def bundle_to_json(report: MaturityReport, measurements: Iterable[Measurement]) -> str:
    """Byte-identical (up to encoding) JSON for the bundle: sorted keys + compact, stable
    separators. `ensure_ascii=False` keeps the Chinese statements readable; UTF-8 encode
    for on-disk bytes."""
    return json.dumps(
        serialize_bundle(report, measurements),
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
) -> dict[str, Any]:
    """The EV-R1 delivery envelope `{schema_version, registry_fingerprint, report, registry,
    measurements}` (docs/REPORT_JSON_SCHEMA.md §1a). The registry is inlined via the EV-W0
    serializer — the same shape EV-W0 renders — so the UI loads one file and never mis-pairs
    parts. `report`/`measurements` are the EV-7 shapes, unchanged."""
    registry_dict = serialize_registry(registry)
    base = serialize_bundle(report, measurements)
    return {
        "schema_version": base["schema_version"],
        "registry_fingerprint": _fingerprint_of(registry_dict),
        "report": base["report"],
        "registry": registry_dict,
        "measurements": base["measurements"],
    }


def self_contained_bundle_to_json(
    report: MaturityReport,
    measurements: Iterable[Measurement],
    registry: DimensionRegistry,
) -> str:
    """Byte-deterministic JSON for the self-contained bundle (sorted keys + compact
    separators + ensure_ascii=False). This is the golden-fixture / delivery form."""
    return json.dumps(
        serialize_self_contained_bundle(report, measurements, registry),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
