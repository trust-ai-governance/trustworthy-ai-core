"""Deterministic JSON serialization of a MaturityReport bundle (EV-7 §1 / EV-R1).

Emits the report-bundle envelope defined in `docs/REPORT_JSON_SCHEMA.md`: the rubric
verdict PLUS the measurements that fed it (the report stores only pass/fail, the UI wants
both). Pure — only `json` + the frozen dataclasses; no web deps, so it imports in the
core/CLI environment (like `treval.web.serialize`, but for the report side).

Determinism (the EV-7 byte-identical requirement): object keys sorted, and every array
has a DEFINED order independent of insertion — `dimensions`/`objectives` in the engine's
(registry) order, `measurements` by `(indicator_id, subject)`, `evidence_refs` by
`(source, seq)`, `gaps` already sorted by the engine.
"""

from __future__ import annotations

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
