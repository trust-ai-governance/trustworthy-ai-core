"""Measurement-bundle I/O (EV-8 §3) — the seam between `collect` and `report`.

The bundle is the `docs/REPORT_JSON_SCHEMA.md` envelope, but `collect` writes only
`measurements[]` (+ run metadata: tenant_id / window / mode); `report` grades it into
the `report` half. Parsing is FAIL-CLOSED (like the corpus/registry loaders): a
malformed measurement raises `BundleError` rather than silently dropping a signal —
a dropped Measurement would quietly understate maturity.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from treval.models import EvidenceRef, IntegrityStatus, Measurement

SCHEMA_VERSION = 6  # EV-CITE: each measurement gains `interval_basis` (EV-CIGATE §1.5 mechanism class)
# The bundle version that INTRODUCED the ci_low/ci_high fields. A bundle below this predates them —
# so an injection_catch_rate with no interval means "produced before the fields existed" (re-collect),
# NOT "a non-rate indicator" (EV-CIGATE F1: without the bump both looked identical and mis-diagnosed).
CI_INTRODUCED_IN = 5
_VALID_INTEGRITY = {s.value for s in IntegrityStatus}


class BundleError(Exception):
    """The bundle file is unreadable or a measurement is malformed (fail-closed)."""


@dataclass(frozen=True)
class LoadedBundle:
    """A parsed bundle plus the non-fatal issues to surface at the report top (§5)."""

    schema_version: int
    tenant_id: str
    window: tuple[int, int]
    measurements: tuple[Measurement, ...]
    warnings: tuple[str, ...]
    # EV-PIN: the run's pin stamp, carried through to the delivery bundle. None for a
    # pre-EV-PIN bundle — that absence is meaningful (unpinned), never faked.
    provenance: dict[str, Any] | None = None
    pinned: bool = False
    # R1: which target this run probed; flows into the graded delivery bundle. Defaults
    # `gateway` — every pre-R1 bundle is a gateway run (R1 §1.5-B).
    target_kind: str = "gateway"


def _require(raw: dict[str, Any], key: str, where: str) -> Any:
    if key not in raw:
        raise BundleError(f"{where}: missing required field {key!r}")
    return raw[key]


def _parse_ref(raw: object, where: str) -> EvidenceRef:
    if not isinstance(raw, dict):
        raise BundleError(f"{where}: each evidence_ref must be an object")
    source = raw.get("source")
    if not isinstance(source, str) or not source:
        raise BundleError(f"{where}: evidence_ref.source must be a non-empty string")
    seq = raw.get("seq")
    if seq is not None and (not isinstance(seq, int) or isinstance(seq, bool)):
        raise BundleError(f"{where}: evidence_ref.seq must be an int or null")
    request_id = raw.get("request_id")
    if request_id is not None and not isinstance(request_id, str):
        raise BundleError(f"{where}: evidence_ref.request_id must be a string or null")
    return EvidenceRef(source=source, seq=seq, request_id=request_id)


def parse_measurement(raw: object, where: str) -> Measurement:
    """One `measurements[]` entry → Measurement (REPORT_JSON_SCHEMA §2). Fail-closed on
    a bad type / unknown integrity; `subject`/`notes`/`integrity`/`evidence_refs` default
    (so a minimal hand-authored fixture still loads)."""
    if not isinstance(raw, dict):
        raise BundleError(f"{where}: measurement must be an object")

    indicator_id = _require(raw, "indicator_id", where)
    dimension = _require(raw, "dimension", where)
    value = _require(raw, "value", where)
    unit = _require(raw, "unit", where)
    sample_size = _require(raw, "sample_size", where)
    if not isinstance(indicator_id, str) or not indicator_id:
        raise BundleError(f"{where}: indicator_id must be a non-empty string")
    if not isinstance(dimension, str) or not dimension:
        raise BundleError(f"{where}: dimension must be a non-empty string")
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BundleError(f"{where}: value must be a number")
    if not isinstance(unit, str) or not unit:
        raise BundleError(f"{where}: unit must be a non-empty string")
    if isinstance(sample_size, bool) or not isinstance(sample_size, int):
        raise BundleError(f"{where}: sample_size must be an int")

    subject = raw.get("subject", "")
    notes = raw.get("notes", "")
    if not isinstance(subject, str) or not isinstance(notes, str):
        raise BundleError(f"{where}: subject/notes must be strings")

    integrity = raw.get("integrity", IntegrityStatus.VERIFIED.value)
    if integrity not in _VALID_INTEGRITY:
        raise BundleError(
            f"{where}: integrity must be one of {sorted(_VALID_INTEGRITY)}, "
            f"got {integrity!r}"
        )

    refs_raw = raw.get("evidence_refs", [])
    if not isinstance(refs_raw, list):
        raise BundleError(f"{where}: evidence_refs must be an array")
    refs = tuple(_parse_ref(r, where) for r in refs_raw)

    # EV-CIGATE §7-A — the Wilson interval MUST survive the round-trip: a collect bundle carries it,
    # and a `ci_low >= τ` objective grading the loaded bundle needs it (else it raises). 🔴 F2: in a
    # v≥CI_INTRODUCED_IN bundle the key is ALWAYS PRESENT — a rate carries a number, a non-rate an
    # EXPLICIT null; "absent" happens ONLY in a pre-CI bundle, and THAT is caught by the schema_version
    # fork (F1), not by treating absent as null here. Both absent and explicit-null map to None; the
    # version tells them apart. Never coerced to 0/1.
    ci_low = _parse_ci(raw.get("ci_low"), "ci_low", where)
    ci_high = _parse_ci(raw.get("ci_high"), "ci_high", where)

    # EV-CITE 件一 (review): the interval MECHANISM must survive the collect→report round-trip, just
    # like ci — else citation_form loses it and falls back on the user's actual path. Absent (a pre-v6
    # bundle, caught by the schema_version fork) or "" defaults to unspecified; never coerced.
    interval_basis = raw.get("interval_basis", "")
    if not isinstance(interval_basis, str):
        raise BundleError(f"{where}: interval_basis must be a string")

    return Measurement(
        indicator_id=indicator_id,
        dimension=dimension,
        value=float(value),
        unit=unit,
        sample_size=sample_size,
        evidence_refs=refs,
        subject=subject,
        notes=notes,
        integrity=IntegrityStatus(integrity),
        ci_low=ci_low,
        ci_high=ci_high,
        interval_basis=interval_basis,
    )


def _parse_ci(v: object, name: str, where: str) -> float | None:
    """A nullable Wilson bound from a bundle (EV-CIGATE §7-A). None (absent/null) stays None — a
    non-rate indicator carries no interval; a bad type is fail-closed, never silently dropped."""
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise BundleError(f"{where}: {name} must be a number or null")
    return float(v)


def load_bundle(path: str | Path) -> LoadedBundle:
    """Load + validate a bundle file. Fatal problems (unreadable / not an object /
    malformed measurement) raise BundleError; soft gaps (missing tenant/window/version)
    are recorded as warnings and defaulted."""
    p = Path(path)
    try:
        doc = json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise BundleError(f"cannot read bundle {p}: {e}") from e
    except json.JSONDecodeError as e:
        raise BundleError(f"bundle {p} is not valid JSON: {e}") from e

    if not isinstance(doc, dict):
        raise BundleError(f"bundle {p}: top level must be an object")

    warnings: list[str] = []

    schema_version = doc.get("schema_version")
    if schema_version != SCHEMA_VERSION:
        warnings.append(
            f"bundle schema_version={schema_version!r}, expected {SCHEMA_VERSION} "
            "— rendering anyway"
        )
        if not isinstance(schema_version, int):
            schema_version = SCHEMA_VERSION

    raw_measurements = doc.get("measurements")
    if not isinstance(raw_measurements, list):
        raise BundleError(f"bundle {p}: 'measurements' must be an array")
    if not raw_measurements:
        warnings.append(
            "bundle carries no measurements — report will be all NotMeasured"
        )
    measurements = tuple(
        parse_measurement(m, f"bundle {p} measurements[{i}]")
        for i, m in enumerate(raw_measurements)
    )

    tenant_id = doc.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id:
        warnings.append("bundle carried no tenant_id; using 'unknown'")
        tenant_id = "unknown"

    window = _parse_window(doc.get("window"), warnings)

    provenance = doc.get("provenance")
    if provenance is not None and not isinstance(provenance, dict):
        raise BundleError(f"bundle {p}: 'provenance' must be an object or absent")
    pinned = bool(doc.get("pinned", False))
    if not pinned:
        warnings.append(
            "this run is NOT pinned (no frozen window) — its numbers must not be cited "
            "in external documents (EV-PIN §1.4)"
        )

    # R1: target_kind (absent ⇒ gateway, the only pre-R1 kind). A bad value fails closed;
    # a stored evidence_basis must equal derive(target_kind) — the derivation gate (§2/§7-2).
    from treval.rubric.serialize import (
        TARGET_KINDS,
        assert_evidence_basis_derived,
    )

    target_kind = doc.get("target_kind", "gateway")
    if target_kind not in TARGET_KINDS:
        raise BundleError(
            f"bundle {p}: target_kind must be one of {list(TARGET_KINDS)}, "
            f"got {target_kind!r}"
        )
    evidence_basis = doc.get("evidence_basis")
    if evidence_basis is not None:
        try:
            assert_evidence_basis_derived(target_kind, evidence_basis)
        except ValueError as e:
            raise BundleError(f"bundle {p}: {e}") from e

    return LoadedBundle(
        schema_version=schema_version,
        tenant_id=tenant_id,
        window=window,
        measurements=measurements,
        warnings=tuple(warnings),
        provenance=provenance,
        pinned=pinned,
        target_kind=target_kind,
    )


def _parse_window(raw: object, warnings: list[str]) -> tuple[int, int]:
    if (
        isinstance(raw, list)
        and len(raw) == 2
        and all(isinstance(x, int) and not isinstance(x, bool) for x in raw)
    ):
        return (raw[0], raw[1])
    warnings.append("bundle carried no valid window; defaulting to [0, 0]")
    return (0, 0)


def build_bundle(
    measurements: tuple[Measurement, ...],
    *,
    tenant_id: str,
    window: tuple[int, int],
    mode: str,
    pinned: bool = False,
    provenance: dict[str, Any] | None = None,
    target_kind: str = "gateway",
    model: str | None = None,
    temperature: float | None = None,
    target_url_host: str | None = None,
    corpus_sha: dict[str, str] | None = None,
    traffic_tier: str = "b_assumed_mix",
) -> dict[str, Any]:
    """The bundle `collect` writes: measurements[] + run metadata (no graded `report`;
    `report` produces that). Reuses the EV-7 serializer for the measurement shape.

    `pinned` / `provenance` are EV-PIN's run stamp: whether this run's window was frozen by
    explicit bounds, and the WAL segment bytes + record count behind it. They are additive
    metadata on the COLLECT bundle (which has no frozen schema) — the EV-R1 delivery envelope
    is untouched. The observed/pinned `window` flows into the graded report through
    `_grade(window=bundle.window)`, so fixing it here fixes the delivered report too.

    `target_kind` (R1) records WHICH target this run probed; `evidence_basis` is DERIVED from
    it (never stored independently, R1 裁定 A). Both flow into the graded delivery bundle.

    🔴 `target_kind` + the evidence_requirement map MUST reach serialize_measurement, or a
    raw_model collect gets `availability=measured` off the gateway default — the EV-FWD live bug.
    This is the SECOND serialization path (the report envelope is the first); both must derive
    availability the same way (R1's "two schemas, one truth" discipline)."""
    from treval.active_eval import EVIDENCE_REQUIREMENTS
    from treval.rubric.serialize import derive_evidence_basis, serialize_measurement

    ordered = sorted(measurements, key=lambda m: (m.indicator_id, m.subject))
    sha_map = corpus_sha or {}
    serialized = []
    for m in ordered:
        entry = serialize_measurement(
            m, target_kind=target_kind, evidence_requirements=EVIDENCE_REQUIREMENTS
        )
        # EV-PAIR §3.1 (P3): per-measurement corpus_sha — the pairing gate compares it PER
        # indicator, so "only one indicator changed corpus" cannot pass unnoticed.
        if m.indicator_id in sha_map:
            entry["corpus_sha"] = sha_map[m.indicator_id]
        serialized.append(entry)
    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "target_kind": target_kind,
        "evidence_basis": derive_evidence_basis(target_kind),
        "tenant_id": tenant_id,
        "window": list(window),
        "mode": mode,
        "pinned": pinned,
        # EV-PAIR §2 — "决定这次结果的配置" travels WITH the numbers (the EV-PIN discipline: what
        # determined the value is recorded next to it). `target_url_host` is HOST:PORT only —
        # 🔴 never the full URL, never the api_key. `traffic_tier` is the §0.1 flow口径 (collect
        # drives curated corpora ⇒ representative-mix (b)); the pairing gate requires both sides
        # to declare it and match, so an (a) real-traffic run can't be silently paired with (b).
        "model": model,
        "temperature": temperature,
        "target_url_host": target_url_host,
        "traffic_tier": traffic_tier,
        "measurements": serialized,
    }
    if provenance is not None:
        doc["provenance"] = provenance
    return doc
