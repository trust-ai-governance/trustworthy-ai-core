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
from collections.abc import Iterable, Mapping
from typing import Any

from treval.citability import CRITERIA_VERSION, citation_form, report_citability
from treval.models import (
    DimensionReport,
    EvidenceRef,
    MaturityReport,
    Measurement,
    ObjectiveResult,
)
from treval.registry import DimensionRegistry, serialize_registry

SCHEMA_VERSION = 5  # EV-CITE: each measurement gains `interval_basis` (the EV-CIGATE §1.5 mechanism class)

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


# --- EV-FWD — availability (indicator-level), DERIVED from (evidence_requirement × target_kind) ---
# `availability` answers "can this indicator be MEASURED in this mode?" (mechanism axis) — a
# SEPARATE, orthogonal axis from `evidence_basis`, which answers "how trustworthy / reproducible
# is what was measured?" (evidence axis). A "measurable-but-not-auditable" indicator is
# `measured` + a weaker `evidence_basis`, NEVER `n/a` (EV-FWD §0.1). Like `evidence_basis`,
# `availability` is a serialization overlay with a single source of truth — never stored
# independently, always derived. The rubric grading is untouched.
EVIDENCE_REQUIREMENTS = ("output_only", "needs_decision", "needs_wal")
AVAILABILITY_VALUES = ("measured", "n/a_needs_gateway", "n/a_self_reported")

# (evidence_requirement × target_kind) → availability (EV-FWD §5). For `gateway` EVERY
# requirement is `measured` (the governed path produces every kind of evidence). Under a
# non-gateway target, `output_only` still measures (harness reads the response itself), while
# `needs_decision` / `needs_wal` are architecturally absent: `n/a_needs_gateway` for a bare model
# (§5), `n/a_self_reported` for a moderation API (no WAL, and "缺网关" would misname a
# vendor-self-report absence — §5.1).
_AVAILABILITY: dict[tuple[str, str], str] = {
    ("output_only", "gateway"): "measured",
    ("output_only", "raw_model"): "measured",
    ("output_only", "moderation_api"): "measured",
    ("needs_decision", "gateway"): "measured",
    ("needs_decision", "raw_model"): "n/a_needs_gateway",
    ("needs_decision", "moderation_api"): "n/a_self_reported",
    ("needs_wal", "gateway"): "measured",
    ("needs_wal", "raw_model"): "n/a_needs_gateway",
    ("needs_wal", "moderation_api"): "n/a_self_reported",
}


def derive_availability(target_kind: str, evidence_requirement: str | None) -> str:
    """The availability of an indicator on a target — the single source of truth (EV-FWD §5).

    `evidence_requirement` is the indicator's declared need (see active_eval's
    EVIDENCE_REQUIREMENTS). `None` means "not one of the classified indicators": that must NEVER
    silently claim `measured` on a non-gateway target, so it defaults to the CONSERVATIVE
    `needs_wal` (a gateway run still resolves to `measured`; a standalone run to n/a). Fail-closed
    on an unknown target_kind so a typo cannot ship a bundle with a bogus availability."""
    req = evidence_requirement or "needs_wal"
    try:
        return _AVAILABILITY[(req, target_kind)]
    except KeyError:
        raise ValueError(
            f"cannot derive availability for (target_kind={target_kind!r}, "
            f"evidence_requirement={req!r}); target_kind must be one of {TARGET_KINDS} "
            f"and requirement one of {EVIDENCE_REQUIREMENTS}"
        ) from None


def assert_availability_derived(
    target_kind: str, evidence_requirement: str | None, availability: str
) -> None:
    """Machine gate (EV-FWD §5, mirrors assert_evidence_basis_derived): a serialized
    `availability` MUST equal derive(). Guards a future regression that stores it independently
    — such a bundle FAILS here rather than shipping a mislabelled availability. 靠门不靠人。"""
    expected = derive_availability(target_kind, evidence_requirement)
    if availability != expected:
        raise ValueError(
            f"availability {availability!r} != derive(target_kind={target_kind!r}, "
            f"requirement={evidence_requirement!r})={expected!r} — availability is derived, "
            "never stored independently (EV-FWD §5)"
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
        # EV-CITE 件二: the kind of `None` + the fact that must ride with it (a null ceiling has two
        # very different meanings — "measured, below the line" vs "not produced this run").
        "measured_state": dim.measured_state,
        "measured_breakpoint": dim.measured_breakpoint,
        "measured_gap": list(dim.measured_gap),
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


def serialize_measurement(
    m: Measurement,
    *,
    target_kind: str,
    evidence_requirements: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """A `measurements[]` entry. `integrity` (EV-7 D1) rides along so the UI can show the
    trust basis of each value without a live call. `availability` (EV-FWD) is DERIVED from
    (this indicator's declared evidence_requirement × target_kind) — the honest per-indicator
    "does this dimension exist in this mode?" mark. `evidence_requirements` maps
    indicator_id → requirement; an id absent from it resolves conservatively (see
    derive_availability).

    🔴 `target_kind` is REQUIRED — no default. A DEFAULT here would turn "a caller forgot to
    thread target_kind" into "silently claims gateway ⇒ measured", which is exactly the EV-FWD
    live bug (cli/bundle.py forgot it and a raw_model run was mislabelled `measured`). Missing
    ⇒ TypeError, loud, at the call site — not a wrong availability shipped in a bundle."""
    req = None
    if evidence_requirements is not None:
        req = evidence_requirements.get(m.indicator_id)
    availability = derive_availability(target_kind, req)
    assert_availability_derived(
        target_kind, req, availability
    )  # single source of truth
    return {
        "indicator_id": m.indicator_id,
        "dimension": m.dimension,
        "value": m.value,
        "unit": m.unit,
        "sample_size": m.sample_size,
        "subject": m.subject,
        "notes": m.notes,
        "integrity": m.integrity.value,
        "availability": availability,
        # EV-CIGATE §7-A — the Wilson interval rides WITH the value so a consumer can see "point
        # estimate crossed the line, lower bound did not". 🔴 null (not 0/1) when the indicator is
        # not a binomial proportion — a `ci_low >= τ` gate over null RAISES, never silently grades.
        "ci_low": m.ci_low,
        "ci_high": m.ci_high,
        # EV-CITE 件一 (review): the interval MECHANISM must ride with the product, not just the
        # in-memory object — else the collect→report round-trip loses it and citation_form falls back.
        # "" (a detector / non-rate) is honest; a census / total_function declares its class.
        "interval_basis": m.interval_basis,
        "evidence_refs": _serialize_refs(m.evidence_refs),
    }


def serialize_bundle(
    report: MaturityReport,
    measurements: Iterable[Measurement],
    *,
    target_kind: str = DEFAULT_TARGET_KIND,
    evidence_requirements: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """The full report bundle: `{schema_version, target_kind, evidence_basis, report,
    measurements}`. `target_kind` (report-level, R1) names what was evaluated; `evidence_basis`
    is DERIVED from it, never an input. Each measurement's `availability` (EV-FWD) is likewise
    derived from (target_kind × the indicator's evidence_requirement). Measurements are sorted
    by `(indicator_id, subject)` for a stable array order (REPORT_JSON_SCHEMA §3)."""
    ordered = sorted(measurements, key=lambda m: (m.indicator_id, m.subject))
    evidence_basis = derive_evidence_basis(target_kind)
    assert_evidence_basis_derived(target_kind, evidence_basis)  # single source of truth
    return {
        "schema_version": SCHEMA_VERSION,
        "target_kind": target_kind,
        "evidence_basis": evidence_basis,
        "report": serialize_report(report),
        "measurements": [
            serialize_measurement(
                m, target_kind=target_kind, evidence_requirements=evidence_requirements
            )
            for m in ordered
        ],
    }


def bundle_to_json(
    report: MaturityReport,
    measurements: Iterable[Measurement],
    *,
    target_kind: str = DEFAULT_TARGET_KIND,
    evidence_requirements: Mapping[str, str] | None = None,
) -> str:
    """Byte-identical (up to encoding) JSON for the bundle: sorted keys + compact, stable
    separators. `ensure_ascii=False` keeps the Chinese statements readable; UTF-8 encode
    for on-disk bytes."""
    return json.dumps(
        serialize_bundle(
            report,
            measurements,
            target_kind=target_kind,
            evidence_requirements=evidence_requirements,
        ),
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
    evidence_requirements: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """The EV-R1 delivery envelope `{schema_version, target_kind, evidence_basis,
    registry_fingerprint, provenance, report, registry, measurements}`
    (docs/REPORT_JSON_SCHEMA.md §1a). `target_kind`/`evidence_basis` (R1) ride the SAME
    derivation as `serialize_bundle` (one source of truth); each measurement's `availability`
    (EV-FWD) is derived from (target_kind × evidence_requirement). The registry is inlined via the
    EV-W0 serializer so the UI loads one file and never mis-pairs parts. `report`/`measurements`
    are the EV-7 shapes, unchanged."""
    registry_dict = serialize_registry(registry)
    materialized = tuple(measurements)
    base = serialize_bundle(
        report,
        materialized,
        target_kind=target_kind,
        evidence_requirements=evidence_requirements,
    )
    # EV-CITE 件一: the citability gate lives ON the delivery artifact — the only envelope that
    # carries `provenance` (pinned / segment hash), so it is the only one that can judge whether a
    # number may leave the room. Disclosure, not refusal: the bundle is emitted either way.
    citable, citable_blockers = report_citability(
        {
            "evidence_basis": base["evidence_basis"],
            "provenance": provenance,
            "report": base["report"],
        }
    )
    # 件一 §1.4: each measurement gets a paste-whole `citation_form` (n + interval, or "普查", per
    # mechanism) computed here where provenance + the citable verdict are known. Same sort order as
    # serialize_bundle so it zips 1:1 onto the serialized rows.
    pred_by_indicator = {
        obj.evidence.indicator_id: obj.evidence.satisfied_when
        for dim in registry.dimensions.values()
        for level in dim.levels.values()
        for obj in level
        if obj.evidence.kind == "measured" and obj.evidence.indicator_id
    }
    pinned = bool(provenance and provenance.get("pinned"))
    window = provenance.get("window") if provenance else None
    first_blocker = citable_blockers[0] if citable_blockers else None
    for m, row in zip(
        sorted(materialized, key=lambda x: (x.indicator_id, x.subject)),
        base["measurements"],
    ):
        row["citation_form"] = citation_form(
            m,
            pinned=pinned,
            window=window,
            evidence_basis=base["evidence_basis"],
            citable=citable,
            first_blocker=first_blocker,
            satisfied_when=pred_by_indicator.get(m.indicator_id),
        )
    return {
        "schema_version": base["schema_version"],
        "target_kind": base["target_kind"],
        "evidence_basis": base["evidence_basis"],
        "citable": citable,
        "citable_blockers": citable_blockers,
        # 🔴 C16 — the criteria version the verdict above was judged under, written in the SAME dict
        # so a verdict can never be serialized without it. A reader (and the web view) recompute
        # under the CURRENT version and, on disagreement, know it is criteria drift, not data change.
        "citability_criteria": CRITERIA_VERSION,
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
    evidence_requirements: Mapping[str, str] | None = None,
) -> str:
    """Byte-deterministic JSON for the self-contained bundle (sorted keys + compact
    separators + ensure_ascii=False). This is the golden-fixture / delivery form."""
    return json.dumps(
        serialize_self_contained_bundle(
            report,
            measurements,
            registry,
            provenance,
            target_kind=target_kind,
            evidence_requirements=evidence_requirements,
        ),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
