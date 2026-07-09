"""MaturityRubricEngine (EV-7) — turn Measurements into a verifiable maturity grade.

Pure + deterministic (EV-7 §1): a function of (registry, measurements, posture) with
no clock, no randomness, and stable key order, so the same input yields byte-identical
output. The engine is SOURCE-AGNOSTIC — it consumes `Measurement`s and never sees the
evidence behind them, so an active-eval ProbeResult signal and a passive WAL-tag signal
are graded identically (that is the point of the Measurement seam). Attestation can only
ever *lower* an awarded level (the min gate), never raise a measured one.

Per objective it emits an `ObjectiveResult`; per dimension a `DimensionReport` with the
measured/attested ceilings, the min-gated `awarded_level`, and the over-claim `gaps`
(attested-met above what measurement supports — the product's headline output).
"""

from __future__ import annotations

from collections.abc import Iterable

from treval.models import (
    DimensionReport,
    EvidenceRef,
    IntegrityStatus,
    MaturityReport,
    Measurement,
    ObjectiveResult,
    PostureEvidence,
)
from treval.registry import ControlObjective, Dimension, DimensionRegistry
from treval.registry.satisfied_when import compile_satisfied_when

_LEVELS = ("L1", "L2", "L3", "L4", "L5")
_LEVEL_INDEX = {level: i for i, level in enumerate(_LEVELS, start=1)}  # L1→1 … L5→5


class DuplicateIndicatorError(ValueError):
    """Two or more aggregate (`subject == ""`) Measurements share one `indicator_id`, so
    the objective binding is ambiguous — the engine REFUSES to grade rather than silently
    pick one (EV-7 D3). A wrong-but-plausible maturity grade is the worst failure for a
    governance engine, so an ambiguous input fails LOUD.

    The contract: the driver (EV-8) feeds a CURATED set — exactly one aggregate per
    `indicator_id`, by selecting the canonical corpus or by namespacing the id. `indicator_id`
    names the offender; `conflicting` holds every aggregate Measurement that shares it.

    `conflicting` is the reserved extension point: a future driver-side merge policy
    (max / mean / weighted) can catch this, collapse the conflict to one value, and
    re-`evaluate` — the engine itself stays merge-free (it never guesses which value wins)."""

    def __init__(self, indicator_id: str, conflicting: tuple[Measurement, ...]) -> None:
        self.indicator_id = indicator_id
        self.conflicting = conflicting
        detail = "; ".join(
            f"value={m.value} sample_size={m.sample_size} "
            f"source={m.evidence_refs[0].source if m.evidence_refs else '?'}"
            for m in conflicting
        )
        super().__init__(
            f"duplicate aggregate indicator_id {indicator_id!r}: {len(conflicting)} "
            f"aggregate Measurements share it [{detail}] — the rubric requires a curated "
            "one-per-id input (the EV-8 driver curates or namespaces; EV-7 D3)"
        )


def evaluate(
    registry: DimensionRegistry,
    measurements: Iterable[Measurement],
    posture: Iterable[PostureEvidence],
    *,
    window: tuple[int, int],
    tenant_id: str,
) -> MaturityReport:
    """Grade `registry` against the measured + attested evidence for one tenant/window.

    `measurements` MUST be CURATED: exactly one aggregate (`subject == ""`) Measurement per
    `indicator_id` (the driver layer ensures this — EV-7 D3). A duplicate aggregate id is an
    ambiguous binding, so `evaluate` raises `DuplicateIndicatorError` (fail-loud, never a
    silent pick). Per-entity rows (`subject != ""`) don't bind to objectives and may repeat.
    Inputs are assumed already tenant-scoped (the readers filter); `tenant_id` labels the
    report, it is not a filter here.
    """
    materialized = tuple(measurements)
    posture_facts = tuple(posture)

    # Aggregate signal per indicator; a duplicate aggregate id is ambiguous → fail loud
    # (EV-7 D3) rather than silently binding one value to the objective.
    agg_by_id: dict[str, Measurement] = {}
    for m in materialized:
        if m.subject != "":
            continue  # per-entity rows never bind to a rubric objective
        if m.indicator_id in agg_by_id:
            conflicting = tuple(
                x
                for x in materialized
                if x.subject == "" and x.indicator_id == m.indicator_id
            )
            raise DuplicateIndicatorError(m.indicator_id, conflicting)
        agg_by_id[m.indicator_id] = m

    # An attested objective is met iff a signed posture fact carries its key. Keep the
    # first fact per key for the evidence back-pointer.
    attested_ref_by_key: dict[str, tuple[EvidenceRef, ...]] = {}
    for p in posture_facts:
        if p.attested_by and p.key not in attested_ref_by_key:
            attested_ref_by_key[p.key] = (p.ref,)

    consumed: list[
        IntegrityStatus
    ] = []  # integrity of measurements a measured obj used
    dimensions = tuple(
        _evaluate_dimension(dim, agg_by_id, attested_ref_by_key, consumed)
        for dim in registry.dimensions.values()  # registry key order (deterministic)
    )

    return MaturityReport(
        tenant_id=tenant_id,
        window=window,
        dimensions=dimensions,
        integrity_summary=_integrity_summary(materialized),
        verification_basis=_verification_basis(consumed),
    )


def _evaluate_dimension(
    dim: Dimension,
    agg_by_id: dict[str, Measurement],
    attested_ref_by_key: dict[str, tuple[EvidenceRef, ...]],
    consumed: list[IntegrityStatus],
) -> DimensionReport:
    results: list[ObjectiveResult] = []
    # Per-level, per-kind status lists drive the ceilings; (level, id) → attested-met
    # feeds the gap list.
    measured_status: dict[str, list[str]] = {level: [] for level in _LEVELS}
    attested_status: dict[str, list[str]] = {level: [] for level in _LEVELS}

    for level in _LEVELS:  # L1 → L5
        for obj in dim.levels[level]:  # registry order within the level
            res = _evaluate_objective(obj, agg_by_id, attested_ref_by_key, consumed)
            results.append(res)
            if res.kind == "measured":
                measured_status[level].append(res.status)
            else:
                attested_status[level].append(res.status)

    measured_ceiling = _ceiling(measured_status)
    attested_ceiling = _ceiling(attested_status)
    awarded = _min_level(measured_ceiling, attested_ceiling)
    gaps = _over_claim_gaps(dim, attested_ref_by_key, measured_ceiling)

    return DimensionReport(
        dimension=dim.dimension,
        measured_ceiling=measured_ceiling,
        attested_ceiling=attested_ceiling,
        awarded_level=awarded,
        objectives=tuple(results),
        gaps=gaps,
    )


def _evaluate_objective(
    obj: ControlObjective,
    agg_by_id: dict[str, Measurement],
    attested_ref_by_key: dict[str, tuple[EvidenceRef, ...]],
    consumed: list[IntegrityStatus],
) -> ObjectiveResult:
    ev = obj.evidence
    if ev.kind == "measured":
        # A measured objective with no indicator/predicate can't be measured (the loader
        # forbids it, but a hand-built registry could) → fail closed to insufficient_data.
        if ev.indicator_id is None or ev.satisfied_when is None:
            return ObjectiveResult(obj.id, "measured", "insufficient_data", ())
        m = agg_by_id.get(ev.indicator_id)
        # Short-circuit an empty sample BEFORE the threshold so a `value <= τ` predicate
        # can't read 0.0 on no data and falsely pass (EV-7 §1).
        if m is None or m.sample_size == 0:
            return ObjectiveResult(obj.id, "measured", "insufficient_data", ())
        consumed.append(m.integrity)  # this measurement backs a measured objective
        if m.integrity is IntegrityStatus.BROKEN or (
            m.integrity is IntegrityStatus.UNVERIFIED and ev.requires_integrity
        ):
            # BROKEN never grades; UNVERIFIED can satisfy an aggregate rate but not an
            # integrity-moat objective (the Postgres path can't claim the chain — D2).
            return ObjectiveResult(
                obj.id, "measured", "unverified_evidence", m.evidence_refs
            )
        predicate = compile_satisfied_when(ev.satisfied_when)
        status = "met" if predicate(m) else "unmet"
        return ObjectiveResult(obj.id, "measured", status, m.evidence_refs)

    # attested — a declaration, never insufficient_data / unverified_evidence (§1).
    refs = (
        attested_ref_by_key.get(ev.posture_key) if ev.posture_key is not None else None
    )
    if refs is not None:
        return ObjectiveResult(obj.id, "attested", "met", refs)
    return ObjectiveResult(obj.id, "attested", "unmet", ())


def _ceiling(status_by_level: dict[str, list[str]]) -> str | None:
    """Highest level with a MET objective of this kind such that every objective of this
    kind at all levels at or below it is met. Empty INTERMEDIATE levels are climbed over
    (they can't fail); empty TOP levels do NOT inflate the ceiling — you only certify a
    level you actually measured (EV-7 §1 + §0's no-vacuous-high rule). None ⇒ no level
    certified (NotMeasured, or measured-but-failing at the bottom)."""
    ceiling: str | None = None
    for level in _LEVELS:  # ascending
        statuses = status_by_level[level]
        if any(s != "met" for s in statuses):
            break  # a not-met objective at this level caps the ceiling below it
        if statuses:  # non-empty and all met → this level is certified
            ceiling = level
    return ceiling


def _min_level(a: str | None, b: str | None) -> str | None:
    """The min gate (EV-7 §1): the awarded level is the weaker of the two ceilings, with
    None as the short board (an axis that certifies nothing forbids any award)."""
    ai = _LEVEL_INDEX.get(a, 0) if a is not None else 0
    bi = _LEVEL_INDEX.get(b, 0) if b is not None else 0
    low = min(ai, bi)
    return _LEVELS[low - 1] if low else None


def _over_claim_gaps(
    dim: Dimension,
    attested_ref_by_key: dict[str, tuple[EvidenceRef, ...]],
    measured_ceiling: str | None,
) -> tuple[str, ...]:
    """Attested objectives that are MET at a level ABOVE what measurement supports — the
    over-claim surface ("claims Ln, measurement backs only Lm"). Sorted (deterministic)."""
    floor = _LEVEL_INDEX.get(measured_ceiling, 0) if measured_ceiling is not None else 0
    gaps: list[str] = []
    for level in _LEVELS:
        if _LEVEL_INDEX[level] <= floor:
            continue
        for obj in dim.levels[level]:
            ev = obj.evidence
            if ev.kind == "attested" and ev.posture_key in attested_ref_by_key:
                gaps.append(obj.id)
    return tuple(sorted(gaps))


def _integrity_summary(measurements: tuple[Measurement, ...]) -> dict[str, int]:
    """Count every input Measurement by its integrity basis. All three keys always
    present (0 if none) so the JSON shape is stable (REPORT_JSON_SCHEMA §2)."""
    summary = {status.value: 0 for status in IntegrityStatus}
    for m in measurements:
        summary[m.integrity.value] += 1
    return summary


def _verification_basis(consumed: list[IntegrityStatus]) -> str:
    """The report's trust basis, over the measurements that actually backed a measured
    objective: all VERIFIED → "wal"; all UNVERIFIED → "index"; anything mixed (incl. a
    BROKEN in the set) → "hybrid". Empty ⇒ "wal" (the frozen default)."""
    distinct = set(consumed)
    if not distinct:
        return "wal"
    if distinct == {IntegrityStatus.VERIFIED}:
        return "wal"
    if distinct == {IntegrityStatus.UNVERIFIED}:
        return "index"
    return "hybrid"
