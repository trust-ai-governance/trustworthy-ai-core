"""Core data model for the open evaluation engine (treval).

Pure data only — frozen dataclasses + one enum, no logic and no I/O. The field
shapes are the contract surface defined in EVAL_ARCHITECTURE §2.1 (evidence),
§2.2 (measurement) and §2.4 (report). Downstream layers (readers, indicators,
the rubric engine, the web layer) build on these types; this module imports
nothing from them, nor from the closed platform.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # The decoded ir-spec audit proto. Type-only import: treval never decodes a
    # record itself (that is the WAL/Postgres readers' job), so no runtime
    # protobuf dependency is pulled in here.
    from trustworthy_ai.v1.request_context_pb2 import RequestContext


class IntegrityStatus(enum.Enum):
    """Trust basis of one piece of evidence (EVAL_ARCHITECTURE §2.1)."""

    VERIFIED = "verified"  # hash chain + CRC + seq continuity all pass
    UNVERIFIED = "unverified"  # source can't be chain-checked (e.g. index reader)
    BROKEN = "broken"  # tamper/corruption detected


# EV-CIGATE §1.5 — the mechanism class that decides whether a value gets an interval, and (when it
# does not) WHY. 🔴 A machine-parseable home for the three-way (EV-CITE 件一 review): `ci is None`
# alone conflates the last two — a census has no sampling uncertainty; a default-deny total function
# has uncertainty, but it lives in COVERAGE (allow-list holes), not in a rate. The INDICATOR declares
# this (it alone knows its mechanism) and it rides on the Measurement so `citation_form` picks its
# wording by declaration, never by the `ci is None` proxy.
INTERVAL_SAMPLED = "sampled"  # open-space partial detector — carries a Wilson interval
INTERVAL_TOTAL_FUNCTION = (
    "total_function"  # default-deny total function — no interval; residual = coverage
)
INTERVAL_CENSUS = "census"  # full enumeration of the window — no sampling uncertainty
# The no-interval mechanisms an indicator MUST declare (a partial detector declares by attaching ci).
INTERVAL_NO_CI_BASES = frozenset({INTERVAL_TOTAL_FUNCTION, INTERVAL_CENSUS})


@dataclass(frozen=True)
class EvidenceRef:
    """Back-pointer so every Measurement traces to its source records."""

    source: str  # "wal:/mnt/wal/..." | "export:audit.db" | "attest:posture.yaml"
    seq: int | None = None  # WAL seq, when applicable
    request_id: str | None = None


@dataclass(frozen=True)
class AuditEvidence:
    """One decoded audit record (RequestContext), source-agnostic."""

    ref: EvidenceRef
    integrity: IntegrityStatus
    tenant_id: str
    received_at_ns: int
    record: RequestContext  # the decoded ir-spec proto


@dataclass(frozen=True)
class PostureEvidence:
    """One attested posture fact (always attested, never measured)."""

    ref: EvidenceRef
    tenant_id: str
    key: str  # e.g. "security.sso_mfa_enabled"
    value: str  # attested value
    attested_by: str  # signer identity (operator accountability)
    attested_at_ns: int


@dataclass(frozen=True)
class Measurement:
    """The smallest unit of interpretation: a normalized, evidence-backed signal."""

    indicator_id: str
    dimension: str  # one of the 5 dimension ids
    value: float  # normalized signal
    unit: str  # "ratio" | "count" | "tokens" | "ms" ...
    sample_size: int  # records backing it (0 = insufficient data)
    evidence_refs: tuple[EvidenceRef, ...]  # MUST be populated — auditability
    subject: str = ""  # per-entity key (e.g. agent_id); "" = aggregate
    notes: str = ""
    # Trust basis of THIS signal: the weakest integrity (min) over its backing
    # evidence, set by the indicator (EV-7 D1). The rubric engine reads it to fill
    # verification_basis and to gate `requires_integrity` objectives — a Measurement
    # loses the per-record IntegrityStatus once aggregated, so it must be carried
    # here. Defaults VERIFIED: every current indicator reads chain-verified WAL; the
    # UNVERIFIED (Postgres index) path lands with EV-2.
    integrity: IntegrityStatus = IntegrityStatus.VERIFIED
    # EV-CIGATE §7-A — the 95% Wilson interval of THIS value WHEN it is a binomial proportion (k/n),
    # so an objective can gate on "we are statistically sure" (ci_low >= τ) instead of a point
    # estimate that only crossed the line by luck. 🔴 None = "no interval", NOT 0/1: a non-rate
    # indicator (duration_p99, a count) or a deterministic census (chain_integrity) leaves these None,
    # and a `ci_low >= τ` gate over a None interval RAISES rather than silently passing/failing
    # (EV-CIGATE §7-B). The INDICATOR fills them (only it knows the value is a proportion — §7-A
    # invariant 2); the engine NEVER infers them from unit.
    ci_low: float | None = None
    ci_high: float | None = None
    # EV-CIGATE §1.5 mechanism class (INTERVAL_SAMPLED / _TOTAL_FUNCTION / _CENSUS), set by the
    # indicator. Rides here so `citation_form` can word "no interval" correctly — a census's "no
    # sampling uncertainty" vs a total function's "residual is in coverage, not a rate". "" = legacy
    # / unspecified (treated as sampled iff a ci is present, else worded WITHOUT claiming a census).
    interval_basis: str = ""


@dataclass(frozen=True)
class ObjectiveResult:
    """Outcome of evaluating one control objective against the evidence."""

    objective_id: str
    kind: str  # "measured" | "attested"
    status: str  # "met" | "unmet" | "insufficient_data" | "unverified_evidence"
    evidence_refs: tuple[EvidenceRef, ...]


@dataclass(frozen=True)
class DimensionReport:
    """Per-dimension rubric outcome, including the over-claim gap list."""

    dimension: str
    measured_ceiling: str | None  # highest level whose MEASURED objectives all pass
    attested_ceiling: str | None  # highest level whose ATTESTED objectives all pass
    awarded_level: str | None  # min(measured_ceiling, attested_ceiling) — the gate
    objectives: tuple[ObjectiveResult, ...]
    gaps: tuple[str, ...]  # attested-but-not-measured = over-claim flags
    # EV-CITE 件二: which kind of `None` a null measured_ceiling is, and the fact that must ride with
    # it. One of certified|below_floor|evidence_unverified|blocked_no_data|not_measured; the gap is
    # the per-objective sentence(s) and is empty ONLY when certified (C8). Computed once by the engine
    # (rubric.measured) so the CLI and Web read the SAME verdict, never re-derive it.
    measured_state: str
    measured_gap: tuple[str, ...]
    # The level where the measured ladder broke (the "未达 L2" the pill/radar show) — serialized so
    # the UI never parses it back out of the prose. None when certified or not_measured.
    measured_breakpoint: str | None


@dataclass(frozen=True)
class MaturityReport:
    """The engine's headline output across the five dimensions."""

    tenant_id: str
    window: tuple[int, int]  # time range covered (ns)
    dimensions: tuple[DimensionReport, ...]
    integrity_summary: Mapping[str, int]  # counts per IntegrityStatus value
    verification_basis: str = "wal"  # "wal" | "index" | "hybrid"
