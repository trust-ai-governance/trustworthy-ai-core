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


@dataclass(frozen=True)
class MaturityReport:
    """The engine's headline output across the five dimensions."""

    tenant_id: str
    window: tuple[int, int]  # time range covered (ns)
    dimensions: tuple[DimensionReport, ...]
    integrity_summary: Mapping[str, int]  # counts per IntegrityStatus value
    verification_basis: str = "wal"  # "wal" | "index" | "hybrid"
