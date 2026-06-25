"""treval — the open trustworthiness-maturity evaluation engine.

EV-0 ships the contract surface only: the evidence/measurement/report data model
and the three extension Protocols. Readers, indicators, the rubric engine, the
CLI and the web layer land in later issues (EV-1 onward).
"""

from __future__ import annotations

from treval.models import (
    AuditEvidence,
    DimensionReport,
    EvidenceRef,
    IntegrityStatus,
    MaturityReport,
    Measurement,
    ObjectiveResult,
    PostureEvidence,
)
from treval.protocols import AuditEvidenceReader, Indicator, PostureProvider
from treval.readers import WalEvidenceReader, WalReadError

__all__ = [
    # models
    "IntegrityStatus",
    "EvidenceRef",
    "AuditEvidence",
    "PostureEvidence",
    "Measurement",
    "ObjectiveResult",
    "DimensionReport",
    "MaturityReport",
    # protocols
    "AuditEvidenceReader",
    "PostureProvider",
    "Indicator",
    # readers
    "WalEvidenceReader",
    "WalReadError",
]
