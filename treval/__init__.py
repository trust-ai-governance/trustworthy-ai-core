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
from treval.indicators import (
    BlockRate,
    IndicatorRegistry,
    build_default_registry,
    run_indicators,
)
from treval.posture import PostureFileError, PostureFileReader
from treval.protocols import AuditEvidenceReader, Indicator, PostureProvider
from treval.readers import WalEvidenceReader, WalReadError
from treval.registry import (
    ControlObjective,
    Dimension,
    DimensionRegistry,
    Evidence,
    RegistryError,
    SatisfiedWhenError,
    compile_satisfied_when,
    load_registry,
    validate_against,
)
from treval.rubric import (
    DuplicateIndicatorError,
    bundle_to_json,
    evaluate,
    serialize_bundle,
    serialize_report,
)

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
    # posture
    "PostureFileReader",
    "PostureFileError",
    # registry
    "Evidence",
    "ControlObjective",
    "Dimension",
    "DimensionRegistry",
    "load_registry",
    "validate_against",
    "RegistryError",
    "compile_satisfied_when",
    "SatisfiedWhenError",
    # indicators
    "IndicatorRegistry",
    "run_indicators",
    "BlockRate",
    "build_default_registry",
    # rubric engine (EV-7)
    "evaluate",
    "DuplicateIndicatorError",
    "serialize_report",
    "serialize_bundle",
    "bundle_to_json",
]
