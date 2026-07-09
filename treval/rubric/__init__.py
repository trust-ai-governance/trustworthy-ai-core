"""Rubric engine (EV-7) — grade Measurements against the DimensionRegistry.

`evaluate(...)` produces a deterministic `MaturityReport` (verified vs declared level +
the over-claim gap); the `serialize`/`bundle_to_json` helpers emit the byte-identical
report bundle the UI consumes (docs/REPORT_JSON_SCHEMA.md).
"""

from __future__ import annotations

from treval.rubric.engine import DuplicateIndicatorError, evaluate
from treval.rubric.serialize import (
    bundle_to_json,
    serialize_bundle,
    serialize_measurement,
    serialize_report,
)

__all__ = [
    "evaluate",
    "DuplicateIndicatorError",
    "serialize_report",
    "serialize_measurement",
    "serialize_bundle",
    "bundle_to_json",
]
