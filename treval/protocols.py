"""Extension seams for the evaluation engine (EVAL_ARCHITECTURE §2.1 / §2.2).

Three structural Protocols define where third parties plug in:
  - AuditEvidenceReader — the MEASURED substrate (WAL-direct, Postgres index, ...)
  - PostureProvider     — the ATTESTED substrate (file reader, IAM/GRC/SIEM, ...)
  - Indicator           — the only place dimension semantics live

No implementations live here — those are EV-1 (WAL reader), EV-3 (posture) and
EV-4+ (indicators). This module is contract-only.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Protocol

from treval.models import AuditEvidence, Measurement, PostureEvidence


class AuditEvidenceReader(Protocol):
    """The MEASURED substrate: chain-verifiable runtime audit records."""

    def read_audit(
        self,
        *,
        tenant_id: str | None = None,
        time_from_ns: int | None = None,
        time_to_ns: int | None = None,
    ) -> Iterator[AuditEvidence]: ...


class PostureProvider(Protocol):
    """The ATTESTED substrate, and the primary extension seam (Charter §10).

    A custom provider can only emit PostureEvidence (always attested, never
    measured), so it can extend evidence sources without raising the measured
    ceiling.
    """

    provider_id: str

    def collect(self, *, tenant_id: str | None = None) -> Iterator[PostureEvidence]: ...


class Indicator(Protocol):
    """Consumes evidence, emits Measurements. Pure over its evidence input.

    measure() returns a tuple: a scalar indicator yields exactly one aggregate
    Measurement (subject==""); a per-entity indicator yields one per subject.
    Empty input yields a single sample_size=0 aggregate, never an empty tuple.
    """

    indicator_id: str
    dimension: str

    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]: ...
