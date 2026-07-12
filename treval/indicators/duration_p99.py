"""duration_p99 — the Efficient-Reliability latency baseline (EV-5a).

p99 of the B-record `response.duration_ms` over the window. Passive (reads the governance
record's own timing, no probing). Meaningful once production traffic flows (EV-8 passive
phase). `sample_size` = B records that carry a duration; `Measurement.integrity = min` (②).
"""

from __future__ import annotations

import math
from collections.abc import Iterable

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.indicators._integrity import min_integrity
from treval.models import AuditEvidence, Measurement

_RESPONSE_OBSERVED = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED


def _p99(values: list[int]) -> float:
    """Nearest-rank p99 (deterministic; no interpolation): rank = ceil(0.99·n), 1-indexed.
    Assumes a non-empty list."""
    ordered = sorted(values)
    rank = math.ceil(0.99 * len(ordered))
    return float(ordered[max(0, rank - 1)])


class DurationP99:
    indicator_id = "duration_p99"
    dimension = "efficient_reliability"  # MUST match the EV-6 dimension id

    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]:
        refs = []
        integrities = []
        durations: list[int] = []
        for ev in evidence:
            if ev.record.record_type != _RESPONSE_OBSERVED:
                continue  # latency lives on the B (response.observed) record
            duration = ev.record.response.duration_ms
            # A scalar proto field can't tell absent from 0; a real response is > 0 ms, so
            # treat <= 0 as "no duration recorded" and exclude it from the sample.
            if duration <= 0:
                continue
            refs.append(ev.ref)
            integrities.append(ev.integrity)
            durations.append(duration)

        total = len(refs)
        value = _p99(durations) if durations else 0.0
        return (
            Measurement(
                indicator_id=self.indicator_id,
                dimension=self.dimension,
                value=value,
                unit="ms",
                sample_size=total,
                evidence_refs=tuple(refs),
                subject="",
                integrity=min_integrity(integrities),
            ),
        )
