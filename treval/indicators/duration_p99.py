"""duration latency percentiles — p50 / p95 / p99 of B-record `response.duration_ms`.

`duration_p99` is the Efficient-Reliability latency baseline (EV-5a). p50/p95 are the rest
of the distribution the P3C selection spike needs: a single p99 hides shape — a model with a
good p99 but a fat p50 body reads very differently from one that is fast until a rare tail.
All three are the SAME passive reading (the governance record's own timing, no probing),
differing only in the rank, so they share one implementation.

`sample_size` = B records that carry a duration; `Measurement.integrity = min` (EV-5 ②).
"""

from __future__ import annotations

import math
from collections.abc import Iterable

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.indicators._integrity import min_integrity
from treval.models import AuditEvidence, Measurement

_RESPONSE_OBSERVED = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED


def _percentile(values: list[int], q: float) -> float:
    """Nearest-rank percentile (deterministic; no interpolation): rank = ceil(q·n),
    1-indexed. Assumes a non-empty list. q=0.99 reproduces the original p99 exactly."""
    ordered = sorted(values)
    rank = math.ceil(q * len(ordered))
    return float(ordered[max(0, rank - 1)])


class _DurationPercentile:
    """Base for the duration percentile family. Subclasses set `indicator_id` and `_q`;
    the body is identical (same records, same exclusions — only the rank differs)."""

    indicator_id: str
    dimension = "efficient_reliability"  # MUST match the EV-6 dimension id
    _q: float

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
        value = _percentile(durations, self._q) if durations else 0.0
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


class DurationP50(_DurationPercentile):
    indicator_id = "duration_p50"
    _q = 0.50


class DurationP95(_DurationPercentile):
    indicator_id = "duration_p95"
    _q = 0.95


class DurationP99(_DurationPercentile):
    indicator_id = "duration_p99"
    _q = 0.99
