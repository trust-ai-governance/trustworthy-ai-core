"""unclosed_loop_rate — the Transparency closed-loop check (EV-5b).

Over ALLOWED decision records (an A that was forwarded → SHOULD produce a B), the fraction
with no paired B AND old enough that the loop should have closed. "Old enough" is measured
STREAM-RELATIVE (against the newest record's timestamp, not a wall clock) so the indicator
stays pure/deterministic: a recent allowed-A with no B yet is IN-FLIGHT, not unclosed.

The close window is `TREVAL_UNCLOSED_WINDOW_NS` (default 5 min); eval traffic is synchronous,
so the driver sets it short (e.g. 30 s) for fast validation. Binds trn.l3.full_chain_trace
(`value<=0`); `Measurement.integrity = min` (②).
"""

from __future__ import annotations

import os
from collections.abc import Iterable

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.indicators._integrity import min_integrity
from treval.indicators.correlate import join_ab
from treval.models import AuditEvidence, Measurement

_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_DECISION_MADE = rc_pb.AUDIT_RECORD_TYPE_DECISION_MADE
_UNSPECIFIED_RT = rc_pb.AUDIT_RECORD_TYPE_UNSPECIFIED
_DEFAULT_WINDOW_NS = 5 * 60 * 1_000_000_000  # 5 minutes


def _default_window_ns() -> int:
    raw = os.environ.get("TREVAL_UNCLOSED_WINDOW_NS")
    if raw is None:
        return _DEFAULT_WINDOW_NS
    try:
        return max(0, int(raw))
    except ValueError:
        return _DEFAULT_WINDOW_NS


class UnclosedLoopRate:
    indicator_id = "unclosed_loop_rate"
    dimension = "transparency_accountability"  # MUST match the EV-6 dimension id

    def __init__(self, close_window_ns: int | None = None) -> None:
        self._window_ns = (
            close_window_ns if close_window_ns is not None else _default_window_ns()
        )

    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]:
        records = tuple(evidence)  # materialize: joined AND scanned for the newest ts
        join = join_ab(records)
        closed_ids = {a.ref.request_id for a, _b in join.paired}

        # Newest record time in the stream = the reference "now"; an allowed-A within
        # `window` of it may still be in-flight (its B not yet written).
        newest_ns = max(
            (ev.record.envelope.received_at_ns for ev in records), default=0
        )
        cutoff_ns = newest_ns - self._window_ns

        refs = []
        integrities = []
        unclosed = 0
        for ev in records:
            if ev.record.record_type not in (_DECISION_MADE, _UNSPECIFIED_RT):
                continue
            if ev.record.decision.final_decision != _ALLOW:
                continue  # only forwarded (ALLOWED) requests should produce a B
            refs.append(ev.ref)
            integrities.append(ev.integrity)
            closed = ev.ref.request_id in closed_ids
            in_flight = ev.record.envelope.received_at_ns > cutoff_ns
            if not closed and not in_flight:
                unclosed += 1

        total = len(refs)
        value = unclosed / total if total else 0.0
        notes = (
            f"{unclosed} of {total} allowed request(s) never closed (past the "
            f"{self._window_ns} ns window)"
            if unclosed
            else ""
        )
        return (
            Measurement(
                indicator_id=self.indicator_id,
                dimension=self.dimension,
                value=value,
                unit="ratio",
                sample_size=total,
                evidence_refs=tuple(refs),
                subject="",
                notes=notes,
                integrity=min_integrity(integrities),
            ),
        )
