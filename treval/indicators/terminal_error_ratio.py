"""terminal_error_ratio — the Efficient-Reliability error baseline (EV-5a).

Fraction of B records that terminated in error. An error = `response.final_terminal` in the
error/timeout set OR `response.errors` / `audit.errors` non-empty (the authoritative signal).
A governance BLOCK is NOT an error — it is a successful control action, so BLOCKED/ALLOWED
terminals are excluded. `sample_size` = B records; `Measurement.integrity = min` (②).
"""

from __future__ import annotations

from collections.abc import Iterable

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.indicators._integrity import min_integrity
from treval.models import INTERVAL_CENSUS, AuditEvidence, Measurement
from treval.terminal import (
    is_error_terminal,
    is_unregistered_terminal,
    response_terminal_class,
)

_RESPONSE_OBSERVED = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED

# 🔴 序8 件3 — final_terminal is a free-form string; the SHARED whitelist (checks.is_error_terminal —
# EXACT membership, not substring) marks an error/timeout terminal. ALLOWED / BLOCKED are NOT errors
# (a block is governance, not a reliability failure). The repeated `errors` fields stay the PRIMARY
# signal; the terminal is secondary. 🔴 An UNREGISTERED terminal RAISES — register + classify it, never
# silently default (a substring match let "NOT_AN_ERROR" read as an error, and left the domain open).


def _is_error(record: rc_pb.RequestContext) -> bool:
    resp = record.response
    if len(resp.errors) > 0 or len(record.audit.errors) > 0:
        return True
    return is_error_terminal(resp.final_terminal)


class TerminalErrorRatio:
    indicator_id = "terminal_error_ratio"
    dimension = "efficient_reliability"  # MUST match the EV-6 dimension id
    interval_basis = (
        INTERVAL_CENSUS  # full-window enumeration of terminal outcomes — a census
    )

    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]:
        refs = []
        integrities = []
        errors = 0
        unregistered: set[str] = (
            set()
        )  # 序8 件2 — terminals we classify by historical convention only
        for ev in evidence:
            rec = ev.record
            if rec.record_type != _RESPONSE_OBSERVED:
                continue  # errors terminate on the B (response.observed) record
            refs.append(ev.ref)
            integrities.append(ev.integrity)
            terminal = rec.response.final_terminal
            # 🔴 序8 件2/3 — validate against the domain (raise on a TRULY-unknown value, even with an
            # errors field: an unknown must be VISIBLE, not blessed); flag the historical-but-unregistered
            # ones (TIMEOUT/TIMED_OUT/FAIL) so the number carries a reconcile-with-gateway note.
            response_terminal_class(terminal)
            if is_unregistered_terminal(terminal):
                unregistered.add(str(terminal).strip().upper())
            if _is_error(rec):
                errors += 1

        total = len(refs)
        value = errors / total if total else 0.0
        notes = f"{errors} of {total} response(s) errored/timed out" if errors else ""
        if unregistered:
            # 🔴 序8 件2 — the warning rides WITH the number (notes), never only stderr, or no one sees it.
            warn = (
                f"🔴 final_terminal 出现未登记取值 {sorted(unregistered)}（网关声明的取值域不含它）；"
                "分类沿用历史约定，请与网关侧对账后再定"
            )
            notes = f"{notes}; {warn}" if notes else warn
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
                interval_basis=self.interval_basis,
            ),
        )
