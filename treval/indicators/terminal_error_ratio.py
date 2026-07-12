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
from treval.models import AuditEvidence, Measurement

_RESPONSE_OBSERVED = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED

# final_terminal is a free-form string; these substrings mark an error/timeout terminal
# (case-insensitive). ALLOWED / BLOCKED deliberately do NOT match — a block is governance,
# not a reliability failure. The exact platform terminal strings are unconfirmed, so the
# repeated `errors` fields are the primary signal and this is a secondary heuristic.
_ERROR_TERMINAL_TOKENS = ("ERROR", "TIMEOUT", "TIMED_OUT", "FAIL")


def _is_error(record: rc_pb.RequestContext) -> bool:
    resp = record.response
    if len(resp.errors) > 0 or len(record.audit.errors) > 0:
        return True
    terminal = str(resp.final_terminal).upper()
    return any(tok in terminal for tok in _ERROR_TERMINAL_TOKENS)


class TerminalErrorRatio:
    indicator_id = "terminal_error_ratio"
    dimension = "efficient_reliability"  # MUST match the EV-6 dimension id

    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]:
        refs = []
        integrities = []
        errors = 0
        for ev in evidence:
            if ev.record.record_type != _RESPONSE_OBSERVED:
                continue  # errors terminate on the B (response.observed) record
            refs.append(ev.ref)
            integrities.append(ev.integrity)
            if _is_error(ev.record):
                errors += 1

        total = len(refs)
        value = errors / total if total else 0.0
        notes = f"{errors} of {total} response(s) errored/timed out" if errors else ""
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
