"""block_rate — the first reference indicator (EV-4 §4).

Fraction of DECIDED requests that were BLOCKed (Security & Alignment). This is
the template every later indicator copies: pure measure(), evidence_refs always
populated (len == sample_size), subject="" aggregate, sample_size==0 distinct
from value==0.0. The indicator stays dumb — it counts recorded decisions and does
NOT filter on integrity (that is the rubric's concern, EV-7). It DOES record the
weakest integrity of the records it consumed on the Measurement (EV-5 ②), so an
UNVERIFIED (Postgres/index) source auto-marks the Measurement UNVERIFIED — the EV-2
hard gate — without changing what is counted.
"""

from __future__ import annotations

from collections.abc import Iterable

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.indicators._integrity import min_integrity
from treval.models import AuditEvidence, Measurement

_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
_RESPONSE_OBSERVED = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED


class BlockRate:
    indicator_id = "block_rate"
    dimension = "security_alignment"  # MUST match the EV-6 dimension id

    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]:
        refs = []
        integrities = []
        blocks = 0
        for ev in evidence:
            record = ev.record
            # B records (response.observed) carry no decision — skip them.
            if record.record_type == _RESPONSE_OBSERVED:
                continue
            final = record.decision.final_decision
            if final not in (_ALLOW, _BLOCK):
                continue  # UNSPECIFIED / UNDECIDED is not a terminal decision
            refs.append(ev.ref)
            integrities.append(ev.integrity)
            if final == _BLOCK:
                blocks += 1

        decided = len(refs)
        value = blocks / decided if decided else 0.0
        return (
            Measurement(
                indicator_id=self.indicator_id,
                dimension=self.dimension,
                value=value,
                unit="ratio",
                sample_size=decided,
                evidence_refs=tuple(refs),
                subject="",
                integrity=min_integrity(integrities),
            ),
        )
