"""A↔B join by request_id — the one shared correlation module (EV-5b ④; EV-9 reuses it).

A request emits a DECISION_MADE record (A) and, when governance observes the response, a
RESPONSE_OBSERVED record (B). `join_ab` pairs them by `request_id` (NOT `seq` — the
multi-instance PK is `(gateway_instance, seq)`, so `seq` is not globally unique). Within a
matched pair, `B.response.decision_seq` back-points to A's seq — a SAME-INSTANCE secondary
check only: a mismatch is a note (cross-instance correlation is legal), never a drop.

Orphans never raise (④): an orphan-A is a documented "incomplete request" (decision with no
observed response); an orphan-B is tolerated (a response whose decision fell outside the
window/stream). Pure + deterministic (stable A-stream / B-stream order).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.models import AuditEvidence

_RESPONSE_OBSERVED = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED
_DECISION_MADE = rc_pb.AUDIT_RECORD_TYPE_DECISION_MADE
_UNSPECIFIED_RT = rc_pb.AUDIT_RECORD_TYPE_UNSPECIFIED


@dataclass(frozen=True)
class JoinResult:
    """The A↔B correlation of one evidence stream (all tuples in stable stream order)."""

    paired: tuple[tuple[AuditEvidence, AuditEvidence], ...]  # (A, B) by request_id
    orphan_a: tuple[
        AuditEvidence, ...
    ]  # decision with no response — incomplete request
    orphan_b: tuple[AuditEvidence, ...]  # response with no decision — tolerated
    seq_mismatches: tuple[
        str, ...
    ]  # request_ids where B.decision_seq != A.seq (note only)


def _is_a(ev: AuditEvidence) -> bool:
    # A DECISION record (legacy UNSPECIFIED record_type is a decision too, per block_rate).
    return ev.record.record_type in (_DECISION_MADE, _UNSPECIFIED_RT)


def _is_b(ev: AuditEvidence) -> bool:
    return ev.record.record_type == _RESPONSE_OBSERVED


def join_ab(evidence: Iterable[AuditEvidence]) -> JoinResult:
    """Correlate DECISION (A) and RESPONSE_OBSERVED (B) records by request_id. First record
    of each kind per request_id wins (duplicates ignored). Records with an empty request_id
    can't correlate → straight to the matching orphan list. Non-A/non-B records (e.g. the
    async GOVERNANCE_OBSERVED) are not part of the request→response loop and are skipped."""
    a_by_id: dict[str, AuditEvidence] = {}
    b_by_id: dict[str, AuditEvidence] = {}
    a_no_id: list[AuditEvidence] = []
    b_no_id: list[AuditEvidence] = []

    for ev in evidence:
        rid = ev.ref.request_id
        if _is_b(ev):
            if not rid:
                b_no_id.append(ev)
            elif rid not in b_by_id:
                b_by_id[rid] = ev
        elif _is_a(ev):
            if not rid:
                a_no_id.append(ev)
            elif rid not in a_by_id:
                a_by_id[rid] = ev

    paired: list[tuple[AuditEvidence, AuditEvidence]] = []
    orphan_a: list[AuditEvidence] = []
    mismatches: list[str] = []
    for rid, a in a_by_id.items():  # A-stream order → deterministic
        b = b_by_id.get(rid)
        if b is None:
            orphan_a.append(a)
            continue
        paired.append((a, b))
        dseq = b.record.response.decision_seq
        # decision_seq==0 ⇒ back-pointer absent (skip); a set value that differs from A's
        # WAL seq is a cross-instance pairing — legal, recorded as a note, not a drop.
        if dseq and a.ref.seq is not None and dseq != a.ref.seq:
            mismatches.append(rid)
    orphan_a.extend(a_no_id)

    orphan_b = [b for rid, b in b_by_id.items() if rid not in a_by_id]
    orphan_b.extend(b_no_id)

    return JoinResult(
        paired=tuple(paired),
        orphan_a=tuple(orphan_a),
        orphan_b=tuple(orphan_b),
        seq_mismatches=tuple(mismatches),
    )
