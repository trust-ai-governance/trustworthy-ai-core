"""min-integrity — the trust basis a passive Measurement inherits (EV-5 ②).

Every passive indicator sets `Measurement.integrity` to the WEAKEST integrity over the
records it consumed. This closes the EV-2 hard gate: when a Postgres/index reader yields
UNVERIFIED records, the aggregate Measurement is auto-marked UNVERIFIED, so the rubric's
`requires_integrity` objectives resolve `unverified_evidence` instead of silently trusting
an unchain-checked source. A single BROKEN record makes the whole Measurement BROKEN.
"""

from __future__ import annotations

from collections.abc import Iterable

from treval.models import IntegrityStatus

# Worst-wins rank: BROKEN < UNVERIFIED < VERIFIED. `min_integrity` returns the lowest seen.
_RANK = {
    IntegrityStatus.BROKEN: 0,
    IntegrityStatus.UNVERIFIED: 1,
    IntegrityStatus.VERIFIED: 2,
}


def min_integrity(integrities: Iterable[IntegrityStatus]) -> IntegrityStatus:
    """The weakest integrity over the consumed records. Empty ⇒ VERIFIED (the frozen
    default; an empty stream makes sample_size==0, so the rubric short-circuits to
    insufficient_data before the integrity is ever read)."""
    worst = IntegrityStatus.VERIFIED
    for it in integrities:
        if _RANK[it] < _RANK[worst]:
            worst = it
    return worst
