"""chain_integrity — the Transparency integrity moat (EV-5a ③).

Fraction of records whose evidence is `IntegrityStatus.VERIFIED` — i.e. the reader could
chain-verify them (hash chain + CRC + seq continuity). A tamper/corruption breaks the chain,
poisons the tail (EV-1), so those records read BROKEN → value < 1 AND the Measurement's own
integrity goes BROKEN (min, ②). It reads only `AuditEvidence.integrity` (no new interface):
WAL-only by nature — a Postgres/index source is UNVERIFIED, which flows to the Measurement.

This is the `requires_integrity` objective (trn.l3.audit_chain_intact `value>=1`,
trn.l4.trace_baseline `sample_size>=100`): the rubric resolves a BROKEN/UNVERIFIED Measurement
to `unverified_evidence` — correct, a broken chain cannot verify itself.
"""

from __future__ import annotations

from collections.abc import Iterable

from treval.indicators._integrity import min_integrity
from treval.models import AuditEvidence, IntegrityStatus, Measurement


class ChainIntegrity:
    indicator_id = "chain_integrity"
    dimension = "transparency_accountability"  # MUST match the EV-6 dimension id

    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]:
        refs = []
        integrities = []
        verified = 0
        for ev in evidence:
            refs.append(ev.ref)
            integrities.append(ev.integrity)
            if ev.integrity is IntegrityStatus.VERIFIED:
                verified += 1

        total = len(refs)
        value = verified / total if total else 0.0
        notes = (
            f"{total - verified} of {total} record(s) not chain-verified"
            if total and verified < total
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
