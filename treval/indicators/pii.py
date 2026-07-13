"""PII indicators — measured Privacy from the B1 marker (EV-9 §2).

Both read `audit.hint_variables["pii_types"]` off the request's records (B1, merged +
live-verified 2026-07-12; value e.g. `"email"`). NOT `Invocation.params_indexed` — that is
user request content and never carries `pii_*` (Platform correction). dim
`privacy_data_protection`; passive; `Measurement.integrity = min` (②).

- **redaction_hit_ratio** = requests with ≥1 PII type detected (∴ redactable) ÷ measurable
  requests.
- **pii_exposure_surface** = count of the distinct PII-type set observed across the window
  (e.g. {email, phone} → 2).

Requests are grouped by `join_ab` (EV-5b) and the PII types are UNIONed across a request's
A + B records — so the marker appearing on both the decision and response record is counted
ONCE per request (this is the "measure per request, not per intermediate record" intent; the
`final_terminal` measurable-set filter is a Platform open item, see EV-9 §2). `pii_types` is a
`map<string,string>` value; a multi-type value is split on commas (only single values seen
live, so this is defensive).
"""

from __future__ import annotations

from collections.abc import Iterable

from treval.indicators._integrity import min_integrity
from treval.indicators.correlate import join_ab
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus, Measurement

_PII_KEY = "pii_types"


def _pii_types(ev: AuditEvidence) -> set[str]:
    """The PII type names on one record's B1 marker. Split on commas (defensive — only single
    values like `"email"` seen live); empty when the marker is absent."""
    hint_variables = ev.record.audit.hint_variables
    if _PII_KEY not in hint_variables:
        return set()
    return {t.strip() for t in hint_variables[_PII_KEY].split(",") if t.strip()}


def _requests_with_pii(
    records: tuple[AuditEvidence, ...],
) -> list[tuple[tuple[AuditEvidence, ...], set[str]]]:
    """Group the stream into requests (join_ab) and union each request's PII types over its
    A + B records. Returns (present_records, pii_types) per request in stable order."""
    join = join_ab(records)
    groups: list[tuple[AuditEvidence | None, AuditEvidence | None]] = []
    groups.extend(join.paired)
    groups.extend((a, None) for a in join.orphan_a)
    groups.extend((None, b) for b in join.orphan_b)

    out: list[tuple[tuple[AuditEvidence, ...], set[str]]] = []
    for a, b in groups:
        present = tuple(r for r in (a, b) if r is not None)
        types: set[str] = set()
        for r in present:
            types |= _pii_types(r)
        out.append((present, types))
    return out


class RedactionHitRatio:
    indicator_id = "redaction_hit_ratio"
    dimension = "privacy_data_protection"  # MUST match the EV-6 dimension id

    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]:
        groups = _requests_with_pii(tuple(evidence))
        refs: list[EvidenceRef] = []
        integrities: list[IntegrityStatus] = []
        hits = 0
        for present, types in groups:
            refs.append(present[0].ref)
            integrities.extend(r.integrity for r in present)
            if types:
                hits += 1

        total = len(refs)
        value = hits / total if total else 0.0
        notes = (
            f"{hits} of {total} request(s) carried ≥1 detected PII type (redactable)"
            if total
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


class PiiExposureSurface:
    indicator_id = "pii_exposure_surface"
    dimension = "privacy_data_protection"  # MUST match the EV-6 dimension id

    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]:
        groups = _requests_with_pii(tuple(evidence))
        refs: list[EvidenceRef] = []
        integrities: list[IntegrityStatus] = []
        surface: set[str] = set()
        for present, types in groups:
            refs.append(present[0].ref)
            integrities.extend(r.integrity for r in present)
            surface |= types

        total = len(refs)
        notes = (
            f"distinct PII-type surface across {total} request(s): {sorted(surface)}"
            if surface
            else ""
        )
        return (
            Measurement(
                indicator_id=self.indicator_id,
                dimension=self.dimension,
                value=float(len(surface)),  # count of distinct PII types
                unit="count",
                sample_size=total,
                evidence_refs=tuple(refs),
                subject="",
                notes=notes,
                integrity=min_integrity(integrities),
            ),
        )
