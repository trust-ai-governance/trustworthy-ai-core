"""run_indicators — fan a single evidence stream across indicators (EV-4 §3.3)."""

from __future__ import annotations

from collections.abc import Iterable

from treval.models import AuditEvidence, Measurement
from treval.protocols import Indicator


def run_indicators(
    indicators: Iterable[Indicator],
    evidence: Iterable[AuditEvidence],
) -> tuple[Measurement, ...]:
    """Run each indicator over the SAME evidence, flatten the results.

    `evidence` may be a single-pass Iterator (the WAL reader yields a generator),
    so materialize it ONCE up front — otherwise only the first indicator sees any
    data. Order = indicators order, then each indicator's own Measurement order.
    """
    records = tuple(evidence)
    out: list[Measurement] = []
    for indicator in indicators:
        out.extend(indicator.measure(records))
    return tuple(out)
