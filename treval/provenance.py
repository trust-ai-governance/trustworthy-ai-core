"""Run provenance — pin an evaluation run to a reproducible window + WAL bytes (EV-PIN).

**The problem this exists to kill.** A report whose window is "the latest" is a snapshot of a
MOVING target: the WAL tail advances and the same citation stops reproducing. That already bit
us — a whitepaper cited `chain_integrity 100% n=463` taken from the live `__eval__` window, and
once the window moved 463 could never be reproduced again.

**The rule.** An externally-quoted number must come from a PINNED run: explicit window bounds +
the WAL segment bytes it read + the date. Given the same WAL and the same bounds, a third party
recomputes the same n and the same value. `pinned: false` marks a moving-window snapshot, which
external documents must not cite.

Pure: stdlib + `tools._wal_format`. No engine grading, no web, no network.

---

**Half-open windows — the off-by-one that would silently break reproducibility.**
`WalEvidenceReader` filters `received_at_ns >= time_from_ns` and `< time_to_ns` — `to` is
EXCLUSIVE. So the observed window of a scan is `[min, max + 1)`, NOT `[min, max]`: re-running
with `to = max` would drop the very last record and yield a different n. `observed_window`
therefore returns the half-open form, which round-trips exactly.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tools._wal_format import list_segments
from treval.models import AuditEvidence


@dataclass(frozen=True)
class WalSegments:
    """The WAL segment range a run read, plus a content hash over their bytes — the handle a
    third party uses to confirm "you ran THIS batch of WAL", not some other one."""

    first: str
    last: str
    count: int
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "first": self.first,
            "last": self.last,
            "count": self.count,
            "sha256": self.sha256,
        }


def segment_provenance(wal_dir: str | Path) -> WalSegments | None:
    """Hash the WAL segments present in `wal_dir`, in segment order.

    The digest binds each segment's NAME and its BYTES (name, NUL, bytes, NUL), so neither a
    rename nor a content edit can pass unnoticed. Returns None for an empty/absent directory —
    a run over no segments has no provenance to claim."""
    directory = Path(wal_dir)
    try:
        paths = list_segments(directory)
    except (OSError, ValueError):
        return None
    if not paths:
        return None

    digest = hashlib.sha256()
    for path in paths:  # list_segments sorts by start seq — deterministic order
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return WalSegments(
        first=paths[0].name,
        last=paths[-1].name,
        count=len(paths),
        sha256="sha256:" + digest.hexdigest(),
    )


def observed_window(evidence: Iterable[AuditEvidence]) -> tuple[int, int] | None:
    """The HALF-OPEN window `[min, max + 1)` actually covered by `evidence`.

    `+1` is not cosmetic: the reader's upper bound is exclusive, so this is the interval that
    re-selects exactly these records. Returns None for an empty scan (no window to claim —
    the caller must not invent one)."""
    times = [ev.received_at_ns for ev in evidence]
    if not times:
        return None
    return (min(times), max(times) + 1)


def build_provenance(
    *,
    wal_dir: str | Path | None,
    window: tuple[int, int] | None,
    pinned: bool,
    tenant_id: str,
    record_count: int,
) -> dict[str, Any]:
    """The run's pin artifact, embedded in the collect bundle (EV-PIN §1.3).

    `pinned` is True only when the operator supplied BOTH window bounds — that is the whole
    claim: this run is reproducible from its inputs. A run whose window was merely *observed*
    is honest about covering that range but is still a snapshot of wherever the WAL happened
    to be, so it reports `pinned: false` and must not be cited externally (§1.4)."""
    segments = segment_provenance(wal_dir) if wal_dir else None
    return {
        # What KIND of data this is, declared positively. A run built here always read a real
        # WAL, so it is `measured`. The demo generator declares `synthetic_demo` instead —
        # both sides state their kind rather than one being inferred from the other's absence,
        # because a synthetic report that renders identically to a measured one is how a
        # fabricated sample size reached an external document once already (PROV §5, n=520).
        "data_source": "measured",
        "pinned": pinned,
        "tenant_id": tenant_id,
        "window": list(window) if window else None,
        "window_semantics": "half-open [from_ns, to_ns)",
        "wal_dir": str(wal_dir) if wal_dir else None,
        "wal_segments": segments.as_dict() if segments else None,
        "record_count": record_count,
    }
