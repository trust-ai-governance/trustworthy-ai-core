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
    observed_window: tuple[int, int] | None = None,
    generated_at_ns: int | None = None,
    language_scope: str | None = None,
    tested_version: str | None = None,
    detect_config: str | None = None,
    exec_mode: str | None = None,
    detection_layer_status: str | None = None,
    upstream_timeout_s: float | None = None,
    config_source: str = "declared",
    tier2_drain_executed: bool = False,
    build_fingerprint_before: dict[str, Any] | None = None,
    build_fingerprint_after: dict[str, Any] | None = None,
    admin_url_declared: bool = False,
    probe_window: tuple[int, int] | None = None,
    arm_parity: str = "hard_or_flag",
    canary_set_id: str | None = None,
) -> dict[str, Any]:
    """The run's pin artifact, embedded in the collect bundle (EV-PIN §1.3).

    `pinned` is True only when the operator supplied BOTH window bounds — that is the whole
    claim: this run is reproducible from its inputs. A run whose window was merely *observed*
    is honest about covering that range but is still a snapshot of wherever the WAL happened
    to be, so it reports `pinned: false` and must not be cited externally (§1.4).

    EV-COVERAGE E3-h (§3.1) — the freeze pack must also record what SCOPES the numbers: the
    tested party's `tested_version`, its detection `detect_config` (esp. encode/decode on-off),
    and the `exec_mode` (`block` = hit⇒deny, `flag` = mark-only). 🔴 These keys are ALWAYS emitted
    (empty when the operator didn't declare them) so citability can tell a v2 run that DIDN'T declare
    (keys present-but-empty) apart from a pre-E3 bundle (keys absent). `config_source` records HOW
    they arrived (`declared` now; `queried` reserved for a future version/config endpoint) — it is
    metadata, NOT part of the citability criterion (the criterion is fields-present, not their source)."""
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
        # EV-CITE C12 — the window the records ACTUALLY occupy. For a normal run it is the span
        # covered by the scan; when a PINNED window caught nothing (record_count==0), the caller
        # supplies the UNFILTERED span so the citability blocker can hand the operator a window to
        # re-pin (they must never have to compute nanoseconds themselves). None ⇒ no records to point at.
        "observed_window": list(observed_window) if observed_window else None,
        # EV-CITE C15 — the wall clock at collect time, stamped INTO the product. citability judges an
        # unclosed (future-upper-bound) window from this field, never by reading the clock at report
        # time — a bundle carries its own basis so it stays judgeable after it changes hands. None ⇒
        # a pre-C15 bundle with no stamp; the future-upper-bound blocker then skips (no clock fallback).
        "generated_at_ns": generated_at_ns,
        # EV-COVERAGE E3-h/E3-m (§3.1 / §2.2.2 / §5) — what scopes "89%": the #1 axis is the
        # `language_scope` (upstream rules English numbers fail-closed for the Chinese market), then
        # the tested party's version, its key detection config switches, and the execution mode
        # (block / flag). 🔴 ALL ALWAYS present (empty when undeclared) so present-but-empty (a v2 run
        # that didn't declare) is distinguishable from absent (a pre-E3 bundle). 🔴 language_scope is
        # an operator DECLARATION (the --language-scope flag), NEVER inferred from case bytes.
        # `config_source` is HOW they arrived — metadata, not the criterion.
        "language_scope": language_scope or "",
        "tested_version": tested_version or "",
        "detect_config": detect_config or "",
        "exec_mode": exec_mode or "",
        # EV-COVERAGE E3-n ③ — the freeze pack must ALSO pin the DETECTION-LAYER STATUS (which layers
        # are live, e.g. tier1_only / tier2 shadow off) and the tested party's UPSTREAM REQUEST-TIMEOUT
        # (its OWN hardcoded value, DECLARED — the client --timeout is then derived as 2×, not guessed).
        # Both fold into the SAME missing_run_config citability criterion. Present-but-empty (""/null on
        # a v2 run that didn't declare) is distinguishable from ABSENT (a pre-E3-n bundle), like the four
        # keys above. upstream_timeout_s stays a number (the declared seconds), null when undeclared.
        "detection_layer_status": detection_layer_status or "",
        "upstream_timeout_s": upstream_timeout_s,
        "config_source": config_source,
        # EV-COVERAGE E3-n ② — did the async Tier-2 drain execute this run? Recorded so a Tier-2 layer
        # that was never drained cannot be read as "0% lift" — the freeze pack states the layer's status.
        "tier2_drain_executed": tier2_drain_executed,
        # EV-COVERAGE E3-n ④ — the tested party's self-reported build fingerprint (git_sha +
        # detection_switches, GET /admin/v1/buildinfo) captured BEFORE and AFTER the run, stored
        # VERBATIM (evidence in the artifact, not just compared-then-discarded). citability compares
        # them: any bit of difference ⇒ the tested party changed mid-run ⇒ NOT citable. null when no
        # admin endpoint was queried (no --admin-url).
        "build_fingerprint_before": build_fingerprint_before,
        "build_fingerprint_after": build_fingerprint_after,
        # E3-n ④ — whether --admin-url was declared. citability fail-closes a declared-but-unfetched
        # build-fingerprint check (both-None blocks ONLY when the admin endpoint was actually named).
        "admin_url_declared": admin_url_declared,
        # E3-n ② — this run's probe span [first, last+ε), half-open. The ACTIVE rates (catch / FPR /
        # four-cell / success) cite THIS in their citation_form; passive / census indicators keep
        # `observed_window` (the WAL range they actually read). None when nothing was probed.
        "probe_window": list(probe_window) if probe_window else None,
        # E3F §1 (F1) — injection_catch_rate now counts a catch ONLY when a matched INJECTION rule
        # earned it (rule-scoped attribution), never "the gateway reacted for any reason". Stamped as a
        # CONSTANT because Core always attributes post-F1: its PRESENCE marks the new epoch, so a
        # rule_scoped run's catch number is 🔴 NOT comparable to a pre-F1 (key-absent) run's (§1.4).
        "catch_attribution": "rule_scoped",
        # E3F §4 (F4) — the ARM-PARITY口径 the catch AND benign arms shared this run (hard_or_flag /
        # hard_only). Recorded so a run whose two arms disagreed can be refused (§4.4-4) and so the
        # benign gate is read on the same basis the catch number was.
        "arm_parity": arm_parity,
        # F7 (E3F §7.3-③/§7.4-4) — this run's canary-set identity: a sha256-of-salt handle, 🔴 NEVER the
        # salt or any canary plaintext. Pins WHICH canary epoch produced the numbers, so two runs stay
        # comparable (same corpus_sha, rotated canaries). None when nothing was probed / no canary set.
        "canary_set_id": canary_set_id or None,
    }
