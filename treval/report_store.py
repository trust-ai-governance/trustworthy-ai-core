"""Report store — the on-disk home of generated EV-R1 bundles (EV-W1 D1).

The store is a directory, not a database: the bundle is already a self-contained,
deterministic JSON file and Core is deliberately dep-light. A directory + a small index
meets the "switching tenant is a sub-second read" requirement with no new dependency.

    DIR/
      index.json                      # [{tenant_id, window, generated_at_ns,
      bundles/<sha256(bytes)[:16]>.json #   registry_fingerprint, file}]

**Content-addressed on purpose.** `tenant_id` originates in the WAL — untrusted input.
Interpolating it into a filename is a path-traversal bug waiting to happen; hashing the
bundle bytes sidesteps the whole class, and the digest doubles as the bundle's identity.

**`generated_at_ns` is stored, never derived from mtime** — mtime is not part of the
contract and does not survive a copy.

This module is shared by BOTH sides of the store — the `treval report --self-contained`
writer (CLI) and the read-only web service — so the format lives in exactly one place.
Pure stdlib: it imports neither the engine (it never grades) nor the web layer.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

INDEX_NAME = "index.json"
BUNDLES_DIR = "bundles"
_DIGEST_LEN = 16


class ReportStoreError(Exception):
    """The store is unreadable or malformed (fail-closed — never guess a report)."""


@dataclass(frozen=True)
class ReportEntry:
    """One stored bundle's index record. `window` is the report's [start_ns, end_ns]."""

    tenant_id: str
    window: tuple[int, int]
    generated_at_ns: int
    registry_fingerprint: str
    file: str  # relative to the store dir, e.g. "bundles/<digest>.json"

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "window": list(self.window),
            "generated_at_ns": self.generated_at_ns,
            "registry_fingerprint": self.registry_fingerprint,
            "file": self.file,
        }


def _digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()[:_DIGEST_LEN]


def _atomic_write(path: Path, payload: bytes) -> None:
    """Write via temp + os.replace so a concurrent reader never sees a half file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def write_bundle(
    store_dir: str | Path, bundle_json: str, *, generated_at_ns: int
) -> ReportEntry:
    """Store one EV-R1 self-contained bundle VERBATIM and update the index atomically.

    The bytes are written exactly as produced — the bundle's whole value is that it is the
    artifact the engine emitted (byte-identical to the customer's copy, still carrying its
    registry_fingerprint). Re-storing the same bytes is idempotent (same digest, one entry).
    """
    root = Path(store_dir)
    payload = bundle_json.encode("utf-8")
    try:
        doc = json.loads(bundle_json)
    except json.JSONDecodeError as e:
        raise ReportStoreError(f"bundle is not valid JSON: {e}") from e
    if not isinstance(doc, dict) or "report" not in doc:
        raise ReportStoreError("bundle is not an EV-R1 envelope (no 'report')")
    report = doc["report"]
    window = report.get("window")
    if not (isinstance(window, list) and len(window) == 2):
        raise ReportStoreError("bundle report.window must be [start_ns, end_ns]")

    entry = ReportEntry(
        tenant_id=str(report.get("tenant_id", "")),
        window=(int(window[0]), int(window[1])),
        generated_at_ns=generated_at_ns,
        registry_fingerprint=str(doc.get("registry_fingerprint", "")),
        file=f"{BUNDLES_DIR}/{_digest(payload)}.json",
    )
    _atomic_write(root / entry.file, payload)

    # Rebuild the index, then rewrite atomically. The store is APPEND-ONLY (§9): a newer
    # report for the same (tenant, window) does NOT replace the older one — `resolve`
    # returns the newest match, and nothing deletes. Dedupe is by CONTENT digest, so
    # re-storing identical bytes is idempotent (one entry) rather than a duplicate row.
    entries = [e for e in _read_index(root, missing_ok=True) if e.file != entry.file]
    entries.append(entry)
    entries.sort(key=lambda e: e.generated_at_ns, reverse=True)  # newest first
    _atomic_write(
        root / INDEX_NAME,
        json.dumps([e.as_dict() for e in entries], ensure_ascii=False, indent=2).encode(
            "utf-8"
        )
        + b"\n",
    )
    return entry


def _parse_entry(raw: object, where: str) -> ReportEntry:
    if not isinstance(raw, dict):
        raise ReportStoreError(f"{where}: each index entry must be an object")
    window = raw.get("window")
    if not (isinstance(window, list) and len(window) == 2):
        raise ReportStoreError(f"{where}: entry.window must be [start_ns, end_ns]")
    file = raw.get("file")
    if not isinstance(file, str) or not file:
        raise ReportStoreError(f"{where}: entry.file must be a non-empty string")
    return ReportEntry(
        tenant_id=str(raw.get("tenant_id", "")),
        window=(int(window[0]), int(window[1])),
        generated_at_ns=int(raw.get("generated_at_ns", 0)),
        registry_fingerprint=str(raw.get("registry_fingerprint", "")),
        file=file,
    )


def _read_index(root: Path, *, missing_ok: bool = False) -> list[ReportEntry]:
    path = root / INDEX_NAME
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if missing_ok:
            return []
        raise ReportStoreError(f"no report store index at {path}") from None
    except OSError as e:
        raise ReportStoreError(f"cannot read {path}: {e}") from e
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ReportStoreError(f"{path} is not valid JSON: {e}") from e
    if not isinstance(doc, list):
        raise ReportStoreError(f"{path}: index must be an array")
    return [_parse_entry(e, f"{path}[{i}]") for i, e in enumerate(doc)]


class ReportStore:
    """Read-only view over a store directory. It resolves and returns STORED BYTES — it
    never grades, never re-serializes, and never imports the engine.

    The index is re-read per call so a producer run shows up without a restart (it is one
    small file; the producer swaps it atomically, so a reader never sees a partial write).
    """

    def __init__(self, store_dir: str | Path) -> None:
        self._root = Path(store_dir)

    @property
    def root(self) -> Path:
        return self._root

    def list(self) -> list[ReportEntry]:
        """Every stored report, NEWEST FIRST — powers the tenant + window selectors."""
        entries = _read_index(self._root, missing_ok=True)
        entries.sort(key=lambda e: e.generated_at_ns, reverse=True)
        return entries

    def resolve(
        self, tenant: str | None = None, window: str | None = None
    ) -> ReportEntry | None:
        """The entry for `(tenant, window)`; the newest report when both are None. `window`
        is the string form "<start_ns>-<end_ns>" (what the URL carries). Returns None when
        nothing matches — the caller renders a 404, never another tenant's report."""
        entries = self.list()
        if tenant is not None:
            entries = [e for e in entries if e.tenant_id == tenant]
        if window is not None:
            entries = [e for e in entries if window_key(e.window) == window]
        return entries[0] if entries else None

    def read_bytes(self, entry: ReportEntry) -> bytes:
        """The stored bundle, byte-for-byte. `file` comes from our own index, but resolve
        it under the store root and refuse anything that escapes (defence in depth: the
        index is a file on disk, so treat it as input)."""
        path = (self._root / entry.file).resolve()
        root = self._root.resolve()
        if not path.is_relative_to(root):
            raise ReportStoreError(f"bundle path escapes the store: {entry.file!r}")
        try:
            return path.read_bytes()
        except OSError as e:
            raise ReportStoreError(f"cannot read bundle {path}: {e}") from e


def window_key(window: tuple[int, int]) -> str:
    """The URL/selector form of a window: "<start_ns>-<end_ns>"."""
    return f"{window[0]}-{window[1]}"
