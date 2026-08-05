"""Case store — the on-disk home of EV-R2 case contracts (UI-3 §5.3), SEPARATE from the report store.

Same dep-light, content-addressed shape as `treval/report_store.py` — but a DIFFERENT index file
name (`cases_index.json`, not `index.json`). 🔴 That name is load-bearing, not cosmetic (§5.3): if
the case store reused `index.json`, `ReportStore(<case dir>).list()` would happily parse case rows,
and "the report export path can't reach case records" would silently become false. Same name = the
separation fails.

The ingest gate is FAIL-CLOSED and lives in `case_ingest_gate` — enforced inside `write_case_bundle`
so the store is safe no matter who calls it (the `cases store` CLI is a thin wrapper). It refuses:
an EV-R1 report envelope (the reverse of report_store refusing case contracts, §6.1-1), a missing/
unknown disclosure_class, `internal_handoff`, 🔴 ANY row carrying response content even if the label
says `operator_only` (don't trust the label, check the shape — P2-4), a pre-tenant (v<3) or
tenant-less contract, and a contract whose rows do not re-add to its aggregates (the SAME re-adder as
`cases verify`, EV-R2 §9.3-c — no second summation path).

Pure stdlib + `treval.case_contract` (also pure): it imports NEITHER the engine NOR a WAL reader, so
the case service that reads this store cannot fire a probe or open a WAL (UI-3 §7).
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from treval.case_contract import (
    TENANT_INTRODUCED_IN,
    CaseContractError,
    compare_cases_to_aggregates,
    contract_is_empty,
    validate_case_contract,
)

CASES_INDEX_NAME = (
    "cases_index.json"  # 🔴 NOT "index.json" — the separation depends on it (§5.3)
)
CASES_DIR = "cases"
_DIGEST_LEN = 16


class CaseStoreError(Exception):
    """The case store is unreadable, or a contract was REFUSED by the ingest gate (fail-closed)."""


@dataclass(frozen=True)
class CaseEntry:
    """One stored contract's index record. `key` (the content digest) is the URL selector AND the
    identity; `tenant_id` is the ONLY scope source (§3.3) — 🔴 derived from the contract, NEVER from
    the file name or path (tenant_id originates in the WAL and is untrusted, same reason report_store
    is content-addressed)."""

    tenant_id: str
    corpus_sha: str
    generated_at_ns: int
    key: str  # sha256(bytes)[:16] — the URL selector + identity
    file: str  # relative to the store dir, e.g. "cases/<key>.json"

    def as_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "corpus_sha": self.corpus_sha,
            "generated_at_ns": self.generated_at_ns,
            "key": self.key,
            "file": self.file,
        }


def case_ingest_gate(doc: object) -> list[str]:
    """UI-3 §5.3 — the fail-closed ingest gate. Returns the list of refusal reasons (empty = admit).
    Every check names WHY, so a rejection is actionable; the recompute uses the shared re-adder."""
    if not isinstance(doc, Mapping):
        return ["case contract must be a JSON object"]
    # Reverse gate (§6.1-1): an EV-R1 report envelope is not a case contract. Symmetric to
    # report_store refusing anything carrying `disclosure_class`.
    if "report" in doc and "disclosure_class" not in doc:
        return [
            "this is an EV-R1 report envelope (has 'report', no 'disclosure_class') — the case store "
            "is SEPARATE from the report store (§6.1-1); refused"
        ]
    # 1. disclosure_class mandatory + closed verdict/observable_via vocab (fail-closed reader).
    try:
        validate_case_contract(doc)
    except CaseContractError as e:
        return [
            str(e)
        ]  # stop: rows are not safe to re-add until the vocab is known-good
    reasons: list[str] = []
    cases = doc.get("cases", [])
    # 2. Tier-1 label refused.
    if doc.get("disclosure_class") == "internal_handoff":
        reasons.append(
            "disclosure_class=internal_handoff (Tier-1 content) never enters the case store (P2-4)"
        )
    # 3. 🔴 shape over label (P2-4): ANY row with response content is refused, even if the label
    #    says operator_only. The label is a claim; the field is the fact.
    if any(
        isinstance(c, Mapping) and ("response_text" in c or "raw_response" in c)
        for c in cases
    ):
        reasons.append(
            "a case row carries response_text/raw_response — Tier-1 content refused regardless of "
            "the disclosure_class label (don't trust the label, check the shape; P2-4)"
        )
    # 4. tenant scoping (§5.2): v<3 or no tenant_id ⇒ refuse. 🔴 the fix is RE-RUN, never hand-add.
    version = doc.get("schema_version")
    if not isinstance(version, int) or version < TENANT_INTRODUCED_IN:
        reasons.append(
            f"schema_version {version!r} predates tenant scoping (needs ≥{TENANT_INTRODUCED_IN}) — "
            "re-run the eval to produce a v3 contract (do NOT hand-add a tenant field)"
        )
    if not doc.get("tenant_id"):
        reasons.append(
            "no tenant_id — a tenant-scoped store cannot accept an unscoped contract; re-run the "
            "eval (do NOT hand-add one)"
        )
    # 5. recompute — the rows must re-add to the declared aggregates (the SAME re-adder as verify).
    mism = compare_cases_to_aggregates(cases, doc.get("aggregates") or {})
    if mism:
        reasons.append("rows do not re-add to the aggregates: " + "; ".join(mism))
    # 6. 🔴 §5.4 — an ALL-errored run (gateway unreachable / eval identity unprovisioned) yields a
    #    contract whose three aggregates are all n=0. It re-adds (0=0), so check 5 passes — but it
    #    measured NOTHING and would be a permanent empty row. Same failure mode EV-PAIR gate 7 rejects.
    if contract_is_empty(doc):
        reasons.append(
            "empty contract — all three aggregates are n=0 (0 measurable cases; the run measured "
            "NOTHING). A gateway-unreachable or unprovisioned-eval-identity run produces this — see "
            "GATE-LASTMILE P4 / EV-PAIR gate 7 (confirm the gateway is ready and the eval identity is "
            "provisioned, then re-run). The store does not hold empty rows."
        )
    return reasons


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


def write_case_bundle(
    store_dir: str | Path, cases_json: str, *, generated_at_ns: int
) -> CaseEntry:
    """Run the ingest gate, then store the contract VERBATIM and update `cases_index.json` atomically.
    Raises CaseStoreError (with the named reasons) on refusal — the store never holds a contract that
    did not pass the gate. Re-storing identical bytes is idempotent (content digest)."""
    payload = cases_json.encode("utf-8")
    try:
        doc = json.loads(cases_json)
    except json.JSONDecodeError as e:
        raise CaseStoreError(f"contract is not valid JSON: {e}") from e
    reasons = case_ingest_gate(doc)
    if reasons:
        raise CaseStoreError(
            "contract REFUSED by the ingest gate: " + " | ".join(reasons)
        )

    root = Path(store_dir)
    key = _digest(payload)
    entry = CaseEntry(
        tenant_id=str(doc["tenant_id"]),
        corpus_sha=str(doc.get("corpus_sha", "")),
        generated_at_ns=generated_at_ns,
        key=key,
        file=f"{CASES_DIR}/{key}.json",
    )
    _atomic_write(root / entry.file, payload)
    # Append-only, dedupe by content digest (idempotent re-store), newest first.
    entries = [e for e in _read_index(root, missing_ok=True) if e.file != entry.file]
    entries.append(entry)
    entries.sort(key=lambda e: e.generated_at_ns, reverse=True)
    _atomic_write(
        root / CASES_INDEX_NAME,
        json.dumps([e.as_dict() for e in entries], ensure_ascii=False, indent=2).encode(
            "utf-8"
        )
        + b"\n",
    )
    return entry


def _parse_entry(raw: object, where: str) -> CaseEntry:
    if not isinstance(raw, dict):
        raise CaseStoreError(f"{where}: each index entry must be an object")
    key = raw.get("key")
    file = raw.get("file")
    if not isinstance(key, str) or not key:
        raise CaseStoreError(f"{where}: entry.key must be a non-empty string")
    if not isinstance(file, str) or not file:
        raise CaseStoreError(f"{where}: entry.file must be a non-empty string")
    return CaseEntry(
        tenant_id=str(raw.get("tenant_id", "")),
        corpus_sha=str(raw.get("corpus_sha", "")),
        generated_at_ns=int(raw.get("generated_at_ns", 0)),
        key=key,
        file=file,
    )


def _read_index(root: Path, *, missing_ok: bool = False) -> list[CaseEntry]:
    path = root / CASES_INDEX_NAME
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        if missing_ok:
            return []
        raise CaseStoreError(f"no case store index at {path}") from None
    except OSError as e:
        raise CaseStoreError(f"cannot read {path}: {e}") from e
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise CaseStoreError(f"{path} is not valid JSON: {e}") from e
    if not isinstance(doc, list):
        raise CaseStoreError(f"{path}: index must be an array")
    return [_parse_entry(e, f"{path}[{i}]") for i, e in enumerate(doc)]


class CaseStore:
    """Read-only view over a case store directory. Returns STORED BYTES — it never re-serializes,
    never grades, never imports the engine or a WAL reader. Tenant scoping is enforced by the CALLER
    (the service compares `entry.tenant_id` to the credential scope, §3.3); this class stays dumb."""

    def __init__(self, store_dir: str | Path) -> None:
        self._root = Path(store_dir)

    @property
    def root(self) -> Path:
        return self._root

    def list(self) -> list[CaseEntry]:
        """Every stored contract, NEWEST FIRST. The caller filters by tenant scope."""
        entries = _read_index(self._root, missing_ok=True)
        entries.sort(key=lambda e: e.generated_at_ns, reverse=True)
        return entries

    def get(self, key: str) -> CaseEntry | None:
        """The entry for a content `key`, or None. 🔴 The caller MUST still compare the entry's
        tenant_id to the credential scope before serving — an unguessable key is not authorization
        (§4: a scope mismatch is a 404, not a 403)."""
        for e in self.list():
            if e.key == key:
                return e
        return None

    def read_bytes(self, entry: CaseEntry) -> bytes:
        """The stored contract, byte-for-byte. `file` comes from our own index, but resolve it under
        the store root and refuse anything that escapes (defence in depth)."""
        path = (self._root / entry.file).resolve()
        root = self._root.resolve()
        if not path.is_relative_to(root):
            raise CaseStoreError(f"contract path escapes the store: {entry.file!r}")
        try:
            return path.read_bytes()
        except OSError as e:
            raise CaseStoreError(f"cannot read contract {path}: {e}") from e
