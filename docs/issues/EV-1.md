# EV-1 — `WalEvidenceReader` (the canonical zero-trust audit source)

> Dev brief. Self-contained with this file + the repo. Parent design:
> `docs/EVAL_ARCHITECTURE(WIP).md` §2.1 (Evidence Reader) + §4a (deployment);
> `docs/EVAL_ISSUES(WIP).md` EV-1. Builds on **EV-0** (frozen models/Protocols,
> already on `main`). 中文背景见 `docs/EVAL_ISSUES(WIP).md`.

## 0. Context

`WalEvidenceReader` is the **canonical, integrity-bearing** audit source: it reads a
**read-only WAL directory** the gateway wrote, decodes each record to a
`RequestContext`, and tags each with an `IntegrityStatus` derived from the **same
production verifier** (`wal_verify`) a customer would run. It never imports the
closed platform and never connects to the gateway — that's the zero-trust invariant.
It implements the EV-0 `AuditEvidenceReader` Protocol.

## 1. Scope

1. **Extract the lazy RequestContext decoder** out of `tools/wal_dump.py` into a
   shared, reusable helper `tools/_rc_decode.py` — **surgical, behavior-preserving**.
2. Implement `treval/readers/wal_reader.py::WalEvidenceReader` over a WAL dir,
   reusing `tools/_wal_format` (framing) + `tools/wal_verify.verify` (integrity) +
   the extracted decoder.
3. Export `WalEvidenceReader` from `treval/__init__.py`.

## 2. Shared files touched (conflict map)

| File | Change | Risk |
|---|---|---|
| `tools/_rc_decode.py` | **new** | none |
| `tools/wal_dump.py` | refactor `_get_decoder` to call the extracted helper; **behavior identical** | guarded by existing `tests/test_wal_dump*.py` |
| `treval/__init__.py` | **append** `WalEvidenceReader` to imports + `__all__` | low (append-only) |
| `treval/readers/__init__.py`, `treval/readers/wal_reader.py` | **new** | none |
| `tests/test_wal_reader.py` | **new** | none |

Do **not** modify `tools/_wal_format.py` or `tools/wal_verify.py` — reuse them as-is.

## 3. Part A — decoder extraction (`tools/_rc_decode.py`)

Today `tools/wal_dump.py::_get_decoder()` lazily imports the proto and returns a
`decode(payload)->dict` (via `RequestContext.FromString` + `MessageToDict`). Core
needs the **proto object**, not a dict. Extract the lazy import + `FromString`:

```python
# tools/_rc_decode.py  (zero-dep until called; proto import is lazy)
from __future__ import annotations

class RcDecodeUnavailable(RuntimeError):
    """The ir-spec proto package isn't importable — decode cannot proceed."""

def decode_request_context(payload: bytes):   # -> trustworthy_ai.v1...RequestContext
    try:
        from trustworthy_ai.v1 import request_context_pb2 as rc_pb
    except Exception as e:
        raise RcDecodeUnavailable(
            "trustworthy-ai-ir-spec proto not importable; cannot decode WAL payload"
        ) from e
    return rc_pb.RequestContext.FromString(payload)
```

Then refactor `wal_dump._get_decoder`'s inner `decode()` to call
`decode_request_context(payload)` before its `MessageToDict` + bytes-rendering (which
**stay in wal_dump**). Keep wal_dump's warn-once + fall-back-to-preview behavior by
catching `RcDecodeUnavailable` where it currently catches the import error. **Net
behavior of wal_dump is unchanged** — prove it by leaving `tests/test_wal_dump*.py`
green.

## 4. Part B — `WalEvidenceReader`

```python
# treval/readers/wal_reader.py
class WalEvidenceReader:                      # satisfies treval.AuditEvidenceReader
    def __init__(self, wal_dir: str | Path) -> None: ...
    def read_audit(self, *, tenant_id=None, time_from_ns=None,
                   time_to_ns=None) -> Iterator[AuditEvidence]: ...
```

Behavior:

- **Integrity, reusing the production verifier.** Call
  `wal_verify.verify(self._dir, full=True)` **once** (eager) → `Report`. Derive the
  poison point:
  ```python
  err_seqs = [f["seq"] for f in rep.findings if f["seq"] is not None]
  broken_from = min(err_seqs) if err_seqs else None
  # per record:
  verified = rep.ok or (broken_from is not None and rec.seq < broken_from)
  integrity = IntegrityStatus.VERIFIED if verified else IntegrityStatus.BROKEN
  ```
  **Rule (conservative / fail-closed in spirit):** the first break poisons the tail —
  a record is `VERIFIED` only if the WAL verified clean, or its `seq` is strictly
  below the first finding's `seq`. If `verify` failed with only structural findings
  (`seq is None`, e.g. unreadable header), `broken_from` is `None` and `rep.ok` is
  `False` → **every** record is `BROKEN` (we cannot trust any of it). This matches
  EV-1's acceptance "tampered record and everything after it → BROKEN".

- **Records + decode.** Stream via `_wal_format`: `list_segments(dir)` →
  `read_segment_header` → `iter_records(data, hdr)` (already stops cleanly at a
  truncated tail → safe on a live WAL). For each `Record`, `decode_request_context(rec.payload)`
  → `RequestContext`. From its `envelope`: `tenant_id`, `received_at_ns`,
  `request_id`. Build:
  ```python
  ref = EvidenceRef(source=f"wal:{segment_path}", seq=rec.seq, request_id=req_id)
  yield AuditEvidence(ref, integrity, tenant_id, received_at_ns, record)
  ```
- **Filters** (applied after decode): `tenant_id ==`; `received_at_ns` in
  `[time_from_ns, time_to_ns)` (half-open; `None` = unbounded each side).
- **Order:** yield in `seq` order (natural WAL order across sorted segments) —
  deterministic.
- **Decode unavailable → raise** `RcDecodeUnavailable` (propagate). Unlike wal_dump,
  the reader does **not** fall back to a preview — evaluation strictly needs the
  decoded record (EV-1 non-negotiable).
- **Edge cases:** non-existent `wal_dir` → raise a clear error. Empty dir (no
  segments) → yield nothing (no evidence is a valid result, not an error).

## 5. Test fixtures — use REAL `RequestContext` payloads

The reader decodes payloads, so fixtures must be **serialized `RequestContext`
bytes**, not random bytes. `tests/walgen.py` writes the WAL framing; you supply the
payloads. Build a small helper that constructs `RequestContext(envelope=Envelope(
request_id=…, tenant_id=…, received_at_ns=…))`, `.SerializeToString()`, and feeds
those to `walgen`. Vary `tenant_id`/`received_at_ns`/`request_id` across records so
the filter tests are meaningful.

## 6. Acceptance (you write the unit tests)

1. **Happy path:** a multi-record fixture (real RCtx payloads via walgen) → N
   `AuditEvidence`, each with correct `seq`/`request_id`/`tenant_id`/`received_at_ns`,
   all `IntegrityStatus.VERIFIED`; yielded in `seq` order.
2. **Tamper:** flip a byte in record k's stored bytes → records `seq >= k` are
   `BROKEN`, `seq < k` are `VERIFIED` (drive it through `wal_verify`, don't hand-roll).
3. **Filters:** `tenant_id` and `[time_from_ns, time_to_ns)` select the expected
   subset (boundaries: `from` inclusive, `to` exclusive).
4. **Decode unavailable:** simulate the proto import failing → `read_audit` raises
   `RcDecodeUnavailable` (not a silent skip, not a preview).
5. **wal_dump unchanged:** `tests/test_wal_dump*.py` still green after the extraction.
6. Non-existent dir raises; empty dir yields nothing.
7. Coverage ≥ 60% on new paths; `mypy tools treval` + ruff clean.
8. *(E2E, test agent — later, not now):* point the reader at a real platform-produced
   read-only mount; record count + integrity agree with the `wal_verify` CLI on the
   same mount.

## 7. Non-goals

- `ExportEvidenceReader` / sqlite / Postgres (EV-2, deferred).
- Archived-segment / object-store reading; `--repair`.
- Any indicator or rubric logic.
- Re-testing the WAL byte format against the golden vectors — that binding already
  exists in `tests/conformance/test_wal_golden.py` for `_wal_format`; the reader sits
  on top of it and inherits it.

## 8. Guardrails

- **Reuse, don't reimplement:** integrity comes from `wal_verify.verify`; framing
  from `_wal_format`. No second copy of the chain/CRC logic in `treval`.
- Never import the closed platform. `treval → tools` is the allowed direction.
- Deterministic: stable `seq` order, no clock, no RNG.
- The `verify`-once-then-stream approach does an extra file pass; that's fine for
  EV-1 (perf tuning is later — don't optimize speculatively).

## 9. Likely questions to raise back

- Confirm the **poison-the-tail** integrity rule (§4) is the intended conservative
  semantics vs. per-record localization (CRC failures are technically localized, but
  the acceptance asks for "record and subsequent" → tail poisoning is correct).
- Source of real `RequestContext` fixtures — extend `walgen` or add a tiny builder?
  (Default: a small builder in the test module; don't bloat `walgen`.)
- Should `EvidenceRef.source` carry the segment file path or the dir? (Default: the
  specific **segment** path — most precise for drill-down.)
