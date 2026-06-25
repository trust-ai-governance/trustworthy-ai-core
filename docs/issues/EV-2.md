# EV-2 — `PostgresEvidenceReader` (the convenience speed-path audit source)

> Dev brief. Self-contained with this file + the repo. Parent contract:
> `docs/POSTGRES_READ_CONTRACT.md` (reconciled with Platform A4 — **A4 satisfies
> it**); A4 design refs (platform): `A4_audit_index_port.md`, `DEPLOYMENT.md`,
> `deploy/postgres/audit_schema.sql`. Builds on **EV-0** + reuses **EV-1**'s shared
> decoder (`tools/_rc_decode`). `docs/EVAL_ISSUES(WIP).md` EV-2.

## 0. Context

WAL-direct (EV-1) is the **canonical, integrity-bearing** source. `PostgresEvidenceReader`
is a **convenience speed-path**: at volume, re-scanning WAL segments is slow, and
Platform's A4 builds a shared audit index on the **customer's own Postgres**. Core
reads it through the **same `AuditEvidenceReader` Protocol** as the WAL reader, so
every indicator works unchanged — the only difference is integrity: index-sourced
evidence is always **`UNVERIFIED`** (core can't re-check a hash chain it didn't parse
byte-for-byte). It never imports the closed platform; it connects with a permissive
driver and reads agreed columns.

This was deferred ("本期不做") while there was no DB. **A4 now ships Postgres**, so it
is reactivated.

## 1. Scope

1. `treval/readers/postgres_reader.py::PostgresEvidenceReader` implementing the EV-0
   `AuditEvidenceReader` Protocol over A4's `audit_events` table.
2. Driver: **`pg8000` (BSD)**, lazily imported (so `import treval` works without it).
3. Export from `treval/readers/__init__.py` + `treval/__init__.py`.
4. Logic tests (CI, no PG) + PG-integration tests (CI-gated, skip without PG).

## 2. Shared files touched (conflict map)

| File | Change | Risk |
|---|---|---|
| `treval/readers/postgres_reader.py` | **new** | none |
| `treval/readers/__init__.py` | **append** `PostgresEvidenceReader` | low |
| `treval/__init__.py` | **append** export | low |
| `requirements-postgres.txt` | **new** (optional dep `pg8000>=1.30`) | none |
| `.github/workflows/ci.yml` | add a PG-integration job (or extend) that installs `pg8000` + runs the gated tests | low |
| `tests/test_postgres_reader.py` (logic), `tests/integration/test_postgres_reader_pg.py` (PG) | **new** | none |

Reuse `tools/_rc_decode.decode_request_context` (EV-1) — do **not** add a second
decoder. **Never** import `psycopg`/`psycopg2` (LGPL, Charter §1.2).

## 3. The contract (A4 `audit_events`, from `POSTGRES_READ_CONTRACT.md`)

Schema (subset core reads), keys + indexes already provided by A4:

```
gateway_instance TEXT, seq BIGINT, request_id TEXT, tenant_id TEXT, agent_id TEXT,
received_at_ns BIGINT, record_type INTEGER, payload BYTEA, ...   PK(gateway_instance, seq)
ix_audit_request(request_id), ix_audit_tenant_t(tenant_id, received_at_ns)
```

Load-bearing rules (verified against the implemented schema):

- **Decode `payload`** (BYTEA = byte-identical WAL bytes) via
  `decode_request_context` → `RequestContext`. The projected columns
  (`agent_id`, `record_type`, …) are for **filter pushdown only**; the signal comes
  from the decoded payload (carries the full E1 fields).
- **Identity = `request_id`** (globally-unique). **`seq` is per-instance, NOT
  global** (multi-instance ships many WALs to one shared table; PK is
  `(gateway_instance, seq)`). So **never key/dedup on `seq`**.
- **Integrity = `UNVERIFIED`** for every row (can't re-check the chain). Hard-wired.
- **Cross-instance read** — the A4 "Search" access pattern: filter by tenant/time,
  **no `gateway_instance` filter**. `gateway_instance` is platform-internal; carry
  it into `EvidenceRef.source` only (for drill-down), not into joins.
- Yield **both** record types (A `record_type=1` decision.made + B `record_type=2`
  response.observed) — same as the WAL reader. A↔B pairing is EV-5b's job (by
  `request_id`), not EV-2's.

## 4. Interface

```python
class PostgresEvidenceReader:                  # satisfies treval.AuditEvidenceReader
    def __init__(self, *, host, port=5432, dbname, user, password,
                 schema_name="trustworthy_audit", sslmode="verify-full",
                 sslrootcert=None, sslcert=None, sslkey=None,
                 connect_timeout=10) -> None: ...
    def read_audit(self, *, tenant_id=None, time_from_ns=None,
                   time_to_ns=None) -> Iterator[AuditEvidence]: ...
    def close(self) -> None: ...               # optional lifecycle
```

Behavior:

- **Lazy driver import** inside `__init__`/connect; raise a clear error if `pg8000`
  isn't installed (mirror `RcDecodeUnavailable`'s pattern — e.g.
  `PostgresDriverUnavailable`). `import treval` must not require `pg8000`.
- **Query** the schema-qualified `"{schema_name}".audit_events`, selecting
  `payload, tenant_id, received_at_ns, request_id, gateway_instance, seq`. Push
  filters into the `WHERE` (this is the whole speed win): `tenant_id = %s`,
  `received_at_ns >= %s`, `received_at_ns < %s` (half-open, matching EV-1). Use the
  `ix_audit_tenant_t` index ordering.
- **Order deterministically:** `ORDER BY received_at_ns, gateway_instance, seq`.
- Per row:
  ```python
  record = decode_request_context(row.payload)     # same decoder as WAL reader
  ref = EvidenceRef(source=f"pg:{schema_name}#{gateway_instance}", seq=seq,
                    request_id=request_id or None)
  yield AuditEvidence(ref, IntegrityStatus.UNVERIFIED, tenant_id, received_at_ns, record)
  ```
- **Read-only:** only `SELECT`. Never write, DDL, or migrate. Document the required
  grant (A4 `DEPLOYMENT.md` §3): a **separate read-only role** with `USAGE` on the
  schema + `SELECT` on `audit_events`.
- A garbage/undecodable payload → reuse EV-1's policy: wrap in a clear error naming
  `request_id`/`seq` (don't leak a raw `DecodeError`). (You may lift EV-1's
  `WalReadError` analog or a shared `EvidenceDecodeError`.)
- TLS: pass `sslmode`/cert paths to the driver; default `verify-full`.

## 5. Testing

- **Logic (CI, no Postgres):** drive the row→`AuditEvidence` mapping, `UNVERIFIED`
  hard-wire, filter SQL construction, `request_id` keying, and `source` encoding via
  a **fake connection/cursor** (a small stand-in returning canned rows with **real
  serialized `RequestContext` payloads** — same fixture style as EV-1). Assert the
  reader is `AuditEvidenceReader`-shaped.
- **PG-integration (CI-gated, skips without PG/pg8000):** against the compose `full`
  profile Postgres (A4 `DEPLOYMENT.md` §6). Create the table from
  `audit_schema.sql` (or inline DDL), `INSERT` known rows (real payloads; include
  two rows with the **same `seq` but different `gateway_instance`** to prove no
  collision), read back, assert evidence + filters. Gate on env (`TRUSTAI_PG_HOST`…)
  and skip cleanly when absent — mirror A4's `test_postgres_sink_pg.py`.

## 6. Acceptance

1. Sample rows → reader yields `AuditEvidence` matching the WAL reader's shape for
   the same records, **except `integrity == UNVERIFIED`** for all.
2. **`request_id` identity:** two rows, same `seq`, different `gateway_instance` →
   both yielded, distinct, no collision; nothing keys on `seq`.
3. Filters: `tenant_id` and `[time_from_ns, time_to_ns)` (half-open) select the
   expected subset, pushed into SQL.
4. Both `record_type` 1 and 2 are yielded (A↔B pairing left to EV-5b).
5. **No `psycopg` anywhere**; `pg8000` lazily imported (so `import treval` works
   without it); missing driver → clear error.
6. Deterministic order (`received_at_ns, gateway_instance, seq`).
7. Logic tests pass in CI without PG; PG tests skip cleanly without PG.
8. Coverage ≥ 60%; `mypy treval` + ruff clean. License CI stays green (pg8000 BSD).

## 7. Non-goals

- Any writes / DDL / schema ownership / SQLite→PG migration (that's platform A4).
- Chain verification against the index (impossible → always `UNVERIFIED`).
- A↔B correlation (EV-5b, by `request_id`).
- Connection pooling (a single connection is fine — reads are not hot-path).
- Mongo / other backends (future, behind the same Protocol).

## 8. Guardrails

- Driver: **`pg8000` only**; lazy import; **never** `psycopg`/`psycopg2` (LGPL §1.2).
- Read-only `SELECT`; never mutate the customer DB.
- Reuse `tools/_rc_decode` — one decoder across WAL + PG (reader-agnostic indicators).
- `UNVERIFIED` is not negotiable — integrity always comes from WAL.
- Never import the closed platform. Deterministic order, no clock/RNG.

## 9. Deployment & connecting to Postgres (from Platform A4 `DEPLOYMENT.md`)

Platform's `DEPLOYMENT.md` is the authoritative A4 guide; core's reader consumes it
as a **separate read-only role**. What EV-2 needs:

- **Read-only consumer role (required, separate from the gateway writer)** — A4
  `DEPLOYMENT.md` §3:
  ```sql
  GRANT USAGE ON SCHEMA trustworthy_audit TO trustai_reader;
  GRANT SELECT ON trustworthy_audit.audit_events TO trustai_reader;   -- SELECT only
  ```
- **Connection config** (env/CLI; secrets from the secret store, never in clear):
  `host`, `port` (5432), `dbname`, `user` (`trustai_reader`), `password` (env),
  `schema_name` (default `trustworthy_audit`), `sslmode` (`verify-full` for prod),
  `sslrootcert`/`sslcert`/`sslkey`, `connect_timeout`. Mirror A4 §1's keys.
- **TLS:** default `verify-full`; pass CA/client certs for mTLS (A4 §4).
- **Tenant + fleet scoping (Charter §7.3).** Core reads **across instances *within
  one tenant*** — a tenant's HA instances all ship to the shared table, and maturity
  eval must aggregate that tenant's traffic ("fleet-within-tenant"). EV-2 therefore
  **always filters `tenant_id`** (never cross-tenant) and applies **no
  `gateway_instance` filter**. NB: this is core's **direct SQL** read path — distinct
  from the admin API's `?scope=fleet` opt-in (A4 §5); core does its own tenant-scoped
  `SELECT`, it does not call the admin endpoint.
- **Integration testing** against the compose `full` profile (A4 §6):
  `postgres:16-alpine`, db/user/pass `audit`/`trustai`/`trustai`, port 5432; env
  `TRUSTAI_PG_HOST/PORT/DBNAME/USER/PASSWORD`; `pip install pg8000`; skip cleanly if
  absent. For core's read tests, create a `trustai_reader` (SELECT-only) role or
  reuse `trustai` for `SELECT` in the test DB.

> Capability boundary (A4 `DEPLOYMENT.md` §9.1): the index holds governance-decision
> events only. Some indicators have **no data source yet** and will read
> `insufficient_data` (not a defect) — see EV-9 / the maturity-model notes.

## 10. Likely questions

- Driver dep packaging: a `requirements-postgres.txt` (chosen) vs a `pyproject`
  extra. Confirm how CI installs it for the PG job.
- Whether to expose a single-record `get_by_request_id` now (EV-1 didn't). Default:
  **no** — keep parity with the WAL reader's `read_audit`-only surface; add drill-down
  later if a consumer needs it.
- Should the reader filter to `record_type=1` by default like a "search"? **No** —
  yield both (parity with WAL reader); downstream decides.
