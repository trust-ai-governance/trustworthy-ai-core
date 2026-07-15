# Postgres Read Contract — what `treval`'s EV-2 reader needs from Platform's audit index

Cross-repo contract, authored by **core** (consumer), implemented by **platform**
(the closed gateway writes the index, design `A4_audit_index_port.md`). Core builds
EV-2 against this; real-data acceptance waits on platform exposing it.

**Status: RECONCILED + ACKNOWLEDGED — A4 satisfies this contract; Platform formally
acknowledged 2026-07-14.** The one open flag (driver license) is **resolved**: A4 acted
on it and switched to `pg8000` (BSD) — see §0 / §7. §0 records the verdict; the rest is
the consumer view (mostly clarifications A4 already answers).

Pairs with: `docs/EVAL_ARCHITECTURE(WIP).md` §4a, `docs/EVAL_ISSUES(WIP).md` EV-2,
and Platform's `A4_audit_index_port.md`.

---

## 0. Verdict vs A4

**A4's `audit_events` table satisfies core's read needs.** Confirmations + the few
clarifications that matter:

| Core need | A4 provides | Status |
|---|---|---|
| Raw `RequestContext` bytes to decode (byte-identical to WAL) | `payload BYTEA`; `get_payload(seq)` = "exact stored bytes"; re-ship overwrites identical bytes | ✅ **met** (the load-bearing req) |
| Filter on tenant + time | `tenant_id`, `received_at_ns` + `ix_audit_tenant_t` | ✅ met |
| Filter on agent | `agent_id` + `ix_audit_agent` | ✅ met |
| A↔B pairing | both rows carry `request_id` + `ix_audit_request` | ✅ met (core pairs on `request_id`, see §3) |
| Record identity | `(gateway_instance, seq)` PK | ⚠️ **core must NOT treat `seq` as global** — key on `request_id` (§3) |
| `record_type`/`final_decision` filters | columns present, not separately indexed | ✅ acceptable (ride tenant/time index) |
| Read access | — | ➕ **ask:** read-only `SELECT` grant + schema-qualified name (§6) |
| Driver license | A4 now uses **`pg8000` (BSD)** — verified live at `pg8000 1.31.5` | ✅ **resolved** — the original `psycopg` v3 (LGPL-3.0) flag was **acted on**; A4 swapped drivers (§7) |

No schema change is required for core. The one remaining action item for platform is the
**read-only `SELECT` grant** (§6) — an ops/deploy step, not code, so it does not block EV-2.

---

## 1. Why core reads Postgres at all

WAL-direct stays the **canonical, integrity-bearing** source (D1). But scanning
every segment is slow at volume, and A4 builds a shared index. Core reads it as a
**speed path** for filtering + aggregates, while every integrity claim stays on
WAL. Index-sourced evidence is always `UNVERIFIED` in core; per the rubric's
`requires_integrity` rule it can satisfy aggregate objectives but **not** the
Transparency/integrity ones — those still require a WAL pass. This matches A4's own
framing exactly: the index is **derived, discardable, off the fail-closed path,
rebuildable by WAL replay**.

## 2. The one design choice: core decodes the payload

Core decodes the **raw `RequestContext` payload bytes** the index stores — the
*same* protobuf decoder the WAL reader uses. It does **not** consume A4's projected
columns as the scored data. Consequences:

- **Reader-agnostic:** every indicator works unchanged on WAL or Postgres input;
  the only difference is `IntegrityStatus`.
- The speed win is entirely in the **`WHERE` clause** (A4's indexed columns), not a
  different data shape.
- A4's projected columns (`agent_id`, `final_decision`, `record_type`,
  `total_tokens`, …) are used by core **only for filter pushdown**; the signal
  comes from decoding `payload` (which carries the full E1 fields:
  `rules_evaluated[*].tags`/`score_deltas`, `decision.scores`,
  `audit_schema_version`).

**Fidelity requirement — confirmed met by A4:** `payload` is the byte-identical
`RequestContext` that landed in the WAL (A4 `get_payload` = exact stored bytes; the
upsert overwrites with identical bytes). This is what keeps the Postgres path from
silently diverging from the WAL path (the double-parser concern, now closed).

## 3. Record identity — **key on `request_id`, not `seq`** (A4 ripple)

A4's load-bearing decision: many WALs (one per gateway instance) ship to one shared
DB, so **`seq` is unique only within a WAL** and the table PK is
`(gateway_instance, seq)`. Therefore **core must not use `seq` as a global key.**
Core's rules:

- **Record identity = `request_id`** (a globally-unique UUID; A4 indexes it via
  `ix_audit_request`). Core dedups and references records by `request_id`.
- **A↔B pairing = `request_id`** (decision.made A and response.observed B share one
  `request_id` — B2 model). This is simpler **and** instance-safe; core does **not**
  pair on `seq`/`decision_seq` across the shared table. (`decision_seq` remains a
  useful intra-instance cross-check only.)
- **`seq` is an ordering/back-pointer hint**, scoped to a `gateway_instance` — not
  a cross-instance identity. `EvidenceRef.seq` stays populated (per-instance), and
  `EvidenceRef.source` encodes the instance (e.g. `"pg:<schema>@<dsn>#<gateway_instance>"`)
  so `(source, seq)` is unambiguous; but core's joins/dedup use `request_id`.
- `gateway_instance` is **platform-internal** (Shipper cursor / gap / Challenge
  scoping). Core reads like A4's **Search** access pattern — **across instances**,
  no instance filter. Core does not need `gateway_instance` for metrics or A↔B; it
  only carries it into `EvidenceRef.source` for drill-down/challenge fetch.

> This means **no change to core's frozen `AuditEvidence`/`EvidenceRef`** (EV-0):
> `request_id` is already the key, `source` already disambiguates the instance.

## 4. Columns core reads (mapped to A4's schema)

Decode-source: `payload`. Filter-pushdown columns: `tenant_id`, `received_at_ns`,
`agent_id`, `record_type`, `final_decision` (+ A4's `user_id`/`tool_id`/`terminal`/
`error_code` available if useful). Pairing/identity: `request_id`. All present in
A4. Indexes core relies on — A4 provides `ix_audit_tenant_t (tenant_id,
received_at_ns)`, `ix_audit_agent (tenant_id, agent_id)`, `ix_audit_request
(request_id)`. A dedicated `(tenant_id, record_type)` index is **not** required
(record_type rides the tenant/time scan). ✅

## 5. Two-record (B2) handling

Core selects **decision.made (A, `record_type=1`)** for the primary scan and
attaches **response.observed (B, `record_type=2`)** by **`request_id`**. B is sparse
(no `agent_id`) so per-agent joins take `agent_id` from A — the same A↔B helper
EV-5b builds for the WAL path, keyed on `request_id`, reused unchanged for Postgres.

## 6. Access core needs (one ask for platform)

- **Read-only `SELECT`** grant on `<schema_name>.audit_events` (A4 default schema
  `trustworthy_audit`). Core never writes — separate from A4's runtime
  `INSERT/SELECT/UPDATE/DELETE` write role.
- **Schema-qualified table name** + connection (DSN/TLS) for a read-only consumer.
  Core honors A4's `schema_name` config.
- Cross-instance read (no `gateway_instance` filter) — the Search pattern.

## 7. Driver / license — ✅ RESOLVED (the flag worked)

Charter §1.2 bans LGPL/GPL/AGPL/SSPL across **all three repos**. Core originally
flagged that A4 §6 selected **`psycopg` v3 (LGPL-3.0)** — non-compliant for platform
too, and the license CI gate would have failed on it.

**Platform acted on the flag and swapped the driver.** A4 now uses **`pg8000` (BSD)**
— verified live at `pg8000 1.31.5`; `postgres_sink.py` and `A4_audit_index_port.md`
both record the rejection in-line ("psycopg v3 is rejected: LGPL-3.0, banned by §1.2
— caught in core's POSTGRES_READ_CONTRACT.md").

Core uses `pg8000` too (behind the `treval[postgres]` extra), so both repos are on the
same permissive driver. **No open license item.**

> **Process note (worth keeping):** this is the cross-repo contract doing exactly what
> it exists for — a consumer-side license review caught a producer-side dependency
> before it shipped. The mechanism is cheap; keep using it.

## 8. What core will NOT do

- No writes, no DDL, no schema ownership — `SELECT` only.
- No chain verification against the index (impossible by construction → always
  `UNVERIFIED`); integrity always from WAL.
- No dependency on platform code; connects with a permissive driver and reads the
  agreed columns.

## 9. Remaining asks for platform (everything else is settled by A4)

Both remaining items are **ops/deploy, not code** — neither blocks EV-2's design or
implementation (Platform confirmed 2026-07-14):

1. **Read-only `SELECT` grant** on `<schema_name>.audit_events` for core's consumer.
2. Confirm the read consumer connection/TLS expectations (likely the same
   `sslmode`/cert config A4 already exposes).

~~3. **Driver license:** swap `psycopg` (LGPL) → `pg8000`~~ — ✅ **done**, see §7.
