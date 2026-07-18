# EV-W1 — Read-only report service (report store + index + SSR endpoints)

**Problem (plain language):** Today the maturity report can only be produced by a CLI that
prints it and forgets it. Nothing stores a generated report, so there is no way to open one
in a browser, no way to switch tenants, and no history at all. EV-W0 ships a read-only
viewer — but it only shows the **rubric** (`/api/registry`), never a **result**. Meanwhile
EV-R1 froze a self-contained delivery bundle that nothing yet serves.

**Value:** EV-W1 makes results viewable online **without giving up the two things that make
them worth anything**: the service stays strictly read-only (it can never grade, re-run, or
mutate), and every bundle it serves is byte-identical to what the engine produced, still
carrying its `registry_fingerprint`. Switching tenant/window becomes a sub-second read
because reports are **pre-generated and stored**, not computed per request.

> Dev brief. **Prereq:** EV-7 (`evaluate`), EV-R1 (bundle contract + schema — merged),
> EV-W0 (`treval/web/app.py` — merged). **Unblocks:** EV-W2 (templates/UX).
> **Status:** design ratified except O1 (§8) — ready to implement.

---

## 0. Verified ground truth (checked against live code, 2026-07-17)

The implementer should re-confirm these still hold — several of them **changed the design**:

1. **EV-W0 already exists and is the host.** `treval/web/app.py::create_app` serves
   `GET /` (SSR, `templates/registry.html`) and `GET /api/registry`. FastAPI + Jinja2 live
   behind the optional `treval[web]` extra. `tests/test_web.py` enforces two invariants that
   EV-W1 must not break: the engine never imports `treval.web`, and importing the serializer
   never pulls FastAPI.
2. **The CLI cannot currently emit the artifact this issue needs to store.**
   `treval/cli/main.py:73` calls `bundle_to_json(report, measurements)` — the **core-layer**
   (decoupled) form. The EV-R1 **delivery** form is a *different function*:
   `self_contained_bundle_to_json(report, measurements, registry)` → `{schema_version,
   registry_fingerprint, report, registry, measurements}`. **`treval report --format json`
   today does NOT produce an EV-R1 bundle.** This is a real gap, not an oversight to
   paper over — see D1.
3. **A bundle is exactly one tenant and one window.** `report.tenant_id` is a scalar and
   `report.window` is a single `[start_ns, end_ns]`. There is no report list, no history, and
   **no component anywhere stores a generated report**. This is why D1 exists.
4. **`evidence_refs` enumerates every sample.** On live data its length **equals**
   `sample_size` (n=1016 → 1016 refs), each with `{source, seq, request_id}`. The
   contract-fixtures carry only one ref because they are hand-authored minimal examples —
   *do not infer contract semantics from the fixtures.* (An earlier round of this design did
   exactly that and drew the wrong conclusion.)
5. **`case_id` is not in the WAL and cannot be.** It exists only in the active-eval
   process's `ProbeResult` (`treval/active_eval/target.py:49`); probes send only
   `x-agent-id` + `{tool_id, params}`. The passive pipeline's samples are **real requests,
   not test cases** — they have a `request_id` and no name. No contract extension can add a
   field the engine never observes. Case-level results belong to the **active** pipeline
   (`tools/eval_report.py`, OWASP LLM Top-10) → a separate issue, not this one.
6. **`tenant_id` is already an indexed filter column** in `docs/POSTGRES_READ_CONTRACT.md`.
   Nothing in this issue requires a new ask on Platform.

---

## 1. D1 — Report store: **the service serves stored bundles; it never grades**

The ratified requirement is "switching to a new tenant may take seconds". That is only
achievable if reports are **pre-generated and stored**. If a tenant switch triggered a fresh
engine run over the WAL it would be minutes, not seconds — which is precisely why EV-W1 was
scoped as "serves a cached report" in the first place.

**Producer (new, small):** `treval report` gains `--self-contained --out-dir DIR`, writing
the EV-R1 delivery bundle via `self_contained_bundle_to_json(...)` (ground truth ②). The
operator/cron runs it; EV-W1 only ever **reads** `DIR`.

**Layout — content-addressed, so no tenant string ever touches a filesystem path:**

```
DIR/
  index.json                 # [{tenant_id, window, generated_at_ns, registry_fingerprint, file}]
  bundles/<sha256(bytes)[:16]>.json
```

- **Why content-addressed:** `tenant_id` originates in the WAL and is **untrusted input**.
  Interpolating it into a filename is a path-traversal bug waiting to happen. Hashing sidesteps
  the entire class, and the digest doubles as the bundle's identity.
- **Why `index.json` and not "parse every bundle at startup":** the index must be readable in
  one small I/O regardless of how many bundles exist. Producer writes temp + `os.replace`
  (atomic); the reader tolerates a concurrent swap.
- **Why not a database:** the bundle is already a self-contained, deterministic JSON file and
  Core is deliberately dep-light. A directory plus an index meets the second-level requirement
  with no new dependency. Introducing storage machinery without a measured need is exactly the
  speculative complexity this repo avoids. Revisit only with evidence (§9).

**`generated_at_ns` is stored, not derived from mtime** — mtime is not part of the contract and
does not survive a copy.

## 2. D2 — Endpoints (all read-only; the two dropdowns are `/reports`)

| Endpoint | Returns |
|---|---|
| `GET /reports` | the index: `[{tenant_id, window, generated_at_ns, registry_fingerprint}]`, newest first — powers the tenant + window selectors |
| `GET /` | Dashboard SSR — `?tenant=&window=`; **default = newest report** |
| `GET /detail` | 报告详情 SSR — same params |
| `GET /report.json` | the stored bundle **verbatim** (same params) |
| `GET /api/registry` | unchanged (EV-W0) |

**`/report.json` MUST return the stored bytes, not a re-serialization.** The bundle's whole
value is that it is the exact artifact the engine produced; re-encoding it would silently
break byte-identity with the customer's copy and with `registry_fingerprint` verification.

**No `POST`/`PUT`/`DELETE`/`PATCH` route exists.** `tests/test_web.py::test_read_only_no_mutating_routes`
already asserts this for the EV-W0 paths; extend it to the new ones.

## 3. D3 — **No `/evidence` endpoint. EV-W1 exposes no request content at all.**

The original plan listed `GET /evidence/{request_id}` for drill-down. The settled UI
(prototype, ratified) **does not drill to request level** — it renders aggregates, rules, and
outcomes. So the endpoint has no consumer.

Dropping it is not just scope hygiene, it **collapses the service's blast radius**: with no
`/evidence`, EV-W1 never reads or renders a request body, so it cannot leak PII (Charter §12
becomes trivially satisfied rather than carefully enforced). The `evidence_refs` pointers stay
in the bundle for anyone who wants to verify against the WAL themselves — which is the
zero-trust story working as designed.

Build it when something actually needs it (§9), and note the shape it must take: `n=1016`
means **1016 point lookups**, so it would need a batched/filtered form
(`/evidence?indicator=&window=&limit=&cursor=`), never an N+1 loop.

## 4. D4 — Auth: operator-scoped, not a multi-tenant portal

The report reveals a tenant's governance posture — commercially sensitive even without PII.
The threat that matters is **cross-tenant disclosure**.

**Core has no identity system, and EV-W1 must not grow one.** Its position is an
operator/auditor view of *one deployment's* store:

- **loopback bind + token by default** (mirrors the platform admin pattern).
- `/reports` lists exactly what is in that deployment's store; `?tenant=` selects among them.
- **Non-goal:** per-viewer tenant ACLs ("each customer sees only their own"). That is a
  portal concern and belongs to Platform, not to the open engine. Anyone deploying EV-W1
  multi-tenant must front it with their own authz — say so in the docstring, do not imply a
  guarantee the code does not make.

## 5. D5 — Re-run is a link, never an action

Ratified: the Dashboard's 重新评测 **navigates to the eval-execution surface** where the user
configures and runs. EV-W1 therefore needs **no admin gate, no async job runner, and no
regenerate trigger** — the read-only property is preserved by construction, not by policy.

**Blocked on O1 (§8): that surface does not exist.**

## 6. D6 — Radar points are computed server-side

The prototype proved a five-axis radar needs **no chart library**: it is ~30 lines of
trigonometry emitting SVG. Put it in the web layer as a pure function
(`radar_points(report) -> list[tuple[float, float]]`) so the template just interpolates
numbers, and the geometry is unit-testable without a browser.

**`null` is not zero.** A dimension with `measured_ceiling = None` has *no signal*; plotting it
at radius 0 renders "we never measured this" as "we scored zero". The function must mark those
axes distinctly (the UI draws them dashed/grey) — see EV-W2 D2.

---

## 7. Acceptance (what the implementer builds)

1. `treval report --self-contained --out-dir DIR` writes `bundles/<sha256>.json` +
   updates `index.json` atomically. Output validates against `docs/report.schema.json`.
2. `treval/web/store.py` — reads `index.json`, resolves `(tenant, window)` → bundle bytes.
   No engine import, no grading.
3. Endpoints per D2. `/report.json` returns **stored bytes byte-for-byte** (test: read the
   file, hit the endpoint, `assert resp.content == file_bytes`).
4. `/reports` newest-first; `/` with no params serves the newest report.
5. **Read-only proven, not asserted:** extend `test_read_only_no_mutating_routes` to every
   route; assert no `/evidence*` route exists; assert the app module never imports
   `treval.active_eval`.
6. Engine purity intact: the two existing guards in `tests/test_web.py` stay green.
7. Unknown `(tenant, window)` → 404, never a stack trace, never another tenant's report.
8. Store E2E on the six EV-R1 fixtures: place them in a temp store → index lists 6 →
   each resolves → each round-trips byte-identically.

## 8. Open question (needs a ruling before D5 can land)

**O1 — where does 重新评测 link to?** No eval-execution page exists; execution today is CLI
only (`tools/eval_report.py`, `treval collect`). Options:

- **(a) Show the exact CLI command, copyable** — honest, zero new surface, ships with EV-W1.
  *Recommended:* it tells the truth about how evaluation is actually run today.
- **(b) Build an execution page** — a real write surface with config, job state, and auth. A
  separate issue with its own threat model; do not smuggle it into a read-only service.
- **(c) Link to a Platform console** — only if one exists; makes the open engine depend on a
  closed surface, so it must be optional/configurable, never hardcoded.

Until O1 is ruled, implement (a); it is a one-line change to swap later.

## 9. Non-goals

- Grading, re-running, or any write path (D3, D5).
- `/evidence` request-level drill-down (D3) — build when a consumer exists.
- Per-viewer tenant ACLs (D4).
- Report retention/GC policy — the store is append-only; nothing deletes yet.
- Case-level results — not in this pipeline (ground truth ⑤); a separate active-eval issue.

## 10. Future improvements — evidence-gated, not pre-filed

| Improvement | Trigger that would justify it |
|---|---|
| `/evidence` (batched) | a real drill-down need in the UI *and* a decision on PII exposure |
| DB-backed store | a deployment where `index.json` demonstrably does not meet the second-level read |
| Report retention/GC | a store that actually grows past operator tolerance |
| Cross-window trend view | more than one window per tenant existing in a real store |
