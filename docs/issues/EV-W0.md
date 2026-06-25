# EV-W0 — Registry / maturity-model viewer (read-only API + frontend)

> Dev brief for the **UI engineer** (frontend) + a thin backend. Self-contained.
> This is the *standard viewer* (renders the 5×5 maturity model), **not** the report
> viewer (that's EV-W1, deferred behind EV-7/EV-R1). Parent: `docs/MATURITY_MODEL.md`
> (content), `docs/web/registry.sample.json` (the contract instance), EV-6 (the live
> data source).

## 0. Context — why this exists and why it can start now

The 5×5 maturity model is authored as YAML (`registry/dimensions/*.yaml`, EV-6) —
fine for the engine, unfriendly to read. EV-W0 renders it as a navigable
**dimensions × levels** grid with objective drill-down. It is **low-prerequisite**:
it shows *static reference content* (the standard), not an evaluation run — so it
needs only EV-6 (the loaded registry) + a thin serializer, **not** the eval pipeline.

**Two tracks, different readiness — run them in parallel:**
- **Frontend (starts NOW):** build against the committed
  `docs/web/registry.sample.json`. **Zero backend dependency** to begin.
- **Backend endpoint (after EV-6):** `GET /api/registry` serializes the loaded
  `DimensionRegistry` to the *same* JSON shape. Small; wire the frontend to it when
  EV-6 lands.

## 1. The contract: `registry.json` shape

The committed sample is `docs/web/registry.sample.json` (72 objectives, full 5×5).
The endpoint returns this exact shape from EV-6's registry — **no translation**, the
field names mirror EV-6's `DimensionRegistry`/`ControlObjective`/`Evidence`:

```jsonc
{
  "schema_version": 1,
  "kind": "dimension_registry",
  "levels_meta": [ { "id": "L1", "name_en": "Initial", "name_zh": "偶发" }, ... L2..L5 ],
  "dimensions": [
    {
      "id": "robustness", "title_en": "Robustness", "title_zh": "强鲁棒性",
      "levels": {
        "L1": [],                                   // L1 = baseline, always empty
        "L2": [
          { "id": "rob.l2.injection_rule_detection",
            "statement_zh": "对 Prompt 注入具备规则级检测（关键词/正则）",
            "kind": "measured",                     // "measured" | "attested"
            "indicator_id": "injection_rule_hit_ratio",  // set iff measured, else null
            "posture_key": null,                    // set iff attested, else null
            "satisfied_when": "sample_size >= 1" }  // set iff measured, else null
        ],
        "L3": [...], "L4": [...], "L5": [...]
      }
    }
    // ...5 dimensions
  ]
}
```

Invariants the frontend can rely on (validated on the sample): every dimension has
`L1..L5`; `L1` is always `[]`; `kind=="measured"` ⟺ `indicator_id != null`;
`kind=="attested"` ⟺ `posture_key != null`.

## 2. Frontend scope (UI engineer — start now on the sample)

- Render a **dimension × level grid** (5 dimensions × 5 levels), each cell showing
  its control objectives (or "N/A" for empty L1).
- **Objective drill-down:** id, `statement_zh`, and a clear **measured vs attested**
  visual distinction (e.g. a badge) — measured shows its `indicator_id` +
  `satisfied_when`; attested shows its `posture_key`.
- Use `levels_meta` for level display names (don't hardcode 偶发/可重复/…).
- Bilingual-friendly: `title_en`/`title_zh` per dimension.
- **Stack is your call.** Constraint: it must render purely from the JSON, work
  **offline against `registry.sample.json` with no backend**, and later point at
  `GET /api/registry` by swapping the data URL. (SSR or SPA both fine; EV-W1 will
  extend this app to the report view, so pick something you'll grow.)

## 3. Backend scope (after EV-6)

- `treval/web/` under a **`treval[web]` extra** (FastAPI + uvicorn — both
  permissive: MIT/BSD; lazily imported so `import treval` works without them).
- `GET /api/registry` → load the registry (`treval.registry.load_registry`, EV-6) →
  serialize to the §1 shape → JSON. **Read-only, no params, no mutation.**
- `levels_meta` is a fixed constant the endpoint adds (levels are universal, not in
  the per-dimension YAML).
- Serve the frontend's static build (or SSR) from the same app.
- Deterministic output (stable dimension + objective order) — same discipline as the
  engine.

## 4. Deployment (part of core's `treval-web` service)

Read-only service, separate container from the gateway. Sketch (full form in
`docs/DEPLOY_CORE.md` when it lands):

```
service: treval-web      ·  port 8090 (gateway 8080 / admin 8081 are taken)
image bakes: registry/dimensions/*.yaml      # the standard ships in the image
read-only: serves the registry; no WAL/PG needed for EV-W0 (that's EV-W1's report view)
```

EV-W0 needs **no evidence source** — it serves the static standard. (EV-W1's report
view is what mounts `wal:ro` / connects PG.)

## 5. Acceptance

**Frontend (against the sample, now):**
1. Renders all 5 dimensions × L1–L5 from `registry.sample.json`; L1 shows N/A.
2. Measured vs attested visually distinct; drill-down shows the right fields per kind.
3. Works with no backend (loads the static JSON).

**Backend (after EV-6):**
4. `GET /api/registry` returns the §1 shape from the **live** registry; a schema
   check passes (same invariants as §1). For the shipped registry, the endpoint
   output and `registry.sample.json` agree on structure (content may differ as YAMLs
   are refined).
5. `import treval` works without `fastapi`/`uvicorn` installed (lazy web extra).
6. Read-only: no route mutates anything. Deterministic ordering.
7. `mypy`/ruff clean on `treval/web`; tests for the serializer + endpoint.

## 6. Non-goals

- **The report viewer** (rendering a `MaturityReport` from an eval run) — that's
  **EV-W1**, deferred behind EV-7 + EV-R1 + readers.
- Any evaluation, indicators, rubric scoring, WAL/PG reading.
- Auth / multi-user / editing the registry (read-only standard viewer).
- Live "pending data source" badges (an enhancement; the capability boundary in
  `MATURITY_MODEL.md` notes which indicators are empty — UI may add later).

## 7. Guardrails

- Web deps (`fastapi`/`uvicorn`) live in a **`treval[web]` extra**, lazily imported;
  never required for the core library or CLI. All permissive-licensed (Charter §1.2).
- Read-only everywhere; never import the closed platform.
- The endpoint mirrors EV-6's model field-for-field — no parallel schema.

## 8. Likely questions

- Frontend location: `treval/web/static/` (served by the app) vs a separate
  `frontend/` build dir. Either; decide with the backend dev so the app can serve it.
- Should `statement_zh` be `statement_en`/`statement_zh` both? The sample uses
  `statement_zh` to mirror EV-6's model; if EV-6 adds an English field later, the
  contract gains `statement_en` additively.
- Confirm port `8090` for `treval-web` (free vs gateway 8080 / admin 8081).
