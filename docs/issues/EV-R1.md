# EV-R1 — Report JSON contract + fixtures (the UI's stable consumption seam)

**Problem (plain language):** The UI engineer (EV-W2) needs to build the maturity dashboard
**before** EV-W1's service exists — against committed example files, not a live engine. Today
`docs/REPORT_JSON_SCHEMA.md` is a *proposal*, there are **no fixtures**, and the contract is
neither machine-checkable nor enforced. Worse, the schema hands the UI both `objectives`
(pass/fail) and `measurements` (values) but **no documented way to join them** — so the UI
can't actually render the grid's value column from the bundle alone.

**Value:** EV-R1 turns the proposal into a **frozen, enforced, self-consistent** contract: a
formal JSON Schema, a set of golden fixtures generated from the *real* serializer (so they
can never drift from what the engine emits), and an explicit join rule. The UI scaffolds
against these immediately, in parallel with the whole backend build.

> Dev brief. **Prereq:** EV-0 (frozen `MaturityReport`/`Measurement`), EV-7 (`bundle_to_json`
> serializer — exists). **Unblocks:** EV-W2 (UI). Pairs with `docs/REPORT_JSON_SCHEMA.md`
> (the prose contract, which this issue upgrades to machine-checkable).
> **Status:** design ratified — ready to implement.

---

## 0. Verified ground truth (checked against live code, 2026-07-15)

Three facts that shaped the decisions — the implementer should re-confirm they still hold:

1. **The prose schema and the emitter already agree.** `bundle_to_json` emits exactly the
   documented keys at every level (envelope `schema_version`/`report`/`measurements`; report
   `tenant_id`/`window`/`dimensions`/`integrity_summary`/`verification_basis`; dimension
   `dimension`/`measured_ceiling`/`attested_ceiling`/`awarded_level`/`objectives`/`gaps`;
   objective `objective_id`/`kind`/`status`/`evidence_refs`; measurement `indicator_id`/
   `dimension`/`value`/`unit`/`sample_size`/`subject`/`integrity`/`notes`/`evidence_refs`).
   ⇒ **Fixtures are GENERATED from the emitter, never hand-authored** (D2).
2. **`ObjectiveResult` has no `indicator_id` and no `value`** — so the objective→value join
   runs *through the registry* (`spec.evidence.indicator_id`), exactly as `render.py` does
   (`agg = {m.indicator_id: m ...}; ind = spec.evidence.indicator_id`). ⇒ **the UI needs the
   registry to render the grid** (D1).
3. **The registry has no version field.** ⇒ mismatch-detection needs a content hash (D1).

---

## 1. D1 — objective↔measured-value join: **via the registry (the UI needs it anyway)**

The report's objectives carry only `objective_id` + `status`. To render a grid row
("`rob.l3.unified_risk_score` — met — `boundary_breach_rate=0.22`") the UI must join through
the registry. **This is not an added burden: the UI already needs the registry for the grid's
level structure and objective statement text** (the report has neither) — EV-W0 already renders
the registry, and `docs/web/registry.sample.json` exists. So the value-join reuses a registry
the UI must load regardless.

**Decision:** the UI join runs through the registry —
```
objective.objective_id → registry.spec.evidence.indicator_id → measurement (by indicator_id, subject=="")
```
Rejected: adding `indicator_id` to the frozen `ObjectiveResult` (reopens the EV-0 contract) and
shipping a redundant binding map (duplicates the registry).

**But the delivery bundle is SELF-CONTAINED (revised 2026-07-15 — see §1a).** The registry the UI
needs is **inlined into the bundle** alongside report + measurements, so the UI loads ONE file and
never mismatches parts. The *join* above is unchanged; only the registry's delivery location
changes (in-bundle, not fetched separately).

**Adopted supplement (refined) — registry mismatch detection.** A live report joined against a
*newer* registry could mis-map. Since the registry has no version, the **envelope carries a
`registry_fingerprint`**: `sha256` over the registry's canonical serialization (implementer
picks a deterministic form — e.g. the loaded `DimensionRegistry` serialized to sorted-key JSON).
- In **fixtures**: report + registry are captured together, so they're consistent by
  construction; the fingerprint is populated but redundant there.
- In **production** (EV-W1): the consumer compares `registry_fingerprint` to the registry it
  loaded and warns on mismatch. **EV-R1 only DEFINES + populates the field; EV-W1 acts on it.**

## 1a. Core layer vs delivery layer — the report bundle is self-contained

> Added 2026-07-15 after a UX review (external analysis). Its concern: a *decoupled* three-file
> delivery (report / measurements / registry) is a bad **product** experience — a user opens
> `report.json`, sees abstract ids (`rob.l3.unified_risk_score`) and no numbers or levels, and can
> mis-pair or lose one of the three files on copy/archive. That undercuts the "verifiable,
> self-evident report" the whole thesis promises. **The concern is valid** (two precisions: the
> measurements are *already* inline per D5, so the "no numbers" gap is only the registry; and the UI
> needs the *whole* registry, not a fragment, to draw the full 5×5 grid incl. NotMeasured cells).

**Resolution — hold both, at two layers:**

| Layer | Consumer | Shape | Why |
|---|---|---|---|
| **Core** (EV-0/7 dataclasses) | engine, internal | `MaturityReport` / `Measurement` / `DimensionRegistry` — **decoupled, unchanged** | keep the engine pure + independently versioned; no dataclass change |
| **Delivery** (EV-R1 defines) | UI engineer, users, archive | **one self-contained bundle** inlining all three | one file → nothing to mis-pair or lose; the UI's "value column" works from the file alone |

The bundle envelope is therefore **self-contained**:
```json
{ "schema_version": 1, "registry_fingerprint": "sha256:…",
  "report": { /* MaturityReport */ },
  "registry": { /* the DimensionRegistry needed to render + join */ },
  "measurements": [ /* Measurement, … */ ] }
```
The engine stays decoupled; **inlining is an assembly step at serialize/CLI time, not a dataclass
change.** ⇒ D1's separate-registry framing is superseded: the registry ships *in* the bundle. The
`registry_fingerprint` is then redundant *within* a self-contained bundle but stays for the future
decoupled path (§8) and as an integrity check.

## 2. D2 — fixtures = generated golden snapshots + a CI drift-guard

Generate every fixture by calling the real `bundle_to_json` (+ the registry serializer), commit
the output, and add a test that **regenerates and byte-compares** against the committed files.
Any change to `MaturityReport`/`Measurement`/the serializer that would break the UI contract
fails CI at that test.

**Adopted supplement — `UPDATE_FIXTURES=1` escape hatch.** The drift-guard test regenerates and
overwrites the committed fixtures when `UPDATE_FIXTURES=1` is set, so a *planned* contract change
is a one-command update + review, not a hand-edit. (Standard golden-test pattern.)

## 3. D3 — scenario coverage (six valid fixtures + a separate invalid set)

The valid golden set — the report states the UI must render without breaking:

| # | fixture | exercises |
|---|---|---|
| 1 | `rich` | multiple dimensions, awarded/measured-only/attested mix, non-empty gaps |
| 2 | `all_not_measured` | empty measurements → every objective `insufficient_data`, awarded null |
| 3 | `over_claim_gaps` | attested-above-measured → non-empty `gaps[]` |
| 4 | `insufficient_data` | the EV-7 `sample_size`-gate refinement (status `insufficient_data`, not `unmet`) |
| 5 | `verification_basis` variants | `wal` / `index` / `hybrid` + an `integrity_summary` with all three keys non-zero |
| 6 | `per_subject` | measurements with `subject != ""` (per-entity breakdown) |

**Adopted supplement (intent) — malformed handling, but NOT in the golden set.** A malformed
file is *not* valid emitter output, so it can't be generated and would corrupt the drift-guard.
Instead: (a) the **formal JSON Schema (D4) is the UI's validation gate** — the UI validates every
payload and degrades gracefully on failure; (b) ship a small **`tests/fixtures/report/invalid/`**
set (truncated / missing-required-field), clearly **outside** the golden contract, for the UI's
rejection-path tests. The drift-guard only covers `valid/`.

## 4. D4 — a formal, machine-checkable JSON Schema

Ship `docs/report.schema.json` (**JSON Schema draft-07** — adopted supplement: broadest
cross-language tooling support, no new dependency burden on the UI team). It formalizes the prose
`REPORT_JSON_SCHEMA.md`. Two enforcement points:
- **Core CI:** every `valid/` fixture validates against the schema (contract ↔ emitter agreement).
- **UI:** validates mock/live payloads against the same file — a shared automated defense.

## 5. D5 — inline everything the bundle needs to self-render (measurements **and** registry)

Inline the `Measurement[]` **and** the `registry` in the bundle (§1a): a self-contained file is
what the static-JSON UI wants, and it's what makes the value column + grid structure work from one
file. Closes the schema doc's open item.

**Declined supplement — reserving an always-null `detail_url`.** YAGNI: the `schema_version`-bump
path (D2/D4) already lets EV-W1 add drill-down externalization *additively* when it's actually
built. Pre-reserving a dead field now buys nothing and violates the simplicity rule. Documented
as the intended future-extension mechanism instead (§8).

---

## 6. Acceptance (what the implementer builds)

1. `docs/report.schema.json` — draft-07 schema for the **self-contained** envelope
   `{schema_version, registry_fingerprint, report, registry, measurements}` (§1a), derived from the
   frozen dataclasses + `REPORT_JSON_SCHEMA.md`.
2. The self-contained bundle assembled at serialize/CLI time: `report` + inline `registry` (canonical
   serialization of the `DimensionRegistry`) + inline `measurements` + `registry_fingerprint` (sha256
   over that same canonical registry). **No dataclass change** — assembly only.
3. `tests/fixtures/report/valid/{rich,all_not_measured,over_claim_gaps,insufficient_data,
   verification_basis,per_subject}.json` — generated from the real serializer, **each a complete
   self-contained bundle** (registry inline, no separate registry fixture to pair).
4. `tests/fixtures/report/invalid/*.json` — 2–3 hand-crafted invalid payloads, outside the golden set.
5. `docs/REPORT_JSON_SCHEMA.md` — updated: the **self-contained bundle** envelope (report+registry+
   measurements), the **join rule** (§1), the core-vs-delivery-layer split (§1a), `registry_fingerprint`.
6. Tests: (a) **drift-guard** — regenerate the `valid/` fixtures + compare (honor `UPDATE_FIXTURES=1`);
   (b) **schema-validation** — every `valid/` fixture validates against `report.schema.json`, every
   `invalid/` fixture fails it.
7. Gate green: `ruff` + `mypy` + `pytest tests/`. A JSON-Schema validator dep (e.g. `jsonschema`)
   goes behind the test/dev extras, not the engine core — confirm the license is clean (MIT).

## 7. Non-goals

- The web service / endpoints (EV-W1) and the templates/UX (EV-W2).
- Acting on `registry_fingerprint` mismatch at serve time (EV-W1).
- Any change to the frozen `MaturityReport` / `Measurement` / `ObjectiveResult` dataclasses.
- Drill-down / `detail_url` externalization (future additive change — §8).

## 8. Future improvements — **evidence-gated, not pre-filed tasks**

These are **not** known work hidden as prose. Each is a decision we *cannot make now*: its trigger
is an observation available only **after** EV-R1 ships and real bundles are generated / the UI builds
against them (the live test). Until the trigger is observed, there is nothing to build and no issue to
file — EV-R1 is complete without them. Both slot in additively (bump `schema_version`), no contract
break. **When a trigger below is observed, THAT is when the corresponding issue gets filed.**

1. **Decoupled serving for scale.**
   - *Trigger to file an issue:* a real generated bundle shows the inlined registry is a large fraction
     of bundle size **and** a deployment (EV-W1) serves enough reports (time-series / per-tenant
     history) that re-shipping the registry per report is a measured cost.
   - *Then:* EV-W1 serves the registry **once**; reports ship without it, paired by `registry_fingerprint`
     (already defined in §1 for exactly this). MVP inlines (few reports, self-contained delivery); scale
     decouples (registry cached, fingerprint-checked).
2. **Drill-down externalization (`detail_url`).**
   - *Trigger to file an issue:* a real measurement's detail (evidence_refs / notes) makes a bundle too
     large for the static-JSON UI to load comfortably.
   - *Then:* an optional `detail_url` on a measurement points at an out-of-band drill-down endpoint
     (EV-W1), keeping the summary bundle small. Declined for MVP (D5) precisely because this path exists.

> **Already definite + already tracked (not here):** acting on a `registry_fingerprint` mismatch at
> serve time is a non-goal pointing at **EV-W1** (a filed issue) — it is not deferred prose.

**Delivery-hygiene conventions (document in `REPORT_JSON_SCHEMA.md`):** the self-contained bundle is
the human/UI deliverable; the *decoupled* three-part form (if ever exposed) is a machine/API shape,
and any multi-file export must share a common prefix (assessment-run id / timestamp) so parts can't
be mis-paired.
