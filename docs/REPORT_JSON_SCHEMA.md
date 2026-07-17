# Report JSON Schema (EV-R1) — the UI's stable consumption contract

Derived from the **frozen** `MaturityReport` / `Measurement` dataclasses (EV-0,
`EVAL_ARCHITECTURE(WIP).md` §2.2/§2.4). It exists so the UI engineer (EV-W2) can
build against committed fixtures **before** EV-W1's service exists.

Status: **implemented (EV-R1).** The machine-checkable form is `docs/report.schema.json`
(JSON Schema draft-07); golden fixtures live under `tests/fixtures/report/valid/` and are
**generated from the real serializer** (`treval.self_contained_bundle_to_json`) with a CI
drift-guard, so this prose and the emitter can never disagree. The tables below are the
human-readable spec; `report.schema.json` is the authority.

---

## 1. Envelope — the self-contained bundle

A run emits ONE **self-contained bundle**: the rubric verdict, the measurements that fed
it, AND the registry needed to render + join them — so the UI loads a single file and can
never mis-pair or lose a part. Assembly happens at serialize time
(`serialize_self_contained_bundle`); the engine dataclasses are **unchanged**.

```json
{
  "schema_version": 1,
  "registry_fingerprint": "sha256:…",
  "report": { /* MaturityReport */ },
  "registry": { /* DimensionRegistry — the EV-W0 serialize_registry shape */ },
  "measurements": [ /* Measurement, ... */ ]
}
```

- `schema_version` (int): this contract's version; bump on any additive change (§8).
- `registry_fingerprint` (string, `sha256:<64 hex>`): sha256 over the registry's canonical
  (sorted-key, compact) serialization. Within a self-contained bundle it is redundant (the
  registry is inlined); it stays for the future decoupled path and as an integrity check.
  **EV-R1 only defines + populates it; EV-W1 acts on a mismatch.**
- `report`: the serialized `MaturityReport` (§2).
- `registry`: the inlined `DimensionRegistry`, needed for the grid's level structure,
  objective statements, AND the objective→value join (§1a).
- `measurements`: the `Measurement[]` the engine produced (values + per-`subject` breakdowns
  without a live call).

## 1a. Core layer vs delivery layer + the value join

**Two layers (EV-R1 §1a).** The **core** shapes (`MaturityReport` / `Measurement` /
`DimensionRegistry`) stay **decoupled** and independently versioned — the engine is pure.
The **delivery** bundle above is a self-contained *assembly step* for the UI/users/archive;
no dataclass changes.

**The objective→value join runs through the registry.** An `ObjectiveResult` carries only
`objective_id` + `status` — no `indicator_id`, no `value`. To render a grid row
(`rob.l3.unified_risk_score — met — boundary_breach_rate=0.22`) the UI joins:
```
objective.objective_id
  → registry.dimensions[*].levels[*][*] where id == objective_id  → .indicator_id
  → measurements[*] where indicator_id == that AND subject == ""   → .value
```
This is why the registry is inlined: the UI needs it for the 5×5 grid + statements anyway,
and the value column resolves from the one file (no live engine). See
`tests/test_report_contract.py::test_value_join_works_from_the_bundle_alone`.

> The **decoupled** three-part form (report / registry / measurements paired by
> `registry_fingerprint`) is a machine/API shape reserved for scale (§8); the self-contained
> bundle is the human/UI deliverable. Any multi-file export must share a common prefix
> (assessment-run id / timestamp) so parts can't be mis-paired.

## 2. Field mapping (Python → JSON)

Rules: snake_case keys identical to the dataclass fields; `tuple` → array; `None`
→ `null`; enums → their `.value` string; `Mapping` → object.

### `report` (`MaturityReport`)
| JSON key | type | from |
|---|---|---|
| `tenant_id` | string | `tenant_id` |
| `window` | `[int, int]` | `window` = `[time_from_ns, time_to_ns]` |
| `dimensions` | array of DimensionReport | `dimensions` |
| `integrity_summary` | object `{string: int}` | counts keyed by `IntegrityStatus.value` (`"verified"/"unverified"/"broken"`); **all three keys always present** (0 if none) |
| `verification_basis` | string | `"wal" \| "index" \| "hybrid"` |

### DimensionReport
| JSON key | type | notes |
|---|---|---|
| `dimension` | string | one of the 5 dimension ids |
| `measured_ceiling` | string \| null | e.g. `"L3"` or null |
| `attested_ceiling` | string \| null | |
| `awarded_level` | string \| null | `min(measured, attested)` |
| `objectives` | array of ObjectiveResult | |
| `gaps` | array of string | objective_ids that are attested-met but measured-unsupported |

### ObjectiveResult
| JSON key | type | notes |
|---|---|---|
| `objective_id` | string | |
| `kind` | string | `"measured" \| "attested"` |
| `status` | string | `"met" \| "unmet" \| "insufficient_data" \| "unverified_evidence"` |
| `evidence_refs` | array of EvidenceRef | |

### EvidenceRef
| JSON key | type |
|---|---|
| `source` | string |
| `seq` | int \| null |
| `request_id` | string \| null |

### Measurement (in `measurements[]`)
| JSON key | type | notes |
|---|---|---|
| `indicator_id` | string | |
| `dimension` | string | |
| `value` | number | |
| `unit` | string | `"ratio"/"count"/"tokens"/"ms"/...` |
| `sample_size` | int | `0` ⇒ insufficient data (distinct from `value: 0`) |
| `evidence_refs` | array of EvidenceRef | |
| `subject` | string | `""` = aggregate; non-empty = per-entity (e.g. agent_id) |
| `notes` | string | |

## 3. Determinism (matches EV-7's byte-identical requirement)

The serializer MUST be reproducible:

- **Object keys sorted** (e.g. `json.dumps(..., sort_keys=True)`).
- **Array order is defined, not insertion-dependent:** `dimensions` in registry
  order; `objectives` in registry order; `measurements` sorted by
  `(indicator_id, subject)`; `evidence_refs` by `(source, seq)`; `gaps` sorted.
- Floats serialized canonically (no locale, fixed repr).
- Same inputs ⇒ byte-identical bundle (the EV-7 determinism test asserts this on
  the full bundle, not just the report).

## 4. Example bundle (a committed fixture shape)

```json
{
  "schema_version": 1,
  "report": {
    "tenant_id": "dogfood",
    "window": [1782191400000000000, 1782191600000000000],
    "verification_basis": "wal",
    "integrity_summary": {"verified": 240, "unverified": 0, "broken": 0},
    "dimensions": [
      {
        "dimension": "security_alignment",
        "measured_ceiling": "L3",
        "attested_ceiling": "L2",
        "awarded_level": "L2",
        "gaps": ["sec.l3.siem_ingest"],
        "objectives": [
          {
            "objective_id": "sec.l2.block_enforced",
            "kind": "measured",
            "status": "met",
            "evidence_refs": [{"source": "wal:/wal/000..018.wal", "seq": 23, "request_id": "019ef2e5-...-8ff9"}]
          },
          {
            "objective_id": "sec.l3.siem_ingest",
            "kind": "attested",
            "status": "unmet",
            "evidence_refs": []
          }
        ]
      },
      {
        "dimension": "transparency_accountability",
        "measured_ceiling": "L1",
        "attested_ceiling": "L3",
        "awarded_level": "L1",
        "gaps": [],
        "objectives": [
          {
            "objective_id": "tr.l3.chain_continuity",
            "kind": "measured",
            "status": "met",
            "evidence_refs": [{"source": "wal:/wal/000..018.wal", "seq": null, "request_id": null}]
          }
        ]
      }
    ]
  },
  "measurements": [
    {
      "indicator_id": "block_rate", "dimension": "security_alignment",
      "value": 0.25, "unit": "ratio", "sample_size": 4, "subject": "", "notes": "",
      "evidence_refs": [{"source": "wal:/wal/000..018.wal", "seq": 23, "request_id": "019ef2e5-...-8ff9"}]
    },
    {
      "indicator_id": "token_cost_per_agent", "dimension": "affordable",
      "value": 1820.0, "unit": "tokens", "sample_size": 12, "subject": "dogfood-agent", "notes": "",
      "evidence_refs": []
    }
  ]
}
```

A second fixture MUST cover `verification_basis: "index"` with an
`integrity_summary` of all-`unverified`, where a `transparency_accountability`
`requires_integrity` objective resolves to `status: "unverified_evidence"` — the
proof that the Postgres path can't claim the integrity moat.

> The example above shows the pre-EV-R1 `{schema_version, report, measurements}` envelope
> for the report/measurement field shapes. The **delivered** bundle wraps these with
> `registry_fingerprint` + inline `registry` (§1); see the committed fixtures for the full
> self-contained form, and `dimension: "affordable"` there is illustrative, not a live id.

## 5. JSON Schema

The machine-checkable contract is **`docs/report.schema.json`** (JSON Schema **draft-07** —
broadest cross-language tooling, no new UI dependency). It formalizes the self-contained
envelope (§1): required keys, enum value sets for `kind`/`status`/`verification_basis`/
`integrity`, `integrity_summary` requiring all three keys, and the registry structure the
join needs. Two enforcement points: **Core CI** validates every `valid/` fixture against it
(and every `invalid/` fixture must fail); the **UI** validates mock/live payloads against
the same file. The `jsonschema` validator (MIT) is a dev/test dep (`requirements-dev.txt`),
never an engine dependency.

## 6. Fixtures (EV-R1 deliverable — GENERATED, drift-guarded)

`tests/fixtures/report/valid/` — six self-contained bundles, **generated from the real
serializer** (`tests/_report_fixtures.py::generate`) and byte-compared in CI
(`test_report_contract.py`); regenerate a planned change with `UPDATE_FIXTURES=1`:
- `rich.json` — multi-dimension measured/attested mix + non-empty `gaps`.
- `all_not_measured.json` — no measurements → every measured objective `insufficient_data`.
- `over_claim_gaps.json` — attested above measured → populated `gaps[]`.
- `insufficient_data.json` — `sample_size: 0` → `insufficient_data` (not `unmet`).
- `verification_basis.json` — `hybrid` + an `integrity_summary` with all three keys non-zero.
- `per_subject.json` — measurements with `subject != ""` (per-entity breakdown).

`tests/fixtures/report/invalid/` — hand-crafted payloads OUTSIDE the golden set (they are
not valid emitter output, so they can't be generated), for the UI's rejection-path tests:
`missing_report.json`, `bad_status_enum.json`, `wrong_type_value.json`. The drift-guard
covers only `valid/`.
