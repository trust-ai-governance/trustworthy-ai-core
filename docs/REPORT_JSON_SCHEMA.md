# Report JSON Schema (EV-R1) — the UI's stable consumption contract

Derived from the **frozen** `MaturityReport` / `Measurement` dataclasses (EV-0,
`EVAL_ARCHITECTURE(WIP).md` §2.2/§2.4). It exists so the UI engineer (EV-W2) can
build against committed fixtures **before** EV-7's serializer or EV-W1's service
exist. EV-7's serialized output MUST validate against this schema.

Status: **contract proposal.** The dataclass fields are frozen; the JSON *naming /
envelope* decisions below are EV-R1's to set.

---

## 1. Envelope

A run emits one **report bundle**: the rubric verdict **plus** the measurements
that fed it (the report itself stores only objective pass/fail, not the measured
numbers — the UI wants both). The bundle is an envelope around two already-frozen
shapes; it does **not** modify the `MaturityReport` dataclass.

```json
{
  "schema_version": 1,
  "report": { /* MaturityReport */ },
  "measurements": [ /* Measurement, ... */ ]
}
```

- `schema_version` (int): this contract's version; bump on any additive change.
- `report`: the serialized `MaturityReport`.
- `measurements`: the `Measurement[]` the engine produced this run (so the UI can
  render measured values + per-`subject` breakdowns without a live call).

> Open item (EV-R1/EV-W1): keep `measurements` inline (this proposal) vs a separate
> `measurements.json` / drill-down endpoint. Inline is simplest for the static-JSON
> UI; revisit if bundle size becomes a problem.

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

## 5. JSON Schema

Ship a draft-2020-12 JSON Schema at `tests/fixtures/report/report.schema.json`
encoding §2 (types, enum value sets for `kind`/`status`/`verification_basis`,
required keys, `integrity_summary` requiring all three keys). UI + EV-7 tests
validate against it. (Schema authored as part of EV-R1; not reproduced here to
avoid drift — the tables above are the spec, the committed `.json` is the
machine-checkable form.)

## 6. Fixtures to commit (EV-R1 deliverable)

Under `tests/fixtures/report/`:
- `award_min_gate.json` — measured L3 + attested L2 → awarded L2 (the example above).
- `overclaim_gap.json` — attested L4 + measured L2 → `gaps` populated.
- `index_unverified.json` — `verification_basis: "index"`; Transparency
  `requires_integrity` objective → `unverified_evidence`.
- `per_agent_subject.json` — multiple `token_cost_per_agent` measurements with
  distinct `subject`s + one aggregate (`subject: ""`).
- `insufficient_data.json` — an objective with `sample_size: 0` → `insufficient_data`.
