# EV-6 — `DimensionRegistry` loader + 5-dimension rubric YAMLs

> Dev brief. Self-contained with this file + the repo. Parent design:
> `docs/EVAL_ARCHITECTURE(WIP).md` §2.3 (Registry shape) + §2.4 (how the rubric
> consumes it); `docs/EVAL_ISSUES(WIP).md` EV-6. Builds on **EV-0**.
>
> **PREREQUISITE:** the 5×5 control-objective content must exist in the repo as
> `docs/MATURITY_MODEL.md` (the ratified 5-dimension × 5-level table) before the
> YAMLs can be authored. See §0.1. Confirm it's committed before starting.

## 0. Context

The Dimension Registry is the **data-driven taxonomy**: the 5 trustworthiness
dimensions × 5 maturity levels, each level a set of **control objectives** mapped to
either a runtime **indicator** (measured) or a **posture key** (attested). It's the
open "fact-standard" carrier (Charter §14.3/§14.5) — *data, not code*, so the
standard can version independently and later move to ir-spec. EV-6 ships the loader,
the locked `satisfied_when` mini-grammar, and the 5 YAMLs.

### 0.1 Authoring source (prerequisite)

The control-objective text + which level each belongs to come from the ratified
**5-dimension × 5-level maturity model** (CSA-AISMM-aligned). That table must be
committed as `docs/MATURITY_MODEL.md`; author the YAMLs from it. Do **not** invent
control objectives — transcribe from that doc. The 5 stable dimension ids:
`robustness`, `efficient_reliability`, `security_alignment`,
`transparency_accountability`, `privacy_data_protection`. **Affordable** is a
cross-cutting ruler (cost indicators referenced inside other dimensions) — **no own
file**.

## 1. Scope

1. Registry data model (frozen dataclasses) + YAML **loader**:
   `treval/registry/`.
2. The **`satisfied_when` mini-grammar evaluator** — locked, safe, no `eval`.
3. The **5 dimension YAMLs** at `registry/dimensions/*.yaml`, authored from
   `docs/MATURITY_MODEL.md`.
4. Structural + completeness **validation**; a separable **cross-reference**
   validation (`indicator_id`/`posture_key` resolution) that runs when the indicator
   set exists.
5. Export the loader + types from `treval/__init__.py`.

PyYAML is already in `requirements.txt`.

## 2. Shared files touched (conflict map)

| File | Change | Risk |
|---|---|---|
| `treval/registry/__init__.py`, `models.py`, `loader.py`, `satisfied_when.py` | **new** | none |
| `registry/dimensions/{robustness,efficient_reliability,security_alignment,transparency_accountability,privacy_data_protection}.yaml` | **new** (5) | none |
| `treval/__init__.py` | **append** registry exports to imports + `__all__` | low (append-only) |
| `tests/test_registry_loader.py`, `tests/test_satisfied_when.py` | **new** | none |

## 3. YAML shape (per `docs/EVAL_ARCHITECTURE(WIP).md` §2.3)

```yaml
dimension: robustness
title_en: Robustness
title_zh: 强鲁棒性
levels:
  L1:
    control_objectives: []           # explicit empty = N/A at this level (see §6 completeness)
  L2:
    control_objectives:
      - id: rob.l2.adversarial_log
        statement_zh: 对高风险模型执行基础对抗测试并形成问题台账
        evidence:
          kind: measured             # measured | attested
          indicator_id: injection_rule_hit_ratio
          satisfied_when: "sample_size >= 1"
      - id: rob.l2.version_freeze
        statement_zh: 建立模型版本冻结要求
        evidence:
          kind: attested
          posture_key: robustness.model_version_freeze
```

Rules: a `measured` objective has `indicator_id` **and** `satisfied_when`; an
`attested` objective has `posture_key` (no `satisfied_when` — attested is
presence/value, evaluated by EV-7, not by a Measurement predicate). Exactly one of
`indicator_id`/`posture_key` per objective.

## 4. `satisfied_when` — LOCKED mini-grammar (security-sensitive)

Ratified grammar — implement **exactly** this, nothing more:

```
satisfied_when := <field> <op> <number>
  field  ∈ { "value", "sample_size" }          # a Measurement attribute
  op     ∈ { ">=", ">", "<=", "<", "==" }
  number := optional '-' , digits , optional '.' digits
```

- Parse with a strict regex/tokenizer, e.g.
  `^(value|sample_size)\s*(>=|<=|==|>|<)\s*(-?\d+(?:\.\d+)?)$`. Anything else →
  clear `SatisfiedWhenError`.
- Evaluate as `getattr(measurement, field) <op> number`. Return a `bool` (or a
  compiled predicate `Callable[[Measurement], bool]`).
- **No `eval`/`exec`, no names beyond the two fields, no function calls, no
  attribute walking** (Charter §4 — never execute arbitrary expressions). This is
  the one file I will review hardest; keep it boringly strict.

## 5. Loader + data model

```python
# treval/registry/models.py (frozen dataclasses)
@dataclass(frozen=True)
class Evidence: kind: str; indicator_id: str|None; posture_key: str|None; satisfied_when: str|None
@dataclass(frozen=True)
class ControlObjective: id: str; statement_zh: str; evidence: Evidence
@dataclass(frozen=True)
class Dimension: dimension: str; title_en: str; title_zh: str; levels: Mapping[str, tuple[ControlObjective, ...]]
@dataclass(frozen=True)
class DimensionRegistry: dimensions: Mapping[str, Dimension]

# treval/registry/loader.py
def load_registry(path: str | Path = <default registry/dimensions>) -> DimensionRegistry: ...
```

- **Loader takes a path** (default resolves to the repo's `registry/dimensions/`),
  so the registry can later move to ir-spec without code change (ratified).
- On load: parse each YAML (`yaml.safe_load`), build the frozen tree, run §6
  structural validation, raise a clear error on any violation.

## 6. Validation

**Structural (in `load_registry`, runs standalone):**
- each objective: valid `kind`; exactly one of `indicator_id`/`posture_key`;
  `measured` ⇒ `satisfied_when` present **and parses** (§4); `attested` ⇒ no
  `satisfied_when`.
- **Completeness:** all 5 dimensions present; each has keys `L1..L5`; an empty cell
  must be an **explicit** `control_objectives: []` (N/A), never a missing key — a
  silent gap is an error.

**Cross-reference (separable method, NOT run at load):**
```python
def validate_against(reg, *, indicator_ids: set[str], posture_keys: set[str] | None) -> list[str]:
    # returns a list of problems: every measured objective's indicator_id ∈ indicator_ids
```
Indicators land across EV-4/5/9, so the registry can't resolve them all at load
time. EV-6 ships `validate_against` and **tests it against the known planned
indicator-id set** (from `EVAL_ARCHITECTURE` §5 / EV-5 / EV-9):
`block_rate, scope_deny_rate, token_cost_per_agent, error_rate,
terminal_error_ratio, duration_p99, unclosed_loop_rate, chain_integrity,
hint_emission_rate, injection_rule_hit_ratio, boundary_breach_rate,
drift_alert_count, redaction_hit_ratio, pii_exposure_surface`. So the YAMLs may only
reference ids from this set — typos are caught now; full wiring is EV-7's job.

## 7. Acceptance (you write the unit tests)

1. All 5 YAMLs round-trip through `load_registry` into a `DimensionRegistry`;
   `mypy`/ruff clean.
2. Structural validation catches: unknown `kind`; both/neither of
   `indicator_id`/`posture_key`; a `measured` objective missing/with-bad
   `satisfied_when`; a missing `Lk` key → each a clear error.
3. **`satisfied_when` evaluator:** rejects arbitrary expressions (`__import__(...)`,
   `value;os.system(...)`, `other_field > 1`, function calls) with `SatisfiedWhenError`;
   accepts the grammar and evaluates correctly (`"value >= 0.5"` on a Measurement of
   value 0.6 → True; `"sample_size < 10"` etc).
4. **Completeness test:** 5 dims × L1–L5 all present; empty levels are explicit `[]`.
5. **Cross-reference:** `validate_against(known_indicator_ids)` returns no problems
   for the shipped YAMLs (proves no indicator-id typos).
6. Coverage ≥ 60%; `mypy treval` + ruff clean.

## 8. Non-goals

- The rubric scoring engine (EV-7) — EV-6 only loads + validates structure.
- Wiring indicator_ids to live indicators (EV-7, via `validate_against`).
- Registry-in-ir-spec migration (loader-takes-path makes it cheap later; not now).
- Editing UI; posture-key registry (posture keys are free-form strings here).

## 9. Guardrails

- `yaml.safe_load` only. `satisfied_when` is the security-critical surface — strict
  grammar, no `eval`, reviewed hardest.
- Frozen dataclasses; deterministic load order (sorted dimension files).
- Never import the closed platform. No network/clock/RNG.

## 10. Likely questions

- Where the YAMLs physically live: repo-root `registry/dimensions/` (chosen, eases
  the later ir-spec move) vs packaged under `treval/`. Confirm the default-path
  resolution works for both `pytest` and an installed package.
- `docs/MATURITY_MODEL.md` not yet committed → **blocked on it**; flag immediately if
  absent (don't invent control objectives).
- Whether `satisfied_when` should support `sample_size`-and-`value` compound
  predicates (e.g. `value >= .9 AND sample_size >= 100`). **Default: NO** — single
  comparison only this round; compound is a future grammar extension if needed.
