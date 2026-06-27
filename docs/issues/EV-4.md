# EV-4 — Indicator SDK (runner + registry) + first reference indicator `block_rate`

> Dev brief. Self-contained: implement from this file + the repo. Parent design:
> `docs/EVAL_ARCHITECTURE(WIP).md` §2.2 (Indicator/Measurement) and §5 (indicator
> table); the `Indicator` Protocol + `Measurement` model already exist (EV-0,
> `treval/protocols.py` / `treval/models.py`). Prereqs **merged**: EV-0, EV-1.

## 0. Context

EV-4 builds the machinery that turns audit evidence into quantified signals, and
ships the **first concrete indicator end-to-end** to prove the pattern. This is a
**contract-defining** issue like EV-0 was: `block_rate` is the template every later
indicator (EV-5a/5b/EV-9) copies — pure `measure()`, `evidence_refs` always
populated, `subject=""` aggregate, `sample_size=0` vs `value=0`. Get it exactly
right; the rest become mechanical.

## 1. Scope

- An **Indicator registry** (`id → indicator`, lookup by dimension).
- An **Indicator runner** (registered indicators + an `AuditEvidence` iterator →
  `tuple[Measurement, ...]`).
- The **`block_rate`** reference indicator (Security & Alignment), fully wired
  evidence → `measure` → `Measurement`.

Nothing else: no other indicators (EV-5/EV-9), no rubric (EV-7), no A↔B
correlation helper (EV-5b).

## 2. Layout

```
treval/indicators/
  __init__.py        # re-export: IndicatorRegistry, run_indicators, BlockRate (+ build_default_registry if used)
  registry.py        # IndicatorRegistry
  runner.py          # run_indicators(...)
  block_rate.py      # BlockRate indicator
tests/
  test_indicator_sdk.py     # registry + runner (dummy indicators)
  test_block_rate.py        # the worked example + edge cases
```

`treval/indicators/` is a new subdir — no overlap with `readers/`, `posture/`,
`registry/`, `web/`. Pure Python, **no new dependency**.

## 3. Exact shapes

### 3.1 Indicator (already defined — EV-0 `treval/protocols.py`, do not redefine)

```python
class Indicator(Protocol):
    indicator_id: str
    dimension: str
    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]: ...
```

A concrete indicator is a plain class with the two attributes + `measure`. It does
**not** need a base class.

### 3.2 `treval/indicators/registry.py`

```python
class IndicatorRegistry:
    """id -> Indicator, with dimension lookup. No I/O, no global state."""
    def __init__(self) -> None: ...
    def register(self, indicator: Indicator) -> None:
        # reject duplicate indicator_id (raise ValueError) — ids are a contract
        ...
    def get(self, indicator_id: str) -> Indicator: ...        # KeyError if absent
    def by_dimension(self, dimension: str) -> tuple[Indicator, ...]: ...  # stable order
    def all(self) -> tuple[Indicator, ...]: ...               # registration order
    def ids(self) -> frozenset[str]: ...                      # feeds registry.validate_against (EV-6)
```

`ids()` is the bridge to EV-6: `validate_against(reg, indicator_ids=sdk.ids())`
checks every registry `indicator_id` resolves.

### 3.3 `treval/indicators/runner.py`

```python
def run_indicators(
    indicators: Iterable[Indicator],
    evidence: Iterable[AuditEvidence],
) -> tuple[Measurement, ...]:
    """Run each indicator over the SAME evidence, flatten the results.

    CRITICAL: `evidence` may be a single-pass Iterator (the WAL reader yields a
    generator). Materialize it ONCE into a tuple before fanning out, or only the
    first indicator sees any data. Order = indicators order, then each indicator's
    own Measurement order.
    """
```

### 3.4 `treval/indicators/block_rate.py`

```python
class BlockRate:
    indicator_id = "block_rate"
    dimension = "security_alignment"      # MUST match the EV-6 dimension id
    def measure(self, evidence): -> tuple[Measurement, ...]
```

## 4. `block_rate` semantics (specify exactly — don't let the dev guess)

Fraction of **decided** requests that were BLOCKed.

- **Consider only decision records.** Skip `record_type == AUDIT_RECORD_TYPE_RESPONSE_OBSERVED`
  (the sparse B record has no decision). decision.made (`==DECISION_MADE`) and legacy
  (`==UNSPECIFIED`/0) both count. Use `rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED`.
- **Denominator = decided records:** those whose `record.decision.final_decision`
  is `FINAL_DECISION_ALLOW` or `FINAL_DECISION_BLOCK`. Exclude `UNSPECIFIED` /
  `UNDECIDED` (not a terminal decision). Use
  `rc_pb.DecisionTrace.FINAL_DECISION_ALLOW` / `...FINAL_DECISION_BLOCK`.
- **Numerator = `BLOCK` count.** `value = blocks / decided` (float); if
  `decided == 0`, `value = 0.0`.
- **`sample_size` = decided** (the denominator).
- **`evidence_refs` = the `EvidenceRef` of each decided record** (so
  `len(evidence_refs) == sample_size`). Carry `evidence.ref` through.
- **`subject = ""`** (aggregate — block_rate is not per-entity), `unit = "ratio"`,
  `dimension = "security_alignment"`, `indicator_id = "block_rate"`.
- Always returns a **1-tuple** (one aggregate Measurement), even for empty input.
- **Integrity:** in EV-4, count a record regardless of `IntegrityStatus` (do not
  filter BROKEN here). Integrity is summarized by the rubric (EV-7); block_rate is
  a plain rate. (If we later want "verified-only" rates, that's a rubric concern,
  not the indicator's — keep the indicator dumb.)

## 5. Acceptance (you write the unit tests)

1. **Worked example:** 3×ALLOW + 1×BLOCK (all decision.made) →
   `value == 0.25`, `sample_size == 4`, `subject == ""`, `len(evidence_refs) == 4`,
   `dimension == "security_alignment"`, `unit == "ratio"`, result is a 1-tuple.
2. **Empty input:** `measure([])` → 1-tuple, `sample_size == 0`, `value == 0.0`
   (the `sample_size==0` "insufficient data" signal, distinct from a real 0.0 rate).
3. **B records excluded:** a `RESPONSE_OBSERVED` record in the stream does not
   change `sample_size` or `value`.
4. **Undecided excluded:** an `UNDECIDED`/`UNSPECIFIED` decision record is not in
   the denominator.
5. **Purity:** same evidence twice → identical tuple (== on Measurements).
6. **Registry:** duplicate `register` → `ValueError`; `get(unknown)` → `KeyError`;
   `by_dimension` returns the right set; `ids()` returns all ids.
7. **Runner:** materializes a single-pass iterator (pass a generator that would be
   exhausted after one pass; assert two indicators both see the data); flattens in
   order.
8. **EV-6 bridge:** `validate_against(load_registry(), indicator_ids=reg.ids())`
   has no `block_rate` complaint once `block_rate` is registered (the other ids will
   still be flagged until EV-5/EV-9 land — assert `block_rate` is **not** among the
   problems, not that the list is empty).
9. Coverage ≥ 60% on new paths; `mypy tools treval` clean; ruff check + format clean.

Build fixtures with real `RequestContext` payloads (set
`decision.final_decision`, `record_type`, `envelope.*`) like
`tests/test_wal_reader.py` does — or construct `AuditEvidence` directly with a
hand-built `RequestContext` (no WAL needed for indicator unit tests).

## 6. CI

No change needed — `treval/indicators/` is pure Python under the existing
`mypy tools treval` / `ruff` / `pytest --cov=treval` gates. No new dependency.

## 7. Guardrails (the pattern others copy)

- **Pure & deterministic:** `measure` does no I/O, no clock, no RNG; same evidence
  ⇒ same tuple. No reliance on dict/set iteration order in output.
- **`evidence_refs` always populated** — a Measurement with no traceable refs is a
  bug (Charter §5.5 spirit). `len == sample_size` for rate indicators.
- **`sample_size == 0` ≠ `value == 0`** — the rubric (EV-7) treats 0-sample as
  *insufficient_data*, not *failing*. Never collapse them.
- **Indicators read decoded facts only** — never re-evaluate Rule IR; the gateway
  already decided. block_rate just counts recorded outcomes.
- **Dimension id must match EV-6** (`security_alignment`) or `validate_against`
  won't resolve it.
- Match repo style (`from __future__ import annotations`, frozen dataclasses are
  EV-0's; indicators are plain classes).

## 8. Non-goals

- Other indicators (EV-5a/5b/EV-9), the rubric engine (EV-7), the CLI (EV-8).
- The A↔B correlation helper (EV-5b) — block_rate needs only A records, via a
  simple `record_type` filter, **not** correlation.
- Integrity-filtered or verified-only variants (a rubric concern).
- Any per-entity (`subject != ""`) indicator — that arrives with
  `token_cost_per_agent` in EV-5b; block_rate is aggregate-only.

## 9. Likely questions to raise (don't guess — ask)

- Should `block_rate`'s denominator include BROKEN-integrity records? (Brief says
  yes — keep the indicator dumb; rubric handles integrity. Confirm if unsure.)
- Where does the "default registry" of indicators live (a `build_default_registry()`
  factory)? Fine to add a small one in `__init__.py`, but EV-4 only registers
  `block_rate`; EV-5+ append to it.
- Proto enum access path (`rc_pb.DecisionTrace.FINAL_DECISION_BLOCK`,
  `rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED`) — confirm against the installed
  `trustworthy_ai.v1.request_context_pb2` if names differ.
