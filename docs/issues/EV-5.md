# EV-5 (5a + 5b) — passive WAL indicators: chain_integrity · duration_p99 · terminal_error_ratio · unclosed_loop_rate (+ A↔B join helper)

**Problem (plain language):** the maturity report can measure attack-detection (active eval) but **cannot
yet measure the deployment's own governance record** — is the audit chain intact? are request→response
loops closed? what's the latency / error baseline? Those rows read `NotMeasured`, so **Transparency (the
moat) and Efficient-Reliability are attested-only** — the exact "trust me" gap the product exists to close.

**Value:** EV-5 lights up those dimensions from the **passive** side. `chain_integrity` +
`unclosed_loop_rate` are meaningful over **any** WAL (including the eval's own), so **Transparency — the
requires_integrity moat — becomes a *verified* level immediately**, no production traffic needed. The
reliability pair gains full meaning once production traffic flows (EV-8 passive phase). It also builds the
shared **A↔B join helper** EV-9 reuses.

> Dev brief. Self-contained: implement from this file + the **EV-4** passive Indicator SDK
> (`treval/indicators/`, `measure(evidence: Iterable[AuditEvidence]) -> tuple[Measurement,...]`) + the
> **EV-1** `WalEvidenceReader` (already sets `AuditEvidence.integrity` VERIFIED/BROKEN, break-poisons-tail).
> **Prereq:** EV-4 ✅, EV-1 ✅. Decisions in §0 (all Platform/Core-ratified 2026-07-11). Pure, deterministic.

---

## 0. RATIFIED

| # | decision |
|---|---|
| ① | **Build + fixture-test now** (walgen, like EV-4). Transparency pair is live over the eval WAL; reliability pair needs production traffic → EV-8 passive phase. |
| ② | **`Measurement.integrity = min(evidence integrities)`** in EVERY indicator here **+ retrofit `block_rate`** — closes the EV-2 hard-gate: a Postgres/UNVERIFIED source auto-marks the Measurement UNVERIFIED. |
| ③ | **`chain_integrity` reads `AuditEvidence.integrity`** (no new interface); WAL-only by nature — a break poisons the tail → value<1 AND `Measurement.integrity=BROKEN`; Postgres → UNVERIFIED. The moat. |
| ④ | **A↔B join by `request_id`** (NOT `seq` — multi-instance PK is `(gateway_instance, seq)`). B carries `response.decision_seq` back-pointer = same-instance secondary check; orphan-A = documented "incomplete request", orphan-B tolerated; never throws. Shared helper. |
| — | **Window = the reader's tenant+time filter** (the driver sets it, consistent time semantics); indicators are pure over the stream. |

## 1. EV-5a — single-record indicators (`treval/indicators/`)

Each: passive Indicator over `AuditEvidence`; `Measurement.integrity = min` over the records it consumed
(②); errored/absent-field records excluded from the denominator + counted in notes.

- **`chain_integrity`** — dim `transparency_accountability`; **`requires_integrity` objective**.
  value = fraction of records `IntegrityStatus.VERIFIED` (a chain break → tail BROKEN → value<1); `sample_size`
  = records seen. Matches the registry bindings `value>=1` (trn.l3.audit_chain_intact) + `sample_size>=100`
  (trn.l4.trace_baseline). `Measurement.integrity = min` → BROKEN if any record broken (rubric resolves
  `unverified_evidence`, which is correct: a broken chain can't verify itself).
- **`duration_p99`** — dim `efficient_reliability`; value = p99 of B-record `response.duration_ms`;
  unit `"ms"`; `sample_size` = B records with a duration. (rel.l4.slo_latency_baseline, `sample_size>=100`.)
- **`terminal_error_ratio`** — dim `efficient_reliability`; value = error responses ÷ measurable, where an
  error = `response.final_terminal` in the error/timeout set **OR** `response.errors`/`audit.errors`
  non-empty; `sample_size` = B records. (rel.l4.slo_success_baseline, `sample_size>=100`.)

## 2. EV-5b — A↔B join helper + `unclosed_loop_rate`

- **Join helper** (`treval/indicators/correlate.py`, the one shared correlation module — EV-9 reuses it):
  `join_ab(evidence) -> {paired: [(A,B)], orphan_a: [A], orphan_b: [B]}`. Key = **`request_id`**; within a
  matched pair, assert `B.response.decision_seq` back-points to A's seq **only as a same-instance secondary
  check** (a mismatch is a note, not a drop — cross-instance is legal). Orphans never raise (④). Pure +
  deterministic (stable order).
- **`unclosed_loop_rate`** — dim `transparency_accountability`; over A records with `final_decision=ALLOW`
  (a forwarded request that SHOULD produce a B). unclosed = an allowed-A with **no paired B** **and** older
  than a **configurable close window** (`TREVAL_UNCLOSED_WINDOW_NS`, default **5 min**; eval traffic is
  synchronous → set short, e.g. 30 s, for fast validation — a recent A with no B yet is *in-flight*, not
  unclosed). value = unclosed ÷ allowed-A; `sample_size` = allowed-A. (trn.l3.full_chain_trace, `value<=0`.)
  `Measurement.integrity = min`.

## 3. EV-8 integration point (design the seam, wire later)

The passive producers plug into EV-8's D3 selection map (the **passive** side, §6 of EV-8) with **no change
to core report logic**: driver builds a reader over `(tenant, window)`, runs these indicators, emits their
Measurements into the bundle. `chain_integrity` is the one live-now over the eval WAL; the rest ride the
production passive phase. Keep the interface identical to `block_rate` (an EV-4 passive Indicator) so
adding an indicator never touches EV-7/EV-8.

## 4. Acceptance (unit, fixture-driven — no gateway)

- **Normal** walgen fixtures: each indicator's hand-computed value/sample_size; `Measurement.integrity`
  = min over the fixture's records.
- **Boundary cases (required):** a **BROKEN-chain** fixture → `chain_integrity` value<1 **and**
  `Measurement.integrity=BROKEN`; **many allowed-A with no B** → `unclosed_loop_rate` counts them (past the
  window) but **not** in-flight (within-window) ones; **empty stream** → `sample_size=0`, value 0 (not a
  crash, distinct from a real 0). Orphan-A / orphan-B in the join → handled, no throw.
- **②-retrofit test:** `block_rate` over a fixture containing an UNVERIFIED record → `Measurement.integrity
  == UNVERIFIED`; a rubric test proving that measurement can't satisfy a `requires_integrity` objective.
- Determinism (same stream → identical Measurements); coverage ≥60% / mypy / ruff clean.

## 5. Non-goals

- The **live production-WAL run** (EV-8 passive phase; needs production traffic + a production reader).
- **EV-9** (dimension-attribution indicators — separate brief; reuses this join helper).
- Postgres reader (EV-2); the ② min-integrity here is what makes EV-2 safe when it lands.
