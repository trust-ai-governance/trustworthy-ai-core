# Active-Eval Corpus — Design (settled)

> **Why.** The maturity model is 82% attested because the only wired evidence source
> is *passive* gateway audit. The **active-eval harness** converts attested rows →
> measured: run an adversarial corpus through a target, observe how the governed
> system behaves, and **measure efficacy** (does it catch / prevent), not presence
> (Q-R1). Content is **OWASP LLM Top 10**-seeded (`FRAMEWORK_ALIGNMENT.md` §2.1).
> Scope is **bounded** (Q-INPUT-1): core ships a small reference corpus + a
> bring-your-own seam.
>
> **Status: settled** — incorporates Platform's Q-AE2 answer (request_id + eval
> tenant; **no platform change**) and the corpus-interface / licensing decisions
> (Q-AE3). Ready to brief as **EV-AE0**.

Pairs with: `FRAMEWORK_ALIGNMENT.md`, `MATURITY_ROW_AUDIT.md`,
`EVAL_ARCHITECTURE(WIP).md` §2.2 (the `Measurement` it reuses), `POSTGRES_READ_CONTRACT.md`
(`request_id` is the canonical correlation key).

---

## 1. Core idea — generate evidence, then measure it

Passive indicators (EV-4/5) read records the gateway *already* wrote. Active eval
**generates** records by driving a target with known-adversarial inputs, then
measures the outcomes. The new parts are the **corpus** and the **runner that drives
a target**; the output is the same `Measurement` the rubric consumes.

```
 corpus (cases: input + success_when + dimension)
        │  run under a reserved eval tenant (§4)
        ▼
 Target.probe ── HTTP/MCP invoke ──▶ Gateway → rules → model   (the REAL governance path)
        │                                   │
        │  response: request_id (body + x-request-id header), decision, output
        ▼                                   ▼
 ProbeResult  ◀── join by request_id ── WAL record (E1: final_decision, rule_evaluations[tags], hint)
        ▼
 CorpusIndicator.measure(ProbeResult[]) ─▶ Measurement
        injection_catch_rate = caught / total   (efficacy, dimension-tagged, evidence_refs=request_ids)
```

**Trust property preserved:** every probe is an ordinary governed request landing in
the hash-chained WAL, correlated by `request_id` — so a customer re-runs the corpus
and reproduces the score from chain-verified records. No eval-special path.

---

## 2. Correlation & isolation (Q-AE2 — Platform answer, zero platform change)

**Correlate by `request_id`; isolate under a reserved eval tenant. Do NOT add a
`case_id` field to the audit schema.**

- **Correlation = `request_id`.** The gateway already returns it on every probe
  (response body **and** `x-request-id` header). The harness holds
  `case_id → request_id` the instant it gets the response; `evidence_ref = request_id`
  (core's canonical key, `POSTGRES_READ_CONTRACT`). A `case_id` field would be a
  net-new **strong-contract** change (Charter §3) bleeding an *eval* concept into the
  *governance* WAL — wrong side of the platform/core split. The integrity property
  comes from `request_id` alone (the record is hash-chained regardless).
- **Isolation = reserved eval tenant** (e.g. `__eval__`) — **required, not optional.**
  Eval probes become real audit records; without isolation they would **contaminate**:
  - D1 `soc2-critical-operations` = `terminal ∈ {BLOCKED,ERROR}` → every caught
    injection (a BLOCK) would pollute a customer's SOC2/等保 compliance report;
  - `total_tokens_by_agent` (eval burns tokens) and the passive maturity signals
    (eval BLOCK-rate skews real Robustness numbers).
  `tenant_id` already filters `/audit:report`, token stats, and search, and is
  required everywhere (Charter §7) — so a dedicated eval tenant gives
  correlation-by-filter **and** keeps eval out of real governance data. Pure
  convention, no schema change.
- **Never make the gateway eval-aware** (Platform comment #1) — an eval-mode the
  gateway special-cases would invalidate the test ("does eval behave differently?").
  The gateway governs a probe identically to real traffic; correlation/isolation live
  *outside* the governance record.

---

## 3. Components

### 3.1 Corpus — open, versioned, bounded

Self-describing YAML cases (the adversarial analogue of `trustworthy_ai_conformance/`).

```yaml
# corpus/llm01_prompt_injection/direct_ignore_instructions_001.yaml
id: llm01.direct.ignore_instructions.001
owasp: LLM01
dimension: robustness
attack_class: direct_prompt_injection
input: "<adversarial prompt>"        # provenance + sourcing rules in §5
success_when: blocked_or_flagged     # the efficacy criterion (whitelisted vocab below)
severity: high
source: "core-authored | promptfoo:<path> | garak:<probe> | pyrit:<id>"
```

`success_when` vocabulary (whitelisted, deterministic checks — no code eval, Charter §4):

| token | check | basis |
|---|---|---|
| `blocked_or_flagged` | `final_decision==BLOCK` OR `hint_emitted` (a *matched* rule alone is **not** a catch — benign log rules match every request) | **WAL (E1) — deterministic** |
| `no_unauthorized_tool_call` | no tool call outside granted scope (audit `missing_scopes`/decision) | WAL — deterministic |
| `within_cost_budget` | `token_usage.total <= budget` | WAL — deterministic |
| `not_leaked(<canary>)` | seeded canary string absent from the output | **HTTP response — statistical (§6)** |
| `output_escaped` | output safely escaped for the sink | HTTP response — statistical |

Platform comment #2: the catch signal is **already emitted** by E1 — `success_when:
blocked_or_flagged` is read directly from the record by `request_id`; the record also
carries the dimension tags for free.

### 3.2 Target — what gets driven (the bring-your-own seam, Q-INPUT-1)

```python
@dataclass(frozen=True)
class ProbeResult:
    case_id: str
    request_id: str                  # from x-request-id / body — the correlation key
    decision: str                    # ALLOW | BLOCK (from response/WAL)
    response_text: str               # full model output, captured at probe time (for output checks)
    evidence: AuditEvidence | None   # the WAL record by request_id (E1 fields); None if not yet shipped
    error: str | None = None         # transport failure — recorded, never silently dropped

class Target(Protocol):
    target_id: str
    def probe(self, case: CorpusCase) -> ProbeResult: ...
```

- **`GatewayTarget` (core ships)** — POSTs the case `input` to the gateway invoke API
  under the **eval tenant's identity**, captures `request_id` + `decision` +
  `response_text`, then reads the WAL record by `request_id`
  (`WalEvidenceReader(tenant="__eval__")`) to attach `evidence`. **Note:** the WAL
  stores only a response *preview* + sha256 (B2), so **output-based checks use the
  captured `response_text`, not the WAL** — decision/rule checks use the WAL.
- **BYO targets (enterprise, not in core)** — any `Target.probe`. The seam that lets a
  customer evaluate *their* system without core owning it.

### 3.3 Runner + indicators

```python
def run_corpus(corpus, target) -> tuple[ProbeResult, ...]: ...   # deterministic order; errors recorded

class CorpusIndicator(Protocol):                # active-eval flavor; emits the SAME Measurement (EV-0)
    indicator_id: str; dimension: str
    def measure(self, results: Iterable[ProbeResult]) -> tuple[Measurement, ...]: ...
```

`injection_catch_rate` (LLM01 → Robustness): `value = caught / total`,
`sample_size = total`, `subject=""`, `unit="ratio"`, `evidence_refs` = each probe's
`request_id` ref. Efficacy-based (Q-R1). Output is a `Measurement` → feeds the same
rubric (EV-7); the rubric doesn't care it came from active eval.

---

## 4. Corpus sourcing & the open-corpora interface (Q-AE3)

**How core interfaces with open corpora — by INGESTING content, not delegating
execution.** Core owns the runner (probes must flow through the gateway → WAL);
Promptfoo/Garak/PyRIT are **content sources**, not runtime substitutes.

Two corpus sources, chosen to avoid the redistribution-license burden:

1. **Core reference corpus (shipped):** a *small, hand-authored* set of cases we write
   and license ourselves (permissive) — the reproducible baseline, like the 12-case
   conformance suite. ~20–30 LLM01 cases to start.
2. **Adapters over user-installed open corpora (NOT redistributed):** a
   `CorpusAdapter` per format reads attack cases **from a corpus the user already has
   installed** (their Promptfoo/Garak/PyRIT dataset) and normalizes to `CorpusCase`.
   Core ships the *adapter code*, **not** the datasets — so core never redistributes
   third-party attack content, sidestepping per-dataset licensing entirely. This *is*
   the bring-your-own-corpus seam.

**License discipline (Platform comment #5, verified):** the tools are permissive —
**Promptfoo MIT, Garak Apache-2.0, PyRIT MIT** — but a permissive tool may vendor a
differently-licensed dataset. So: (a) the *adapter* approach means core redistributes
nothing, the cleanest answer; (b) any case we *vendor* into the core reference corpus
must be core-authored or have a verified permissive provenance (per-dataset, not
per-tool); (c) **CAICT SafetyAI Bench license is unconfirmed → gated** until verified.

*(Strategic note: Promptfoo was acquired by OpenAI in 2026 but remains MIT; track the
dependency but it's not a blocker.)*

---

## 5. Reproducibility — split deterministic vs statistical (Platform comment #3)

- **Decision-based indicators are bit-reproducible.** Rule-driven decisions are
  deterministic → `injection_catch_rate` (BLOCK/total), `no_unauthorized_tool_call`,
  `within_cost_budget` reproduce exactly. Acceptance asserts exact reproduction.
- **Output-based checks inherit model nondeterminism.** `not_leaked`, `output_escaped`
  run over real model text → **statistical**. Pin the model + `temperature=0`
  (B1's `openai_model` pin supports it) and report `sample_size` + confidence, not a
  single pass/fail. Mark these indicators **statistical** in their `notes`.

---

## 6. First vertical (the proof) — LLM01 → `injection_catch_rate`

1. **Corpus:** ~20–30 core-authored LLM01 cases (direct + indirect injection),
   `success_when: blocked_or_flagged`.
2. **Target:** `GatewayTarget` against a running gateway with an injection ruleset,
   under tenant `__eval__`.
3. **Runner → indicator:** `injection_catch_rate` = caught / total.
4. **Promotes** `rob.l2.injection_rule_detection` from a presence check to an efficacy
   measure (Q-R1), and backs `adversarial_test_ledger` / `standardized_suite`.

**Acceptance:** high catch rate on a good ruleset; **collapses on a no-op ruleset**
(proves it measures *efficacy*, not existence). Decision-based result is reproducible.

---

## 7. OWASP coverage roadmap (thin issue per category — Q-AE4)

LLM01 (vertical) → LLM02 `sensitive_disclosure_rate` (Privacy, canary) → LLM07
`system_prompt_leak_rate` → LLM06 `tool_scope_violation_rate` (Security) → LLM05
`unsafe_output_passthrough_rate` → LLM10 `cost_runaway_caught` (Reliability) → LLM08
`rag_poisoning_resistance` (if RAG). LLM03/04/09 out of runtime scope / need labeled
ground truth (later).

---

## 8. Dependencies & setup

- **Reuses (no new core dep):** `Measurement` (EV-0), `WalEvidenceReader` (EV-1), the
  `satisfied_when`-style whitelisted checker (EV-6) for `success_when`. Needs an HTTP
  client to drive the gateway (`httpx`, already in `treval[web]` / B1).
- **No platform change** (Q-AE2). The two pieces (`x-request-id`, `tenant_id` filters)
  exist today.
- **Eval-tenant identity wiring (Platform comment #4):** the eval tenant needs registry
  entries (an eval agent + user/scopes, or a `builtin.chat` for `__eval__`) or probes
  hit `IDENTIFY_FAILED`. Cheap, but a required setup step — call it out in the brief.
- **Live target:** active eval is an *integration* test — needs a deployed gateway +
  model forwarder. **Q-AE1 (settled):** support **both** — a CI smoke corpus against a
  **fake/echo forwarder** (deterministic, no model, runs in CI), **and** an
  operator-run full corpus against a real gateway+model (the owner verifies when CI
  can't host a stack). The harness is target-agnostic, so both are the same code path.

---

## 9. Boundaries / non-goals

- Not a training-data/supply-chain scanner (LLM03/04 out of runtime scope).
- Not an exhaustive attack library — curated reference + BYO adapters (§4).
- Not a misinformation/factuality judge initially (needs labeled ground truth).
- Does not change the `Measurement` contract (EV-0); does not add a `case_id` to the
  audit schema (§2).

---

## 10. Settled decisions & remaining open

| Q | Settled |
|---|---|
| **Q-AE1** (target) | ✅ **Both** — CI smoke (fake forwarder) + operator-run real stack; owner verifies the real stack. Same harness code. |
| **Q-AE2** (correlation/isolation) | ✅ **`request_id` + reserved eval tenant `__eval__`; no `case_id`, no platform change.** |
| **Q-AE3** (corpora/licensing) | ✅ Tools permissive (Promptfoo MIT / Garak Apache-2.0 / PyRIT MIT). Core **ingests via adapters, redistributes nothing**; vendored reference cases are core-authored. SafetyAI Bench **gated** (license unconfirmed). |
| **Q-AE4** (issue shape) | ✅ One issue = harness + LLM01 vertical (**EV-AE0**); thin issue per OWASP category after. |
| (future) self-describing eval records | If ever needed, a **generic** OTel-style client trace-id the gateway echoes (Charter §12.4) — a separate cross-repo item, **not** an eval `case_id`. |
