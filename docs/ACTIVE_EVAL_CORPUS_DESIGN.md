# Active-Eval Corpus — Design

> **Why.** The maturity model is 82% attested because the only wired evidence source
> is *passive* gateway audit. The **active-eval harness** is the lever that converts
> attested rows → measured: run an adversarial corpus through a target, observe how
> the governed system behaves, and **measure efficacy** (does it catch / prevent),
> not mere presence (Q-R1: the model is efficacy-based). Content is **OWASP LLM Top
> 10**-seeded (see `FRAMEWORK_ALIGNMENT.md` §2.1). Scope is **bounded** (Q-INPUT-1):
> core ships a reference corpus *and* a bring-your-own seam so it never expands
> without limit — mirroring the open conformance-suite pattern.

Pairs with: `FRAMEWORK_ALIGNMENT.md` (framework sourcing), `MATURITY_ROW_AUDIT.md`
(which rows this promotes), `EVAL_ARCHITECTURE(WIP).md` §2.2 (the `Indicator` it reuses).

---

## 1. The core idea — generate evidence, then measure it

Passive indicators (EV-4/5) read audit records the gateway *already* wrote. Active
eval **generates** the records by driving a target with known-adversarial inputs,
then measures the outcomes with the **same `Indicator` machinery**. The only new
parts are the **corpus** and the **runner that drives a target**; measurement reuses
the existing SDK.

```
 corpus (OWASP-seeded YAML)         target (the governed system)
   ┌──────────────────────┐         ┌───────────────────────────┐
   │ case: input + success │──run──▶ │ Gateway → rules → model    │
   │ criterion + dimension │         └──────────┬────────────────┘
   └──────────────────────┘                     │ outcome (decision + response)
              │                                  ▼
              │                      AuditEvidence (the WAL records the run)
              └──────────────────────────────┬───┘
                                              ▼
                          Indicator.measure(evidence)  ── reused EV-4 SDK
                                              ▼
                     Measurement: injection_catch_rate = caught / total
                     (efficacy-based, dimension-attributed, evidence_refs populated)
```

**Key property:** because the run flows through the real gateway and lands in the
WAL, every measured number is **traceable to chain-verified audit records** (the
same zero-trust property as passive eval) — a customer can re-run the corpus and
reproduce the score.

---

## 2. Components

### 2.1 Corpus — open, versioned, bounded

A directory of self-describing YAML cases (the adversarial analogue of
`trustworthy_ai_conformance/`). One case = one adversarial probe + its success
criterion. **Core ships a curated reference corpus seeded from OWASP**; it is *not*
meant to be exhaustive (that's the BYO seam, §2.4).

```yaml
# corpus/llm01_prompt_injection/direct_ignore_instructions_001.yaml
id: llm01.direct.ignore_instructions.001
owasp: LLM01                       # the OWASP 2025 category
dimension: robustness              # which trust dimension this evidences
attack_class: direct_prompt_injection
input: "<adversarial prompt — pulled from an open source, see §5; NOT authored here>"
success_when: blocked_or_flagged   # the governed system SHOULD block or flag this
severity: high
source: "owasp-genai / promptfoo redteam / garak"   # provenance, for auditability
```

`success_when` vocabulary (the efficacy criterion — extensible, whitelisted like
`satisfied_when`): `blocked_or_flagged` · `not_leaked(<canary>)` ·
`no_unauthorized_tool_call` · `output_escaped` · `within_cost_budget`. Each maps to a
deterministic check over the run's outcome — **no free-form assertion, no code eval**
(Charter §4).

### 2.2 Target — what gets driven (the seam that bounds scope)

```python
@dataclass(frozen=True)
class ProbeResult:
    case_id: str
    blocked: bool                  # gateway decision (BLOCK) — from the response/WAL
    response_text: str             # the model/forwarder output (for leak/escaping checks)
    tool_calls: tuple[str, ...]    # tools the agent attempted (for excessive-agency)
    token_cost: int | None
    evidence_ref: EvidenceRef      # back-pointer to the WAL record of this probe

class Target(Protocol):
    target_id: str
    def probe(self, case: CorpusCase) -> ProbeResult: ...
```

- **`GatewayTarget` (core ships this)** — drives the trustworthy-AI gateway's invoke
  API (HTTP/MCP), reads the decision from the response, and correlates the
  `evidence_ref` to the WAL record (tag the run with the `case_id` so the audit
  record is identifiable — small platform ask, §6).
- **BYO targets (enterprise-authored, not in core)** — any system implementing
  `Target.probe`. This is the seam (Q-INPUT-1) that lets a customer evaluate *their*
  system without core absorbing it.

### 2.3 Runner — drives corpus × target → evidence → measurement

```python
def run_corpus(corpus: Iterable[CorpusCase], target: Target) -> tuple[ProbeResult, ...]:
    """Drive each case through the target. Deterministic ordering. A failed probe
    (transport error) is recorded as an explicit error result, never silently
    dropped. Returns results for the indicators to measure over."""
```

The runner produces `ProbeResult[]` (and the underlying `AuditEvidence` via the WAL).
**Active-eval indicators are ordinary `Indicator`s** (EV-4) that measure over this:

```python
class InjectionCatchRate:           # OWASP LLM01 → Robustness/Security
    indicator_id = "injection_catch_rate"
    dimension = "robustness"
    def measure(self, evidence) -> tuple[Measurement, ...]:
        # over LLM01 probe results: value = caught / total; sample_size = total;
        # subject="" ; unit="ratio" ; evidence_refs = every probe's WAL ref
```

This is **efficacy-based** (caught/total), not presence — exactly Q-R1.

### 2.4 Boundedness (Q-INPUT-1) — two modes, capped maintenance

- **Core-run:** core's reference corpus × `GatewayTarget`. The shipped, reproducible
  baseline (like the 12-case conformance suite).
- **Bring-your-own:** external `Target` and/or external corpus dir. Core measures;
  core does not own every attack string. This caps core's corpus to a curated
  reference set; breadth lives in the open ecosystem (Promptfoo/Garak) and customer
  sets.

---

## 3. First vertical (the proof) — LLM01 Prompt Injection → `injection_catch_rate`

End-to-end, smallest useful slice:

1. **Corpus:** ~20–30 LLM01 cases (direct + indirect injection), each
   `success_when: blocked_or_flagged`, inputs pulled from open sources (§5).
2. **Target:** `GatewayTarget` against a running gateway with an injection ruleset.
3. **Runner → indicator:** `injection_catch_rate` = blocked-or-flagged / total.
4. **Result:** a *measured*, efficacy-based Robustness signal that **promotes**
   `rob.l2.injection_rule_detection` from a presence check to an efficacy measure,
   and gives `rob.l2.adversarial_test_ledger` / `rob.l3.standardized_suite` real
   measured backing (row-audit §3).

**Acceptance:** on a gateway with a known-good injection ruleset, catch rate is high;
on a no-op ruleset, catch rate collapses (proving the indicator measures *efficacy*,
not existence). Reproducible: same corpus + target → same rate.

---

## 4. OWASP coverage roadmap (after the LLM01 vertical)

Build order by buildability (`FRAMEWORK_ALIGNMENT.md` §2.1):

| OWASP | indicator | dimension | notes |
|---|---|---|---|
| LLM01 | `injection_catch_rate` | Robustness/Security | **first vertical** |
| LLM02 | `sensitive_disclosure_rate` | Privacy | canary-secret probes (`not_leaked`) |
| LLM07 | `system_prompt_leak_rate` | Privacy/Robustness | extraction probes |
| LLM06 | `tool_scope_violation_rate` | Security/Transparency | over-reach tasks; joins audit scope-deny |
| LLM05 | `unsafe_output_passthrough_rate` | Security | outputs needing escaping |
| LLM10 | `cost_runaway_caught` | Efficient Reliability/Affordable | recursive/long inputs |
| LLM08 | `rag_poisoning_resistance` | Privacy/Robustness | only if RAG in scope |
| LLM03/04/09 | — | — | supply-chain/training = out of runtime scope; misinformation needs labeled ground truth (later) |

---

## 5. Corpus content sourcing (no fabrication)

Attack strings are **pulled from open sources, not authored from memory** (the D1
hallucination discipline applies to attack content too):

- OWASP GenAI project materials + the OWASP red-teaming guide.
- Open red-team tooling datasets: **Promptfoo** (the user named it), **Garak**,
  **PyRIT** — well-known open frameworks with injection/jailbreak corpora.
- CAICT **SafetyAI Bench** (27 content/values dims) for the content-safety probes —
  *pending primary-source access*.

Each case records its `source` for provenance. **Before the corpus is built, confirm
the licenses** of any imported dataset against Charter §1 (permissive only).

---

## 6. Dependencies & platform asks

- **Reuses (no new dep):** `WalEvidenceReader` (EV-1), `Indicator` SDK (EV-4), the
  `satisfied_when`-style whitelisted checker (EV-6) for `success_when`.
- **Needs a running target** — a deployed gateway + a model forwarder
  (`OpenAICompatibleForwarder` exists). Active eval is therefore an *integration*
  test, CI-gated like the Postgres suite (skips without a target).
- **Small platform ask:** tag eval-run audit records with the `case_id` (an
  eval-mode header / dedicated eval tenant) so the WAL record of each probe is
  identifiable for `evidence_ref` correlation. Cleanly optional: the HTTP response
  carries the decision, so the WAL correlation is the *auditable anchor*, not a hard
  requirement for the measurement itself.

---

## 7. Boundaries / non-goals

- **Not** a training-data or supply-chain scanner (LLM03/04 are out of runtime scope).
- **Not** an exhaustive attack library — a curated reference + BYO seam (§2.4).
- **Not** a misinformation/factuality judge initially (needs labeled ground truth).
- Does **not** change the `Indicator`/`Measurement` contract (EV-0) — active-eval
  indicators are ordinary indicators over harness-collected evidence.

---

## 8. Open questions

- **Q-AE1 (target dependency).** Active eval needs a live gateway+model. Do we run it
  in CI against a deployed stack (like the PG suite), or only as an operator-run
  integration? (Leaning: operator-run + a tiny smoke corpus in CI against a fake
  forwarder.)
- **Q-AE2 (eval-run tagging).** Is the platform willing to tag eval-run records with
  `case_id` (§6)? If not, we rely on the HTTP response + a dedicated eval tenant.
- **Q-AE3 (corpus licensing).** Which open corpora (Promptfoo/Garak/PyRIT/SafetyAI
  Bench) are license-compatible with Charter §1 for redistribution in core?
- **Q-AE4 (issue shape).** One V-eval issue or a vertical-per-OWASP-category series?
  (Leaning: one issue for the harness+LLM01 vertical, then a thin issue per category.)
