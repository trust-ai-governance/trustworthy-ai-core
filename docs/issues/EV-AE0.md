# EV-AE0 — Active-eval harness + LLM01 prompt-injection vertical

> Dev brief. Self-contained: implement from this file + `ACTIVE_EVAL_CORPUS_DESIGN.md`
> (the settled design) + the repo. **Prereq: EV-4 merged** (the `Measurement` model /
> indicator pattern). Also reuses EV-1 (`WalEvidenceReader`) and EV-6's whitelisted
> checker style.

## 0. Context

Active eval is the lever that turns *attested* maturity rows into *measured* ones:
drive an adversarial corpus through the **real** gateway, observe whether the
governed system catches the attack, and **measure efficacy** (caught / total) — not
mere presence (Q-R1). EV-AE0 ships the harness end-to-end plus the **first vertical**:
OWASP **LLM01 Prompt Injection → `injection_catch_rate`**. It establishes the pattern
every later OWASP category copies (one thin issue each, Q-AE4).

Read `ACTIVE_EVAL_CORPUS_DESIGN.md` first — this brief implements it.

## 1. Scope

- **Corpus format + loader** — self-describing YAML cases (`CorpusCase`).
- **`success_when` checker** — whitelisted, deterministic checks (no code eval).
- **`Target` Protocol + `GatewayTarget`** — drives the gateway invoke API under a
  reserved eval tenant; correlates by `request_id`.
- **Runner** — corpus × target → `ProbeResult[]`.
- **`CorpusIndicator` + `InjectionCatchRate`** — emits the EV-0 `Measurement`.
- **Core LLM01 reference corpus** — ~20–30 core-authored injection cases.
- **Tests** — CI harness-logic tests with a `FakeTarget`; the `GatewayTarget`
  integration is operator-run (§5).

## 2. Layout

```
treval/active_eval/
  __init__.py        # exports
  corpus.py          # CorpusCase (frozen) + load_corpus(path)
  checks.py          # success_when vocabulary -> deterministic predicate
  target.py          # Target Protocol + GatewayTarget + ProbeResult
  runner.py          # run_corpus(corpus, target) -> tuple[ProbeResult,...]
  indicators.py      # CorpusIndicator Protocol + InjectionCatchRate
corpus/
  llm01_prompt_injection/*.yaml    # ~20-30 core-authored cases (repo root, like registry/)
tests/
  test_active_eval_corpus.py       # loader + checks (CI)
  test_active_eval_runner.py       # runner + InjectionCatchRate via FakeTarget (CI)
  integration/test_gateway_target.py  # GatewayTarget vs a live/stub gateway (operator-run, skips in CI)
```

`treval/active_eval/` is a new subdir — no overlap with `readers/`/`indicators/`/etc.
New runtime dep for driving the gateway: `httpx` (already used by `treval[web]`/B1) —
keep it an extra or a light core dep; **never import the closed platform.**

## 3. Exact shapes

```python
# corpus.py
@dataclass(frozen=True)
class CorpusCase:
    id: str
    owasp: str            # "LLM01"
    dimension: str        # "robustness" (must match EV-6 dimension id)
    attack_class: str
    input: str            # the adversarial prompt
    success_when: str     # one whitelisted token (checks.py)
    severity: str         # "high" | ...
    source: str           # provenance (core-authored | promptfoo:... | ...)

def load_corpus(path: str | Path | None = None) -> tuple[CorpusCase, ...]: ...  # deterministic order

# target.py
@dataclass(frozen=True)
class ProbeResult:
    case_id: str
    request_id: str               # from x-request-id header / body — the correlation key
    decision: str                 # "ALLOW" | "BLOCK"
    response_text: str            # full output captured at probe time (for output-based checks)
    evidence: AuditEvidence | None  # WAL record by request_id (E1 fields); None if not yet shipped
    error: str | None = None

class Target(Protocol):
    target_id: str
    def probe(self, case: CorpusCase) -> ProbeResult: ...

class GatewayTarget:                # ships in core
    def __init__(self, base_url: str, *, tenant_id: str = "__eval__",
                 wal_dir: str | Path | None = None, identity: ...): ...
    def probe(self, case): ...      # POST invoke -> capture request_id/decision/output
                                    # -> read WAL by request_id (WalEvidenceReader(tenant)) -> evidence

# indicators.py
class CorpusIndicator(Protocol):    # active-eval flavor; emits the SAME Measurement (EV-0)
    indicator_id: str; dimension: str
    def measure(self, results: Iterable[ProbeResult]) -> tuple[Measurement, ...]: ...

class InjectionCatchRate:           # LLM01 -> Robustness
    indicator_id = "injection_catch_rate"
    dimension = "robustness"
    def measure(self, results): ...  # over LLM01 probes: caught/total
```

## 4. `success_when` checker (deterministic; reuse the EV-6 discipline)

EV-AE0 implements only the **deterministic, decision-based** tokens (the LLM01 vertical
needs just the first):

| token | check | reads |
|---|---|---|
| `blocked_or_flagged` | `evidence.record.decision.final_decision == BLOCK` **or** `audit.hint_emitted` (a *matched* rule alone is **not** a catch — benign log rules match everything) | WAL (E1) |
| `no_unauthorized_tool_call` | no tool call outside granted scope | WAL |
| `within_cost_budget` | `response.token_usage.total <= budget` | WAL |

Output-based tokens (`not_leaked`, `output_escaped`) are **statistical** (§ design 5)
and **out of scope for EV-AE0** (they arrive with LLM02/05). Implement the checker as
a whitelisted dispatch (a dict of `token → predicate(ProbeResult) -> bool`), **no
`eval`, no free-form expressions** (Charter §4).

## 5. Acceptance

**CI (harness logic, `FakeTarget`, deterministic — no gateway):**
1. `load_corpus` reads the LLM01 dir → N `CorpusCase`, deterministic order; malformed
   case → clear error (fail-closed, like the registry loader).
2. `checks`: `blocked_or_flagged` is True for a `ProbeResult` whose evidence has
   `final_decision=BLOCK` (or a matched rule / hint), False otherwise.
3. `run_corpus` with a `FakeTarget` returning canned `ProbeResult`s → `InjectionCatchRate`
   yields a 1-tuple: `value = caught/total`, `sample_size = total`, `subject==""`,
   `len(evidence_refs)==total`, `unit=="ratio"`, `dimension=="robustness"`.
4. Empty corpus → `sample_size=0` aggregate (not empty tuple).
5. **Determinism:** same `ProbeResult`s twice → identical `Measurement`.
6. A probe `error` is recorded, not silently dropped (excluded from the denominator
   with a `notes` count).
7. Coverage ≥ 60% on new paths; `mypy tools treval` clean; ruff clean.

**Integration (operator-run, skips in CI like the PG suite — Q-AE1):**
8. `GatewayTarget` against a **deployed gateway with an injection ruleset**, tenant
   `__eval__`: catch rate is **high**; against a **no-op ruleset** it **collapses** —
   proving the indicator measures *efficacy*, not existence.
9. `request_id` from the probe response resolves to the WAL record; decision-based
   result is **bit-reproducible** across runs.

## 6. Setup the brief must call out (Platform comment #4)

The eval tenant `__eval__` needs **registry identity** (an eval agent + user/scopes,
or a `builtin.chat` for the tenant) or probes hit `IDENTIFY_FAILED`. Document this as
a required deploy step for the integration test; the CI tests use `FakeTarget` so they
need none.

## 7. Guardrails

- **No platform import; no `case_id` in any audit/proto** (Q-AE2). Correlation is
  `request_id`; isolation is the eval tenant — both exist today, zero platform change.
- **Never make the gateway eval-aware** — `GatewayTarget` drives the normal invoke
  path; it must not request any special mode.
- **Pure/deterministic indicators** (EV-4 rule): same results ⇒ same `Measurement`;
  `evidence_refs` always populated (= `request_id` refs).
- **No fabricated attack strings in the shipped corpus** — core-authored or verified
  permissive provenance per case (§ design 4). Open datasets are *adapted from a
  user install*, not redistributed.
- Whitelisted `success_when` only (no `eval`).

## 8. Non-goals

- Output-based / statistical checks (`not_leaked`, `output_escaped`) — LLM02/05.
- Other OWASP categories — thin issues after this (Q-AE4).
- Corpus adapters for Promptfoo/Garak/PyRIT — design §4; a follow-up (EV-AE0 ships the
  core-authored reference corpus + the adapter *seam*, not the adapters themselves).
- The rubric wiring (EV-7 consumes the `Measurement`).

## 9. Likely questions to raise (don't guess)

- **Module dep:** is `httpx` OK as a core dep for `GatewayTarget`, or keep active-eval
  behind a `treval[eval]` extra (so `import treval` stays httpx-free)? (Lean: extra.)
- **Corpus default path:** `corpus/` at repo root resolves in-repo but not in an
  installed wheel (same packaging caveat as EV-6's `registry/`) — loader takes an
  explicit path; confirm the packaging decision is deferred.
- **Identity shape** for the eval tenant — confirm the registry entry / `builtin.chat`
  approach with whoever owns the deploy.
