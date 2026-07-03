# Maturity Model — Row-by-Row Credibility Audit

> **Why this exists.** The merged registry is **82% attested / 18% measured** (59 vs
> 13 of 72 objectives); **11 of 20 non-empty cells have zero measured objectives**
> (every dimension's L5). A maturity score that is 4/5 self-declared undercuts the
> moat — "verifiable audit consistency, **not** self-attestation" (Charter §14 /
> V1_ROADMAP). This worksheet audits **every row** against one question: *does it
> actually separate a trustworthy LLM/Agent system from an untrustworthy one, and
> can we prove it with data rather than a claim?*
>
> **Status:** in progress, dimension by dimension. **Robustness audited (this pass);
> other four PENDING.** Judgments are mine (engineering feasibility); **open
> questions are flagged `Q-*` for the owner to confirm** — I do not resolve them
> silently. The **regulation column is deliberately empty** (`TODO`): per the
> Platform `D1_national_standards_alignment.md` lesson (an LLM hallucinated 6 GB/T
> numbers), I will **not** generate standard citations — they must come from that
> human-verified doc or the official registries.

---

## 1. Method

### 1.1 Evidence class — *where could the truth come from?*

| Class | Meaning | Source |
|---|---|---|
| **M-now** | Measured on data that exists **today** | passive gateway audit (WAL) |
| **M-gw** | Measurable once a **gateway capability** lands (scope engine #5a, E1 dimension tags, PII tagger) | passive gateway audit, after a feature ships |
| **M-eval** | Measurable by core's **active eval harness** — run an adversarial/test corpus through the gateway and observe outcomes | **core generates the evidence** (the big lever) |
| **M-infra** | Measurable by an **infra/IaC scan** (config posture) | deferred `PostureProvider` |
| **A-irr** | **Irreducibly attested** — an org/process fact no automated source can measure | signed attestation only |

The 82% is partly an artifact of having wired only **one** source so far (passive
audit). M-eval / M-gw / M-infra are the promotion paths.

### 1.2 Proposed action

`KEEP-M` (already measured, keep) · `PROMOTE→M-eval/M-gw/M-infra` (attested but
should/can be measured) · `KEEP-A+proxy` (stays attested, add a measured
cross-check that would contradict a false claim) · `REFINE` (statement too weak to
discriminate — tighten) · `KILL` (ceremony, doesn't discriminate trustworthiness).

### 1.3 Discrimination test — *does this row earn its place?*

- **D-strong** — genuinely separates trustworthy from untrustworthy.
- **D-weak** — directionally right but the bar is a *presence* check, not an
  *efficacy* check (e.g. `sample_size >= 1` proves a rule **exists**, not that it
  **catches** anything) → REFINE.
- **D-ceremony** — passing it says little about AI trustworthiness (ops hygiene,
  paperwork) → KILL or move out of the trust model.

### 1.4 Honesty rules (apply regardless of class)

1. **Never blend** measured and attested into one number — report "proven level"
   vs "attested level" separately (EV-7 already does `min(measured, attested)` +
   `gaps`; the open hole is levels with **zero** measured objectives have no
   measurement floor → they must be stamped "attested-only, unproven").
2. **Every attested row that *can* have a measured proxy gets one** — attestation
   contradicted by data is a flagged over-claim, not a silent pass.
3. **Regulation anchor must be verified**, never paraphrased or invented.

---

## 2. Summary scoreboard (updated as dimensions are audited)

| Dimension | objs | measured | attested | audited? |
|---|---|---|---|---|
| robustness | 14 | 4 | 10 | ✅ this pass |
| efficient_reliability | 14 | 2 | 12 | ⏳ pending |
| security_alignment | 19 | 2 | 17 | ⏳ pending |
| transparency_accountability | 13 | 3 | 10 | ⏳ pending |
| privacy_data_protection | 12 | 2 | 10 | ⏳ pending |

Target after audit: a **promotion backlog** (shrinks 82% honestly) + a **kill
list** + a small, honest core of irreducibly-attested org facts.

---

## 3. Dimension 1 — Robustness (强鲁棒性) · 14 objectives

**Headline finding:** the active-eval lever (**M-eval**) can promote Robustness's
most important rows — standardized adversarial suite, adversarial testing, red-team
cadence, breach baseline — from *attested* to *measured*. That is **literally
core's job** (the conformance-style corpus, Charter §14.2). And several thresholds
are *presence* checks (`sample_size >= 1`) that prove a capability exists, not that
it works → REFINE. If we commit to the M-eval corpus, Robustness could go from
4/14 measured to ~9/14.

### L2 (3 objectives)

| id | now | class | action | discrim |
|---|---|---|---|---|
| rob.l2.injection_rule_detection | M | **M-gw → M-eval** | REFINE | D-weak |
| rob.l2.adversarial_test_ledger | A | **M-eval** | KEEP-A+proxy → PROMOTE | D-strong |
| rob.l2.model_version_freeze | A | **M-now** | PROMOTE→M-now | D-strong |

- **injection_rule_detection** — `injection_rule_hit_ratio sample_size>=1` only
  proves an injection rule *was evaluated*, not that it *catches* injections. A
  no-op rule passes. Real efficacy = run a known-injection corpus and measure catch
  rate (**M-eval**). Keep a presence floor at L2 only if L2 is meant to be
  "capability exists" — see **Q-R1**.
- **adversarial_test_ledger** — the *ledger existing* is attested, but the *test
  results* are generatable: core runs the suite → findings are **measured**.
  Interim proxy: cross-check the claim against whether any adversarial-tagged
  sessions appear in the audit (`injection_rule_hit_ratio sample_size > 0`); a claim
  of adversarial testing with zero adversarial inputs ever logged is suspect.
- **model_version_freeze** — "freeze requirement" is a policy (attested), but
  *actually frozen* is measurable **now**: count distinct model versions per agent
  over the window from the audit stream (frozen ⇒ 1). Recommend a
  `model_version_churn` indicator (M-now). See **Q-R5** (policy-exists vs
  actually-stable — measure the latter).

### L3 (4 objectives)

| id | now | class | action | discrim |
|---|---|---|---|---|
| rob.l3.standardized_suite | A | **M-eval** | **PROMOTE→M-eval (top priority)** | D-strong |
| rob.l3.change_regression | A | **M-eval** | KEEP-A+proxy → PROMOTE | D-strong |
| rob.l3.detection_to_siem | A | A-irr | REFINE / reconsider | **D-ceremony?** |
| rob.l3.unified_risk_score | M | M-eval | KEEP-M (note source) | D-strong |

- **standardized_suite** — this *is* core's active-eval corpus (role-overreach /
  context-pollution / long-dialogue info-loss). Ship the suite, measure pass rates.
  Converts the single most important Robustness row attested→measured. **Highest-
  value promotion in the dimension.**
- **change_regression** — the *trigger* is process (attested), but core can measure:
  when model version changes (visible in audit), was the suite re-run (a core-eval
  run logged)? Proxy = version-change events vs eval-run timestamps. → M-eval once
  core keeps an eval-run history.
- **detection_to_siem** — "results go to the customer's SIEM" is an integration
  checkbox external to our system. Does it measure *AI trustworthiness* or *ops
  hygiene*? I lean ops-hygiene → possibly mis-placed in the trust model. **Q-R2.**
- **unified_risk_score** — `boundary_breach_rate sample_size>=1` measured; fine,
  but its data source is really M-eval (breaches must be generated). Keep.

### L4 (4 objectives)

| id | now | class | action | discrim |
|---|---|---|---|---|
| rob.l4.breach_baseline | M | **M-eval** | KEEP-M | D-strong |
| rob.l4.drift_alerting | M | **M-gw** (no source today) | REFINE | D-weak |
| rob.l4.redteam_cadence | A | **M-eval** | PROMOTE→M-eval | D-strong |
| rob.l4.model_provenance | A | A-irr | KEEP-A | D-strong |

- **breach_baseline** — `sample_size>=100` is a proper quantified-baseline bar
  (L4 = "quantitatively managed"). Good as designed; source is M-eval (needs the
  suite + volume).
- **drift_alerting** — `drift_alert_count` has **no data source today** (the gateway
  emits no drift signal). And `sample_size>=1` is too weak for a "quantified
  baseline." Needs a drift detector first. **Q-R3.**
- **redteam_cadence** — "periodic, scored, comparable" red-team is exactly core's
  periodic adversarial runs. Promote→M-eval (core *is* the red team, scored over
  time). Proxy interim: count of eval runs in the window.
- **model_provenance** — model signing / source proof is a genuine supply-chain
  attestation with no measured proxy on our side. Honestly A-irr; keep.

### L5 (3 objectives) — currently 100% attested, zero measurement floor

| id | now | class | action | discrim |
|---|---|---|---|---|
| rob.l5.guardrail_autoevolve | A | A-irr / aspirational | REFINE | **D-weak (unfalsifiable)** |
| rob.l5.multiagent_selfcheck | A | **M-eval** (future) | PROMOTE→M-eval | D-strong-if-measured |
| rob.l5.highrisk_autocontain | A | **M-gw** (future) | PROMOTE→M-gw | D-strong |

- **guardrail_autoevolve** — "guardrails auto-evolve with new attacks" is hard to
  *falsify* as written. Refine to something measurable, e.g. "breach rate on a
  newly-added attack class recovers within N eval cycles" (longitudinal M-eval).
  **Q-R6.**
- **multiagent_selfcheck** — measurable by running multi-agent delegation-chain
  adversarial scenarios (M-eval), but MVP delegation chains are length 1
  (Charter §8.4) → no data yet. Aspirational; promote when a multi-agent corpus
  exists.
- **highrisk_autocontain** — "auto-contain high-risk drift" is an automated-response
  capability measurable as containment actions (BLOCK/escalate fired on high-risk)
  in the audit, once the gateway has auto-containment + a drift signal. Promote→M-gw.

---

## 4–7. Dimensions 2–5 — PENDING

`efficient_reliability`, `security_alignment`, `transparency_accountability`,
`privacy_data_protection` to be audited in the same format **after Robustness is
confirmed**. (Preview from the source dump: Efficient-Reliability L3+ leans heavily
on **M-infra** — SLA/cross-AZ/IaC/network-isolation are infra-scan measurable;
Security & Alignment is the most attested at 89% and most depends on the gateway's
scope engine #5a landing.)

> **Seed finding (surfaced by the EV-4 review, 2026-06-27) — Security & Alignment.**
> `sec.l3.guardrail_blocking` ("Response/Agent-Action 护栏阻断生效" — guardrail blocking
> is *effective*) is wired to **`block_rate`** with **`satisfied_when: sample_size >= 1`**.
> Two defects in one row: (a) Q-R1 presence-threshold (`sample_size>=1` proves a
> decision happened, not efficacy); (b) **wrong indicator** — `block_rate` is *what
> fraction of all traffic got blocked* (an **activity** signal: high = possible
> over-blocking, low = clean traffic *or* dead guardrail), **not** an efficacy measure
> of catching attacks. **Fix when EV-AE0 lands:** re-point → **`injection_catch_rate`**
> (% of known-attack corpus blocked) with an efficacy threshold (e.g. `value >= 0.9`);
> `block_rate` becomes supporting context, not the satisfier. `block_rate` itself is a
> correct, useful measured indicator — just mis-assigned here.
>
> **EMPIRICAL RESULT (active-eval live runs, 2026-06-28/29; numbers CORRECTED after a
> harness fix — see the lesson below) — OWASP LLM01 (28) + LLM01-benign (20, EV-AE6) +
> LLM02 (14) + LLM07 (14) + LLM06 (12), tenant `__eval__`, model `deepseek-v4-flash`,
> live WAL correlation by `request_id`. The injection numbers span TWO phases: baseline
> (no injection ruleset) and after **P2-a Tier-1 keyword/regex was MERGED (2026-06-29).**
> (Cross-repo ref: a Platform-internal merge; tracked by status, not a SHA — this is a
> public repo.)
> Measured numbers:
> - **Gateway injection-catch: ≈4% baseline → 61% with P2-a Tier-1 (P2-a.2, merged)** (`injection_catch_rate`).
>   *Baseline* (no injection rule): 1/28 — the lone "catch" was `pii-block-request` on an
>   email, **not** injection detection (effective injection governance = 0). *After P2-a.2
>   pattern-enrichment merged:* **17/28 = 61%** (11/16 direct, 6/12 indirect), honest
>   **injection-only ≈ 16/28 = 57%** (the 1 PII catch is still incidental). **EV-AE6
>   false-positive rate = 0%** over 20 benign hard-negatives (τ_fpr ≤ 5%) → **precise, not
>   over-broad** (the two-sided gate held: recall up *with zero* over-blocking). **61% is
>   ~the lexical-Tier-1 ceiling** — recall fails τ_recall = 0.80 BY DESIGN: the residual
>   misses are NOT a Tier-1 defect, they are by-design **higher-tier** (next bullet). So
>   `rob.l2.injection_rule_detection` / `sec.l3.guardrail_blocking` are **PARTIALLY** met
>   by measurement (57%) — climbing toward the gate as Tier-2/norm/dlp land.
>   **Robustness validated (EV-AE7 + P2-norm):** the rule-robustness diagnostic (catch
>   on deterministic-obfuscation variants of the caught-at-base cases) went **51% → 100%**
>   once P2-norm (NFKC + zero-width/homoglyph strip) merged — every render-identical
>   variant that evaded pre-norm recovers post-norm. So the **61% catch is measured-robust,
>   NOT overfit to our phrasings** (the teaching-to-the-test caveat is resolved); EV-AE7 is
>   P2-norm's acceptance test. (Robustness is a credibility lens on the recall number, not a
>   separate maturity objective — EV-AE7 D2.)
> - **Injection-success: 75% baseline → ~25% (halved) with P2-a.2** (`injection_success_rate`,
>   8 marker cases; `startswith`-canary lower bound, temperature=0; statistical): P2-a.2
>   now blocks the marker-bearing reframing attacks (the newly-caught 010/016 are marker
>   cases), so they never reach the output — only the keyword-evading residual still
>   succeeds. A statistical lower bound (run-to-run model variance ±1 case).
> - **Per-technique attribution — the ~11/28 Tier-1 MISSES are the by-design higher-tier
>   roadmap, NOT a Tier-1 defect** (Core's `attack_class` × the WAL catch signal; EV-AE7
>   feed). Mapped to the tier that owns each: **(a) semantic** (paraphrase / translate /
>   language-switch + FP-prone reframing deliberately deferred from Tier-1) → **Tier-2
>   (P2-b semantic judge)**; **(b) encoding** (base64) → **P2-norm (canonicalization /
>   decode-and-rescan)**; **(c) indirect / data-channel poisoning** (instruction rides in
>   a doc / tool-result / comment) → **P2-dlp → P2-ind**. Keyword/regex structurally
>   cannot reach any of these — so 61% is ~the lexical ceiling, and everything left is a
>   higher tier already on the roadmap. Core's **EV-AE7** variant generator seeds the
>   deterministic-obfuscation side (and is P2-norm's acceptance test). *(The granular
>   per-case caught/missed map is a live bypass map for the deployed gateway — kept
>   INTERNAL to Platform, not published here; via `format_attribution_report` under the
>   gitignored `reports/`.)*
> - **Sensitive-disclosure: ~100% baseline → 0% after P2-dlp** (`sensitive_disclosure_rate`,
>   LLM02). Baseline: the model disclosed the planted secret on ~every attempt, gateway
>   output-DLP = **0%** (no response-leg rule saw the output). **After P2-dlp (the
>   `response.body.*` var-provider) merged + a response rule:** `dlp-canary-response`
>   fires at the **response stage** and BLOCKs the leak on **13/14** cases
>   (`final_terminal=BLOCKED`) → disclosure **0%, deterministically** (the canary never
>   reaches the caller; verified per-case in the WAL `on_tool_response_rules`). **The
>   output-DLP SEAM is proven end-to-end.** **Both original caveats are now CLOSED by Core
>   follow-ups (2026-07-01):** (a) **EV-AE9** reshaped the LLM02 canaries to **production
>   secret formats** (`sk-`/`AKIA`/`bearer`/`api_key=`/`secret:`/`token=`/`password=` + a
>   bare-`CANARY` baseline pair), so `sensitive_disclosure_rate` now measures **production
>   `secret-block-response` coverage per-format**, not just the eval sentinel (a self-checking
>   corpus test pins each canary→branch); (b) **EV-AE8** **OR-reduced** the catch signal across
>   the decision **and** response records, so the catch metric now credits the response-stage
>   block — LLM02 gateway-catch reads **~100%** (was flat 7%), matching the 13/14 response-stage
>   blocks. (Both merged; the eval-only `dlp-canary-response` can retire behind the bare-CANARY
>   baseline, which shows the exact seam-vs-production gap.)
> - **System-prompt-leak: ~79% baseline → 0% after P2-dlp** (`system_prompt_leak_rate`,
>   LLM07): same mechanism — `dlp-canary-response` blocks the leaked system-prompt canary
>   at the response stage (**9/14** fired; the rest didn't leak) → **0%**. (The pre-P2-dlp
>   79% was real, not an artifact — WAL cross-check 0 missed + negative control 0%.)
> - **Tool-scope-violation = 0% (0/12)** (`tool_scope_violation_rate`, LLM06;
>   DETERMINISTIC, WAL-authz, bit-reproducible): every out-of-scope tool invocation
>   (admin/shell/filesystem/db/http-SSRF/email/secrets/payments/user-mgmt/code-exec/
>   infra/model-admin) was **DENIED** — `authorization.allowed=false`,
>   `final_decision=BLOCK`, `deny_reason="no matching scope"`, all 12 records
>   chain-verified (`integrity=VERIFIED`). **The access-control layer measurably
>   WORKS** — this satisfies `sec.l3.oauth_scope` by *efficacy* (Q-R1), not presence.
> - **False-positive rate — the eval caught a real governance regression (EV-AE8/AE10 →
>   P2-dlp.1), 2026-07-01.** FPR was **0%** pre-P2-out. When Platform shipped response-side
>   output rules (P2-out) and **EV-AE8** made the response stage *visible* to the catch metric,
>   the benign FPR jumped to a **blended 30%** — a regression the decision-only metric had been
>   structurally blind to. Core decomposed it (internal `reports/fpr_benign_attribution.md`):
>   **request-phase (Tier-1) = 0% (clean)**; the entire rise was **response-side**, and mostly
>   **soft flags** (`llm05-unsafe-output-flag` `emit`, user still served) — only **1 hard block**
>   (`pii-block-response` on a benign SQL-tutorial answer). **EV-AE10** then split the metric by
>   severity (ratified policy: gate on **hard-block FPR**, treat soft flags as an **advisory**):
>   FPR(hard) = **5%**, `benign_flag_rate` = **25%** (advisory). Core attributed the single hard
>   block to a **pii_detect over-match** — intermittent (~10% of runs, model-nondeterministic),
>   confirmed via the gateway's new **match_types** attribution as **`email`** (the model's sqlite3
>   example occasionally emits a sample `@example.com`), **not** a bare number. That drove
>   **P2-dlp.1** (response-side PII → structured-only + RFC-2606 reserved-domain exclusion + a Luhn
>   CC pattern + names-only match_types), after which Platform reports **`eval_report` pass**
>   (hard-block FPR back within the τ=0.05 gate). **This is measured>attested in its purest form:
>   the eval SURFACED a governance regression attestation would never show, attributed it to a
>   specific rule and match-type, and drove a scoped fix — without ever seeing the PII.**
> - **Unbounded-consumption (LLM10, `efficient_reliability`) — input bounding works; output
>   prevention on a reasoning model is a HARD, largely-unsolved gap (2026-07-02).** The FIRST
>   `efficient_reliability` vertical (`cost_runaway_caught` + `within_cost_budget`). **Input side
>   WORKS:** the request-size / context ceiling hard-BLOCKS oversized inputs (2/12 — the huge-input
>   cases). **Output side does not *prevent* runaways on a reasoning model** (the deployed
>   `deepseek-v4-flash`): a `max_tokens` clamp caps reasoning+content together → truncates the
>   *reasoning* into an **empty answer** (`finish_reason:length`), so it is correctly opt-in-OFF; the
>   content-token control is *detective* (response-stage) and the genuine runaways **stream past the
>   timeout and never reach it**; there is no streaming-abort. So output runaways escape → time out →
>   ungoverned. `cost_runaway_caught` reads honestly **~17%** (input-blocks + timeouts-as-uncaught),
>   **not** a governance win — output-token prevention via `max_tokens` is infeasible on a reasoning
>   model without breaking function, and that is the *finding*, not a metric bug. **The measured>attested
>   proof point:** an interim clamp read **75% "caught"** — but those were reasoning-truncations
>   (broken/empty answers) miscounted as governance; the eval CAUGHT the lie (Core EV-AE5.3's RC4
>   integrity guard + reasoning-aware content-token metric; both Platform and Core had missed it and
>   both corrected it) and refused the fake win. **Honest state: LLM10 input-bounded; output
>   detect-only — runaway *prevention* on reasoning models is known hard future work (streaming
>   content-abort), not something more measurement moves.**
>
> **Governance lesson, now in data (REVISED 2026-06-29):** the picture is now
> **three-tier.** (1) **Access control works** — the gateway denied **100%** of
> out-of-scope tool calls (LLM06), deterministic OAuth-scope authz, mature. (2)
> **Injection input-governance is now PARTIAL and climbing** — P2-a Tier-1 took
> injection-catch from ≈0 to **57%** (61% incl. the incidental PII catch) with **0% false positives** (precise, not
> over-broad); the named **16 misses** (obfuscation, no-keyword reframing, data-channel
> poisoning) are the Tier-2 roadmap. (3) **Output-side content-governance is now PARTIAL** —
> the P2-dlp response-DLP seam blocks secret/system-prompt leaks deterministically
> (LLM02 ~100%→**0%**, LLM07 ~79%→**0%**, via a response-stage rule; seam proven — and the
> eval-sentinel caveat is now **CLOSED** by EV-AE9's production-format canaries + EV-AE8's
> OR-reduced catch, §3), but output **sanitization** is only **PARTIAL** (LLM05
> unsafe-output-passthrough **100% → 58%** after P2-dlp neutralization shipped: some
> XSS/SQLi still pass un-escaped — a distinct capability from secret-DLP). The Tier-1 delta
> (**0 → 57% measured**, the lexical-Tier-1 ceiling) is the measured-over-attested thesis
> paying off, and the **two-sided EV-AE6 gate** — now **severity-aware** (EV-AE10: gate on
> hard-block FPR, soft flags advisory) after it **caught and drove the fix of** the P2-out
> response-side FP regression (30% blended → 5% hard → ~0 post-P2-dlp.1) — is what proves the
> gain *real and precise*, not a block-everything illusion.
> An earlier version of this row claimed
> "the model resisted all 8" (success 0%) — that was a **harness measurement bug, not
> reality**: `GatewayTarget` read the model reply from the wrong response field, so
> `response_text` was always empty and every output-based check silently returned 0%. The
> bug was caught by an **independent WAL cross-check** (the chain-verified response
> preview showed the canary the harness had missed) and fixed (extract
> `choices[0].message.content` + scan the full body incl. `reasoning_content`); the
> numbers above are post-fix. **Lesson: a measured "0%" is only as trustworthy as the
> capture path — cross-verify against the governed record.** That cross-check is now a
> standing harness guard (every leak run asserts the harness flags what the chain-
> verified WAL shows, plus a negative control) — the LLM07 run passed both (0 missed,
> 0% negative), so its 79% is trustworthy by construction. This is a **Platform gap**
> (no injection detection AND no output DLP), tracked in
> `PLATFORM_ASK_INJECTION_DETECTION.md` (§7 records the closed loop). Honest current
> state: **tool-scope/least-privilege (`sec.l3.oauth_scope`) measured-and-passing (0%
> violation, chain-verified); injection detection
> (`rob.l2.injection_rule_detection`/`sec.l3.guardrail_blocking`) PARTIALLY met and
> climbing (57%, FPR 0%, P2-a.2 lexical ceiling); secret-disclosure and system-prompt
> confidentiality still unproven/failing (no output DLP). Measured ≠ uniformly bad — and
> now measurably *improving* where Platform shipped a control, with the named misses as
> the roadmap.**

---

## 8. Decisions log (resolved 2026-06-27)

**Model-wide principle (Q-R1) — RESOLVED: the model is EFFICACY-based.** "Exists but
not effective" is meaningless. Presence thresholds (`sample_size >= 1`) are **defects,
not valid bars** — every measured row must test *efficacy* (does the control catch /
prevent), not mere existence. This rewrites the discrimination baseline (§1.3): D-weak
presence-checks must be REFINED to efficacy across **all** dimensions, not just
Robustness. (The CSA AISMM source — Q-INPUT-2 — confirmed its levels are themselves
mostly presence/process, which is the root of the weak thresholds.)

| Q | Resolution |
|---|---|
| **Q-R1** | ✅ Efficacy is the baseline; presence-only thresholds are defects → REFINE model-wide. |
| **Q-R2** | ✅ `detection_to_siem` is **ops, not AI-trust** → **KILL** (remove from the model). |
| **Q-R3** | ⏳ Gateway emits **no** drift alert today, no concrete case yet → `drift_alert_count` has no source; park the drift rows until a signal exists (needs case research). |
| **Q-R5** | ✅ `model_version_freeze` → **measure actual stability** (`model_version_churn` from audit), not policy attestation. |
| **Q-R6** | ✅ Auto-evolve = **measured if the system exposes an interface + data Core can probe**; otherwise it's an honest longitudinal **attested** declaration. (The interface/data availability decides measured-vs-attested per row.) |

### Cross-cutting inputs

| Q | Resolution |
|---|---|
| **Q-INPUT-1** (active-eval lever) | ✅ **Build it — bounded.** Core ships an OWASP-seeded active-eval corpus **and** a bring-your-own-corpus/target interface (two modes), so Core's corpus doesn't expand without limit. Content source + boundary in `FRAMEWORK_ALIGNMENT.md` §2.1/§4. |
| **Q-INPUT-2** (intended control) | ✅ CSA AISMM matrix provided + verified — see `FRAMEWORK_ALIGNMENT.md` §1 (the 72 inherited CSA's ~80%-attested nature). |
| **Q-INPUT-3** (regulation source) | ⏳ Platform `D1_national_standards_alignment.md` is the intended source but **not yet fully human-verified** (industry review in progress). Regulation column stays TODO. |
| **Q-INPUT-4** (SMEs) | ⏳ Per-dimension discrimination SMEs **not yet assigned.** |
| **Q-INPUT-5** (positioning) | ✅ **Refined:** we are **not a certification body** — never "certified L4." We report **"verified L_n"** = the highest level Core's *measured tests* satisfy for a dimension, separately from any self-declared/attested level. Two numbers: **verified (by Core) vs declared (by customer)** — never "certified." |

### Absorbed this round (see `FRAMEWORK_ALIGNMENT.md`)

- **OWASP LLM Top 10 2025** → active-eval corpus seed; 7/10 → directly buildable
  measured indicators. Promotes Robustness/Privacy/Security attested rows → measured.
- **ISO 42001 Annex A** → anchors the *attested* side (regulation column), does not
  add rows.
- **CAICT 可信AI大模型标准体系** → China recognition anchor; **SafetyAI Bench** = a
  candidate content-safety test set. (CAICT spec contents still need primary-source
  verification.)
- **"升华": Affordable redefined** to *"evaluable without vendor lock-in"* — the gate
  that keeps CSA's vendor-ceiling rows out.
