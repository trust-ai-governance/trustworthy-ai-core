# Framework Alignment — CSA AISMM verification + OWASP / ISO 42001 / CAICT absorption

> **Purpose.** (1) Verify the claim that our 72 control objectives were borrowed from
> **CSA AISMM** but lack operationality. (2) Decide how to absorb three public
> frameworks — **OWASP LLM Top 10**, **ISO/IEC 42001**, **CAICT 可信AI** — into the
> 5-dimension model *within the operationality test*: a row earns its place only if
> it is **evaluable with open tools (no vendor product) and discriminates
> trustworthiness**. Pairs with `MATURITY_ROW_AUDIT.md`.
>
> **Verification discipline (D1 lesson).** Framework *orientation* below is verified
> against the cited sources. **Exact clause/standard IDs and CAICT spec contents are
> NOT reconstructed from memory** — where a specific number matters it is cited to a
> source URL; CAICT spec *contents* are marked "orientation-verified, contents need
> primary-source confirmation."

---

## 1. CSA AISMM cross-check — the operationality gap is real, and inherited

CSA AISMM (poster, © 2026 Cloud Security Alliance) = **12 categories × 5 levels**
(Initial / Repeatable / Defined / Capable / Efficient), in three domain groups:

- **Foundational:** Governance · Organization Management · IAM · Security Monitoring
- **Structural:** Infrastructure Security & Resilience · Model Security · App Security · Data Security
- **Procedural:** Risk & Provider Assessment · AI Dev & Supply Chain · Privacy/Compliance/Audit · Incident Response

Our 5 dimensions mirror this structure (the original `MATURITY_MODEL.md` mapped each
to "CSA 等效控制项"). **Reading the actual L3–L5 cells, CSA is dominated by two
non-operational kinds of content:**

- **Vendor tooling** (the "budget ceiling"): AI-SPM, CSPM, CNAPP, CASB, EDR, **SOAR**,
  SIEM, **AI-CAIQ**, **AICM**, **AI-BOM**, policy-as-code, ZTA, confidential computing.
- **Org/process** (attestation): AI Council, CoE, ethics review board, deployment
  registries, role-based training, named owners, IR playbooks, treatment plans.

The **operationally testable** content sits in only **3 of 12 categories** — **App
Security · Data Security · Model Security** (prompt-injection handling, I/O
validation, guardrails, adversarial / red-team testing, cross-context denial test,
PII filtering, poisoning scanning, drift monitoring). That subset is **exactly OWASP
LLM Top 10 territory.**

### 1.1 The precise diagnosis (sharper than "not operational")

Our 72 didn't pick the *wrong* CSA cells. The failure is subtler and twofold:

1. **Testable concepts transcribed as attestations.** "Standardized adversarial
   suite," "red-team cadence," "adversarial test ledger" are *measurable* (run the
   test) but we recorded them as `attested` posture keys instead of building the
   test. **OWASP + active-eval converts these attested→measured.**
2. **CSA's heavy governance/vendor weighting inherited wholesale.** ~8 of 12 CSA
   categories are governance/process/vendor — so a faithful transcription is ~80%
   attested *by construction*. That is the root of our 82%.

**Fix:** (a) build the tests (OWASP-seeded active eval) for the testable concepts;
(b) prune or honestly relabel the vendor/process cells (the "leave in vendor PPT"
set — SOAR/AI-SPM/CASB do not belong in an *open, operational* eval); (c) anchor the
irreducibly-attested org facts to ISO 42001 / 管理办法 / CAICT rather than CSA.

| CSA category | → our dimension(s) | operational? |
|---|---|---|
| App Security | Robustness, Security & Alignment | **YES — OWASP/active-eval** |
| Data Security | Privacy, Robustness | **YES — OWASP/active-eval** |
| Model Security (testing parts) | Robustness | **YES — active-eval**; signing/provenance = attested |
| IAM | Security & Alignment | partial — scope-deny measurable; JIT/MCP/policy-as-code = config/attested |
| Security Monitoring | Transparency/Accountability | audit-trail integrity = measurable (our moat); SIEM/SOAR = ops/vendor |
| Infrastructure Security & Resilience | Efficient Reliability | M-infra (IaC/network/cross-AZ scan); ZTA/confidential-compute = vendor |
| Governance / Org Mgmt | Transparency/Accountability | **attested org facts** (AI Council, registries) → ISO 42001 anchor |
| Risk & Provider / AI Dev & Supply Chain / Privacy-Compliance-Audit / Incident Response | cross-cutting | mostly **vendor/process — candidates to prune** |

---

## 2. Absorption decision — three frameworks onto the existing measured/attested split

**No 6th dimension** (confirmed). Each framework lands on a part of the architecture
we already have:

### 2.1 OWASP LLM Top 10 → the MEASURED substance (active-eval corpus seed)

Source (verified): OWASP Top 10 for LLM Applications **2025**. The ten entries are
**testable attack classes**, so each becomes a measured indicator via active eval —
run a corpus through the gateway, observe outcomes. This is the concrete content for
the active-eval harness.

| OWASP 2025 | → dimension | measured indicator (active-eval) | buildable? |
|---|---|---|---|
| **LLM01 Prompt Injection** | Robustness / Security | `injection_catch_rate` (% of injection corpus blocked/flagged) | **yes (priority)** |
| **LLM02 Sensitive Info Disclosure** | Privacy | `sensitive_disclosure_rate` (seeded-canary leakage %) | **yes** |
| **LLM05 Improper Output Handling** | Security & Alignment | `unsafe_output_passthrough_rate` | **yes** |
| **LLM06 Excessive Agency** | Security & Alignment / Transparency | `tool_scope_violation_rate` (unauthorized tool calls under over-reach tasks) | **yes** (joins audit scope-deny) |
| **LLM07 System Prompt Leakage** | Privacy / Robustness | `system_prompt_leak_rate` | **yes** |
| **LLM08 Vector/Embedding Weaknesses** | Privacy / Robustness | `rag_poisoning_resistance` (adversarial-doc hijack %) | yes if RAG in scope |
| **LLM10 Unbounded Consumption** | Efficient Reliability / Affordable | `cost_runaway_caught` (recursive/long-input guardrail) | **yes** |
| **LLM03 Supply Chain** | Security & Alignment | mostly **attested** (model/plugin provenance) + SBOM proxy | attested |
| **LLM04 Data/Model Poisoning** | Robustness / Privacy | training-side = **out of runtime scope**; RAG-poisoning ⊂ LLM08 | partial |
| **LLM09 Misinformation** | Robustness / Transparency | needs ground truth — `factuality_error_rate` on a labeled set | hard |

**7 of 10 are directly buildable** as active-eval indicators → this is the path from
Robustness 4/14 measured toward ~9/14, and it lifts Privacy and Security too.

**Corpus content sources (open, to pull concrete prompts from — verify before use):**
OWASP's own materials, and open red-team tooling the OWASP ecosystem points to —
**Promptfoo**, **Garak**, **PyRIT** (well-known open red-team frameworks; the user
named Promptfoo). We seed the corpus from these rather than authoring attack strings
from scratch. *(The improving.com summary did not name tools; the official OWASP GenAI
red-teaming guide does — confirm the current tool list at the OWASP source.)*

### 2.2 ISO/IEC 42001 → the ATTESTED structure (governance legitimacy, not measurement)

Source (verified): ISO/IEC 42001:2023, **Annex A = 38 controls across 9 objectives
(A.2–A.10): AI policy, internal organization, resources, impact assessment, AI system
lifecycle, data, information for interested parties, responsible use, third-party
relationships.** Objective-based (you decide how to meet them), process-oriented.

⇒ ISO 42001 is **inherently attestation** — it maps onto our `A-irr` org-fact rows
(AI Council, asset ownership, risk process, transparency management). **Use it to
*anchor and structure* the attested side** (the `regulation_reference` column), **not
to expand it.** It is the vendor-neutral *international* anchor; it never says "buy a
product." Do **not** absorb it as new rows.

### 2.3 CAICT 可信AI → China-market recognition + an operational test set

Source (verified, orientation): CAICT **可信AI大模型标准体系 ("四横一纵")** — four
horizontal tracks (模型开发 / 模型能力 / 模型运行 / 模型应用) + one vertical
(安全可信), **with maturity levels** (e.g. model-development track: 4 domains / 16
sub-domains / 60+ items / five maturity levels). Governance-and-maturity oriented —
the closest China analogue to our model, and the **金融/央国企 recognition anchor**.

Two adjacent CAICT assets, with a sharp boundary:
- **SafetyAI Bench** — a **content/values test set** (27 dimensions: 正确价值观 /
  法律合规 / 隐私保护 / 文明健康 / AI自主意识 …). **Operational** — a candidate input
  to the active-eval corpus for the content-safety parts of Robustness / Privacy /
  Alignment.
- ⚠️ **"安全大模型能力要求与评估方法"** — this is **Security-*through*-AI** (LLMs doing
  malware/intrusion/pentest detection). **NOT our domain** (we are *Security-of-AI*;
  PHASE1_PLAN §3 explicitly excludes Security-through-AI). Do not absorb.

**CAICT caveat:** orientation is source-verified; the **exact spec names/numbers and
item contents need primary-source confirmation** before any citation. CAICT is where
I am least able to verify detail — treat its specifics as TODO, like the regulation
column.

---

## 3. The "升华" — Affordable becomes the anti-vendor-lock-in gate

Encode the user's "别给厂商送钱" insight as a **structural model principle**, not a
comment: redefine the cross-cutting **Affordable** axis from "token cost" to
**"evaluable without vendor lock-in."** It becomes the explicit gate on every row:

> A row may enter the model only if its evidence is obtainable with **open tooling /
> the customer's own data / our active-eval harness** — never *only* by purchasing a
> named vendor product (AI-SPM, SOAR, CASB, AI-CAIQ tooling …).

This is what structurally keeps the CSA "budget ceiling" out and the OWASP "open
tools" in — and it is the Core repo's reason to exist.

---

## 4. Active-eval corpus — design seam (bounded, per Q-INPUT-1)

Q-INPUT-1 confirmed: build the active-eval harness, **but bound it** with a pluggable
interface so Core's own corpus doesn't expand without limit:

- **Built-in seed corpus** — OWASP-derived (§2.1), shipped in core as the
  conformance-style fixture set (mirrors `trustworthy_ai_conformance`).
- **External eval-object/data interface** — a seam (like `Indicator` / `PostureProvider`)
  so a customer or third party plugs in *their own* test set / target without us
  absorbing it. Core measures; it does not own every corpus.

Two modes coexist (Core-run active eval **and** bring-your-own-corpus), which caps
Core's maintenance surface. Detailed design = a later issue (the V-eval workstream);
this doc fixes the **content source** (OWASP) and the **boundary** (seam).

---

## 5. Verification status & sources

| Item | Status | Source |
|---|---|---|
| OWASP LLM Top 10 2025 (LLM01–10) | ✅ verified | OWASP GenAI project (PDF v2025) + practitioner summary |
| OWASP red-team tools (Promptfoo/Garak/PyRIT) | ⚠️ named-but-confirm at OWASP source | OWASP GenAI red-teaming guide |
| ISO 42001 Annex A (38 controls / 9 obj) | ✅ verified (orientation + counts) | multiple ISO-42001 control guides |
| CAICT 可信AI大模型标准体系 "四横一纵" + maturity levels | ✅ orientation; ⚠️ spec contents TODO | CAICT / 安全内参 summary |
| CAICT SafetyAI Bench (27 dims) | ✅ orientation; ⚠️ dataset contents TODO | 安全内参 / CAICT |
| CAICT "安全大模型能力要求" = Security-through-AI (excluded) | ✅ verified boundary | 安全内参 |
| CSA AISMM 12×5 matrix | ✅ have the source poster | CSA AISMM poster 2025 |

**Sources:**
- [OWASP Top 10 for LLM Applications 2025 (official PDF)](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
- [OWASP LLM Top 10 — practitioner summary (Improving)](https://www.improving.com/thoughts/owasp-top-10-llm-security-guide/)
- [ISO 42001 Annex A controls overview (ISMS.online)](https://www.isms.online/iso-42001/annex-a-controls/)
- [CAICT 可信AI大模型标准体系 (一文读懂, 安全内参)](https://www.secrss.com/articles/56467)
- [CAICT《安全大模型能力要求与评估方法》系列规范 (安全内参) — out-of-domain reference](https://www.secrss.com/articles/68188)

---

## 6. What this changes in the row-audit (next pass)

- **Robustness:** `adversarial_test_ledger`, `standardized_suite`, `change_regression`,
  `redteam_cadence` → **promote to M-eval (OWASP LLM01 corpus)**.
- **Privacy:** add OWASP LLM02 (`sensitive_disclosure_rate`) / LLM07
  (`system_prompt_leak_rate`) measured indicators.
- **Security & Alignment** (89% attested — worst): OWASP LLM05/LLM06 give it real
  measured indicators (`unsafe_output_passthrough_rate`, `tool_scope_violation_rate`).
- **Efficient Reliability:** OWASP LLM10 (`cost_runaway_caught`) + M-infra (IaC scan)
  for the SLA/cross-AZ rows.
- **Prune candidates:** CSA-inherited vendor/process rows (SIEM/SOAR integration,
  AI-SPM discovery) fail the §3 Affordable gate → relabel attested or remove.
