# Trustworthy-AI Maturity Model — 5 dimensions × 5 levels (authoring source)

This is the **ratified content source** for the EV-6 Dimension Registry YAMLs. It is
data/spec, not code. EV-6 transcribes the control objectives here into
`registry/dimensions/*.yaml` — **do not invent objectives; transcribe from this
file.** Structure aligns with CSA AISMM control domains; the 5 dimensions are the
trustworthy-AI engineering dimensions (Wittgenstein-informed, engineering-scoped).

Pairs with: `docs/EVAL_ARCHITECTURE(WIP).md` §2.3 (registry shape) + §1
(measured ∪ attested), `docs/issues/EV-6.md`.

## How EV-6 uses this

- Each **dimension** → one YAML (`dimension:` = the stable id below).
- Each **level L1–L5** → `control_objectives: [...]`. **L1 is the baseline state
  (no controls in place) → `control_objectives: []`** for every dimension (you are at
  L1 by default; nothing to satisfy).
- Each objective is **`measured`** (mapped to a runtime indicator + `satisfied_when`)
  or **`attested`** (mapped to a `posture_key`, evaluated against `PostureEvidence`).
- **Most objectives are `attested`** — SSO, IaC, red-team cadence, AI Council, model
  signing are things telemetry cannot see (PHASE1_PLAN §4). Only a handful map to
  measured indicators; those are flagged below with the indicator id.
- `posture_key` convention: `"<dimension>.<snake_key>"`.

## The 5 dimensions (stable ids)

| id | name | one-line |
|---|---|---|
| `robustness` | Robustness 强鲁棒性 | resist adversarial/noise/OOD; keep reference-point constancy in long dialogue |
| `efficient_reliability` | Efficient Reliability 高效且可靠 | LB / parallelism / low-latency; graceful degrade, no loss/dup on node failure |
| `security_alignment` | Comprehensive Security & Alignment 全域安全与价值观对齐 | guardrails, zero-trust, supply-chain; strict instruction-following, no manipulation/bias |
| `transparency_accountability` | Transparency, Control & Accountability 透明可控可问责 | explainable + human-in-loop control + complete audit closed-loop |
| `privacy_data_protection` | Privacy & Data Protection 隐私与数据保护 | minimization, data-no-egress, conversation isolation; an independent security sub-domain |

## The 5 levels

`L1 偶发 (Initial)` · `L2 可重复 (Repeatable)` · `L3 标准化 (Standardized)` ·
`L4 量化管理 (Quantitatively Managed)` · `L5 优化 (Optimizing)`.

## Cross-cutting (NOT dimensions)

- **Affordable 普惠可负担** — a *ruler* across all dimensions (Token/compute cost as a
  constraint on every engineering choice). Surfaces as cost indicators **inside**
  other dimensions (e.g. `token_cost_per_agent` under efficient_reliability), **not**
  a 6th dimension / its own YAML.
- **领域有效 (domain effectiveness)** — per NIST AI RMF this is *base model
  performance* (MAP), distinct from deployment-time trustworthiness governance
  (GOVERN/MEASURE/MANAGE). **Out of scope** for this maturity model.

---

## Master 5×5 table (condensed)

| L | Robustness | Efficient Reliability | Security & Alignment | Transparency/Accountability | Privacy & Data Protection |
|---|---|---|---|---|---|
| **1** | no adversarial test; no drift monitoring; trivial injection breaks through | single point, no redundancy, manual restart, no asset control | no guardrails; shared human creds; no AI identity | no logging; no AI asset inventory; decisions untraceable | no classification; plaintext storage; no PIA |
| **2** | basic adversarial test on high-risk models; problem ledger; version freeze; prompt-injection rule-level (kw/regex) | basic capacity monitoring; recovery runbook; train/inference logical isolation | SSO+MFA; independent NHI; initial risk assessment; AI incident-response plan; acceptable-use policy | AI asset discovery & ledger; RAG/vector/log min retention; documented procurement/launch approval owner | basic sensitive-data discovery & redaction (regex/NER); retention+deletion process; PIA trigger conditions |
| **3** | standardized adversarial suite (role-overreach, context-pollution, long-dialogue info-loss); change→regression; unified overreach risk scoring | LB + auto-failover + health-check, SLA≥99.5%; IaC provisioning; train/inference network isolation | MCP/Tool OAuth + fine-grained scope; agent↔user dual-identity chain; Prompt/Response/Agent-Action → SIEM; model version pin + supply-chain inventory; CI/CD security checks | authoritative AI deployment registry; full-chain traceability; AI Council/CoE; role-based AI training | full-lifecycle standardized protection; conversation user-level isolation; minors special protection |
| **4** | breach-rate / abnormal-session / drift-alert quantified baseline; red-team drills scored & comparable; model signing & provenance | SLO baseline quantified (latency/success/elasticity); fault-injection drills institutionalized; cross-AZ redundancy | continuous mediation & posture mgmt of agent tool calls; central AI gateway for prod traffic; model signing & provenance; compliance evidence auto-collected | behavior-telemetry ⟂ runtime-intervention decoupled; cross-code/cloud/endpoint full-view decision trace; domain-trust quantified baseline | quantified privacy risk metrics (re-id rate / leak blast-radius / non-consent violation); periodic PIA reports; low privacy risk verifiable |
| **5** | guardrails auto-evolve with new attacks; multi-agent delegation-chain robustness self-check; high-risk drift auto-containment | dynamic workflow/resource adaptation; predictive scaling; auto-remediation runbooks | JIT ephemeral creds; multi-agent delegation-chain validation; guardrails auto-evolve; high-risk event auto-containment | human-AI co-evolution loop (intervention feeds back to decision framework); governance evidence & exception auto-flow | user data sovereignty (view/export/delete); verifiable unlearning within bounded time; minors guardian decision UI |

---

## Per-dimension objectives (the EV-6 authoring detail)

Format: `id` · statement · **kind** · indicator/`posture_key`. `satisfied_when` shown
for measured (over a `Measurement`'s `value`/`sample_size`). L1 = `[]` for all.

### robustness

**L2**
- `rob.l2.injection_rule_detection` · prompt-injection rule-level detection (kw/regex) · **measured** · `injection_rule_hit_ratio`, `satisfied_when: "sample_size >= 1"`
- `rob.l2.adversarial_test_ledger` · basic adversarial test on high-risk models + problem ledger · **attested** · `robustness.adversarial_test_ledger`
- `rob.l2.model_version_freeze` · model version freeze requirement · **attested** · `robustness.model_version_freeze`

**L3**
- `rob.l3.standardized_suite` · standardized adversarial suite (role-overreach / context-pollution / long-dialogue info-loss) · **attested** · `robustness.adversarial_suite_standardized`
- `rob.l3.change_regression` · model change triggers adversarial regression · **attested** · `robustness.change_triggers_regression`
- `rob.l3.detection_to_siem` · detection results into SIEM · **attested** · `robustness.detection_to_siem`
- `rob.l3.unified_risk_score` · unified risk scoring for overreach behavior · **measured** · `boundary_breach_rate`, `satisfied_when: "sample_size >= 1"`

**L4**
- `rob.l4.breach_baseline` · breach-rate / abnormal-session / drift quantified baseline · **measured** · `boundary_breach_rate`, `satisfied_when: "sample_size >= 100"`
- `rob.l4.drift_alerting` · drift alerting in the quantified baseline · **measured** · `drift_alert_count`, `satisfied_when: "sample_size >= 1"`
- `rob.l4.redteam_cadence` · red-team periodic drills, scored & comparable · **attested** · `robustness.redteam_cadence`
- `rob.l4.model_provenance` · model signing & source provenance · **attested** · `robustness.model_provenance_signing`

**L5**
- `rob.l5.guardrail_autoevolve` · guardrails auto-evolve with new attacks · **attested** · `robustness.guardrail_autoevolve`
- `rob.l5.multiagent_selfcheck` · multi-agent delegation-chain robustness self-check · **attested** · `robustness.multiagent_chain_selfcheck`
- `rob.l5.highrisk_autocontain` · high-risk drift auto-containment · **attested** · `robustness.highrisk_autocontain`

### efficient_reliability

**L2**
- `rel.l2.capacity_monitoring` · basic capacity monitoring · **attested** · `efficient_reliability.capacity_monitoring`
- `rel.l2.recovery_runbook` · written failure-recovery runbook · **attested** · `efficient_reliability.recovery_runbook`
- `rel.l2.train_infer_logical_isolation` · train/inference at least logically isolated · **attested** · `efficient_reliability.train_infer_logical_isolation`

**L3**
- `rel.l3.lb_failover_healthcheck` · LB + auto-failover + health-check standardized · **attested** · `efficient_reliability.lb_failover_healthcheck`
- `rel.l3.sla_99_5` · SLA ≥ 99.5% · **attested** · `efficient_reliability.sla_99_5`
- `rel.l3.iac_provisioned` · AI infra provisioned/managed via IaC · **attested** · `efficient_reliability.iac_provisioned`
- `rel.l3.train_infer_network_isolation` · train/inference network isolation · **attested** · `efficient_reliability.train_infer_network_isolation`

**L4**
- `rel.l4.slo_latency_baseline` · SLO latency quantified baseline · **measured** · `duration_p99`, `satisfied_when: "sample_size >= 100"`
- `rel.l4.slo_success_baseline` · end-to-end success / error baseline · **measured** · `terminal_error_ratio`, `satisfied_when: "sample_size >= 100"`
- `rel.l4.fault_injection_drills` · fault-injection drills institutionalized · **attested** · `efficient_reliability.fault_injection_drills`
- `rel.l4.cross_az_redundancy` · cross-AZ / cross-cloud redundancy for key workloads · **attested** · `efficient_reliability.cross_az_redundancy`

**L5**
- `rel.l5.dynamic_resource` · dynamic workflow/resource adaptation · **attested** · `efficient_reliability.dynamic_resource_allocation`
- `rel.l5.predictive_scaling` · predictive pre-scaling for foreseeable load · **attested** · `efficient_reliability.predictive_scaling`
- `rel.l5.auto_remediation` · auto-remediation runbooks for mid/high failures · **attested** · `efficient_reliability.auto_remediation`

### security_alignment

**L2**
- `sec.l2.sso_mfa` · SSO + MFA for AI app access · **attested** · `security_alignment.sso_mfa`
- `sec.l2.independent_nhi` · AI workloads use independent NHI · **attested** · `security_alignment.independent_nhi`
- `sec.l2.initial_risk_assessment` · initial risk assessment on major AI projects · **attested** · `security_alignment.initial_risk_assessment`
- `sec.l2.incident_response` · AI content in the incident-response plan · **attested** · `security_alignment.ai_incident_response`
- `sec.l2.acceptable_use_policy` · AI acceptable-use policy · **attested** · `security_alignment.acceptable_use_policy`

**L3**
- `sec.l3.oauth_scope` · MCP/Tool calls use OAuth + fine-grained scope (enforced) · **measured** · `scope_deny_rate`, `satisfied_when: "sample_size >= 1"`
- `sec.l3.guardrail_blocking` · response/agent-action guardrail blocking active · **measured** · `block_rate`, `satisfied_when: "sample_size >= 1"`
- `sec.l3.dual_identity_chain` · agent↔user identity separation (dual-identity chain) · **attested** · `security_alignment.dual_identity_chain`
- `sec.l3.actions_to_siem` · Prompt/Response/Agent-Action into SIEM · **attested** · `security_alignment.actions_to_siem`
- `sec.l3.supply_chain_inventory` · model version pin + supply-chain inventory · **attested** · `security_alignment.supply_chain_inventory`
- `sec.l3.cicd_security_checks` · CI/CD security checks for key AI apps · **attested** · `security_alignment.cicd_security_checks`

**L4**
- `sec.l4.central_gateway` · central AI gateway mediates prod traffic + policy · **attested** · `security_alignment.central_gateway`
- `sec.l4.continuous_mediation` · continuous mediation & posture mgmt of tool calls · **attested** · `security_alignment.continuous_tool_mediation`
- `sec.l4.model_provenance` · model signing & provenance · **attested** · `security_alignment.model_provenance_signing`
- `sec.l4.compliance_auto` · compliance evidence auto-collected · **attested** · `security_alignment.compliance_evidence_auto`

**L5**
- `sec.l5.jit_credentials` · agents use JIT ephemeral credentials · **attested** · `security_alignment.jit_credentials`
- `sec.l5.multiagent_validation` · multi-agent delegation-chain validation · **attested** · `security_alignment.multiagent_chain_validation`
- `sec.l5.guardrail_autoevolve` · guardrails auto-evolve with attack patterns · **attested** · `security_alignment.guardrail_autoevolve`
- `sec.l5.highrisk_autocontain` · high-risk AI event auto-containment · **attested** · `security_alignment.highrisk_autocontain`

### transparency_accountability

**L2**
- `trn.l2.asset_inventory` · AI asset discovery & ledger · **attested** · `transparency_accountability.ai_asset_inventory`
- `trn.l2.min_logging` · RAG/vector/log minimum retention requirements · **attested** · `transparency_accountability.min_logging_retention`
- `trn.l2.approval_owner` · documented AI procurement/launch approval owner · **attested** · `transparency_accountability.approval_owner_documented`

**L3**
- `trn.l3.deployment_registry` · authoritative AI deployment registry (all prod on record) · **attested** · `transparency_accountability.deployment_registry`
- `trn.l3.full_chain_trace` · full-chain decision traceability (closed loop) · **measured** · `unclosed_loop_rate`, `satisfied_when: "value <= 0"`
- `trn.l3.audit_chain_intact` · audit seq continuity / chain integrity · **measured** · `chain_integrity`, `satisfied_when: "value >= 1"`
- `trn.l3.ai_council` · AI Council / CoE established · **attested** · `transparency_accountability.ai_council`
- `trn.l3.role_training` · role-based AI training system · **attested** · `transparency_accountability.role_based_training`

**L4**
- `trn.l4.trace_baseline` · cross-code/cloud/endpoint decision-trace quantified baseline · **measured** · `chain_integrity`, `satisfied_when: "sample_size >= 100"`
- `trn.l4.telemetry_intervention_decoupled` · behavior telemetry ⟂ runtime intervention decoupled · **attested** · `transparency_accountability.telemetry_intervention_decoupled`
- `trn.l4.e2e_delegation_audit` · end-to-end delegation-chain audit · **attested** · `transparency_accountability.e2e_delegation_audit`

**L5**
- `trn.l5.human_ai_coevolution` · human-AI co-evolution loop (intervention feeds back) · **attested** · `transparency_accountability.human_ai_coevolution`
- `trn.l5.governance_autoflow` · governance evidence & exception auto-flow · **attested** · `transparency_accountability.governance_evidence_autoflow`

### privacy_data_protection

**L2**
- `prv.l2.redaction` · basic sensitive-data discovery & redaction (regex/NER) · **measured** · `redaction_hit_ratio`, `satisfied_when: "sample_size >= 1"` *(pending PII tagger — see notes)*
- `prv.l2.retention_deletion` · retention period & deletion process · **attested** · `privacy_data_protection.retention_deletion_process`
- `prv.l2.pia_triggers` · PIA trigger conditions established · **attested** · `privacy_data_protection.pia_trigger_conditions`

**L3**
- `prv.l3.lifecycle_protection` · full-lifecycle standardized protection (collect/store/use/delete) · **attested** · `privacy_data_protection.lifecycle_protection`
- `prv.l3.conversation_isolation` · conversation data user-level isolation · **attested** · `privacy_data_protection.conversation_isolation`
- `prv.l3.minors_protection` · minors special protection (《办法》compliance) · **attested** · `privacy_data_protection.minors_protection`

**L4**
- `prv.l4.risk_metrics` · quantified privacy risk metrics (re-id / blast-radius / non-consent) · **measured** · `pii_exposure_surface`, `satisfied_when: "sample_size >= 100"` *(pending PII tagger)*
- `prv.l4.periodic_pia` · periodic privacy-impact reports · **attested** · `privacy_data_protection.periodic_pia_reports`
- `prv.l4.low_risk_verifiable` · low privacy risk verifiable · **attested** · `privacy_data_protection.low_risk_verifiable`

**L5**
- `prv.l5.data_sovereignty` · user data sovereignty (view / export / delete) · **attested** · `privacy_data_protection.data_sovereignty`
- `prv.l5.unlearning` · verifiable unlearning within bounded time · **attested** · `privacy_data_protection.unlearning_verifiable`
- `prv.l5.minors_guardian_ui` · minors-data guardian decision UI · **attested** · `privacy_data_protection.minors_guardian_ui`

---

## Notes for EV-6

- **L1 is `[]`** for all 5 dimensions (baseline / no controls). Make it explicit, not
  a missing key (the completeness check requires every `Lk` present).
- **Some measured indicators have no live data source yet** (Platform A4
  `DEPLOYMENT.md` §9.1 capability boundary). Their ids are stable and belong in the
  YAML now; they read `sample_size=0` (insufficient_data) until the source lands —
  the rubric treats that as *not yet satisfied*, **not failing**:
  - `redaction_hit_ratio`, `pii_exposure_surface` — pending the V1.1 PII tagger.
  - `scope_deny_rate` (`sec.l3.oauth_scope`) — path wired, but MVP `AlwaysAllow`
    stub ⇒ **always empty** until the real scope engine (#5a). Keep the objective;
    it self-activates when scope denials become real.
  - With **live data today:** `block_rate`, `injection_rule_hit_ratio`,
    `chain_integrity`, `unclosed_loop_rate`, `error_rate`, `terminal_error_ratio`,
    `duration_p99` (`boundary_breach_rate`/`drift_alert_count` need robustness rules
    tagged + firing).
- All indicator ids used here are in EV-6's known-set for `validate_against`:
  `block_rate, scope_deny_rate, token_cost_per_agent, error_rate,
  terminal_error_ratio, duration_p99, unclosed_loop_rate, chain_integrity,
  hint_emission_rate, injection_rule_hit_ratio, boundary_breach_rate,
  drift_alert_count, redaction_hit_ratio, pii_exposure_surface`.
- `chain_integrity`'s `Measurement.value` convention (decide in EV-5a and reflect
  here): suggest `1.0` = all evidence VERIFIED, `0.0` = any BROKEN — so
  `satisfied_when: "value >= 1"` means "no integrity breaks". Confirm the convention
  when EV-5a lands and align the two `trn.l3.audit_chain_intact` / `trn.l4` rows.
- `token_cost_per_agent` (Affordable ruler) is intentionally **not** a rubric gate
  here — it's a reported cost signal, not a maturity threshold. Leave it out of the
  control objectives (report-only).
