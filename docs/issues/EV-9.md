# EV-9 — dimension-attribution indicators: boundary_breach_rate · redaction_hit_ratio · pii_exposure_surface (build) · drift_alert_count (deferred, gated on P3-drift)

**Problem (plain language):** Robustness and Privacy still read partly `NotMeasured` — we want to measure
**boundary breaches** (untrusted-channel injections, authz crossings) and **PII/redaction** from the
governance record's per-rule **dimension tags**, not just attest them.

**Value:** EV-9 turns the E1 `tags["dimension"]` attribution into measured Robustness/Privacy signals.
With B1 merged (2026-07-12), **three** indicators are buildable now — `boundary_breach_rate` +
`redaction_hit_ratio` + `pii_exposure_surface` — and they **ship together in this cycle / one commit**
(same passive seam, no ordering between them). Only `drift_alert_count` stays **honestly deferred** to a
Platform surface that doesn't exist yet (P3-drift alert semantics, on the B2 posture path). This brief
builds the three and **documents the precise unlock** for drift — so when P3-drift lands, it plugs into the
same seam with no engine change.

> Dev brief. Builds on **EV-4** passive Indicator SDK + **EV-5b** A↔B join helper (`correlate.py`, reused
> for response-side rules). **Prereq:** EV-4 ✅, EV-5b (this cycle). Platform-confirmed surfaces (2026-07-11,
> B1 2026-07-12) in §0. Same **②** rule as EV-5: `Measurement.integrity = min(evidence)`.

---

## 0. What Platform can emit (confirmed 2026-07-11 · B1 2026-07-12) — the buildable/deferred line

| indicator | needs | status |
|---|---|---|
| **boundary_breach_rate** | `rules_evaluated.tags["dimension"]="robustness"` (**fully populated**, values {transparency, privacy, availability, security, robustness}) + existing rule surfaces | ✅ **BUILD** |
| **redaction_hit_ratio**, **pii_exposure_surface** | `audit.hint_variables["pii_types"]` (A/B records) + pii_types index col + final_terminal filter | ✅ **BUILD** — **B1 MERGED 2026-07-12, LIVE-VERIFIED** (`hint_variables["pii_types"]` present in the WAL, e.g. `"email"`). NB: **NOT `Invocation.params_indexed`** (that's user request content, never `pii_*`) |
| **drift_alert_count** | model-drift alert signal | 🔴 **DEFER** — B2 (`AUDIT_RECORD_TYPE_POSTURE_DECLARED=4`) implemented, pending merge; the two sequences (type-4 declared / B-record upstream_model observed) exist post-merge, **but "what counts as an alert" is P3-drift (not built)**. Platform recommends waiting for P3-drift's alert records (single source of truth for drift semantics on the declaration side — don't fork drift logic into Core). NotMeasured until then |

> **No boundary/drift `decision.scores` keys** — `scores` holds only `injection_score` (type-3). Platform
> advises **not** to invent score keys; `boundary_breach_rate` composes existing rule surfaces instead (§1).

## 1. `boundary_breach_rate` — BUILD (deps LIVE-VERIFIED 2026-07-11)

**Deps confirmed on the live `/home/olvan/wal` (`__eval__`):** `tags["dimension"]` populated on **1926/1926**
rules (values seen {availability, privacy, robustness, transparency}); **48** decisions with
`authorization.allowed==false`; both `inj-indirect-channel-shadow` + `inj-indirect-phrasing-shadow` present.
`join_ab` (EV-5b) + `min_integrity` (②) merged. **Nothing else blocks this indicator.**

- dim `robustness`; passive Indicator over `AuditEvidence`; `Measurement.integrity = min` (②).
- **Composite** (Platform §5): a request is a boundary breach iff, on its records,
  **(a)** an **untrusted-channel shadow** rule matched — `inj-indirect-channel-shadow` (the channel/boundary
  rule; `inj-indirect-phrasing-shadow` is injection *phrasing*, not a channel crossing — **confirm with
  Platform whether it also counts** before widening), **OR** **(b)** an **LLM06 authz denial**
  (`decision.authorization.allowed == false`). Reuse `join_ab` to read A (authz) + B (response-side shadow)
  per request.
  > ⚠ **Identify the shadow rule by `rule_id`** (there is no "boundary" tag — `tags["dimension"]="robustness"`
  > is on ALL robustness rules incl. the direct-block ones, so it would over-count injection detection as
  > boundary breach). rule_id matching is brittle to renames; if boundary_breach becomes load-bearing,
  > ask Platform for a `tags["boundary"]` / rule-family marker (same pattern as the Tier-2 `tags["tier"]`).
- value = breach requests ÷ measurable; `sample_size` = requests. Registry: rob.l3.unified_risk_score
  (`sample_size>=1`) + rob.l4.breach_baseline (`sample_size>=100`).
- **Honest note:** this is a **production-traffic** rate (how often boundaries are breached in real
  traffic). Over the eval WAL it reflects the deliberately-breaching probes, so it's live-meaningful only
  on the production passive path (EV-8 §6) — like duration/error, buildable+fixture-tested now.

## 2. `redaction_hit_ratio` + `pii_exposure_surface` — BUILD (B1 merged + live-verified 2026-07-12)

**Ships in the same cycle / commit as `boundary_breach_rate`** — B1 landed, so there is no remaining blocker
and no reason to stage them apart. Both are passive Indicators over `AuditEvidence`; dim
`privacy_data_protection`; `Measurement.integrity = min` (②).

- Read `audit.hint_variables["pii_types"]` off A/B records (**NOT `Invocation.params_indexed`** — that's user
  request content, never `pii_*`). Reuse `join_ab` (EV-5b) if A + B both carry markers.
- **`redaction_hit_ratio`** = requests with ≥1 PII type detected (∴ redactable) ÷ measurable requests;
  `sample_size` = measurable requests.
- **`pii_exposure_surface`** = count of the distinct PII-type set observed across the window (e.g.
  {email, phone} → 2); `sample_size` = measurable requests.
- Confirm the **`final_terminal` filter** (Platform: part of the B1 surface — measure on the terminal record
  per request, not intermediate) with the implementer before fixing the measurable-set definition.
- Registry: prv.l2.redaction (`sample_size>=1`), prv.l4.risk_metrics.
- **Honest note:** like the other passive rates this is production-traffic-shaped; over the eval WAL it
  reflects the probe corpus's PII, so it's fixture-tested now + production-meaningful on the passive path
  (EV-8 §6).

## 3. `drift_alert_count` — DEFER (the one deferred indicator; NO dead stub)

Per **⑤**, do **not** ship an indicator class that always returns `insufficient_data` (dead code — the rubric
already resolves a missing measurement to `insufficient_data`, keeping the row honestly `NotMeasured`).
Record the exact unlock instead:

- **drift_alert_count** (robustness) — B2 (`AUDIT_RECORD_TYPE_POSTURE_DECLARED=4`, ir-spec accepted
  2026-07-11) is implemented/pending-merge; post-merge the two sequences exist (type-4 declared / B-record
  upstream_model observed), **but "what counts as an alert" is P3-drift (not built)**. Platform recommends
  waiting for P3-drift's alert records — single source of truth for drift semantics on the declaration side;
  don't fork drift logic into Core. **NotMeasured until P3-drift.** When it lands: read type-4 as a **time
  series** (one record per posture change, snapshot-on-change, carried in `audit.hint_variables`), diff
  consecutive declarations vs the upstream-model-observed value → alert count. Resolve the type-4 enum **by
  descriptor name** (`AUDIT_RECORD_TYPE_POSTURE_DECLARED`), like record_type=3 — never a hard-coded int.
  *(Also connects to EV-3: B2 is Platform writing posture declarations INTO the WAL; a future
  `WalPostureProvider` could read type-4 instead of `posture.yaml`.)*

## 4. Acceptance

- `boundary_breach_rate`: walgen fixtures — hand-computed breach count over the (a)/(b) composite;
  `sample_size`; `Measurement.integrity = min`; boundary cases (all-clean → 0; authz-deny-only;
  shadow-hit-only; both; empty → sample_size 0). Reuses EV-5b `correlate.join_ab` (tested there).
- `redaction_hit_ratio` / `pii_exposure_surface`: walgen fixtures with `hint_variables["pii_types"]`
  present / absent / multi-type — hand-computed hit ratio + distinct-type surface; `Measurement.integrity =
  min`; boundary cases (no PII markers → hit ratio 0, surface 0; empty stream → sample_size 0).
- Determinism; coverage ≥60% / mypy / ruff clean.
- Deferred one (`drift_alert_count`): **no code**; a docs/registry note that its row is `insufficient_data`
  pending P3-drift.

## 5. Non-goals / coordination

- **drift_alert_count** (gated on P3-drift alert semantics — Platform roadmap; not Core-blocked).
- Inventing `decision.scores` keys for boundary/drift (Platform advised against; use rule surfaces).
- **Cross-repo (already answered):** `tags["dimension"]` populated ✅; PII surface = `hint_variables["pii_types"]`
  (B1, merged 2026-07-12) ✅; drift = type-4 + P3-drift (B2) ✅. Two open confirmations for the implementer
  (non-blocking): whether `inj-indirect-phrasing-shadow` counts toward boundary (§1); the `final_terminal`
  measurable-set filter for PII (§2). EV-9's build scope is now **three** indicators; drift documented for
  when P3-drift arrives.
