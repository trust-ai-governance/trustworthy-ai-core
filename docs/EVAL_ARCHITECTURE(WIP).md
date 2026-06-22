# Trustworthy-AI Core — Evaluation Architecture (测评架构设计)

Design baseline for the **open** evaluation engine in `trustworthy-ai-core`.
This document is the contract surface + build order, enough for a developer to
implement against without re-reading the platform/spec history. Pair with:

- Engineering Charter §14 (open-source strategy; what core may contain)
- `PHASE1_PLAN.md` §1, §4 (emit-vs-interpret boundary; maturity = measured ∪ attested)
- `PHASE1_ISSUES.md` E1 (the audit-event schema bump this design depends on)
- ir-spec `trustworthy_ai/v1/request_context_pb2` (the audit record contract)
- ir-spec `trustworthy_ai_conformance/` (the precedent for an open "fact-standard" corpus)

Status: **design only**. No runtime code exists yet — core today is the WAL
tooling (`wal_verify.py`, `wal_dump.py`, `_wal_format.py`).

---

## 0. What this engine is, and what it is NOT

It **is** the open, customer-runnable engine that reads governance evidence and
produces a **trustworthiness maturity assessment** across the five engineering
dimensions. It is the "interpret + score" half of the system.

It is **NOT**:

- a runtime component — it never sits in the request path, never blocks a call;
- a dimension *calculator inside the Gateway* — Charter / PLAN §1 forbid the
  Gateway from interpreting dimensions. The Gateway **emits neutral facts**; this
  engine **interprets** them. That boundary is the whole reason core is a
  separate, open repo;
- a re-implementation of the Rule IR executor or the conformance suite — those
  certify *IR semantics*; this engine evaluates *governance maturity*. Distinct
  concerns (see §8).

### 0.1 The trust invariant (inherited from `wal_verify`)

The existing tools re-declare the WAL byte format and **do not import the
closed platform**, so a customer can verify audit integrity without trusting —
or possessing — the Gateway. **The eval engine inherits this discipline
verbatim:**

> The eval engine depends only on the **open** ir-spec proto (audit contract) and
> reads the customer's own **read-only WAL mount**. It MUST NOT import any
> closed platform module. A customer can therefore reproduce the maturity
> assessment independently — the assessment is *verifiable*, not *asserted*.

This is the same moat logic as Charter §14.5: code is copyable, the **open
standard the engine encodes** (dimensions, rubrics, scenario corpus) is the asset.

---

## 1. Two input classes, never conflated

From PLAN §4 — the single most important design constraint:

| Class | Source | Trust basis | Examples |
|---|---|---|---|
| **Measured (可测)** | Runtime audit stream (WAL records) | Hash-chain + CRC verifiable | BLOCK rate, scope-deny rate, per-agent token cost, error rate, seq continuity, injection rule-hit ratio, redaction-hit rate |
| **Attested (声明)** | Operator-signed posture files | Operator accountability (signed config) | SSO+MFA enabled, IaC provisioning, SLA ≥ 99.5%, red-team cadence, cross-AZ redundancy, AI Council exists |

**The engine never derives a maturity level from telemetry alone.** Telemetry
measures *what happened*; posture attests *what is structurally in place*. A
level is reachable only when *both* the measured signals and the attested
controls for that level's rubric are satisfied. The engine's headline output is a
**claimed-vs-measured gap report** — it exists precisely to stop over-promising
("we attest L4" while measured signals say L2).

---

## 2. The four components (Charter §14.2 open scope)

Charter §14.2 names exactly four open components. This design implements those
four, nothing more:

```
 Evidence sources                      Core (open)
 ─────────────────                     ─────────────────────────────────────────
 read-only WAL mount  ──┐
 (decision.made A +     │   ┌──────────────────┐  Evidence[]
  response.observed B)  ├──►│ Evidence Reader  │────────────┐
                        │   │ (Evidence Store  │            ▼
 audit export (opt.)  ──┤   │  interface)      │     ┌───────────────┐  Measurement[]
 (sqlite/csv adapter)   │   │ + wal_verify     │     │  Indicators   │  (dimension-
                        │   │  integrity gate  │────►│  (Plugin SDK) │   tagged, with
 posture attestations ──┤   └──────────────────┘     └───────┬───────┘   evidence refs)
 (The extened framework)│            ▲                       │
                        │            │ dimension/indicator   ▼
 infra/IaC scan  ───────┘  ┌──────────────────┐      ┌────────────────────┐
 (future evidence)         │ Dimension        │─────►│ Maturity Rubric    │──► Report
                           │ Registry         │      │ Engine             │   (per-dim
                           │ (5 dim × 5 L,    │      │ measured ∪ attested│    rubric +
                           │  control objs)   │      │ → checklist + gap  │    gap +
                           └──────────────────┘      └────────────────────┘    evidence)
```

### 2.1 Evidence Reader (Evidence Store interface)

Normalizes every input into a uniform `Evidence` stream with provenance, so
downstream layers never know whether a fact came from WAL, an export, or an
attestation file.

```python
class IntegrityStatus(enum.Enum):
    VERIFIED = "verified"      # hash chain + CRC + seq continuity all pass
    UNVERIFIED = "unverified"  # source can't be chain-checked (e.g. export adapter)
    BROKEN = "broken"          # tamper/corruption detected — see note

@dataclass(frozen=True)
class EvidenceRef:
    """Back-pointer so every Measurement traces to its source records."""
    source: str          # "wal:/mnt/wal/000..0042.wal" | "export:audit.db" | "attest:posture.yaml"
    seq: int | None      # WAL seq, when applicable
    request_id: str | None

@dataclass(frozen=True)
class AuditEvidence:
    """One decoded audit record (RequestContext), source-agnostic."""
    ref: EvidenceRef
    integrity: IntegrityStatus
    tenant_id: str
    received_at_ns: int
    record: "RequestContext"     # the decoded ir-spec proto

@dataclass(frozen=True)
class PostureEvidence:
    ref: EvidenceRef
    tenant_id: str
    key: str                     # e.g. "security.sso_mfa_enabled"
    value: str                   # attested value
    attested_by: str             # signer identity (operator accountability)
    attested_at_ns: int

class AuditEvidenceReader(Protocol):
    """The MEASURED substrate: chain-verifiable runtime audit records."""
    def read_audit(self, *, tenant_id: str | None = None,
                   time_from_ns: int | None = None,
                   time_to_ns: int | None = None) -> Iterator[AuditEvidence]: ...

class PostureProvider(Protocol):
    """The ATTESTED substrate, and the PRIMARY extension seam (Charter §10).

    Produces attested posture evidence from any source the operator trusts. Core
    ships PostureFileReader; an enterprise developer plugs in their OWN provider
    (IAM/GRC/SIEM exporter, IaC scanner, ...) WITHOUT forking the engine — we
    ship the framework, they customize the source.
    """
    provider_id: str
    def collect(self, *, tenant_id: str | None = None) -> Iterator[PostureEvidence]: ...
```

**Audit readers (per the chosen "both, WAL-direct first"):**

- `WalEvidenceReader` — **canonical / zero-trust.** Reuses `_wal_format.iter_records`
  + the lazy proto decoder already in `wal_dump.py`, and runs the
  `wal_verify` chain check first. Records on a broken chain are emitted with
  `integrity=BROKEN` (the engine surfaces them as un-scorable, never silently
  drops or trusts them — Charter §4 fail-closed in spirit: untrusted evidence is
  not counted as passing).
- `ExportEvidenceReader` — **convenience.** Reads a platform audit export
  (SQLite/CSV) behind the same Protocol; emits `integrity=UNVERIFIED` (it cannot
  re-check a chain it didn't parse byte-for-byte). The rubric engine may discount
  unverified evidence; that policy lives in the engine, not the reader.

Reuse note: the WAL parse + decode path is **already written** in
[wal_dump.py](../tools/wal_dump.py) (`_get_decoder`, `_wal_format`). `WalEvidenceReader`
should factor the shared decode out rather than duplicate it.

**Posture providers (the extension framework — answers "enterprise customizes,
we provide framework"):**

- `PostureFileReader` — **the only implementation core ships.** Loads
  attested posture from YAML/JSON (operator-signed). MVP may accept unsigned and
  record `attested_by` as a plain claim; real signing is a later item (§7).
- *Custom providers (enterprise-authored, NOT in core):* an IAM/Entra exporter,
  a GRC/compliance tool connector, a SIEM posture query, etc. Each is a third-party
  `PostureProvider` the enterprise drops in. Core never sees their internals.
- *`IaCScanProvider` (future, deferred — see §7):* infra/IaC scan is simply
  **another `PostureProvider` implementation**, not a separate subsystem. The seam
  already admits it; we build zero scan code now and add it after the core
  functions land.

**Two extension axes, both open by construction:**

1. **Code seam** — implement `PostureProvider` to pull evidence from your own
   systems. (This is point 1's request, generalized.)
2. **Data seam** — the Dimension Registry (§2.3) is YAML, so an enterprise adds
   its *own* control objectives and `posture_key`s without touching engine code.

**The invariant that keeps the seam safe:** a custom provider can only emit
`PostureEvidence` (fixed shape: carries `attested_by` + provenance), which is
**always attested, never measured**. A posture plugin therefore **cannot raise
the `measured_ceiling`** — measured signals come only from the chain-verified
audit stream (§2.4). This means a third-party provider can attest posture but
**cannot fabricate a green light** past what the audit data independently shows.
Custom providers extend evidence *sources*; they do not relax the
`min(measured, attested)` gate.

### 2.2 Indicator Plugin SDK

An Indicator is the smallest unit of interpretation: it consumes Evidence and
emits a `Measurement`. This is the **only** place dimension semantics live
(`tags["dimension"]` is read here, never in the Gateway).

```python
@dataclass(frozen=True)
class Measurement:
    indicator_id: str
    dimension: str               # one of the 5 dimension ids (see Registry)
    value: float                 # normalized signal
    unit: str                    # "ratio" | "count" | "tokens" | "ms" ...
    sample_size: int             # how many records backed it (0 ⇒ insufficient data)
    evidence_refs: tuple[EvidenceRef, ...]   # MUST be populated — auditability
    notes: str = ""

class Indicator(Protocol):
    indicator_id: str
    dimension: str
    def measure(self, evidence: Iterable[AuditEvidence]) -> Measurement: ...
```

Contract rules:

- An Indicator declares its `dimension` and is **pure** over its evidence input
  (same evidence ⇒ same Measurement; no I/O, no clock — so a customer reproduces
  it bit-for-bit).
- Every Measurement carries `evidence_refs`. A score with no traceable evidence
  is a bug (mirrors Charter §5.5 "missing field = bug").
- `sample_size == 0` ⇒ "insufficient data," distinct from `value == 0`. The
  rubric engine treats them differently (insufficient ≠ failing).
- Indicators only **read decoded facts**; they never re-evaluate Rule IR. The
  Gateway already ran the rules; the Indicator aggregates the recorded outcomes.

### 2.3 Dimension Registry

The authoritative, **data-driven** taxonomy: the 5 dimensions × 5 levels and the
CSA-derived control objectives per cell, each mapped to either a runtime
indicator or a posture key. Data, not code, so the standard versions
independently and can become the open de-facto reference (Charter §14.3).

Proposed on-disk shape (`registry/dimensions/*.yaml`, one file per dimension):

```yaml
dimension: robustness            # stable id; matches tags["dimension"]
title_en: Robustness
title_zh: 强鲁棒性
levels:
  L2:
    control_objectives:
      - id: rob.l2.adversarial_log
        statement_zh: 对高风险模型执行基础对抗测试并形成问题台账
        evidence:
          kind: measured           # measured | attested
          indicator_id: injection_rule_hit_ratio
          satisfied_when: "value >= 0"   # presence of the signal, not a threshold gate at L2
      - id: rob.l2.version_freeze
        statement_zh: 建立模型版本冻结要求
        evidence:
          kind: attested
          posture_key: robustness.model_version_freeze
  L4:
    control_objectives:
      - id: rob.l4.breach_baseline
        statement_zh: 边界突破率/异常会话比/漂移告警量化基线
        evidence:
          kind: measured
          indicator_id: boundary_breach_rate
          satisfied_when: "sample_size >= 100"   # quantified baseline requires data volume
      - id: rob.l4.model_signing
        statement_zh: 模型签名与来源证明
        evidence:
          kind: attested
          posture_key: robustness.model_provenance_signing
```

The five dimension ids (stable, match `tags["dimension"]`):
`robustness · efficient_reliability · security_alignment ·
transparency_accountability · privacy_data_protection`. **Affordable** is modeled
as a **cross-cutting ruler**, not a sixth dimension (per the framework): it
surfaces as per-dimension cost indicators (token cost), not its own rubric.

### 2.4 Maturity Rubric Engine

Combines Measurements (measured) + PostureEvidence (attested), evaluates each
control objective in the Registry, and produces the report.

```python
@dataclass(frozen=True)
class ObjectiveResult:
    objective_id: str
    kind: str                    # "measured" | "attested"
    status: str                  # "met" | "unmet" | "insufficient_data" | "unverified_evidence"
    evidence_refs: tuple[EvidenceRef, ...]

@dataclass(frozen=True)
class DimensionReport:
    dimension: str
    measured_ceiling: str | None   # highest level whose MEASURED objectives all pass
    attested_ceiling: str | None   # highest level whose ATTESTED objectives all pass
    awarded_level: str | None      # min(measured_ceiling, attested_ceiling) — the gate
    objectives: tuple[ObjectiveResult, ...]
    gaps: tuple[str, ...]          # attested-but-not-measured = over-claim flags

@dataclass(frozen=True)
class MaturityReport:
    tenant_id: str
    window: tuple[int, int]        # time range covered
    dimensions: tuple[DimensionReport, ...]
    integrity_summary: dict        # counts of VERIFIED / UNVERIFIED / BROKEN evidence

class RubricEngine:
    def evaluate(self, registry: DimensionRegistry,
                 measurements: Iterable[Measurement],
                 posture: Iterable[PostureEvidence]) -> MaturityReport: ...
```

Engine rules:

- `awarded_level = min(measured_ceiling, attested_ceiling)` — **neither input
  alone can lift a dimension.** This is PLAN §4 made mechanical.
- A control objective backed by `BROKEN` or `UNVERIFIED` evidence resolves to
  `unverified_evidence`, which **cannot** satisfy a level (fail-closed on
  integrity).
- `gaps` lists every objective that is attested-met but whose corresponding
  measured signal is absent or contradicts — the over-claim report.
- The engine is also **pure** over its inputs ⇒ a customer reruns it and gets the
  identical report from the identical WAL + attestations.

---

## 3. Data flow (end to end)

```
read-only WAL mount ─► WalEvidenceReader (wal_verify gate) ─► AuditEvidence[]
                                                                  │
posture.yaml ─► PostureFileReader ─► PostureEvidence[] ───────────┤
                                                                  ▼
                              Indicators (one per signal) ─► Measurement[]
                                                                  │
                      DimensionRegistry (5×5 control objs) ───────┤
                                                                  ▼
                                  RubricEngine.evaluate ─► MaturityReport
                                                                  │
                                          renderer ─► JSON / human report / CSV
```

Every arrow is reproducible by the customer on their own hardware against their
own read-only mount. No platform code, no network, no clock dependency.

---

## 4. Dependency on E1 (decided: design against E1's assumed shape)

The richest measured signals need **per-rule dimension attribution**, which is
**not in the current audit proto**. Today `RuleEvaluation` is:

```
RuleEvaluation { rule_id; rule_version; matched; actions_fired[]; eval_duration_ns }
```

E1 (PHASE1_ISSUES.md, *Not started*) adds dimension `tags` + optional `score`.
**This design assumes E1's planned shape:**

```
# ASSUMED post-E1 — depends on ir-spec change landing first
RuleEvaluation {
    rule_id; rule_version; matched; actions_fired[]; eval_duration_ns;
    map<string,string> tags;     # E1 — includes tags["dimension"], passed through verbatim
    float score;                 # E1 — optional per-rule score
}
```

Consequence for the build:

- **Buildable today (no E1):** indicators over fields that already exist —
  `block_rate`, `scope_deny_rate` (`authorization.missing_scopes`),
  `token_cost_per_agent` (`response.token_usage`), `error_rate`
  (`audit.errors[].error_code`), `seq_continuity` / `chain_integrity` (via
  `wal_verify`), `hint_emission_rate` (`audit.hint_emitted`). These already cover
  parts of Security&Alignment, Affordable, Efficient-Reliability, and
  Transparency.
- **Blocked on E1:** dimension-attributed indicators that read
  `RuleEvaluation.tags["dimension"]` and per-rule `score` (e.g. Robustness
  injection/boundary signals split by dimension). Design them now against the
  assumed shape; they cannot be exercised on real data until E1 ships in
  ir-spec + platform.

The Evidence/Indicator contracts above are **identical** in both cases — only the
set of registered indicators differs — so no rework when E1 lands.

### 4.1 Exact E1 dependency list (the three-repo split)

Verified against the *live* proto via descriptor introspection (not the docs).
Current field numbers — **`RuleEvaluation`**: `rule_id(1)`, `rule_version(2)`,
`matched(3)`, `actions_fired[](4)`, `eval_duration_ns(5)` → **free: #6, #7**.
**`DecisionTrace`**: `authorization(1)`, `rules_evaluated(2)`,
`policy_snapshot_version(3)`, `final_decision(4)`, `decision_reason(5)`,
`decided_by(6)`, `actions(20)` → **free: #7–#19**. The `tags` on the `Rule`
message in `rule_ir` are the **closed ruleset definition**, unreachable to core;
E1 must put tags into the audit event itself.

**Confirmed: A-side and B-side share ONE message.**
`DecisionTrace.rules_evaluated` and `ResponseObservation.on_tool_response_rules`
both reference `trustworthy_ai.v1.RuleEvaluation` (identity-equal). ⇒ adding
`tags`/`score_deltas` to `RuleEvaluation` is **one change covering both sides.**

**A. proto changes — `trustworthy-ai-ir-spec` (core's compile-time dep)**

1. **`RuleEvaluation.tags: map<string,string>`** (new, optional, field #6) —
   rule tags incl. `dimension`, passed through verbatim. **Hard blocker**: no
   dimension attribution without it → every EV-9 indicator is impossible.
2. **`RuleEvaluation.score_deltas: map<string,double>`** (new, optional, field #7)
   — per-rule **named** score increments. *(Corrected from `score: double`.)* A
   rule's action chain can contain multiple `ScoreStmt`s with different names
   (`risk_score += 5; pii_severity += 2`); `ScoreStmt` is `(score_name, delta)`, so
   a single scalar loses the name and can't carry multi-score. The map matches
   `ScoreStmt.score_name` and is **same-shaped as A3** — core can then cross-check
   `Σ per-rule deltas == aggregate` as a free integrity check. Dimension
   attribution = *which rule contributed which named score* × *that rule's
   `dimension` tag* — so per-rule named increments are the real need for EV-9's
   score indicators.
3. *(recommended)* **`DecisionTrace.scores: map<string,double>`** (field #7 in
   DecisionTrace's numbering) — request-scoped aggregated scoreboard (matches
   `conformance 011` `expected.scores`). Persisting it is **not "interpreting"**:
   the scoreboard is already the executor's request-scoped state (aggregating
   rules read it to decide BLOCK); writing it to audit just records an existing
   execution product. Without it, EV-9 score indicators fall back to summing A2.
4. *(recommended, NOT blocker)* **`RequestContext.audit_schema_version: uint32`**
   (new top-level, e.g. field #9) — **correction:** B2 added only `record_type`
   (`#7`, enum `AuditRecordType`), *not* a version; "merged into B2" was wrong.
   proto3 `map` has no presence, so empty `tags` can't distinguish *pre-E1
   (absent)* from *post-E1 untagged rule*. An explicit version lets core exclude
   legacy records from the dimension-coverage *denominator*. Core still works
   without it (reports "X% of records carry dimension tags"), so it is a
   precision aid, not a gate.
5. Field discipline: additive / optional / never-reuse numbers; fields 1–6
   (RuleEvaluation 1–5) untouched (Charter §3.2/§3.3/§3.5).

**B. platform emit behavior — closed gateway (core's runtime *data* dep)**

6. Populate `tags` on **every evaluated** `RuleEvaluation` (matched and unmatched
   alike — one message, both sides), else ratio indicators lose their denominator.
7. Strictly emit, never interpret (PLAN §1): the gateway must not compute
   `dimension`.

**C. spec conformance — optional**

8. One conformance case asserting tags + score_deltas survive into the audit
   event, so any third-party executor must preserve them.

**D. WAL v2 golden vectors — `trustworthy-ai-ir-spec` (this-round deliverable, NOT
optional).** Core's `_wal_format` reads *production* WAL bytes; platform's `wal.py`
writes them. The two are independent re-declarations of the v2 frame (record
header `>II32s`, segment header `>8sIqq32s`, genesis
`7dc8a92266863c5abcecfba93a49935663a44f69959529377d926baec0d32d04`). Any
single-field drift means core mis-reads or rejects genuine records — and it
detonates at the *customer* (deployment shape C), not in CI. **`walgen.py` cannot
be the oracle: it derives fixtures from `_wal_format`'s own constants, so core's
WAL tests validate core against itself and stay green under drift.** Fix:
ir-spec ships a committed, independently-authored golden set —
*known bytes → expected `(seq, payload, record_hash)` + decoded segment header* —
that **both** parsers run in CI. A2's genesis pinning is one cell of this; the
whole frame must be bound. (This consumes into core via EV-1's acceptance.)

**Sequencing:** core *builds* EV-9 once **A** lands (spec proto); EV-9 is
*acceptance-tested on real data* only once **B** lands (platform emit). **D** is
independent and should land early — it de-risks every deployment, not just EV-9.
None of A/B/C/D is a core-repo authoring task — core only consumes the contracts
(and runs the golden).

**Governance + volume notes (small but record them):**

- *tags are audit-visible.* Verbatim passthrough + deployment shape C carry tags
  into the customer-side WAL, so rule authors must treat `tags` as audit-visible —
  **no secrets in tags** (Charter §12.3 spirit).
- *audit volume.* `tags`/`score_deltas` on every `RuleEvaluation` × both sides
  grows the record linearly with `max_rules_per_request` (default 10). Acceptable;
  noted.

---

## 4a. Deployment & evidence access (Docker)

The real deployment is Docker. The gateway container writes the WAL to a mounted
volume (`wal-data -> /var/wal`, absolute per the known path gotcha) and the
derived sqlite index to `audit-data -> /var/audit/audit.db`. How core reads:

**Canonical path = WAL files, read-only (EV-1).** Core runs as a **separate
process / container / CLI**, mounts the *same WAL volume read-only*, and parses
segment files with `_wal_format`. It never enters the gateway container and never
connects to the gateway process — this is the zero-trust invariant (§0.1) made
operational.

```yaml
# compose sketch — core is its own service, NOT inside the gateway
treval:
  volumes: ["wal-data:/wal:ro"]      # read-only mount of the gateway's WAL volume
  # python -m treval /wal --posture /etc/posture.yaml --json
```

- **Concurrent-read safe:** the gateway keeps appending; `iter_records` already
  *stops cleanly at a truncated tail*, so reading a live segment reads up to the
  last complete record. Read-only + tolerate-truncated-tail = safe.
- **Multi-segment:** the WAL **rolls segments** (multiple files by size/age) but
  does not yet **archive/remove** them (MVP boundary 3.2) — so all segments sit in
  the dir; `list_segments` sorts + reads them all. When archive (A3) lands, shipped
  segments move to object store and core gains an *archive `EvidenceReader`*
  (future, not now).

**The sqlite `audit.db` is NOT required, by design.** D1: the WAL is the permanent
sole source of truth; the sqlite index is derived + disposable (platform admin
search). For maturity eval — which scans everything and needs chain integrity —
WAL-direct is the *more correct* source anyway. Reading the sqlite would only be
a speed convenience and could only ever be `UNVERIFIED` (core can't re-check a
chain it didn't parse). **⇒ `ExportEvidenceReader` (EV-2) is deferred, not this
round.** Postgres is further out, same reasoning.

**Deployment shapes (any of):** (A) core as a sidecar in the same compose with
`wal-data:/wal:ro`; (B) core CLI on the host against a read-only host-path WAL
mount; (C) the customer syncs WAL segments to their *own* environment and runs
core there — the strongest zero-trust story.

---

## 5. Dimension → indicator sketch (the measured half)

Maps each dimension's quantifiable signals (from the maturity tables) to a
concrete indicator. ⚠ = needs E1; ✓ = buildable on current proto.

| Dimension | Indicator (id) | Source field | E1? |
|---|---|---|---|
| Robustness | `injection_rule_hit_ratio`, `boundary_breach_rate`, `drift_alert_count` | `rules_evaluated[].tags[dimension=robustness]`, `score` | ⚠ |
| Efficient Reliability | `error_rate`, `terminal_error_ratio`, `duration_p99` | `audit.errors[]`, `response.final_terminal`, `response.duration_ms` | ✓ |
| Security & Alignment | `block_rate`, `scope_deny_rate`, `dual_identity_coverage` | `final_decision`, `missing_scopes`, `principal_type` + `delegation_chain` | ✓ |
| Transparency/Accountability | `chain_integrity`, `seq_continuity`, `decision_traceability`, `challenge_success_rate` | `wal_verify`, `policy_snapshot_version` presence, A↔B closure | ✓ |
| Privacy & Data Protection | `redaction_hit_ratio`, `pii_exposure_surface` | `params_indexed` pii_*/phi_* keys (post V1.1 tagger), `response_body_preview` policy | ⚠ |
| Affordable (cross-cut) | `token_cost_per_agent`, `cost_per_governed_call` | `response.token_usage` joined to `agent_id` | ✓ |

The A↔B closure signal (a `decision.made` with `final_decision=ALLOW` and no
matching `response.observed`) is the "unclosed loop" alert from B2 — a
ready-made Transparency indicator.

---

## 6. Build order (when implementation starts — out of scope this session)

1. `AuditEvidenceReader` + `PostureProvider` Protocols; `WalEvidenceReader`
   (reuse `_wal_format` + decode, gate on `wal_verify`) + `PostureFileReader` (the
   one shipped posture impl). → verify: feed a known WAL fixture, get N
   AuditEvidence with correct integrity status; tamper one record → that record is
   `BROKEN`; load a posture YAML → PostureEvidence with `attested_by` populated.
   (Custom providers + `IaCScanProvider` are out of scope — only the seam ships.)
2. `Indicator` SDK + the ✓ indicators (no E1). → verify: each indicator's
   Measurement on a hand-built fixture matches a computed-by-hand expected value;
   `evidence_refs` populated; `sample_size==0` on empty input.
3. `DimensionRegistry` loader + the 5 dimension YAMLs (control objectives, both
   kinds). → verify: registry round-trips; every `indicator_id`/`posture_key`
   referenced resolves.
4. `RubricEngine` + `MaturityReport`. → verify: a fixture with measured L3 +
   attested L2 awards L2; attested L4 + measured L2 produces an over-claim gap;
   BROKEN evidence cannot satisfy an objective.
5. Eval corpus format + first scenarios (§8). → verify: each corpus case runs
   end-to-end and reproduces its `expected` report.
6. (post-E1) the ⚠ dimension-tagged indicators.

Test discipline: corpus cases are YAML fixtures (like `walgen.py` builds WAL
fixtures), so the suite stays independent of the platform. Coverage gate 60%
(Charter §13.3), no third-party copyleft (CI already enforces).

---

## 7. Open questions / deferred

- **Posture attestation signing**: this design assumes signed YAML but does not
  specify the signature scheme. MVP can accept unsigned + record `attested_by` as
  a plain claim; real signing is a later item. Flag, don't build speculatively.
- **IaC / infra scan provider (deferred, explicitly)**: a direction, not a
  near-term commitment. It is **a future `PostureProvider` implementation**
  (§2.1), so it requires no new architecture — the seam already admits it. Build
  it **after** the core functions (Evidence/Indicator/Registry/Rubric + the ✓
  indicators) land. Building zero scan code now is the intended state.
- **Custom posture providers are an enterprise responsibility, not a core
  deliverable**: core ships only `PostureFileReader` + the documented
  `PostureProvider` Protocol. Enterprise-specific connectors (IAM, GRC, SIEM)
  live in the enterprise's own tree. Core's job is the stable seam + reference
  impl, per Charter §10.
- **Cross-tenant aggregation**: the engine is per-tenant (Charter §7). A
  multi-tenant operator rollup is explicitly out of scope until asked.
- **Eval corpus ↔ conformance suite**: kept separate (§8). If they should share a
  loader, decide later — don't unify speculatively.
- **Where the Registry lives**: in core (open) vs ir-spec (open contract). Both
  are open; placing the rubric data in ir-spec would make it a published contract
  schema like the conformance suite. Decision deferred — noted as a fork.

---

## 8. The eval corpus is the moat (mirrors the conformance suite)

ir-spec's `trustworthy_ai_conformance/` (12 YAML cases) turns "conformant Rule IR
executor" into machine-verifiable criteria — Charter §14.5 calls it the material
basis of the de-facto standard. **The eval corpus is the analogous asset for
maturity assessment:** each case is a self-describing scenario (input audit
records + posture + `expected` MaturityReport). The incident cases already in the
maturity tables are exactly these scenarios — e.g. Character.AI boundary drift
(Robustness L1), TwinGate (Robustness L3), EigenShield quantified attack/defense
(Robustness L4), AWS Bedrock full-trace (Transparency L3), OpenAI/Mixpanel
supply-chain leak (Privacy, failure exemplar).

> Every new dimension scenario = one new corpus case → "100+ future scenarios" as
> a scaling rule, identical to §14.5's logic for the conformance suite. The
> engine code is copyable; **the corpus + the registry are the standard**.
