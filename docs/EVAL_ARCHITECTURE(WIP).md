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
    subject: str = ""            # per-entity key (e.g. agent_id); "" = aggregate
    notes: str = ""

class Indicator(Protocol):
    indicator_id: str
    dimension: str
    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]: ...
```

Contract rules:

- **`measure` returns a tuple** (ratified): a scalar indicator yields exactly one
  Measurement with `subject=""` (aggregate); a per-entity indicator
  (`token_cost_per_agent`) yields one per subject (`subject=agent_id`). Empty input
  ⇒ a single `sample_size=0` aggregate, not an empty tuple. The rubric matches a
  control objective's `indicator_id` against the **aggregate** (`subject==""`)
  Measurement; per-subject rows are report/breakdown detail.
- An Indicator declares its `dimension` and is **pure** over its evidence input
  (same evidence ⇒ same tuple of Measurements; no I/O, no clock — so a customer
  reproduces it bit-for-bit).
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
    verification_basis: str = "wal"  # "wal" | "index" | "hybrid" — trust basis of this report

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

## 4. E1 contract — **LANDED** (dimension attribution + scoring)

> **Status: landed** (ir-spec proto A1–A4, platform emit, core WAL-golden
> conformance incl. case 005 — all merged, CI green). Source of truth for the
> semantics: platform/spec handover `E1_audit_dimension_scoring.md`. This section
> records what core now *consumes*; it is no longer a forward dependency.

The richest measured signals need **per-rule dimension attribution**. Pre-E1,
`RuleEvaluation` had no tags/score and `DecisionTrace` had no scoreboard. E1 added
them, **additive + optional, numbers never reused** (Charter §3.2/3.3/3.5):

```proto
message RuleEvaluation {            // 1–5 unchanged
  map<string, string> tags = 6;          // A1 — verbatim from rule_ir Rule.tags (incl. 'dimension')
  map<string, double> score_deltas = 7;  // A2 — this rule's named ScoreStmt deltas
}
message DecisionTrace {             // 1–6, 20 unchanged
  map<string, double> scores = 7;        // A3 — aggregate scoreboard = Σ rules_evaluated[*].score_deltas
}
message RequestContext {           // 1–8, 99 unchanged
  optional uint32 audit_schema_version = 9;  // A4 — set to 1 from E1 on; absent ⇒ pre-E1 history
}
```

Build consequence — **EV-9 is unblocked.** All measured indicators are now
buildable on landed fields:

- *Already buildable pre-E1 (unchanged):* `block_rate`, `scope_deny_rate`
  (`authorization.missing_scopes`), `token_cost_per_agent` (`response.token_usage`),
  `error_rate` (`audit.errors[].error_code`), `seq_continuity`/`chain_integrity`
  (via `wal_verify`), `hint_emission_rate` (`audit.hint_emitted`).
- *Newly unblocked by E1:* dimension-attributed indicators reading
  `rules_evaluated[*].tags["dimension"]` + `score_deltas`, and the aggregate
  `decision.scores` (Robustness/Privacy dimension splits — EV-9).

The Evidence/Indicator contracts (§2) are unchanged by E1 — only the set of
registered indicators grows.

### 4.1 What landed, and the semantics core relies on

All additive/optional, numbers never reused. `RuleEvaluation` keeps 1–5;
`DecisionTrace` keeps 1–6 + 20. **A-side and B-side share ONE `RuleEvaluation`
message** (`DecisionTrace.rules_evaluated` and
`ResponseObservation.on_tool_response_rules` are identity-equal), so A1/A2 cover
both sides in one change. `dimension` lives in `rule_ir` `Rule.tags = 7`
(pre-existing) — **no rule_ir change was needed**; the gateway copies it verbatim.

| ID | message.field (#) | type | meaning core consumes |
|---|---|---|---|
| A1 | `RuleEvaluation.tags` (6) | `map<string,string>` | dimension attribution: `tags["dimension"]` (may be absent ⇒ rule has no dimension); other tags = metadata |
| A2 | `RuleEvaluation.score_deltas` (7) | `map<string,double>` | this rule's **named** ScoreStmt deltas (a rule may move several names) |
| A3 | `DecisionTrace.scores` (7) | `map<string,double>` | aggregate scoreboard, `decision.scores[n] == Σ rules_evaluated[*].score_deltas[n]` |
| A4 | `RequestContext.audit_schema_version` (9) | `optional uint32` | generation discriminator; **= 1** from E1 on, **absent ⇒ pre-E1 history** |

Semantics that matter to core (from the handover doc):

- **Verbatim, never interpreted.** `tags`/`score_deltas` are byte-equal to the
  rule's tags and executed deltas. The gateway's *only* arithmetic is the per-name
  sum into `decision.scores` — arithmetic, not semantics. The dimension taxonomy
  lives entirely in core.
- **Coverage:** every *evaluated* rule carries `tags` (matched **and** unmatched —
  so "what dimensions were considered" is answerable); only score-firing rules
  carry non-empty `score_deltas`.
- **Two-record split (B2, unchanged):** record **A** (`decision.made`) carries the
  request-path rules **and** the aggregate `decision.scores`; record **B**
  (`response.observed`) is sparse — it carries response-path rules per-rule on
  `response.on_tool_response_rules` but **no `DecisionTrace`, hence no aggregate
  scoreboard**. Core must read the board from A and the response rules from B
  (correlated by `decision_seq`).
- **Scoreboard invariant = free integrity check.** `decision.scores[n] == Σ
  score_deltas[n]` holds by construction (`conformance 011_score_aggregation`);
  EV-9 should assert it and flag any record that violates it.
- **A4 presence, not value, is the discriminator.** `HasField("audit_schema_version")`
  goes False→True on set; pre-E1 records leave it unset and read as history — no
  migration. (`HasField` on a *map* would raise — that's why A4 is a scalar.)

**WAL v2 golden — landed (was item D).** ir-spec ships independently-authored
frozen vectors at `gen/python/trustworthy_ai_conformance/wal_v2_golden/`
(`.wal` bytes + `manifest.yaml`), run by **both** parsers in CI (platform `wal.py`,
core `_wal_format` + `wal_verify`) with an ir-spec `regen == committed` oracle test.
Five cases: `001 genesis_chain`, `002 cross_segment`, `003 truncated_tail`,
`004 crc_corrupt`, **`005 hash_field_corrupt`**. Case 005 corrupts the *stored*
`record_hash` (payload+CRC intact), forcing each parser to **read the stored hash,
not recompute it** — a recompute-only reader would reproduce the correct value and
silently miss tampering. Core asserts 005 two ways: the per-record loop reproduces
the stored (corrupt) value, and a `chain_verify: reject` path routes through
production `wal_verify` and requires rejection. This closes the double-parser
drift risk — `walgen.py` is now only a convenience fixture builder, **not** the
oracle. (On this branch: `tests/conformance/test_wal_golden.py`.)

### 4.2 How core verifies E1 — and why `admin/v1/audit/...` shows no tags

**Core does not consume the admin API.** The admin endpoint serves the *derived
SQLite index* (a projected summary), not the raw audit record; its JSON shape does
**not** surface `rule_evaluations[*].tags`. So tags being absent from that curl
says **nothing** about whether the WAL record carries them. Two more reasons a
field can be missing from any JSON view:

1. **proto3 omits empty maps** — if that request matched no tagged rule (or the
   ruleset in use carries no `dimension` tag yet), `tags` legitimately renders as
   absent. Confirm the *ruleset* actually tags rules before concluding emit is broken.
2. The record may be **pre-E1** (`audit_schema_version` unset) if it predates the
   emit wiring.

**The authoritative core verification path = read the WAL record, not the index:**

```bash
# 1. ensure core compiles against the E1 ir-spec (the venv may hold a stale proto)
pip install -U -r requirements.txt        # re-pulls trustworthy-ai-ir-spec @ main

# 2. decode the actual WAL bytes and look at the rule evaluations
python tools/wal_dump.py /var/wal --decode | less     # inspect rules_evaluated[*].tags / score_deltas / decision.scores
#    (--decode lazily imports the open proto; if it warns "decode unavailable",
#     the installed ir-spec predates E1 → step 1)
```

Acceptance core asserts (becomes EV-9's tests, see EVAL_ISSUES EV-9):

- a decoded record with `audit_schema_version == 1` exposes `tags` on its rule
  evaluations, and `score_deltas`/`decision.scores` **on records whose ruleset
  fired a `score` action** (see gotcha below);
- the **Σ invariant** holds on any record that has scores;
- a known pre-E1 record reads with `audit_schema_version` unset and is handled as
  "no dimension data" (skipped from the dimension-coverage denominator), not as an
  error.

> **Verified end-to-end (dogfood WAL export):** a `decision.made` record decoded
> via `wal_dump --decode` shows `audit_schema_version: 1` and per-rule `tags` —
> e.g. `pii-block-request` with `{dimension: privacy, severity: high}` and
> `log-chat-requests` with `{dimension: transparency}`. E1 emit is live.
>
> **Gotcha — empty `score_deltas`/`scores` is correct, not a bug.** `score_deltas`
> populates **only** for a rule whose action chain runs a `score:` statement
> (`ScoreStmt`); a `block`/`log`-only rule yields an empty map, and **proto3 omits
> empty maps from JSON**, so it doesn't render. Likewise `decision.scores` is
> absent when no rule scored (Σ of nothing). To exercise the score path, use a
> ruleset with a scoring rule (the `conformance 011` shape, `risk_score += N`);
> then both the per-rule `score_deltas` and the aggregate `decision.scores` appear
> and the Σ invariant is checkable. Read `actions_fired` to see what a rule
> actually did — `["block"]`/`["log"]` ⇒ no deltas expected.

**Governance + volume notes:**

- *tags are audit-visible.* Verbatim passthrough + deployment shape C carry tags
  into the customer-side WAL, so rule authors must treat `tags` as audit-visible —
  **no secrets in tags** (Charter §12.3 spirit).
- *audit volume.* `tags`/`score_deltas` on every `RuleEvaluation` × both sides
  grows the record linearly with `max_rules_per_request` (default 10). Acceptable.

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

**WAL stays the integrity source; the index is the scale path (updated).** D1
still holds: the WAL is the permanent sole source of truth; a derived DB index is
disposable. WAL-direct is the *more correct* source for integrity, and it remains
canonical. **But WAL scans are slow at volume**, and Platform is building a
**Postgres audit index + query**. So core gains a **`PostgresEvidenceReader`
(EV-2, no longer deferred)** behind the same `AuditEvidenceReader` Protocol:

- It SQL-filters on indexed columns and decodes the **raw RequestContext payload
  bytes** the index stores (the *same* decoder the WAL reader uses — reader-agnostic;
  the speed win is the `WHERE` clause, not a different data shape). See
  `POSTGRES_READ_CONTRACT.md` for the cross-repo column contract.
- Index-sourced evidence is **`UNVERIFIED`** — core can't re-check a chain it
  didn't parse byte-for-byte. The reconciliation: a new **`requires_integrity`**
  flag on control objectives (EV-6) lets `UNVERIFIED` data satisfy *aggregate*
  objectives (rates/counts) but **not** integrity ones. **The Transparency
  dimension — the moat — stays WAL-only.** The report's `verification_basis`
  (`"wal" | "index" | "hybrid"`) self-declares which path produced it.
- Driver must be permissive-licensed: **`pg8000` (BSD)** or **`asyncpg`
  (Apache-2.0)** — **not** `psycopg`/`psycopg2` (LGPL, banned by Charter §1.2).
  Lives behind the `treval[postgres]` extra so the engine core stays dep-light.

Hybrid spot-verify (Postgres selects, WAL verifies a sample) is a later
enhancement, not this round.

**Deployment shapes (any of):** (A) core as a sidecar in the same compose with
`wal-data:/wal:ro`; (B) core CLI on the host against a read-only host-path WAL
mount; (C) the customer syncs WAL segments to their *own* environment and runs
core there — the strongest zero-trust story.

---

## 4b. Web layer — SSR dashboard (read-only, optional)

The maturity results need a dashboard, not just CLI text/JSON. Core ships a
**read-only Python web service that server-renders the dashboard** (client
downloads rendered HTML); the same service exposes the report JSON API. It lives
behind the **`treval[web]` extra** — the engine library and CLI never pull it.

```
 cached MaturityReport (deterministic JSON, produced by a treval run)
            │
            ▼
 treval.web  (FastAPI + Jinja2 SSR, + HTMX for drill-down; read-only)
   GET /            ─► SSR HTML: 5×5 maturity grid + verification_basis banner
   GET /report      ─► SSR HTML of the cached report
   GET /report.json ─► the report JSON (REPORT_JSON_SCHEMA.md contract)
   GET /evidence/{request_id} ─► live drill-down (reader point-lookup)
```

Design rules:

- **Engine purity.** `treval.web` imports the engine; the **engine never imports
  the web layer** (nor the closed platform). Web deps (FastAPI MIT, Starlette /
  Jinja2 / uvicorn BSD, HTMX BSD-2) are all permissive and isolated to the extra.
- **Serve cached, don't recompute.** A full engine run is slow; the service serves
  a **pre-generated** report (with `generated_at_ns`) and only does **live
  drill-down by `request_id`** (a point lookup — fast on the Postgres index, or a
  targeted WAL read). Regenerate is admin-only / async.
- **It exposes audit evidence → treat as sensitive.** Read-only is *not* safe by
  itself: drill-down surfaces request data that may contain PII. **Loopback-bind +
  optional token by default** (mirror the platform admin plane); every query is
  **tenant-scoped** (§7); **never render full response bodies** (§12). These are
  acceptance gates, not nice-to-haves.
- **The report JSON is the open contract** (`REPORT_JSON_SCHEMA.md`); the SSR
  templates render it. The UI engineer builds against committed report fixtures in
  parallel with the backend — see issues EV-R1 / EV-W1 / EV-W2.

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
