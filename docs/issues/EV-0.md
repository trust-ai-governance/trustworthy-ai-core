# EV-0 — `treval` package skeleton + Evidence/Measurement models + core Protocols

> Dev brief for the first eval-engine issue. Self-contained: you should be able to
> implement this from this file + the repo alone. Parent design:
> `docs/EVAL_ARCHITECTURE(WIP).md` §2 (data model) and §0–§1 (invariants);
> issue index: `docs/EVAL_ISSUES(WIP).md` (EV-0, and the ratified-decisions table).
> 中文背景见 `docs/EVAL_ISSUES(WIP).md`；本文用英文以与 §2 的签名零漂移。

## 0. One-paragraph context

`trustworthy-ai-core` is the **open** evaluation engine. It reads governance
evidence the closed gateway already wrote (the WAL audit records) plus operator
posture attestations, and scores trustworthiness maturity across 5 dimensions. The
gateway **emits** neutral facts; this engine **interprets** them — that split is
why core is a separate open repo. EV-0 lays the foundation: the frozen data model
and the Protocol seams **everything else plugs into**. It contains **no logic and
no I/O** — just types. Get the shapes exactly right; the whole tree imports them.

## 1. Scope

Create the `treval` package and define, precisely as specified in §3:

- the package skeleton (`treval/__init__.py`, `treval/py.typed`);
- the `IntegrityStatus` enum;
- the frozen dataclasses: `EvidenceRef`, `AuditEvidence`, `PostureEvidence`,
  `Measurement`, `ObjectiveResult`, `DimensionReport`, `MaturityReport`;
- the `typing.Protocol`s: `AuditEvidenceReader`, `PostureProvider`, `Indicator`;
- the CI wiring so `treval` is linted / type-checked / tested.

**Nothing else.** No reader, indicator, engine, parsing, serialization, or YAML.

## 2. Layout

```
treval/
  __init__.py        # re-export the public names (see §3.4)
  py.typed           # empty marker file (PEP 561) — treval ships types
  models.py          # IntegrityStatus + all 7 dataclasses
  protocols.py       # the 3 Protocols
tests/
  test_treval_models.py      # construct/read-back + frozen + enum tests
  test_treval_protocols.py   # dummy impls satisfy the Protocols + typecheck
```

(Tests live in the repo's existing top-level `tests/`, alongside `test_wal_*.py`.)

## 3. Exact definitions

Use `from __future__ import annotations` at the top of every module. Target
Python **3.11 and 3.12** (CI matrix) — `X | None` unions are fine.

### 3.1 `treval/models.py`

```python
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Mapping

# treval depends on the OPEN ir-spec proto (ratified). Never import the platform.
from trustworthy_ai.v1.request_context_pb2 import RequestContext


class IntegrityStatus(enum.Enum):
    VERIFIED = "verified"      # hash chain + CRC + seq continuity all pass
    UNVERIFIED = "unverified"  # source cannot be chain-checked (e.g. an export)
    BROKEN = "broken"          # tamper / corruption detected


@dataclass(frozen=True)
class EvidenceRef:
    """Back-pointer so every Measurement/Objective traces to its source records."""
    source: str                # "wal:/mnt/wal/000..0042.wal" | "attest:posture.yaml" | ...
    seq: int | None = None     # WAL seq when applicable
    request_id: str | None = None


@dataclass(frozen=True)
class AuditEvidence:
    """One decoded audit record (RequestContext), source-agnostic."""
    ref: EvidenceRef
    integrity: IntegrityStatus
    tenant_id: str
    received_at_ns: int
    record: RequestContext     # the decoded ir-spec proto (held as-is)


@dataclass(frozen=True)
class PostureEvidence:
    """An attested posture fact. ATTESTED ONLY — carries no 'measured' field by
    design, so a posture source can never raise a measured ceiling (§1 invariant)."""
    ref: EvidenceRef
    tenant_id: str
    key: str                   # e.g. "security.sso_mfa_enabled"
    value: str                 # attested value (string; typed interpretation is later)
    attested_by: str           # signer / claimant identity (operator accountability)
    attested_at_ns: int


@dataclass(frozen=True)
class Measurement:
    """A quantified signal produced by one Indicator over some evidence."""
    indicator_id: str
    dimension: str                          # one of the 5 dimension ids (Registry, EV-6)
    value: float                            # normalized signal
    unit: str                               # "ratio" | "count" | "tokens" | "ms" | ...
    sample_size: int                        # records backing it; 0 ⇒ insufficient data
    evidence_refs: tuple[EvidenceRef, ...]  # MUST be populated by producers (auditability)
    subject: str = ""                       # per-entity key (e.g. agent_id); "" = aggregate
    notes: str = ""


@dataclass(frozen=True)
class ObjectiveResult:
    objective_id: str
    kind: str                               # "measured" | "attested"
    status: str                             # "met"|"unmet"|"insufficient_data"|"unverified_evidence"
    evidence_refs: tuple[EvidenceRef, ...]


@dataclass(frozen=True)
class DimensionReport:
    dimension: str
    measured_ceiling: str | None            # highest level whose MEASURED objectives all pass
    attested_ceiling: str | None            # highest level whose ATTESTED objectives all pass
    awarded_level: str | None               # min(measured_ceiling, attested_ceiling)
    objectives: tuple[ObjectiveResult, ...]
    gaps: tuple[str, ...]                    # attested-but-not-measured = over-claim flags


@dataclass(frozen=True)
class MaturityReport:
    tenant_id: str
    window: tuple[int, int]                  # (time_from_ns, time_to_ns) covered
    dimensions: tuple[DimensionReport, ...]
    integrity_summary: Mapping[str, int]     # counts per IntegrityStatus.value
    verification_basis: str = "wal"          # "wal" | "index" | "hybrid" (Postgres reader / EV-7)
```

### 3.2 `treval/protocols.py`

```python
from __future__ import annotations

from typing import Iterable, Iterator, Protocol

from treval.models import AuditEvidence, Measurement, PostureEvidence


class AuditEvidenceReader(Protocol):
    """The MEASURED substrate: chain-verifiable runtime audit records."""
    def read_audit(
        self,
        *,
        tenant_id: str | None = None,
        time_from_ns: int | None = None,
        time_to_ns: int | None = None,
    ) -> Iterator[AuditEvidence]: ...


class PostureProvider(Protocol):
    """The ATTESTED substrate, and the enterprise extension seam (Charter §10)."""
    provider_id: str
    def collect(self, *, tenant_id: str | None = None) -> Iterator[PostureEvidence]: ...


class Indicator(Protocol):
    """Smallest unit of interpretation; the only place dimension semantics live.

    Returns a TUPLE (ratified): a scalar indicator yields one Measurement with
    subject==""; a per-entity indicator (e.g. token cost per agent) yields one per
    subject. Empty input ⇒ a single sample_size=0 aggregate, not an empty tuple.
    Implementations (EV-4+) must be pure: same evidence ⇒ same tuple, no I/O/clock.
    """
    indicator_id: str
    dimension: str
    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]: ...
```

### 3.3 Notes on the shapes (don't deviate without asking)

- **`Indicator.measure -> tuple[Measurement, ...]`** and **`Measurement.subject`**
  are ratified decisions — they let `token_cost_per_agent` (EV-5b) emit one row per
  agent. Do not collapse `measure` back to a single `Measurement`.
- **`integrity_summary: Mapping[str, int]`** keyed by `IntegrityStatus.value`
  (`"verified"/"unverified"/"broken"`). A frozen dataclass with a `Mapping` field is
  **not hashable** — that's fine; report types are never used as dict keys / set
  members. Do not work around it by setting `eq=False`.
- `AuditEvidence.record` holds the decoded proto **as-is** (no copy, no projection).
- All dataclasses are `frozen=True`. Defaults are only where shown
  (`EvidenceRef.seq/request_id`, `Measurement.subject/notes`).

### 3.4 `treval/__init__.py`

Re-export the public surface so callers do `from treval import Measurement, ...`:
the enum, all 7 dataclasses, and the 3 Protocols. Define `__all__`. No logic.

## 4. CI wiring (extend `.github/workflows/ci.yml`)

Minimal, surgical edits — `treval` joins the same gates `tools` has:

- `mypy tools` → `mypy tools treval`
- `bandit -r tools` → `bandit -r tools treval`
- pytest coverage: add `--cov=treval` alongside `--cov=tools` (keep the 60% gate).
- `ruff check .` / `ruff format --check .` already cover `treval` (no change).
- No new third-party dependency in EV-0 (ir-spec proto is already in
  `requirements.txt`; PyYAML arrives later with EV-3/EV-6).

## 5. Acceptance criteria (you write the unit tests)

1. `import treval` succeeds; `treval/py.typed` exists and is packaged.
2. `mypy tools treval` clean on **3.11 and 3.12**; `ruff check .` and
   `ruff format --check .` clean.
3. Every dataclass is `frozen=True`: constructing one with the documented fields
   and reading them back is equal; attempting to set an attribute raises
   `FrozenInstanceError` (assert this for at least one).
4. `IntegrityStatus` has exactly `VERIFIED/UNVERIFIED/BROKEN` with the string
   values above (assert the values — they're a stable contract).
5. `Measurement.subject` defaults to `""`; `Measurement.notes` to `""`;
   `EvidenceRef.seq`/`request_id` to `None`; `MaturityReport.verification_basis`
   to `"wal"`.
6. A test-local **dummy** `AuditEvidenceReader`, `PostureProvider`, and `Indicator`
   each satisfy their Protocol: assign an instance to a variable annotated as the
   Protocol type so `mypy` enforces structural conformance. The dummy `Indicator`
   returns `tuple[Measurement, ...]`; include one case returning a single
   `sample_size=0` aggregate (constructed by hand — **no logic in EV-0**).
7. New paths are CI-green.

## 6. Non-goals (explicitly out of scope)

- Any reader / indicator / rubric **logic** or **I/O** (EV-1/EV-3/EV-4+).
- The shared RequestContext decoder extraction from `wal_dump.py` (that's **EV-1**).
- `MaturityReport` JSON serialization / key ordering (that's **EV-7**).
- `satisfied_when` grammar, registry YAML, PyYAML (EV-6 / EV-3).
- Validation of field values (e.g. "dimension must be one of 5") — models are dumb
  carriers in EV-0; validation lives where data is produced/consumed.

## 7. Guardrails

- **Never import the closed platform.** Allowed deps: stdlib + the open
  `trustworthy_ai.v1` proto. (Charter §1.5 / §14.)
- **Determinism is a standing rule** for the whole engine: no clock, no RNG, no
  reliance on set/dict iteration order in anything that will be serialized. EV-0
  has no logic, but build the habit — and don't add `__hash__`-defeating tricks.
- Match the repo's existing style (`from __future__ import annotations`, precise
  type hints, frozen dataclasses, module docstrings like `tools/_wal_format.py`).
- Keep it small. If a file grows past the definitions, you've added logic that
  doesn't belong in EV-0.

## 8. Likely questions to raise back (don't guess — ask)

- Split `models.py` further, or keep enum+dataclasses together? (Default: one
  `models.py` is fine.)
- Anything about `integrity_summary` typing if `mypy` flags a `Mapping` default —
  it has no default here (required field); construct with a literal dict in tests.
- If the installed ir-spec import path differs from
  `trustworthy_ai.v1.request_context_pb2` on your machine, flag it (the venv may
  hold a pre-E1 build — `RequestContext` still exists there, so EV-0 is unaffected,
  but confirm before assuming).
