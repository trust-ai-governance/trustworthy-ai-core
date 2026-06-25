# EV-3 — `PostureProvider` extension seam + `PostureFileReader`

> Dev brief. Self-contained with this file + the repo. Parent design:
> `docs/EVAL_ARCHITECTURE(WIP).md` §2.1 (the two substrates + the PostureProvider
> seam); `docs/EVAL_ISSUES(WIP).md` EV-3. Builds on **EV-0** (the `PostureProvider`
> Protocol + `PostureEvidence` are already defined on `main`).

## 0. Context

Posture is the **attested** substrate — operator-declared facts telemetry can't see
(SSO enabled, IaC, SLA, red-team cadence). EV-3 ships the **one reference provider**
(`PostureFileReader`) plus the documented extension seam so enterprises can plug in
their own providers (IAM/GRC/SIEM exporters, a future IaC scanner) **without forking
the engine**. The invariant that makes the seam safe: a provider can only emit
`PostureEvidence` (attested), so it can never raise a *measured* ceiling.

## 1. Scope

1. `treval/posture/file_reader.py::PostureFileReader` implementing the EV-0
   `PostureProvider` Protocol (`provider_id` + `collect(*, tenant_id=None)`).
2. Define + document the **posture file schema** (YAML/JSON).
3. `docs/POSTURE_PROVIDERS.md` — a short "write your own PostureProvider" guide that
   exposes the seam (per EV-3 acceptance).
4. Export `PostureFileReader` from `treval/__init__.py`.

PyYAML is **already** in `requirements.txt` — no dependency change.

## 2. Shared files touched (conflict map)

| File | Change | Risk |
|---|---|---|
| `treval/posture/__init__.py`, `treval/posture/file_reader.py` | **new** | none |
| `treval/__init__.py` | **append** `PostureFileReader` to imports + `__all__` | low (append-only) |
| `docs/POSTURE_PROVIDERS.md` | **new** | none |
| `tests/test_posture_file_reader.py` | **new** | none |

## 3. Posture file schema

A tenant-scoped list of attestations. Accept **YAML or JSON** (PyYAML's
`safe_load` parses both):

```yaml
tenant_id: default                 # required; file-level scope
attestations:
  - key: security.sso_mfa_enabled  # required
    value: "true"                  # required (string; typed interpretation is later)
    attested_by: jane@corp.example # required (operator accountability)
    attested_at_ns: 1782000000000000000   # optional (default 0 in MVP)
  - key: reliability.iac_provisioned
    value: "true"
    attested_by: ops-team
```

- **MVP accepts unsigned** attestations; `attested_by` is recorded as a plain claim.
  Signature verification is a **non-goal** (later item).
- `attested_at_ns` optional → default `0` (document this; note it's unsigned/MVP).

## 4. `PostureFileReader`

```python
class PostureFileReader:                       # satisfies treval.PostureProvider
    provider_id: str = "file"
    def __init__(self, path: str | Path) -> None: ...
    def collect(self, *, tenant_id: str | None = None) -> Iterator[PostureEvidence]: ...
```

Behavior:

- Load the file (`yaml.safe_load`). For each attestation, yield:
  ```python
  PostureEvidence(
      ref=EvidenceRef(source=f"attest:{path}"),
      tenant_id=<file tenant_id>,
      key=…, value=…, attested_by=…, attested_at_ns=… or 0,
  )
  ```
- `collect(tenant_id=X)` → yield only if the file's `tenant_id == X`; `None` =
  no filter.
- **Fail-closed on malformed input:** a missing **required** field
  (`tenant_id`/`key`/`value`/`attested_by`), or unparseable file, raises a **clear
  error** — never silently skips an attestation (a dropped attestation would
  silently lower a maturity claim). Use a typed error (e.g. `PostureFileError`).
- Deterministic: yield in file order.

## 5. The safety invariant (test it)

`PostureEvidence` (EV-0) carries only attested provenance — there is **no field a
provider could use to inject a measured signal**. Add a test that documents/locks
this: assert `PostureEvidence`'s field set is exactly
`{ref, tenant_id, key, value, attested_by, attested_at_ns}` — i.e. no
`Measurement`/`value-as-signal`/`integrity` field. This is the type-level guarantee
that custom providers extend evidence *sources* without relaxing the
`min(measured, attested)` gate.

## 6. Acceptance (you write the unit tests)

1. Read a sample `posture.yaml` → list of `PostureEvidence`, each with `attested_by`
   populated and `attested_at_ns` defaulting to `0` when omitted.
2. A JSON posture file parses to the identical evidence (same loader path).
3. Missing a required field → clear `PostureFileError` (fail-closed), **not** a
   silent skip. `collect(tenant_id=…)` filters by file scope.
4. **Seam proof:** a second, test-local dummy `PostureProvider` (e.g. an in-memory
   list provider) satisfies the Protocol and feeds the same downstream — typecheck +
   runtime.
5. **Invariant test** from §5.
6. Coverage ≥ 60%; `mypy treval` + ruff clean.

## 7. `docs/POSTURE_PROVIDERS.md` (the seam doc)

Short, concrete: the `PostureProvider` Protocol signature, the `PostureEvidence`
fields a provider must fill, the attested-only invariant (can't raise a measured
ceiling), and a ~15-line worked example of a custom provider (e.g. "read SSO state
from our IAM export"). State plainly that IAM/IaC/SIEM providers are
**enterprise-authored**, not shipped by core.

## 8. Non-goals

- Signature/attestation verification scheme.
- Any concrete IAM / IaC-scan / SIEM provider (enterprise-authored / future).
- Registry content or rubric evaluation (EV-6 / EV-7).

## 9. Guardrails

- `yaml.safe_load` only (never `yaml.load`).
- Fail-closed on malformed input (Charter §4 spirit) — clear errors, no silent drop.
- Never import the closed platform. Deterministic (file order, no clock/RNG).

## 10. Likely questions

- File schema: file-level `tenant_id` (chosen) vs per-attestation tenant? (Default:
  file-level — simplest, matches "tenant-scoped file".)
- Is `attested_at_ns=0` default acceptable for MVP unsigned attestations? (Yes —
  flagged as MVP; real timestamps/signing later.)
