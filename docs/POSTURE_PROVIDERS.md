# Writing your own `PostureProvider`

Posture is the **attested** substrate of the eval engine — operator-declared
facts the runtime audit stream can't see (SSO/MFA enabled, IaC provisioning, SLA,
red-team cadence, AI Council exists). Core ships exactly **one** provider,
`PostureFileReader` (reads a YAML/JSON attestation file). Everything else —
IAM/Entra exporters, GRC/compliance connectors, SIEM queries, a future IaC
scanner — is **enterprise-authored**: you drop in your own provider **without
forking the engine**.

## The seam

A provider implements the `PostureProvider` Protocol (defined in
`treval.protocols`):

```python
class PostureProvider(Protocol):
    provider_id: str
    def collect(self, *, tenant_id: str | None = None) -> Iterator[PostureEvidence]: ...
```

`collect()` yields `PostureEvidence` (from `treval.models`). You must fill:

| field | meaning |
|---|---|
| `ref` | `EvidenceRef(source="...")` — where the fact came from, for drill-down |
| `tenant_id` | the tenant this attestation scopes to |
| `key` | the posture key a registry control objective references, e.g. `security.sso_mfa_enabled` |
| `value` | the attested value (string; typed interpretation happens in the rubric layer) |
| `attested_by` | the operator/identity making the claim (accountability) |
| `attested_at_ns` | when it was attested (`0` is acceptable for unsigned MVP claims) |

When `tenant_id` is passed, return only that tenant's evidence; `None` means no
filter.

## The attested-only invariant (why the seam is safe)

`PostureEvidence` carries **only attested provenance** — there is no field a
provider could use to inject a *measured* signal (no `Measurement`, no numeric
indicator value, no `IntegrityStatus`). Measured signals come **only** from the
chain-verified audit stream (the `AuditEvidenceReader` side). So a custom posture
provider can attest posture but **cannot raise the measured ceiling** — it extends
evidence *sources*, it does not relax the `min(measured, attested)` gate.

> A posture plugin therefore cannot fabricate a green light past what the audit
> data independently shows.

## Worked example — a custom provider over an IAM export

```python
from collections.abc import Iterator

from treval.models import EvidenceRef, PostureEvidence


class IamSsoProvider:
    """Reads SSO/MFA state from our IAM export and attests it as posture.

    Enterprise-authored — lives in your own tree, not in core.
    """

    provider_id = "iam-sso"

    def __init__(self, iam_export: dict, tenant: str) -> None:
        self._iam = iam_export
        self._tenant = tenant

    def collect(self, *, tenant_id: str | None = None) -> Iterator[PostureEvidence]:
        if tenant_id is not None and tenant_id != self._tenant:
            return
        yield PostureEvidence(
            ref=EvidenceRef(source="iam:prod-export-2026-06"),
            tenant_id=self._tenant,
            key="security.sso_mfa_enabled",
            value="true" if self._iam["mfa_enforced"] else "false",
            attested_by="iam-sync-bot",
            attested_at_ns=0,
        )
```

Register it the same way you'd use `PostureFileReader`: instantiate it and pass
it to the engine wherever posture providers are collected. No engine code
changes — that's the seam.
