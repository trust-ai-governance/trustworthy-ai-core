"""PostureFileReader — the one reference PostureProvider core ships (EV-3).

Posture is the ATTESTED substrate: operator-declared facts telemetry can't see
(SSO enabled, IaC, SLA, red-team cadence). This reader loads a tenant-scoped
YAML/JSON attestation file and yields PostureEvidence. Custom providers (IAM,
GRC, SIEM, a future IaC scanner) are enterprise-authored — see
docs/POSTURE_PROVIDERS.md. The seam is safe because a provider can only emit
PostureEvidence (always attested), so it can never raise a measured ceiling.

MVP accepts unsigned attestations; attested_by is recorded as a plain claim.
Signature verification is a non-goal (a later item).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import yaml

from treval.models import EvidenceRef, PostureEvidence

# Required fields per attestation (attested_at_ns is optional, defaults to 0).
_REQUIRED = ("key", "value", "attested_by")


class PostureFileError(Exception):
    """The posture file is unparseable or missing a required field. Raised
    instead of silently skipping — a dropped attestation would quietly lower a
    maturity claim (fail-closed, Charter §4 spirit)."""


class PostureFileReader:
    """Reads a posture attestation file (satisfies treval.PostureProvider)."""

    provider_id: str = "file"

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def collect(self, *, tenant_id: str | None = None) -> Iterator[PostureEvidence]:
        try:
            raw = self._path.read_text(encoding="utf-8")
            doc = yaml.safe_load(raw)
        except (OSError, yaml.YAMLError) as e:
            raise PostureFileError(f"cannot read posture file {self._path}: {e}") from e

        if not isinstance(doc, dict):
            raise PostureFileError(
                f"posture file {self._path} must be a mapping with 'tenant_id' "
                f"and 'attestations'"
            )

        file_tenant = doc.get("tenant_id")
        if file_tenant is None:
            raise PostureFileError(f"posture file {self._path}: missing 'tenant_id'")

        attestations = doc.get("attestations")
        if not isinstance(attestations, list):
            raise PostureFileError(
                f"posture file {self._path}: 'attestations' must be a list"
            )

        if tenant_id is not None and file_tenant != tenant_id:
            return

        ref = EvidenceRef(source=f"attest:{self._path}")
        for i, att in enumerate(attestations):
            if not isinstance(att, dict):
                raise PostureFileError(
                    f"posture file {self._path}: attestation #{i} must be a mapping"
                )
            for field in _REQUIRED:
                if att.get(field) is None:
                    raise PostureFileError(
                        f"posture file {self._path}: attestation #{i} "
                        f"(key={att.get('key')!r}) missing required '{field}'"
                    )
                # YAML auto-types unquoted scalars (value: true -> bool, 99.5 ->
                # float); the model declares these str. Force unambiguous input.
                if not isinstance(att[field], str):
                    raise PostureFileError(
                        f"posture file {self._path}: attestation #{i} "
                        f"(key={att.get('key')!r}) '{field}' must be a string — "
                        f"quote the value"
                    )
            attested_at_ns = att.get("attested_at_ns", 0)
            if not isinstance(attested_at_ns, int) or isinstance(attested_at_ns, bool):
                raise PostureFileError(
                    f"posture file {self._path}: attestation #{i} "
                    f"(key={att['key']!r}) 'attested_at_ns' must be an integer"
                )
            yield PostureEvidence(
                ref=ref,
                tenant_id=file_tenant,
                key=att["key"],
                value=att["value"],
                attested_by=att["attested_by"],
                attested_at_ns=attested_at_ns,
            )
