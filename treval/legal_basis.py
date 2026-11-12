"""B-06 legal basis registry loader and reader-side resolution.

Reads the private ``trustworthy_ai_legal_basis`` bundle (``registry.json``,
``manifest.json``, ``provenance.json``), verifies its pin/hash/provenance, and
answers one read-side question: is a type-7 record's legal basis valid, invalid,
or not measured? It does not implement the Platform writer's operation,
lineage, or forbidden-basis checks.
"""

from __future__ import annotations

import enum
import hashlib
import importlib.util
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

if TYPE_CHECKING:
    from trustworthy_ai.v1.request_context_pb2 import RequestContext

BUNDLE_ENV = "TRUSTAI_LEGAL_BASIS_BUNDLE"

_CODE_RE = re.compile(r"[A-Z][A-Z0-9_]*")
_FORBIDDEN_ENTRY_CODES = frozenset({"PIPL_19", "CSL_37"})
_OPS_WITHOUT_LEGAL_BASIS = frozenset(
    {
        rc_pb.COMPLIANCE_OPERATION_KILL_SWITCH_ON,
        rc_pb.COMPLIANCE_OPERATION_KILL_SWITCH_OFF,
        rc_pb.COMPLIANCE_OPERATION_EVIDENCE_ISSUED,
    }
)


class LegalBasisError(Exception):
    code: str | None = None


class LegalBasisUnavailable(LegalBasisError):
    code = "REGISTRY_UNAVAILABLE"


class LegalBasisPinMismatch(LegalBasisError):
    code = "REGISTRY_PIN_MISMATCH"


class LegalBasisHashMismatch(LegalBasisError):
    code = "REGISTRY_HASH_MISMATCH"


class LegalBasisEntryForbidden(LegalBasisError):
    code = "REGISTRY_ENTRY_FORBIDDEN"


@dataclass(frozen=True)
class RegistryPin:
    registry_version: str
    entries_sha256: str
    source_commit: str


@dataclass(frozen=True)
class LegalBasisEntry:
    code: str
    entry_version: int
    status: str


@dataclass(frozen=True)
class LegalBasisRegistry:
    registry_version: str
    entries_sha256: str
    source_commit: str
    entries: Mapping[str, LegalBasisEntry]


class LegalBasisResolution(enum.Enum):
    VALID = "valid"
    INVALID = "invalid"
    NOT_MEASURED = "not_measured"


def _installed_bundle_root() -> Traversable | None:
    try:
        spec = importlib.util.find_spec("trustworthy_ai_legal_basis")
    except Exception as exc:
        raise LegalBasisUnavailable(
            "trustworthy_ai_legal_basis is installed but not importable"
        ) from exc
    if spec is None:
        return None
    try:
        return resources.files("trustworthy_ai_legal_basis")
    except Exception as exc:
        raise LegalBasisUnavailable(
            "trustworthy_ai_legal_basis is installed but not importable"
        ) from exc


def _bundle_root(bundle_dir: str | Path | None) -> Traversable | Path | None:
    if bundle_dir is not None:
        if not str(bundle_dir).strip():
            raise LegalBasisUnavailable("legal basis bundle path is empty")
        root = Path(bundle_dir)
        if not root.is_dir():
            raise LegalBasisUnavailable(f"legal basis bundle not found: {root}")
        return root
    if BUNDLE_ENV in os.environ:
        env_dir = os.environ[BUNDLE_ENV]
        if not env_dir.strip():
            raise LegalBasisUnavailable("legal basis bundle path is empty")
        root = Path(env_dir)
        if not root.is_dir():
            raise LegalBasisUnavailable(f"legal basis bundle not found: {root}")
        return root
    return _installed_bundle_root()


def _read_bytes(root: Traversable | Path, name: str) -> bytes:
    try:
        return root.joinpath(name).read_bytes()
    except (OSError, AttributeError) as exc:
        raise LegalBasisUnavailable(f"cannot read {name}") from exc


def _load_json(raw: bytes, where: str) -> Mapping[str, Any]:
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise LegalBasisUnavailable(f"{where} is not valid JSON") from exc
    if not isinstance(payload, Mapping):
        raise LegalBasisUnavailable(f"{where} must be a mapping")
    return payload


def _required_str(mapping: Mapping[str, Any], key: str, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise LegalBasisUnavailable(f"{where}.{key} is required")
    return value


def _required_int(mapping: Mapping[str, Any], key: str, where: str) -> int:
    value = mapping.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise LegalBasisUnavailable(f"{where}.{key} must be an integer")
    return value


def _parse_registry(
    payload: Mapping[str, Any],
) -> tuple[str, dict[str, LegalBasisEntry]]:
    schema = _required_int(payload, "registry_schema_version", "registry")
    if schema != 1:
        raise LegalBasisUnavailable(
            f"unsupported registry_schema_version {schema}; expected 1"
        )
    version = _required_str(payload, "registry_version", "registry")

    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list) or not raw_entries:
        raise LegalBasisUnavailable("registry.entries must be a non-empty list")

    entries: dict[str, LegalBasisEntry] = {}
    for raw in raw_entries:
        if not isinstance(raw, Mapping):
            raise LegalBasisUnavailable("registry entry must be a mapping")
        code = _required_str(raw, "code", "registry entry")
        if _CODE_RE.fullmatch(code) is None:
            raise LegalBasisUnavailable(f"invalid registry code {code!r}")
        if code in _FORBIDDEN_ENTRY_CODES:
            raise LegalBasisEntryForbidden(
                f"{code} is not allowed in the legal basis registry"
            )
        entry_version = _required_int(raw, "entry_version", code)
        if entry_version < 1:
            raise LegalBasisUnavailable(f"{code}.entry_version must be >= 1")
        status = _required_str(raw, "status", code).strip().upper()
        if not status:
            raise LegalBasisUnavailable(f"{code}.status must not be blank")
        if code in entries:
            raise LegalBasisUnavailable(f"duplicate registry entry {code}")
        entries[code] = LegalBasisEntry(
            code=code,
            entry_version=entry_version,
            status=status,
        )
    return version, entries


def load_registry(
    bundle_dir: str | Path | None = None,
    *,
    pin: RegistryPin | None = None,
) -> LegalBasisRegistry | None:
    """Load and verify the legal basis bundle.

    ``pin`` is an optional identity check applied only when a bundle is present;
    no declared bundle and no installed package still returns ``None``
    (``not_measured``). A declared-but-unreadable bundle always raises a
    ``LegalBasisError``.
    """
    root = _bundle_root(bundle_dir)
    if root is None:
        return None

    registry_raw = _read_bytes(root, "registry.json")
    manifest_raw = _read_bytes(root, "manifest.json")
    provenance_raw = _read_bytes(root, "provenance.json")

    manifest = _load_json(manifest_raw, "manifest.json")
    manifest_version = _required_str(manifest, "registry_version", "manifest")
    manifest_schema = _required_int(manifest, "registry_schema_version", "manifest")
    manifest_sha = _required_str(manifest, "entries_sha256", "manifest")
    manifest_source = _required_str(manifest, "source_commit", "manifest")

    digest = hashlib.sha256(registry_raw).hexdigest()
    if digest != manifest_sha:
        raise LegalBasisHashMismatch(
            "registry.json sha256 does not match manifest.entries_sha256"
        )

    registry = _load_json(registry_raw, "registry.json")
    registry_version, entries = _parse_registry(registry)

    provenance = _load_json(provenance_raw, "provenance.json")
    provenance_version = _required_str(provenance, "registry_version", "provenance")
    provenance_schema = _required_int(
        provenance, "registry_schema_version", "provenance"
    )
    provenance_sha = _required_str(provenance, "entries_sha256", "provenance")
    provenance_source = _required_str(provenance, "source_commit", "provenance")

    if manifest_schema != 1 or provenance_schema != 1:
        raise LegalBasisUnavailable(
            "unsupported registry_schema_version in manifest/provenance; expected 1"
        )
    if registry_version != manifest_version or registry_version != provenance_version:
        raise LegalBasisPinMismatch("registry version differs across bundle files")
    if manifest_sha != provenance_sha:
        raise LegalBasisPinMismatch("entries_sha256 differs across bundle files")
    if manifest_source != provenance_source:
        raise LegalBasisPinMismatch("source_commit differs across bundle files")

    if pin is not None and (
        pin.registry_version != manifest_version
        or pin.entries_sha256 != manifest_sha
        or pin.source_commit != manifest_source
    ):
        raise LegalBasisPinMismatch("bundle does not match the fixture pin")

    return LegalBasisRegistry(
        registry_version=manifest_version,
        entries_sha256=digest,
        source_commit=manifest_source,
        entries=entries,
    )


def resolve_legal_basis(
    record: RequestContext,
    registry: LegalBasisRegistry | None,
) -> LegalBasisResolution:
    """Resolve only the record's legal basis; never validates writer rules."""
    if registry is None:
        return LegalBasisResolution.NOT_MEASURED
    if record.record_type != rc_pb.AUDIT_RECORD_TYPE_COMPLIANCE_OPERATION:
        return LegalBasisResolution.NOT_MEASURED
    if not record.HasField("compliance_operation"):
        return LegalBasisResolution.NOT_MEASURED
    operation = record.compliance_operation
    if operation.operation_type in _OPS_WITHOUT_LEGAL_BASIS:
        return LegalBasisResolution.NOT_MEASURED
    if not operation.HasField("legal_basis"):
        return LegalBasisResolution.INVALID

    basis = operation.legal_basis
    code = str(basis.code)
    version = str(basis.version)
    if not code:
        return LegalBasisResolution.INVALID
    entry = registry.entries.get(code)
    if entry is None:
        return LegalBasisResolution.INVALID
    if entry.status.upper() != "ACTIVE":
        return LegalBasisResolution.INVALID
    if not version or str(entry.entry_version) != version:
        return LegalBasisResolution.INVALID
    return LegalBasisResolution.VALID
