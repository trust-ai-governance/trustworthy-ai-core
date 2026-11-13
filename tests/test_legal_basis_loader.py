"""Unit tests for the B-06 legal basis registry loader."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

import treval.legal_basis as lb


def _registry(
    *,
    version: str = "test-1",
    schema: int = 1,
    entries: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "registry_version": version,
        "registry_schema_version": schema,
        "entries": entries
        if entries is not None
        else [
            {
                "code": "PIPL_47_1",
                "entry_version": 1,
                "status": "ACTIVE",
                "allowed_operations": ["RETENTION_EXPIRED"],
            }
        ],
    }


def _write_bundle(
    root: Path,
    *,
    registry: dict[str, object] | None = None,
    manifest_overrides: dict[str, object] | None = None,
    provenance_overrides: dict[str, object] | None = None,
) -> lb.RegistryPin:
    root.mkdir(parents=True, exist_ok=True)
    reg = registry if registry is not None else _registry()
    registry_raw = json.dumps(reg, sort_keys=True).encode("utf-8")
    (root / "registry.json").write_bytes(registry_raw)
    digest = hashlib.sha256(registry_raw).hexdigest()

    manifest: dict[str, object] = {
        "registry_version": reg["registry_version"],
        "registry_schema_version": reg["registry_schema_version"],
        "entries_sha256": digest,
        "source_commit": "commit-1",
    }
    if manifest_overrides is not None:
        manifest.update(manifest_overrides)
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    provenance: dict[str, object] = {
        "registry_version": reg["registry_version"],
        "registry_schema_version": reg["registry_schema_version"],
        "entries_sha256": digest,
        "source_commit": "commit-1",
        "generator": "test",
    }
    if provenance_overrides is not None:
        provenance.update(provenance_overrides)
    (root / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")

    return lb.RegistryPin(
        registry_version=str(reg["registry_version"]),
        entries_sha256=str(manifest["entries_sha256"]),
        source_commit=str(manifest["source_commit"]),
    )


def _record(
    *,
    code: str = "PIPL_47_1",
    version: str = "1",
    record_type: int = int(rc_pb.AUDIT_RECORD_TYPE_COMPLIANCE_OPERATION),
    operation_type: int = int(rc_pb.COMPLIANCE_OPERATION_RETENTION_EXPIRED),
    legal_basis: bool = True,
    empty_legal_basis: bool = False,
) -> rc_pb.RequestContext:
    ctx = rc_pb.RequestContext()
    ctx.record_type = record_type
    if record_type != int(rc_pb.AUDIT_RECORD_TYPE_COMPLIANCE_OPERATION):
        return ctx
    op = ctx.compliance_operation
    op.operation_type = operation_type
    if legal_basis:
        if empty_legal_basis:
            op.legal_basis.SetInParent()
        else:
            op.legal_basis.code = code
            op.legal_basis.version = version
    return ctx


def _load(tmp_path: Path) -> tuple[Path, lb.RegistryPin, lb.LegalBasisRegistry]:
    root = tmp_path / "bundle"
    pin = _write_bundle(root)
    registry = lb.load_registry(root, pin=pin)
    assert registry is not None
    return root, pin, registry


def test_no_bundle_returns_none_and_not_measured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(lb.BUNDLE_ENV, raising=False)
    monkeypatch.setattr(lb, "_installed_bundle_root", lambda: None)
    assert lb.load_registry() is None
    assert (
        lb.resolve_legal_basis(_record(), None) is lb.LegalBasisResolution.NOT_MEASURED
    )


def test_installed_but_broken_package_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "trustworthy_ai_legal_basis"
    package.mkdir()
    (package / "__init__.py").write_text(
        "import missing_legal_basis_dependency\n", encoding="utf-8"
    )
    monkeypatch.delenv(lb.BUNDLE_ENV, raising=False)
    monkeypatch.syspath_prepend(str(tmp_path))
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry()


def test_empty_bundle_paths_are_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(lb.BUNDLE_ENV, "")
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry()
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(bundle_dir="")


def test_explicit_missing_bundle_does_not_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = tmp_path / "good"
    pin = _write_bundle(good)
    monkeypatch.setenv(lb.BUNDLE_ENV, str(good))
    monkeypatch.setattr(lb, "_installed_bundle_root", lambda: good)
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(tmp_path / "missing", pin=pin)


def test_env_missing_bundle_does_not_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = tmp_path / "good"
    pin = _write_bundle(good)
    monkeypatch.setattr(lb, "_installed_bundle_root", lambda: good)
    monkeypatch.setenv(lb.BUNDLE_ENV, str(tmp_path / "missing"))
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(pin=pin)


def test_unset_env_uses_installed_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    good = tmp_path / "good"
    pin = _write_bundle(good)
    monkeypatch.delenv(lb.BUNDLE_ENV, raising=False)
    monkeypatch.setattr(lb, "_installed_bundle_root", lambda: good)
    registry = lb.load_registry(pin=pin)
    assert registry is not None
    assert registry.registry_version == "test-1"


def test_valid_and_invalid_reader_resolutions(tmp_path: Path) -> None:
    _, _, registry = _load(tmp_path)
    assert lb.resolve_legal_basis(_record(), registry) is lb.LegalBasisResolution.VALID
    assert (
        lb.resolve_legal_basis(_record(code="UNKNOWN"), registry)
        is lb.LegalBasisResolution.INVALID
    )
    assert (
        lb.resolve_legal_basis(_record(version="2"), registry)
        is lb.LegalBasisResolution.INVALID
    )
    assert (
        lb.resolve_legal_basis(_record(empty_legal_basis=True), registry)
        is lb.LegalBasisResolution.INVALID
    )


def test_non_type7_is_not_measured(tmp_path: Path) -> None:
    _, _, registry = _load(tmp_path)
    non_type7 = _record(record_type=int(rc_pb.AUDIT_RECORD_TYPE_DECISION_MADE))
    assert (
        lb.resolve_legal_basis(non_type7, registry)
        is lb.LegalBasisResolution.NOT_MEASURED
    )


def test_required_operations_missing_or_empty_basis_are_invalid(
    tmp_path: Path,
) -> None:
    _, _, registry = _load(tmp_path)
    for operation_type in (
        rc_pb.COMPLIANCE_OPERATION_DELETE_ACCEPTED,
        rc_pb.COMPLIANCE_OPERATION_RETENTION_EXPIRED,
    ):
        missing = _record(
            operation_type=int(operation_type),
            legal_basis=False,
        )
        assert (
            lb.resolve_legal_basis(missing, registry) is lb.LegalBasisResolution.INVALID
        )
        empty = _record(
            operation_type=int(operation_type),
            legal_basis=True,
            empty_legal_basis=True,
        )
        assert (
            lb.resolve_legal_basis(empty, registry) is lb.LegalBasisResolution.INVALID
        )


def test_empty_basis_operations_are_not_measured(tmp_path: Path) -> None:
    _, _, registry = _load(tmp_path)
    for operation_type in (
        rc_pb.COMPLIANCE_OPERATION_KILL_SWITCH_ON,
        rc_pb.COMPLIANCE_OPERATION_KILL_SWITCH_OFF,
        rc_pb.COMPLIANCE_OPERATION_EVIDENCE_ISSUED,
    ):
        absent = _record(
            operation_type=int(operation_type),
            legal_basis=False,
        )
        assert (
            lb.resolve_legal_basis(absent, registry)
            is lb.LegalBasisResolution.NOT_MEASURED
        )
        empty = _record(
            operation_type=int(operation_type),
            legal_basis=True,
            empty_legal_basis=True,
        )
        assert (
            lb.resolve_legal_basis(empty, registry)
            is lb.LegalBasisResolution.NOT_MEASURED
        )
        nonempty = _record(
            operation_type=int(operation_type),
            legal_basis=True,
        )
        assert (
            lb.resolve_legal_basis(nonempty, registry)
            is lb.LegalBasisResolution.NOT_MEASURED
        )


def test_entry_version_is_parsed_as_int_and_status_is_normalized(
    tmp_path: Path,
) -> None:
    root = tmp_path / "version"
    pin = _write_bundle(
        root,
        registry=_registry(
            entries=[
                {
                    "code": "PIPL_47_1",
                    "entry_version": 1,
                    "status": "active",
                    "allowed_operations": ["RETENTION_EXPIRED"],
                }
            ]
        ),
    )
    registry = lb.load_registry(root, pin=pin)
    assert registry is not None
    assert (
        lb.resolve_legal_basis(_record(version="1"), registry)
        is lb.LegalBasisResolution.VALID
    )
    assert (
        lb.resolve_legal_basis(_record(version="01"), registry)
        is lb.LegalBasisResolution.INVALID
    )


def test_non_active_entry_is_invalid(tmp_path: Path) -> None:
    root = tmp_path / "inactive"
    pin = _write_bundle(
        root,
        registry=_registry(
            entries=[
                {
                    "code": "PIPL_47_1",
                    "entry_version": 1,
                    "status": "SUPERSEDED",
                    "allowed_operations": ["RETENTION_EXPIRED"],
                }
            ]
        ),
    )
    registry = lb.load_registry(root, pin=pin)
    assert registry is not None
    assert (
        lb.resolve_legal_basis(_record(), registry) is lb.LegalBasisResolution.INVALID
    )


@pytest.mark.parametrize(
    "field", ["registry_version", "entries_sha256", "source_commit"]
)
def test_pin_mismatch_is_fail_closed(tmp_path: Path, field: str) -> None:
    root = tmp_path / "bundle"
    pin = _write_bundle(root)
    bad_pin = replace(pin, **{field: "different"})
    with pytest.raises(lb.LegalBasisPinMismatch):
        lb.load_registry(root, pin=bad_pin)


def test_registry_hash_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root)
    (root / "registry.json").write_bytes(b"tampered")
    with pytest.raises(lb.LegalBasisHashMismatch):
        lb.load_registry(root)


def test_provenance_missing_is_unavailable(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root)
    (root / "provenance.json").unlink()
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


def test_provenance_mismatch_is_pin_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, provenance_overrides={"source_commit": "other"})
    with pytest.raises(lb.LegalBasisPinMismatch):
        lb.load_registry(root)


def test_provenance_version_mismatch_is_pin_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, provenance_overrides={"registry_version": "other"})
    with pytest.raises(lb.LegalBasisPinMismatch):
        lb.load_registry(root)


def test_provenance_hash_mismatch_is_pin_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, provenance_overrides={"entries_sha256": "other"})
    with pytest.raises(lb.LegalBasisPinMismatch):
        lb.load_registry(root)


def test_provenance_schema_mismatch_is_unavailable(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, provenance_overrides={"registry_schema_version": 2})
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


@pytest.mark.parametrize(
    "field",
    ["registry_version", "registry_schema_version", "entries_sha256", "source_commit"],
)
def test_manifest_missing_pin_field_is_unavailable(tmp_path: Path, field: str) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, manifest_overrides={field: None})
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


@pytest.mark.parametrize(
    "field",
    ["registry_version", "registry_schema_version", "entries_sha256", "source_commit"],
)
def test_provenance_missing_pin_field_is_unavailable(
    tmp_path: Path, field: str
) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, provenance_overrides={field: None})
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


def test_registry_and_manifest_version_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, manifest_overrides={"registry_version": "other"})
    with pytest.raises(lb.LegalBasisPinMismatch):
        lb.load_registry(root)


def test_manifest_schema_mismatch_is_unavailable(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, manifest_overrides={"registry_schema_version": 2})
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


def test_forbidden_entry_hash_order(tmp_path: Path) -> None:
    root = tmp_path / "forbidden"
    forbidden = _registry(
        entries=[
            {
                "code": "PIPL_19",
                "entry_version": 1,
                "status": "ACTIVE",
                "allowed_operations": ["DELETE_REQUESTED"],
            }
        ]
    )
    _write_bundle(root, registry=forbidden)
    with pytest.raises(lb.LegalBasisEntryForbidden):
        lb.load_registry(root)

    bad_hash = tmp_path / "bad-hash"
    _write_bundle(
        bad_hash,
        registry=forbidden,
        manifest_overrides={"entries_sha256": "0" * 64},
    )
    with pytest.raises(lb.LegalBasisHashMismatch):
        lb.load_registry(bad_hash)


@pytest.mark.parametrize("name", ["registry.json", "manifest.json", "provenance.json"])
def test_individual_bundle_file_missing(tmp_path: Path, name: str) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root)
    (root / name).unlink()
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


def test_installed_bundle_missing_files_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(lb.BUNDLE_ENV, raising=False)
    monkeypatch.setattr(lb, "_installed_bundle_root", lambda: tmp_path)
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry()


def test_duplicate_entry_is_unavailable(tmp_path: Path) -> None:
    entry = {
        "code": "PIPL_47_1",
        "entry_version": 1,
        "status": "ACTIVE",
        "allowed_operations": ["RETENTION_EXPIRED"],
    }
    root = tmp_path / "bundle"
    _write_bundle(root, registry=_registry(entries=[entry, entry]))
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


def test_empty_entries_is_unavailable(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, registry=_registry(entries=[]))
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


@pytest.mark.parametrize("field", ["code", "entry_version", "status"])
def test_entry_missing_field_is_unavailable(tmp_path: Path, field: str) -> None:
    entry = {
        "code": "PIPL_47_1",
        "entry_version": 1,
        "status": "ACTIVE",
        "allowed_operations": ["RETENTION_EXPIRED"],
    }
    del entry[field]
    root = tmp_path / "bundle"
    _write_bundle(root, registry=_registry(entries=[entry]))
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


def test_invalid_registry_code_is_unavailable(tmp_path: Path) -> None:
    entry = {
        "code": "lowercase",
        "entry_version": 1,
        "status": "ACTIVE",
        "allowed_operations": ["RETENTION_EXPIRED"],
    }
    root = tmp_path / "bundle"
    _write_bundle(root, registry=_registry(entries=[entry]))
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


def test_blank_status_is_unavailable(tmp_path: Path) -> None:
    entry = {
        "code": "PIPL_47_1",
        "entry_version": 1,
        "status": " ",
        "allowed_operations": ["RETENTION_EXPIRED"],
    }
    root = tmp_path / "bundle"
    _write_bundle(root, registry=_registry(entries=[entry]))
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


@pytest.mark.parametrize("name", ["manifest.json", "provenance.json"])
def test_non_json_metadata_is_unavailable(tmp_path: Path, name: str) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root)
    (root / name).write_bytes(b"not-json")
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


def test_registry_schema_unknown_is_unavailable(tmp_path: Path) -> None:
    root = tmp_path / "bundle"
    _write_bundle(root, registry=_registry(schema=2))
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry(root)


def test_installed_bundle_corrupt_registry_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    corrupt = b"not-json"
    digest = hashlib.sha256(corrupt).hexdigest()
    (tmp_path / "registry.json").write_bytes(corrupt)
    (tmp_path / "manifest.json").write_text(
        json.dumps(
            {
                "registry_version": "test-1",
                "registry_schema_version": 1,
                "entries_sha256": digest,
                "source_commit": "commit-1",
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "provenance.json").write_text(
        json.dumps(
            {
                "registry_version": "test-1",
                "registry_schema_version": 1,
                "entries_sha256": digest,
                "source_commit": "commit-1",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv(lb.BUNDLE_ENV, raising=False)
    monkeypatch.setattr(lb, "_installed_bundle_root", lambda: tmp_path)
    with pytest.raises(lb.LegalBasisUnavailable):
        lb.load_registry()


def test_error_codes_match_shared_vocabulary() -> None:
    assert lb.LegalBasisUnavailable.code == "REGISTRY_UNAVAILABLE"
    assert lb.LegalBasisPinMismatch.code == "REGISTRY_PIN_MISMATCH"
    assert lb.LegalBasisHashMismatch.code == "REGISTRY_HASH_MISMATCH"
    assert lb.LegalBasisEntryForbidden.code == "REGISTRY_ENTRY_FORBIDDEN"
