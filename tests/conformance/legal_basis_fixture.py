"""Test-only loader for the final legal_basis_v1 conformance fixture."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from importlib import resources
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any

FIXTURE_ENV = "TRUSTAI_LEGAL_BASIS_FIXTURE"
EXPECTED_BUNDLE_PROTOCOL = {
    "pin_mismatch": "fail_closed",
    "hash_mismatch": "fail_closed",
    "provenance_missing": "fail_closed",
    "bundle_missing": "not_measured",
}


class FixtureError(Exception):
    """The conformance fixture itself is unreadable or malformed."""


class FixtureSchemaError(FixtureError):
    """The fixture schema, protocol, or case shape is not the agreed version."""


def _fixture_root(fixture_dir: str | Path | None) -> Traversable | Path:
    if fixture_dir is not None:
        if not str(fixture_dir).strip():
            raise FixtureSchemaError("fixture path is empty")
        return Path(fixture_dir)
    if FIXTURE_ENV in os.environ:
        env_dir = os.environ[FIXTURE_ENV]
        if not env_dir.strip():
            raise FixtureSchemaError("fixture path is empty")
        return Path(env_dir)
    try:
        return resources.files("trustworthy_ai_conformance").joinpath("legal_basis_v1")
    except (ImportError, ModuleNotFoundError) as exc:
        raise FixtureError("trustworthy_ai_conformance is not installed") from exc


def _validate_case(case: object, seen: set[str]) -> None:
    if not isinstance(case, Mapping):
        raise FixtureSchemaError("fixture case must be a mapping")
    case_id = case.get("case_id")
    if not isinstance(case_id, str) or not case_id:
        raise FixtureSchemaError("fixture case_id is required")
    if case_id in seen:
        raise FixtureSchemaError(f"duplicate fixture case_id {case_id!r}")
    seen.add(case_id)
    if not isinstance(case.get("spec_ref"), str) or not case.get("spec_ref"):
        raise FixtureSchemaError(f"{case_id}.spec_ref is required")
    kind = case.get("kind")
    if kind not in {"writer", "reader"}:
        raise FixtureSchemaError(f"{case_id}.kind must be writer or reader")
    expect = case.get("expect")
    if not isinstance(expect, Mapping):
        raise FixtureSchemaError(f"{case_id}.expect must be a mapping")
    if kind == "writer":
        decision = expect.get("decision")
        if decision not in {"allow", "deny"}:
            raise FixtureSchemaError(f"{case_id}.expect.decision is invalid")
        if (decision == "deny") != ("error_code" in expect):
            raise FixtureSchemaError(f"{case_id}.expect.error_code shape is invalid")
    else:
        resolution = expect.get("resolution")
        if resolution not in {"valid", "invalid", "not_measured"}:
            raise FixtureSchemaError(f"{case_id}.expect.resolution is invalid")


def load_fixture(fixture_dir: str | Path | None = None) -> Mapping[str, Any]:
    root = _fixture_root(fixture_dir)
    try:
        raw = root.joinpath("legal_basis_v1.json").read_bytes()
    except (OSError, AttributeError) as exc:
        raise FixtureError("cannot read legal_basis_v1.json") from exc
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FixtureError("legal_basis_v1.json is not valid JSON") from exc
    if not isinstance(payload, Mapping):
        raise FixtureError("legal_basis_v1.json must be a mapping")

    schema = payload.get("fixture_schema_version")
    if isinstance(schema, bool) or not isinstance(schema, int) or schema != 1:
        raise FixtureSchemaError(
            f"unsupported fixture_schema_version {schema!r}; expected 1"
        )

    registry = payload.get("registry")
    if not isinstance(registry, Mapping) or any(
        not isinstance(registry.get(key), str) or not registry.get(key).strip()
        for key in ("registry_version", "entries_sha256", "source_commit")
    ):
        raise FixtureSchemaError("fixture.registry is incomplete")

    if payload.get("bundle_protocol") != EXPECTED_BUNDLE_PROTOCOL:
        raise FixtureSchemaError(
            "fixture.bundle_protocol does not match the agreed four values"
        )

    cases = payload.get("cases")
    if not isinstance(cases, list):
        raise FixtureSchemaError("fixture.cases must be a list")
    seen: set[str] = set()
    for case in cases:
        _validate_case(case, seen)
    return payload
