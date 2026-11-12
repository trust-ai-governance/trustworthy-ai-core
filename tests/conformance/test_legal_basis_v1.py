"""Core reader conformance for the final legal_basis_v1 fixture."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from google.protobuf import json_format
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

import treval.legal_basis as lb
from legal_basis_fixture import FixtureSchemaError, load_fixture


def _records(
    fixture: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    writers = [c for c in fixture["cases"] if c["kind"] == "writer"]
    readers = [c for c in fixture["cases"] if c["kind"] == "reader"]
    return writers, readers


def _record(case: dict[str, Any]) -> rc_pb.RequestContext:
    return json_format.ParseDict(case["record"], rc_pb.RequestContext())


def test_frozen_fixture_inventory() -> None:
    fixture = load_fixture()
    writers, readers = _records(fixture)
    assert len(writers) == 65
    assert len(readers) == 3
    assert [c["case_id"] for c in readers] == [
        "read-valid-pipl-47-1",
        "read-invalid-unknown-code",
        "read-unavailable-no-bundle",
    ]


def test_reader_cases_without_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(lb.BUNDLE_ENV, raising=False)
    monkeypatch.setattr(lb, "_installed_bundle_root", lambda: None)

    fixture = load_fixture()
    writers, readers = _records(fixture)
    pin = lb.RegistryPin(**fixture["registry"])
    assert lb.load_registry(pin=pin) is None

    run = 0
    skipped = 0
    for case in readers:
        if case["case_id"] == "read-unavailable-no-bundle":
            expected = lb.LegalBasisResolution(case["expect"]["resolution"])
            assert expected is lb.LegalBasisResolution.NOT_MEASURED
            assert lb.resolve_legal_basis(_record(case), None) is expected
            run += 1
        else:
            # No pin-matching bundle: these cases are counted as skipped, never
            # run against a fabricated not_measured result.
            skipped += 1

    assert run == 1
    assert skipped == 2
    assert len(writers) == 65


def test_reader_cases_with_bundle() -> None:
    fixture = load_fixture()
    _writers, readers = _records(fixture)
    pin = lb.RegistryPin(**fixture["registry"])

    registry = lb.load_registry(pin=pin)
    if registry is None:
        pytest.skip("no pin-matching trustworthy_ai_legal_basis bundle installed")

    run = 0
    skipped = 0
    for case in readers:
        if case["case_id"] == "read-unavailable-no-bundle":
            # This is a runner mode, not a case that can be run with a bundle.
            skipped += 1
            continue
        expected = lb.LegalBasisResolution(case["expect"]["resolution"])
        assert expected in {
            lb.LegalBasisResolution.VALID,
            lb.LegalBasisResolution.INVALID,
        }
        assert lb.resolve_legal_basis(_record(case), registry) is expected
        run += 1

    assert run == 2
    assert skipped == 1


def test_fixture_case_schema_is_validated(tmp_path: Any) -> None:
    base = copy.deepcopy(dict(load_fixture()))
    base["cases"][0]["kind"] = "unknown"
    (tmp_path / "legal_basis_v1.json").write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(FixtureSchemaError):
        load_fixture(tmp_path)

    base = copy.deepcopy(dict(load_fixture()))
    base["cases"][1]["case_id"] = base["cases"][0]["case_id"]
    (tmp_path / "legal_basis_v1.json").write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(FixtureSchemaError):
        load_fixture(tmp_path)

    base = copy.deepcopy(dict(load_fixture()))
    del base["cases"][0]["spec_ref"]
    (tmp_path / "legal_basis_v1.json").write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(FixtureSchemaError):
        load_fixture(tmp_path)


def test_fixture_schema_and_bundle_protocol_are_rejected(tmp_path: Any) -> None:
    base = copy.deepcopy(dict(load_fixture()))
    base["fixture_schema_version"] = 2
    (tmp_path / "legal_basis_v1.json").write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(FixtureSchemaError):
        load_fixture(tmp_path)

    base = copy.deepcopy(dict(load_fixture()))
    base["bundle_protocol"]["unknown"] = "fail_closed"
    (tmp_path / "legal_basis_v1.json").write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(FixtureSchemaError):
        load_fixture(tmp_path)

    base = copy.deepcopy(dict(load_fixture()))
    base["bundle_protocol"]["pin_mismatch"] = "unknown"
    (tmp_path / "legal_basis_v1.json").write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(FixtureSchemaError):
        load_fixture(tmp_path)
