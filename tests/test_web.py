"""Tests for treval-web — the read-only registry viewer (EV-W0).

Covers the pure serializer (§1 shape + invariants, no web deps) and the FastAPI
endpoints. Web-dependent tests skip cleanly when the optional `treval[web]` extra
(fastapi) is not installed — the core suite stays green without it.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from treval import load_registry
from treval.web.serialize import (
    DIMENSION_ORDER,
    LEVELS,
    LEVELS_META,
    serialize_registry,
)

_SAMPLE = Path(__file__).resolve().parents[1] / "docs" / "web" / "registry.sample.json"

# Starlette's TestClient emits a forward-deprecation about its httpx backend on
# import ("install httpx2 instead") — upstream and not actionable here. Silence
# just that one message so the web-test output stays clean.
pytestmark = pytest.mark.filterwarnings(
    "ignore:Using `httpx` with `starlette.testclient` is deprecated"
)


# --------------------------------------------------------------------------- #
# Serializer (pure — no web deps)
# --------------------------------------------------------------------------- #
def _serialized() -> dict:
    return serialize_registry(load_registry())


def test_serialize_top_level_shape():
    data = _serialized()
    assert data["schema_version"] == 1
    assert data["kind"] == "dimension_registry"
    assert [m["id"] for m in data["levels_meta"]] == list(LEVELS)
    assert len(data["dimensions"]) == 5


def test_dimensions_in_canonical_order():
    data = _serialized()
    assert [d["id"] for d in data["dimensions"]] == list(DIMENSION_ORDER)


def test_every_dimension_has_l1_to_l5_and_l1_empty():
    for dim in _serialized()["dimensions"]:
        assert list(dim["levels"]) == list(LEVELS)
        assert dim["levels"]["L1"] == []  # L1 is always the empty baseline


def test_objective_kind_invariants():
    """kind=='measured' ⟺ indicator_id set (+ satisfied_when, no posture_key);
    kind=='attested' ⟺ posture_key set (no indicator_id / satisfied_when)."""
    for dim in _serialized()["dimensions"]:
        for objs in dim["levels"].values():
            for o in objs:
                if o["kind"] == "measured":
                    assert o["indicator_id"] is not None
                    assert o["satisfied_when"] is not None
                    assert o["posture_key"] is None
                elif o["kind"] == "attested":
                    assert o["posture_key"] is not None
                    assert o["indicator_id"] is None
                    assert o["satisfied_when"] is None
                else:
                    pytest.fail(f"unexpected kind {o['kind']!r} on {o['id']}")


def test_objective_field_set_matches_contract():
    expected = {
        "id",
        "statement_zh",
        "kind",
        "indicator_id",
        "posture_key",
        "satisfied_when",
    }
    for dim in _serialized()["dimensions"]:
        for objs in dim["levels"].values():
            for o in objs:
                assert set(o) == expected


def test_serialize_is_deterministic():
    assert _serialized() == _serialized()


def test_levels_meta_is_bilingual_constant():
    for meta in LEVELS_META:
        assert set(meta) == {"id", "name_en", "name_zh"}


def test_serialized_structure_matches_sample():
    """Live serializer output and the committed sample agree on structure: same
    dimensions, same levels, and the same objective ids per (dimension, level).
    (Statement text may be refined independently — that's checked elsewhere.)"""
    sample = json.loads(_SAMPLE.read_text(encoding="utf-8"))
    live = _serialized()

    def skeleton(doc: dict) -> dict:
        return {
            dim["id"]: {
                lvl: [o["id"] for o in objs] for lvl, objs in dim["levels"].items()
            }
            for dim in doc["dimensions"]
        }

    assert skeleton(live) == skeleton(sample)


# --------------------------------------------------------------------------- #
# Lazy web extra — importing the serializer must NOT pull in FastAPI
# --------------------------------------------------------------------------- #
def test_serializer_import_does_not_require_fastapi():
    """`import treval` + the pure serializer must work with no web deps loaded —
    proves FastAPI/uvicorn/Jinja2 stay in the optional extra (run in a clean
    subprocess so an already-imported fastapi can't mask a leak)."""
    code = (
        "import sys; import treval; import treval.web.serialize; "
        "assert 'fastapi' not in sys.modules, 'fastapi leaked into core import'; "
        "assert 'uvicorn' not in sys.modules, 'uvicorn leaked into core import'"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


# --------------------------------------------------------------------------- #
# Endpoints (skip if the optional web extra is absent)
# --------------------------------------------------------------------------- #
@pytest.fixture
def client():
    pytest.importorskip("fastapi", reason="optional treval[web] extra not installed")
    from fastapi.testclient import TestClient

    from treval.web import create_app

    return TestClient(create_app())


def test_api_registry_returns_contract_shape(client):
    resp = client.get("/api/registry")
    assert resp.status_code == 200
    data = resp.json()
    assert data["schema_version"] == 1
    assert data["kind"] == "dimension_registry"
    assert [d["id"] for d in data["dimensions"]] == list(DIMENSION_ORDER)
    # endpoint output equals the pure serializer (no endpoint-side translation)
    assert data == _serialized()


def test_api_registry_is_deterministic(client):
    assert client.get("/api/registry").json() == client.get("/api/registry").json()


def test_index_renders_grid(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    body = resp.text
    # a measured objective + its drill-down fields are present in the SSR output
    assert "rob.l2.injection_rule_detection" in body
    assert "injection_catch_rate" in body
    assert "measured" in body and "attested" in body
    assert "N/A" in body  # L1 baseline cells


def test_read_only_no_mutating_routes(client):
    """No route mutates: POST/PUT/DELETE/PATCH on the known paths are rejected."""
    for method in ("post", "put", "delete", "patch"):
        for path in ("/", "/api/registry"):
            resp = getattr(client, method)(path)
            assert resp.status_code in (404, 405), (
                f"{method} {path} -> {resp.status_code}"
            )
