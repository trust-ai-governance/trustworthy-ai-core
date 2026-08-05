"""UI-3 §3.3 — credential-scope logic, unit-tested off HTTP (§11: the one authz module must be
testable without a server). The cross-tenant boundary is a 403 (over-reach), a key mismatch is a 404
(don't confirm existence), admin is an explicit `*` row, and a missing map fails closed."""

from __future__ import annotations

import json

import pytest

from treval.web.cases_auth import (
    CasesAuthError,
    Forbidden,
    can_see_tenant,
    load_token_map,
    resolve_query_tenant,
    scope_for_token,
)


def _map(tmp_path, obj):
    p = tmp_path / "tok.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def test_load_token_map_reads_a_file(tmp_path):
    m = load_token_map(_map(tmp_path, {"tok-a": "acme", "tok-admin": "*"}))
    assert m == {"tok-a": "acme", "tok-admin": "*"}


@pytest.mark.parametrize(
    "obj",
    [{}, {"": "acme"}, {"tok": ""}, {"tok": 1}, [1, 2], "nope"],
)
def test_load_token_map_fails_closed_on_bad_input(tmp_path, obj):
    with pytest.raises(CasesAuthError):
        load_token_map(_map(tmp_path, obj))


def test_load_token_map_missing_file_fails_closed(tmp_path):
    with pytest.raises(CasesAuthError, match="cannot read"):
        load_token_map(tmp_path / "nope.json")


def test_scope_for_token():
    m = {"tok-a": "acme", "tok-admin": "*"}
    assert scope_for_token(m, "tok-a") == "acme"
    assert scope_for_token(m, "tok-admin") == "*"
    assert scope_for_token(m, "unknown") is None  # → 401
    assert scope_for_token(m, None) is None
    assert scope_for_token(m, "") is None


def test_can_see_tenant():
    assert can_see_tenant("*", "acme")  # admin sees all
    assert can_see_tenant("acme", "acme")
    assert not can_see_tenant("acme", "beta")  # → 404 at the key lookup


def test_resolve_query_tenant_scoped_is_a_boundary():
    assert resolve_query_tenant("acme", None) == "acme"  # defaults to own
    assert resolve_query_tenant("acme", "acme") == "acme"  # idempotent
    with pytest.raises(Forbidden):  # 🔴 403, not a silent fall-back to "acme"
        resolve_query_tenant("acme", "beta")


def test_resolve_query_tenant_admin_selects():
    assert resolve_query_tenant("*", None) is None  # admin, no selection → list all
    assert resolve_query_tenant("*", "acme") == "acme"  # admin selector
    assert resolve_query_tenant("*", "beta") == "beta"
