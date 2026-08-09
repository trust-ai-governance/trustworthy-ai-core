"""UI-3 §3.3 / UI-3-AUTH — credential logic, unit-tested off HTTP (§11: the one authz module must be
testable without a server). The cross-tenant boundary is a 403 (over-reach), a key mismatch is a 404
(don't confirm existence), admin is an explicit `*` row, and a missing map fails closed.

UI-3-AUTH additions: the object-format map (label / scope / expires_at) fails closed and names the
offending row by LABEL — never the token; old str→tenant rows still start (WARN, acceptance 14); an
expired key resolves like an unknown one (acceptance 3); and TokenMap hot-reloads on file change —
revoke-by-delete (4), scope-change (5), and last-good-on-corrupt (6)."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone

import pytest

from treval.web.cases_auth import (
    CasesAuthError,
    Forbidden,
    TokenInfo,
    TokenMap,
    can_see_tenant,
    failure_delay_seconds,
    load_token_map,
    resolve_query_tenant,
    scope_for_token,
)

FUTURE = "2099-12-31T00:00:00Z"


def _map(tmp_path, obj):
    p = tmp_path / "tok.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return p


def _bump_mtime(path):
    # 🔴 the change signature is (mtime, size), so make a rewrite's mtime distinct (a real edit lands
    # at a later instant; here we set it explicitly so the reload is deterministic, never flaky).
    ns = path.stat().st_mtime_ns + 1_000_000_000
    os.utime(path, ns=(ns, ns))


# --------------------------------------------------------------------------- #
# load_token_map — the object format + fail-closed validation
# --------------------------------------------------------------------------- #


def test_load_token_map_object_format(tmp_path):
    m = load_token_map(
        _map(
            tmp_path,
            {
                "k": {
                    "label": "auditor-acme",
                    "scope": "acme",
                    "expires_at": FUTURE,
                    "note": "Q4 audit",
                }
            },
        )
    )
    info = m["k"]
    assert isinstance(info, TokenInfo)
    assert info.label == "auditor-acme" and info.scope == "acme"
    assert info.note == "Q4 audit" and not info.legacy
    assert info.expires_at is not None and info.expires_at.year == 2099


@pytest.mark.parametrize(
    "obj",
    [{}, {"": "acme"}, {"tok": ""}, {"tok": 1}, [1, 2], "nope"],
)
def test_load_token_map_fails_closed_on_bad_input(tmp_path, obj):
    with pytest.raises(CasesAuthError):
        load_token_map(_map(tmp_path, obj))


@pytest.mark.parametrize(
    "obj",
    [
        {"k": {"scope": "acme", "expires_at": FUTURE}},  # missing label
        {"k": {"label": "a", "expires_at": FUTURE}},  # missing scope
        {
            "k": {"label": "a", "scope": "acme"}
        },  # 🔴 missing expires_at — no permanent keys (§3.1)
        {
            "k": {"label": "a", "scope": "acme", "expires_at": "not-a-date"}
        },  # unparseable
        {  # 🔴 duplicate label — label must be globally unique (§2.1)
            "k1": {"label": "dup", "scope": "acme", "expires_at": FUTURE},
            "k2": {"label": "dup", "scope": "beta", "expires_at": FUTURE},
        },
    ],
)
def test_object_format_fails_closed(tmp_path, obj):
    with pytest.raises(CasesAuthError):
        load_token_map(_map(tmp_path, obj))


def test_error_message_never_leaks_the_token(tmp_path):
    """🔴 §5: a fail-closed message names the row by label/index, NEVER by its token — a token in a log
    line is a leaked key. RED input: interpolate the token into the error string."""
    secret = "super-secret-key-DO-NOT-LOG"
    with pytest.raises(CasesAuthError) as ei:
        load_token_map(_map(tmp_path, {secret: {"label": "a", "scope": "acme"}}))
    assert secret not in str(ei.value)


def test_load_token_map_missing_file_fails_closed(tmp_path):
    with pytest.raises(CasesAuthError, match="cannot read"):
        load_token_map(tmp_path / "nope.json")


def test_legacy_str_map_starts_with_warn_naming_rows(tmp_path, caplog):
    """🔴 acceptance 14: an old str→tenant map STILL starts (normalized to legacy TokenInfo that never
    expires) and logs ONE WARN naming the rows — NOT fail-closed. RED input: fail-close the old format
    (a fail-closed upgrade gets routed around by 'revert to the old version', §2.1)."""
    with caplog.at_level(logging.WARNING):
        m = load_token_map(_map(tmp_path, {"t1": "acme", "t2": "*"}))
    assert scope_for_token(m, "t1") == "acme" and scope_for_token(m, "t2") == "*"
    assert m["t1"].legacy and m["t1"].expires_at is None  # legacy never expires
    assert (
        "legacy" in caplog.text.lower() and "acme" in caplog.text
    )  # names the row (by tenant)


# --------------------------------------------------------------------------- #
# scope_for_token — semantics UNCHANGED (§6 non-goal), plus expiry
# --------------------------------------------------------------------------- #


def test_scope_for_token():
    future = datetime(2099, 1, 1, tzinfo=timezone.utc)
    m = {
        "tok-a": TokenInfo("auditor-acme", "acme", future),
        "tok-admin": TokenInfo("platform-admin", "*", future),
    }
    assert scope_for_token(m, "tok-a") == "acme"
    assert scope_for_token(m, "tok-admin") == "*"
    assert scope_for_token(m, "unknown") is None  # → access page / 404
    assert scope_for_token(m, None) is None
    assert scope_for_token(m, "") is None


def test_scope_for_token_expiry_resolves_like_unknown(tmp_path):
    """🔴 acceptance 3: an expired object key resolves EXACTLY like an unknown one (None), so §5 stays
    un-enumerable. RED input: return the scope for an expired key ('exists but expired' leaks)."""
    past = datetime(2000, 1, 1, tzinfo=timezone.utc)
    future = datetime(2099, 1, 1, tzinfo=timezone.utc)
    m = {"exp": TokenInfo("x", "acme", past), "ok": TokenInfo("y", "acme", future)}
    assert scope_for_token(m, "exp") is None  # expired == unknown
    assert scope_for_token(m, "ok") == "acme"
    # injectable `now`: the moment the key crosses its expiry, it flips to None (next request)
    now = datetime(2099, 1, 1, tzinfo=timezone.utc)
    assert scope_for_token(m, "ok", now=now) is None  # now >= expires_at
    # a legacy row (expires_at is None) never expires
    assert (
        scope_for_token({"leg": TokenInfo("z", "acme", None, legacy=True)}, "leg")
        == "acme"
    )


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


# --------------------------------------------------------------------------- #
# TokenMap — §3.3 hot reload (acceptance 4,5,6)
# --------------------------------------------------------------------------- #


def test_token_map_hot_reload_revokes_a_deleted_row(tmp_path):
    """🔴 acceptance 4: deleting a row ⇒ the NEXT lookup fails, no restart. RED input: keep serving a
    deleted token's scope."""
    p = _map(
        tmp_path,
        {
            "k1": {"label": "a", "scope": "acme", "expires_at": FUTURE},
            "k2": {"label": "b", "scope": "beta", "expires_at": FUTURE},
        },
    )
    tm = TokenMap(p)
    assert scope_for_token(tm.current(), "k2") == "beta"
    _map(tmp_path, {"k1": {"label": "a", "scope": "acme", "expires_at": FUTURE}})
    _bump_mtime(p)
    assert scope_for_token(tm.current(), "k2") is None  # revoked on the next request
    assert scope_for_token(tm.current(), "k1") == "acme"  # k1 still valid


def test_token_map_hot_reload_changes_scope(tmp_path):
    """🔴 acceptance 5: change a row's scope ⇒ the next request is judged by the NEW scope."""
    p = _map(tmp_path, {"k": {"label": "a", "scope": "acme", "expires_at": FUTURE}})
    tm = TokenMap(p)
    assert scope_for_token(tm.current(), "k") == "acme"
    _map(tmp_path, {"k": {"label": "a", "scope": "beta", "expires_at": FUTURE}})
    _bump_mtime(p)
    assert scope_for_token(tm.current(), "k") == "beta"


def test_token_map_keeps_last_good_on_corrupt_reload(tmp_path, caplog):
    """🔴 acceptance 6: an illegal-JSON edit ⇒ keep the LAST-GOOD map and log ERROR — NOT cleared
    (locks everyone out), NOT fallen open (lets everyone in). RED input: clear the map, or reload the
    broken one, on a corrupt file."""
    p = _map(tmp_path, {"k": {"label": "a", "scope": "acme", "expires_at": FUTURE}})
    tm = TokenMap(p)
    assert scope_for_token(tm.current(), "k") == "acme"
    p.write_text("{ this is not valid json", encoding="utf-8")
    _bump_mtime(p)
    with caplog.at_level(logging.ERROR):
        current = tm.current()
    assert scope_for_token(current, "k") == "acme"  # last-good kept
    assert (
        "LAST-GOOD" in caplog.text and str(p) in caplog.text
    )  # and it said so, at ERROR


def test_failure_delay_increments_and_caps():
    """§5 件D — the incrementing, kind-independent delay: strictly grows with the failure count, first
    failure already waits, and is capped so it can never wedge the process."""
    assert failure_delay_seconds(0) == failure_delay_seconds(
        1
    )  # a first failure still waits
    assert failure_delay_seconds(2) > failure_delay_seconds(1)
    assert failure_delay_seconds(10_000) <= 1.0  # capped
