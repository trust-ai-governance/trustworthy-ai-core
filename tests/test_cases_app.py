"""UI-3 §10 — the case service (UI-3a). Acceptance 3, 7–14, each with the input that turns it red.

fastapi is required to exercise the routes; where it is absent these skip (like the report tests).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from trustworthy_ai.v1 import request_context_pb2 as rc_pb  # noqa: E402

from test_case_store import module_imports_wal_reader  # noqa: E402
from test_ev_r2 import _case, _probe  # noqa: E402
from treval.active_eval import serialize_case_contract  # noqa: E402
from treval.case_store import CaseStore, write_case_bundle  # noqa: E402
from treval.cli.cases_verify import _SCOPE_DECLARATION_ZH  # noqa: E402
from treval.web.cases_app import create_cases_app  # noqa: E402
from treval.web.cases_auth import CasesAuthError  # noqa: E402

_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_ROOT = Path(__file__).resolve().parents[1]


def _contract(tenant: str, *, with_detection_only: bool = False) -> dict:
    cases = [_case("s", technique="role_override"), _case("h", technique="delim")]
    results = [
        _probe("s", decision=_ALLOW, followed=True),
        _probe("h", decision=_BLOCK),
    ]
    if with_detection_only:
        # a no-marker case the gateway ALLOWED ⇒ declined_by_model, observable_via=None (block B)
        cases.append(_case("base64_smuggle", technique="base64_smuggle", marker=""))
        results.append(_probe("base64_smuggle", decision=_ALLOW, marker=""))
    return serialize_case_contract(
        cases, results, target_kind="gateway", tenant_id=tenant, generated_at_ns=1
    )


@pytest.fixture()
def store_dir(tmp_path):
    d = tmp_path / "casestore"
    write_case_bundle(
        d, json.dumps(_contract("acme", with_detection_only=True)), generated_at_ns=1
    )
    write_case_bundle(d, json.dumps(_contract("beta")), generated_at_ns=2)
    return d


@pytest.fixture()
def tokens(tmp_path):
    p = tmp_path / "tok.json"
    p.write_text(json.dumps({"tok-a": "acme", "tok-admin": "*"}), encoding="utf-8")
    return p


@pytest.fixture()
def client(store_dir, tokens):
    return TestClient(create_cases_app(store_dir=store_dir, tokens_path=tokens))


def _key_for(store_dir, tenant: str) -> str:
    return next(e.key for e in CaseStore(store_dir).list() if e.tenant_id == tenant)


def _h(tok: str) -> dict:
    return {"x-treval-token": tok}


def _is_access(text: str) -> bool:
    """The access page (§3.4) — the login form, not a data view."""
    return "case-loginform" in text


def _is_listing(text: str) -> bool:
    return "案级契约" in text and "case-loginform" not in text


def _snapshot(root: Path) -> dict[str, bytes]:
    """Every CONTRACT/index file under a store, path→bytes — for the acceptance-10 'teeth' (byte-for-
    byte unchanged). Excludes `access.jsonl`: 件C access logging is a NEW, legitimate write to the
    case-store side (UI-3-AUTH §4), separate from the contracts and index this snapshot protects."""
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file() and p.name != "access.jsonl"
    }


# --------------------------------------------------------------------------- #
# 12 — no map ⇒ refuse to start
# --------------------------------------------------------------------------- #


def test_no_token_map_refuses_to_start(store_dir, monkeypatch):
    """🔴 acceptance 12: no TREVAL_CASES_TOKENS ⇒ the app refuses to start (NOT 'no token = allow')."""
    monkeypatch.delenv("TREVAL_CASES_TOKENS", raising=False)
    with pytest.raises(CasesAuthError, match="refusing to start"):
        create_cases_app(store_dir=store_dir, tokens_path=None)


def test_unauthenticated_gets_the_access_page_not_a_401(client):
    """🔴 P1/§3.4: a human with no credential lands on the ACCESS PAGE (200), never a 401 JSON.
    The header/Bearer channels still authenticate directly (scripts/CI); a bad token also just
    re-shows the access page — nothing 401s."""
    home = client.get("/")
    assert home.status_code == 200 and _is_access(
        home.text
    )  # no credential ⇒ access page
    assert _is_listing(
        client.get("/", headers=_h("tok-a")).text
    )  # header channel authenticates
    assert _is_listing(client.get("/", headers={"authorization": "Bearer tok-a"}).text)
    bad = client.get("/", headers=_h("nope"))
    assert bad.status_code == 200 and _is_access(
        bad.text
    )  # bad token ⇒ access page, not 401


# --------------------------------------------------------------------------- #
# 3 — the cross-tenant triple
# --------------------------------------------------------------------------- #


def test_cross_tenant_triple(client, store_dir):
    """🔴 acceptance 3: ① scoped token asking for another tenant ⇒ 403 (not a silent fall-back);
    ② that tenant's key fetched directly ⇒ 404 (don't confirm existence); ③ its id never in the body."""
    # ① 403, not a silent fall-back to acme
    assert client.get("/?tenant=beta", headers=_h("tok-a")).status_code == 403
    # ② 404 on beta's key with acme's token (both /run and /cases.json)
    beta_key = _key_for(store_dir, "beta")
    assert client.get(f"/run?key={beta_key}", headers=_h("tok-a")).status_code == 404
    assert (
        client.get(f"/cases.json?key={beta_key}", headers=_h("tok-a")).status_code
        == 404
    )
    # ③ 'beta' appears nowhere in acme's listing
    body = client.get("/", headers=_h("tok-a")).text
    assert "beta" not in body and "acme" in body


def test_basic_auth_is_the_script_channel(client):
    """🔴 F3 (now the CI/script channel, superseded for browsers by the access page): HTTP Basic
    (password = token, username ignored — `curl -u :tok-a`) authenticates directly to the listing.
    A bad Basic token just re-shows the access page (no 401)."""
    import base64

    ok = base64.b64encode(b":tok-a").decode()
    assert _is_listing(client.get("/", headers={"authorization": f"Basic {ok}"}).text)
    bad = base64.b64encode(b":nope").decode()
    r = client.get("/", headers={"authorization": f"Basic {bad}"})
    assert r.status_code == 200 and _is_access(r.text)


def test_query_token_does_not_authenticate(client):
    """🔴 acceptance 16 (F3): `?token=` must NOT work — it would land in browser history, access logs
    and Referer. The credential travels only in a header/Basic/cookie, never the URL. An unknown
    `?token=` just yields the access page."""
    for r in (client.get("/?token=tok-a"), client.get("/?token=tok-admin")):
        assert r.status_code == 200 and _is_access(r.text)


def test_admin_sees_every_tenant(client):
    """The other half of §3.3: `*` is admin — it lists both tenants. 'admin sees all, tenant sees
    self', but the credential IS the identity (no login)."""
    body = client.get("/", headers=_h("tok-admin")).text
    assert "acme" in body and "beta" in body
    # admin can select a tenant, and can open beta's page
    assert client.get("/?tenant=beta", headers=_h("tok-admin")).status_code == 200


# --------------------------------------------------------------------------- #
# 6.1 / 6.2 — the recompute page
# --------------------------------------------------------------------------- #


def test_cases_json_is_stored_bytes_verbatim(client, store_dir):
    """🔴 §6.1: /cases.json is the STORED bytes, byte-for-byte (never re-serialized)."""
    key = _key_for(store_dir, "acme")
    got = client.get(f"/cases.json?key={key}", headers=_h("tok-a")).content
    entry = CaseStore(store_dir).get(key)
    assert got == CaseStore(store_dir).read_bytes(entry)


def test_run_page_carries_the_scope_declaration_constant(client, store_dir):
    """🔴 acceptance 11: the recompute page contains the scope declaration — and the test uses the
    CONSTANT itself, so editing cases_verify._SCOPE_DECLARATION_ZH (or dropping it from the page)
    reds this. A copied literal would not be caught. §12.1 件二: the PAGE carries the 中文 part only
    (the CLI still prints both); an English block operators skip is a warning that did not happen."""
    from markupsafe import (
        escape,
    )  # Jinja escapes `<audit-log>` → `&lt;…&gt;` (correct for display)

    key = _key_for(store_dir, "acme")
    html = client.get(f"/run?key={key}", headers=_h("tok-a")).text
    # derived FROM the constant, so editing _SCOPE_DECLARATION (or dropping it) still reds this
    assert str(escape(_SCOPE_DECLARATION_ZH)) in html
    assert "它不证明：探针真的跑过" in html  # the honest boundary is on the page
    # 🔴 §12.1 件二: the English block is NOT on the page (it is CLI-only)
    assert "WHAT THIS CHECK COVERS" not in html


def test_run_page_splits_by_denominator_block_b_is_invisible(client, store_dir):
    """🔴 acceptance 13: the null-observable_via case lands in block B ('INVISIBLE to the four cells')
    and is NOT in the four-cell count (declined_by_model stays 0 in the marker subset)."""
    key = _key_for(store_dir, "acme")
    html = client.get(f"/run?key={key}", headers=_h("tok-a")).text
    b_index = html.index("INVISIBLE to the four cells")
    assert (
        html.index("base64_smuggle") > b_index
    )  # the detection-only miss sits in block B
    # the declared four_cell (marker subset) does not count it: declined_by_model = 0
    assert "declined_by_model=0" in html


def test_run_banner_ticket_ref_not_in_visible_body(client, store_dir):
    """🔴 §12.1 ②: the internal ticket ref (EV-CIGATE F1 / §9.1) lives in the banner's title=
    attribute ONLY — never the visible 正文. RED input: put `（EV-CIGATE F1 / §9.1）` back in the body."""
    import re

    key = _key_for(store_dir, "acme")
    html = client.get(f"/run?key={key}", headers=_h("tok-a")).text
    visible = re.sub(r"<[^>]+>", "", html)  # strips tags AND their attributes
    assert "EV-CIGATE" not in visible and "§9.1" not in visible  # not in the 正文
    assert "EV-CIGATE" in html  # but retained in the title attribute (not lost)


def test_run_banner_first_line_names_the_reference(client, store_dir):
    """🔴 §12.1 ③: the banner's first line NAMES 「成熟度报告」 (someone opening /cases/ directly may
    never have seen it) and drops the reference-less 「另一次」. RED input: the old 「另一次评测运行」 banner."""
    key = _key_for(store_dir, "acme")
    html = client.get(f"/run?key={key}", headers=_h("tok-a")).text
    assert "本页与「成熟度报告」不是同一次评测" in html
    assert "另一次" not in html


def test_no_drilldown_wording_on_the_case_page(client, store_dir):
    """🔴 P2 (全站): 「下钻」 (drill-down, jargon) appears nowhere in the rendered case UI — the run
    page and the listing are '用例明细', a peer view, never a 'drill-down'."""
    key = _key_for(store_dir, "acme")
    assert "下钻" not in client.get(f"/run?key={key}", headers=_h("tok-a")).text
    assert "下钻" not in client.get("/", headers=_h("tok-a")).text


def test_run_page_shows_a_fork_when_stored_bytes_are_tampered(client, store_dir):
    """🔴 acceptance 7 (page side): the store rejects a non-re-adding contract at ingest, but if the
    stored bytes are tampered on disk, the page must SHOW the fork (not silently pass)."""
    key = _key_for(store_dir, "acme")
    entry = CaseStore(store_dir).get(key)
    doc = json.loads((store_dir / entry.file).read_text())
    doc["aggregates"]["injection_catch_rate"]["value"] = (
        0.999  # a lie the rows won't support
    )
    (store_dir / entry.file).write_text(json.dumps(doc), encoding="utf-8")
    html = client.get(f"/run?key={key}", headers=_h("tok-a")).text
    assert "分叉" in html and "injection_catch_rate" in html


# --------------------------------------------------------------------------- #
# 8,9,10 — structural guarantees
# --------------------------------------------------------------------------- #


def test_app_never_imports_the_active_eval_harness():
    """🔴 acceptance 8: the service cannot run a probe — it does not pull the harness."""
    code = (
        "import sys; import treval.web.cases_app; "
        "leaked = [m for m in sys.modules if m.startswith('treval.active_eval')]; "
        "assert not leaked, leaked"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=_ROOT
    )
    assert proc.returncode == 0, proc.stderr


def test_app_source_imports_no_wal_reader():
    """🔴 acceptance 9 / §7: the service never imports a WAL reader — add one and this reds."""
    import treval.web.cases_app as mod

    assert not module_imports_wal_reader(mod)


def test_read_only_no_mutating_routes_and_no_evidence(client):
    """acceptance 10: no POST/PUT/DELETE/PATCH; no /evidence (the EV-W1 D3 shape stays on the case
    service too)."""
    key = _key_for  # noqa: F841  (silence unused in some interpreters)
    for path in ("/", "/run", "/cases.json"):
        for method in ("post", "put", "delete", "patch"):
            assert getattr(client, method)(path, headers=_h("tok-a")).status_code in (
                404,
                405,
            )
    for path in ("/evidence", "/evidence/req-1"):
        assert client.get(path, headers=_h("tok-a")).status_code == 404


def test_responses_are_no_store_and_noindex(client, store_dir):
    key = _key_for(store_dir, "acme")
    resp = client.get(f"/run?key={key}", headers=_h("tok-a"))
    assert resp.headers["cache-control"] == "no-store"
    assert "noindex" in resp.headers["x-robots-tag"]


def test_case_page_carries_the_operator_only_warning(client):
    """§4 (revised per PM 2026-08-05): the case page now SHARES the main-app chrome (logo + banner
    colour + tables). The disclosure discipline rides the LOUD operator_only warning line that
    travels with any screenshot — asserted present, in its own warning style."""
    html = client.get("/", headers=_h("tok-a")).text
    assert "operator_only" in html and "case-warn" in html and "勿贴" in html


# --------------------------------------------------------------------------- #
# P1 (§3.4) — the human entry: access page ▸ session cookie ▸ logout
# --------------------------------------------------------------------------- #


def test_session_login_sets_cookie_and_opens_the_listing(store_dir, tokens):
    """🔴 P1: POST /session with a valid key ⇒ 303 + an HttpOnly/SameSite=Strict cookie holding the
    SAME shared secret; the cookie (no header) then opens the listing."""
    client = TestClient(create_cases_app(store_dir=store_dir, tokens_path=tokens))
    r = client.post(
        "/session", data={"key": "tok-a", "next": "/"}, follow_redirects=False
    )
    assert r.status_code == 303 and r.headers["location"] == "/"
    setc = r.headers.get("set-cookie", "")
    assert "treval_cases=tok-a" in setc and "httponly" in setc.lower()
    assert "samesite=strict" in setc.lower() and "path=/" in setc.lower()
    # the cookie now in the jar opens the listing with NO header
    assert _is_listing(client.get("/").text)


def test_wrong_key_stays_on_the_access_page_with_no_cookie(client):
    """🔴 P1: a wrong key ⇒ the access page again with a readable error — NOT a 401 JSON — and NO
    cookie is set (a bad secret never becomes a session)."""
    r = client.post(
        "/session", data={"key": "nope", "next": "/"}, follow_redirects=False
    )
    assert r.status_code == 200 and _is_access(r.text) and "无效" in r.text
    assert "set-cookie" not in r.headers


def test_logout_clears_the_cookie(client):
    """🔴 P1: /logout deletes the cookie and 303s back to the access page."""
    client.post("/session", data={"key": "tok-a", "next": "/"})
    r = client.get("/logout", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    # the delete-cookie clears the jar ⇒ back to the access page
    assert 'treval_cases=""' in r.headers.get("set-cookie", "").lower().replace(
        " ", ""
    ) or "treval_cases=;" in r.headers.get("set-cookie", "").replace(" ", "")
    assert _is_access(client.get("/").text)


def test_deep_link_without_a_cookie_redirects_to_the_access_page(client, store_dir):
    """🔴 P1: a browser opening /run (a deep link) with no cookie is 303'd to the access page, its
    destination preserved in ?next= — not a 401 JSON."""
    key = _key_for(store_dir, "acme")
    r = client.get(f"/run?key={key}", follow_redirects=False)
    assert r.status_code == 303
    loc = r.headers["location"]
    assert loc.startswith("/?next=") and quote(f"/run?key={key}", safe="") in loc


def test_open_redirect_in_next_is_sanitized(client):
    """🔴 P1: `next` is attacker-controllable (it rides the URL) — an off-site or scheme-relative
    target must fall back to the service root, never redirect off-origin."""
    for evil in (
        "//evil.example",
        "https://evil.example",
        "/\r/evil",
        "javascript:alert(1)",
    ):
        r = client.post(
            "/session", data={"key": "tok-a", "next": evil}, follow_redirects=False
        )
        assert r.status_code == 303 and r.headers["location"] == "/"


def test_session_writes_nothing_to_the_store(store_dir, tokens):
    """🔴 acceptance 10 (teeth): /session is the ONLY write route and it touches NO store — hammer it
    with good AND bad keys; the case store's files, bytes and index are byte-for-byte unchanged."""
    client = TestClient(create_cases_app(store_dir=store_dir, tokens_path=tokens))
    before = _snapshot(store_dir)
    for _ in range(5):
        client.post(
            "/session", data={"key": "tok-a", "next": "/"}, follow_redirects=False
        )
        client.post(
            "/session", data={"key": "nope", "next": "/"}, follow_redirects=False
        )
    assert _snapshot(store_dir) == before  # not one byte moved


# --------------------------------------------------------------------------- #
# 14 — mount does not leak the report token (and is off by default)
# --------------------------------------------------------------------------- #


def test_mount_keeps_its_own_auth(store_dir, tokens):
    """🔴 acceptance 14: mounted under the report app, `/cases/` still honours ONLY
    TREVAL_CASES_TOKENS — the report token never opens it (a mount is a separate app). With the
    access-page model the report token just gets the access page; the cases token gets the listing."""
    from treval.web.app import create_app

    report = create_app(store_dir=store_dir, token="report-secret")
    report.mount("/cases", create_cases_app(store_dir=store_dir, tokens_path=tokens))
    c = TestClient(report)
    r = c.get("/cases/", headers=_h("report-secret"))
    assert r.status_code == 200 and _is_access(
        r.text
    )  # report token ⇒ access page, not the data
    assert _is_listing(
        c.get("/cases/", headers=_h("tok-a")).text
    )  # cases token ⇒ listing


def test_mounted_internal_urls_are_prefixed(store_dir, tokens):
    """🔴 P1 (mount-correctness): under `/cases` every internal link the browser follows — the login
    form action, the stylesheet, the /run and /cases.json links, the deep-link redirect and the
    cookie Path — carries the `/cases` prefix, so the mounted deployment actually navigates."""
    from treval.web.app import create_app

    report = create_app(store_dir=store_dir, token="report-secret")
    report.mount("/cases", create_cases_app(store_dir=store_dir, tokens_path=tokens))
    c = TestClient(report)
    # access page: the form posts to the prefixed /session, stylesheet is prefixed
    access = c.get("/cases/").text
    assert 'action="/cases/session"' in access and "/cases/static/style.css" in access
    # deep link with no cookie ⇒ redirect to the PREFIXED access page
    key = _key_for(store_dir, "acme")
    r = c.get(f"/cases/run?key={key}", headers=_h("nope"), follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/cases/?next=")
    # login sets a cookie scoped to the mount path
    login = c.post(
        "/cases/session",
        data={"key": "tok-a", "next": "/cases/"},
        follow_redirects=False,
    )
    assert "path=/cases/" in login.headers.get("set-cookie", "").lower()
    # the listing's /run links and the run page's download link are prefixed too
    assert '"/cases/run?key=' in c.get("/cases/", headers=_h("tok-a")).text
    assert (
        "/cases/cases.json?key="
        in c.get(f"/cases/run?key={key}", headers=_h("tok-a")).text
    )


def test_cases_not_reachable_without_mount(store_dir):
    """🔴 acceptance 14: default (no TREVAL_CASES_MOUNT) ⇒ /cases/ is 404 on the report app."""
    from treval.web.app import create_app

    c = TestClient(create_app(store_dir=store_dir, token=None))
    assert c.get("/cases/").status_code == 404


# =========================================================================== #
# UI-3-AUTH — 件A 密钥有身份 · 件C 访问留痕 · 件D 不可枚举 (acceptance 1,2,3,7,8,9,11,12)
# =========================================================================== #

# distinctive keys so "the page HTML contains no token" (acceptance 1) is a MEANINGFUL grep
_KEY_A = "sentinel-acme-0a0a0a0a"
_KEY_B = "sentinel-beta-0b0b0b0b"
_KEY_ADMIN = "sentinel-admin-0d0d0d0d"
_KEY_EXPIRED = "sentinel-expired-0e0e0e"


@pytest.fixture()
def obj_tokens(tmp_path):
    """The UI-3-AUTH object-format map: label / scope / expires_at per key."""
    p = tmp_path / "tok_obj.json"
    p.write_text(
        json.dumps(
            {
                _KEY_A: {
                    "label": "auditor-acme",
                    "scope": "acme",
                    "expires_at": "2099-12-31T00:00:00Z",
                },
                _KEY_B: {
                    "label": "auditor-beta",
                    "scope": "beta",
                    "expires_at": "2099-12-31T00:00:00Z",
                },
                _KEY_ADMIN: {
                    "label": "platform-admin",
                    "scope": "*",
                    "expires_at": "2099-12-31T00:00:00Z",
                },
                _KEY_EXPIRED: {
                    "label": "expired-acme",
                    "scope": "acme",
                    "expires_at": "2000-01-01T00:00:00Z",
                },
            }
        ),
        encoding="utf-8",
    )
    return p


@pytest.fixture()
def obj_client(store_dir, obj_tokens):
    return TestClient(create_cases_app(store_dir=store_dir, tokens_path=obj_tokens))


def test_identity_is_visible_and_carries_no_key(obj_client):
    """🔴 acceptance 1: a signed-in page shows `以 <label> 身份查看` — and the page HTML contains NO
    token string. RED input: render the token, or drop the identity line."""
    html = obj_client.get("/", headers=_h(_KEY_A)).text
    assert "以" in html and "身份查看" in html and "auditor-acme" in html
    assert (
        _KEY_A not in html
    )  # 🔴 the key is never on the page (cookie is HttpOnly; ctx has no token)
    assert "有效至 2099-12-31" in html  # the expiry is shown


def test_admin_identity_is_explicit(obj_client):
    """🔴 acceptance 2: an admin (`scope="*"`) session says `全部租户（admin）` on the page. RED input:
    delete the admin marker — a session that can see every tenant's bypass map must say so."""
    html = obj_client.get("/", headers=_h(_KEY_ADMIN)).text
    assert "全部租户（admin）" in html and "platform-admin" in html


def test_rotation_reminder_within_14_days(store_dir, tmp_path):
    """§3.1: a key expiring in ≤14 days shows a rotation reminder (give ops time to rotate)."""
    soon = (datetime.now(timezone.utc) + timedelta(days=7)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    p = tmp_path / "tok_soon.json"
    p.write_text(
        json.dumps(
            {_KEY_A: {"label": "auditor-acme", "scope": "acme", "expires_at": soon}}
        ),
        encoding="utf-8",
    )
    c = TestClient(create_cases_app(store_dir=store_dir, tokens_path=p))
    assert "请轮换" in c.get("/", headers=_h(_KEY_A)).text


def test_expired_key_is_rejected_like_an_unknown_one(obj_client):
    """🔴 acceptance 3: an expired key is refused, and its rejection is byte-identical to an unknown
    key's — no 'expired' hint. RED input: a distinct message/status for the expired key."""
    # both land on the access page (no data), never a listing
    assert _is_access(obj_client.get("/", headers=_h(_KEY_EXPIRED)).text)
    assert _is_access(obj_client.get("/", headers=_h("totally-unknown")).text)


def test_access_log_gains_a_line_on_a_view(obj_client, store_dir):
    """🔴 acceptance 7: one successful /run ⇒ access.jsonl gains a line with `label` and `run_key`.
    RED input: delete the `_log_success` call in the /run route — this test goes red."""
    key = _key_for(store_dir, "acme")
    obj_client.get(f"/run?key={key}", headers=_h(_KEY_A))
    lines = (store_dir / "access.jsonl").read_text(encoding="utf-8").splitlines()
    assert any(
        '"view_run"' in ln and "auditor-acme" in ln and key in ln and '"ok": true' in ln
        for ln in lines
    )


def test_failed_login_never_writes_the_key(obj_client, store_dir):
    """🔴 acceptance 8: failing to log in with a sentinel key several times ⇒ the key appears 0 times
    in the log. RED input: log the submitted key (a key dictionary on disk)."""
    for _ in range(4):
        obj_client.post(
            "/session",
            data={"key": _KEY_A + "-wrong", "next": "/"},
            follow_redirects=False,
        )
    raw = (store_dir / "access.jsonl").read_text(encoding="utf-8")
    assert (_KEY_A + "-wrong") not in raw
    assert (
        '"ok": false' in raw and '"reason": "rejected"' in raw
    )  # but the failures ARE recorded


def test_write_failure_refuses_to_serve(obj_client, store_dir, tmp_path, monkeypatch):
    """🔴 acceptance 9: if the access line cannot be written, the request is REFUSED (503) — not served
    untraced. RED input: serve the run page anyway. Point the log at a directory so the append fails
    regardless of the running user."""
    key = _key_for(store_dir, "acme")
    a_dir = tmp_path / "logdir"
    a_dir.mkdir()
    monkeypatch.setenv("TREVAL_CASES_ACCESS_LOG", str(a_dir))
    r = obj_client.get(f"/run?key={key}", headers=_h(_KEY_A))
    assert r.status_code == 503
    assert "复算" not in r.text  # the bypass map was NOT rendered


def test_access_log_page_is_tenant_scoped(obj_client, store_dir):
    """🔴 acceptance 11: `/access-log` — a scoped tenant sees ONLY its own rows; admin sees all. RED
    input: show tenant B's access rows to tenant A."""
    ka, kb = _key_for(store_dir, "acme"), _key_for(store_dir, "beta")
    obj_client.get(f"/run?key={ka}", headers=_h(_KEY_A))  # an acme view
    obj_client.get(f"/run?key={kb}", headers=_h(_KEY_B))  # a beta view
    acme = obj_client.get("/access-log", headers=_h(_KEY_A)).text
    beta = obj_client.get("/access-log", headers=_h(_KEY_B)).text
    admin = obj_client.get("/access-log", headers=_h(_KEY_ADMIN)).text
    assert "auditor-acme" in acme and "auditor-beta" not in acme and kb not in acme
    assert "auditor-beta" in beta and ka not in beta
    assert "auditor-acme" in admin and "auditor-beta" in admin  # admin sees both


def test_invalid_keys_are_not_enumerable(obj_client, store_dir, tmp_path):
    """🔴 acceptance 12: unknown / expired / revoked all yield the SAME message and status — byte-
    identical, no 'expired' or 'revoked' hint. RED input: a kind-specific message for any of them."""
    unknown = obj_client.post(
        "/session", data={"key": "totally-unknown", "next": "/"}, follow_redirects=False
    )
    expired = obj_client.post(
        "/session", data={"key": _KEY_EXPIRED, "next": "/"}, follow_redirects=False
    )
    # revoke _KEY_A by deleting its row, then attempt it (hot reload picks up the change)
    obj_tokens_path = tmp_path / "tok_obj.json"
    obj_tokens_path.write_text(
        json.dumps(
            {
                _KEY_ADMIN: {
                    "label": "platform-admin",
                    "scope": "*",
                    "expires_at": "2099-12-31T00:00:00Z",
                }
            }
        ),
        encoding="utf-8",
    )
    os.utime(
        obj_tokens_path, ns=(obj_tokens_path.stat().st_mtime_ns + 1_000_000_000,) * 2
    )
    revoked = obj_client.post(
        "/session", data={"key": _KEY_A, "next": "/"}, follow_redirects=False
    )
    assert unknown.status_code == expired.status_code == revoked.status_code == 200
    assert unknown.text == expired.text == revoked.text  # 🔴 byte-identical
    for r in (unknown, expired, revoked):
        assert "访问密钥无效" in r.text
        assert (
            "过期" not in r.text and "expired" not in r.text.lower()
        )  # no leak of the KIND
