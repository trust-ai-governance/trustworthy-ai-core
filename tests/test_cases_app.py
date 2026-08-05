"""UI-3 §10 — the case service (UI-3a). Acceptance 3, 7–14, each with the input that turns it red.

fastapi is required to exercise the routes; where it is absent these skip (like the report tests).
"""

from __future__ import annotations

import json
import subprocess
import sys
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
from treval.cli.cases_verify import _SCOPE_DECLARATION  # noqa: E402
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
    """Every file under a store, path→bytes — for the acceptance-10 'teeth' (byte-for-byte unchanged)."""
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
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
    """🔴 acceptance 11: the recompute page contains the four scope lines — and the test uses the
    CONSTANT itself, so editing cases_verify._SCOPE_DECLARATION (or dropping it from the page) reds
    this. A copied literal would not be caught."""
    from markupsafe import (
        escape,
    )  # Jinja escapes `<audit-log>` → `&lt;…&gt;` (correct for display)

    key = _key_for(store_dir, "acme")
    html = client.get(f"/run?key={key}", headers=_h("tok-a")).text
    # derived FROM the constant, so editing _SCOPE_DECLARATION (or dropping it) still reds this
    assert str(escape(_SCOPE_DECLARATION)) in html
    assert (
        "does NOT prove the probes ever ran" in html
    )  # the honest boundary is on the page


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
