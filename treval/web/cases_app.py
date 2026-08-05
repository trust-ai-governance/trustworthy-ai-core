"""treval-web CASE service (UI-3a) — a Tier-0 recompute service, SEPARATE from the report viewer.

The page's主体 is not "browse cases" — it is **re-add 89.3% here** (§6): declared aggregates ‖ the
same aggregates re-added from the rows, the per-case list split by denominator, and — the actual
承重物 — a byte-for-byte `cases.json` download plus the `treval cases verify` command to re-run in
YOUR OWN terminal (§6.1: the green check on OUR page proves nothing to someone who doesn't trust us).

🔴 Structural guarantees, each with a regression:
  • credential scope (§3.3) — tenant comes from the credential, `?tenant=` is a boundary not a selector;
  • human entry is an ACCESS PAGE (§3.4) — `GET /` unauthenticated renders a page with an 「访问密钥」
    field; `POST /session` sets an HttpOnly/SameSite=Strict cookie holding the SAME shared secret;
    Basic (`curl -u :key`) stays for scripts/CI. 🔴 still NOT identity: no users/sessions/roles,
    scope_for_token unchanged. The ONLY write route is /session, and it touches no store (regression);
  • never dereferences a pointer (§7) — imports NO WAL reader, opens NO WAL; `evidence_ref` is TEXT;
  • cannot run a probe (§5.1) — imports NO active-eval harness (reads the PURE contract module);
  • default-unreachable (§4.3) — a separate app; mounting is a deployment choice (`TREVAL_CASES_MOUNT`).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from treval.case_contract import compare_cases_to_aggregates, recompute_from_cases
from treval.case_store import CaseStore
from treval.cli.cases_verify import (
    _SCOPE_DECLARATION,
)  # verbatim reuse (§6.2 ②); pure module
from treval.web.cases_auth import (
    CasesAuthError,
    Forbidden,
    can_see_tenant,
    load_token_map,
    resolve_query_tenant,
    scope_for_token,
)

_HERE = Path(__file__).resolve().parent
_TEMPLATES = _HERE / "templates"
_STATIC = _HERE / "static"

VERIFY_COMMAND = "python -m treval.cli cases verify <cases.json>"
_COOKIE = "treval_cases"  # holds the shared secret (§3.4) — NOT a session id; there is no session store


def _static_version(static_dir: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(static_dir.glob("*")):
        if f.is_file():
            h.update(f.read_bytes())
    return h.hexdigest()[:8]


def _base(request: Request) -> str:
    """The mount prefix ("" standalone, "/cases" when mounted, §4.3) — prepended to internal links,
    redirects and the cookie path so the service works both standalone (:8091) and mounted."""
    return request.scope.get("root_path", "")


def _safe_next(raw: str | None, base: str) -> str:
    """Open-redirect guard: only a SAME-ORIGIN absolute path (one leading `/`, no `//`, no CR/LF);
    anything else (or empty) falls back to the service root `base + "/"`."""
    if (
        raw
        and raw.startswith("/")
        and not raw.startswith("//")
        and "\n" not in raw
        and "\r" not in raw
    ):
        return raw
    return base + "/"


class _NeedsLogin(Exception):
    """A protected data route was hit without a credential — redirect the human to the access page."""

    def __init__(self, next_url: str) -> None:
        self.next_url = next_url


def create_cases_app(
    store_dir: str | Path | None = None, tokens_path: str | Path | None = None
) -> FastAPI:
    """Build the case service. `store_dir` defaults to `$TREVAL_CASE_STORE` — 🔴 NEVER the report
    store. `tokens_path` defaults to `$TREVAL_CASES_TOKENS`; with no map the service REFUSES to start
    (fail-closed — a bypass map has no 'no token = allow' posture, §4)."""
    store_path = store_dir or os.environ.get("TREVAL_CASE_STORE")
    if not store_path:
        raise CasesAuthError(
            "🔴 no case store — set $TREVAL_CASE_STORE (or pass store_dir). It is NEVER the report "
            "store (reports/store)."
        )
    tokens = (
        tokens_path
        if tokens_path is not None
        else os.environ.get("TREVAL_CASES_TOKENS")
    )
    if not tokens:
        raise CasesAuthError(
            "🔴 no TREVAL_CASES_TOKENS — refusing to start. A case (bypass-map) service has no "
            "'no token = allow' loopback posture; a credential→tenant map is mandatory (§4)."
        )
    token_map = load_token_map(
        tokens
    )  # fail-closed on unreadable / not-object / bad value
    store = CaseStore(store_path)
    templates = Jinja2Templates(directory=str(_TEMPLATES))
    static_v = _static_version(_STATIC)

    def _supplied(request: Request) -> str | None:
        # The COOKIE is the human channel (§3.4); the header/Basic channels are for scripts/CI.
        tok = request.cookies.get(_COOKIE) or ""
        if not tok:
            tok = request.headers.get("x-treval-token") or ""
            header = request.headers.get("authorization") or ""
            low = header.lower()
            if low.startswith("bearer "):
                tok = tok or header[7:]
            elif low.startswith("basic "):
                # `curl -u :tok` — username ignored, password = the token. NOT in URL/history/Referer.
                try:
                    tok = (
                        tok
                        or base64.b64decode(header[6:]).decode("utf-8").split(":", 1)[1]
                    )
                except (ValueError, IndexError):
                    pass
        return tok or None

    def _optional_scope(request: Request) -> str | None:
        return scope_for_token(token_map, _supplied(request))

    def require_scope(request: Request) -> str:
        s = _optional_scope(request)
        if s is None:
            q = request.url.query
            raise _NeedsLogin(request.url.path + (f"?{q}" if q else ""))
        return s

    app = FastAPI(
        title="treval-web — case-level Tier-0 recompute service",
        docs_url=None,
        redoc_url=None,
    )
    app.mount("/static", StaticFiles(directory=_STATIC), name="static")

    @app.exception_handler(_NeedsLogin)
    async def _login_redirect(request: Request, exc: _NeedsLogin) -> Response:
        # 🔴 a browser hitting /run or /cases.json without a cookie lands on the access page, keeping
        # its deep link in ?next= — NOT a 401 JSON (§3.4).
        base = _base(request)
        return RedirectResponse(
            url=f"{base}/?next={quote(exc.next_url, safe='')}", status_code=303
        )

    @app.middleware("http")
    async def _no_store_no_index(request: Request, call_next):
        # 🔴 §4: every response — a case page WILL be screenshotted; keep copies out of caches/indexes.
        resp = await call_next(request)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Robots-Tag"] = "noindex, nofollow"
        return resp

    def _access_page(request: Request, *, next_url: str, error: str | None) -> Response:
        base = _base(request)
        return templates.TemplateResponse(
            request,
            "cases_access.html",
            {
                "next": _safe_next(next_url, base),
                "error": error,
                "banner_tenant": "（未登录 · not signed in）",
                "base": base,
                "static_v": static_v,
            },
            status_code=200,
        )

    def _visible(scope_tenant: str, want_tenant: str | None):
        entries = [e for e in store.list() if can_see_tenant(scope_tenant, e.tenant_id)]
        if want_tenant is not None:
            entries = [e for e in entries if e.tenant_id == want_tenant]
        return entries

    def _entry_or_404(scope_tenant: str, key: str):
        entry = store.get(key)
        # 🔴 §4: an unguessable key is NOT authorization — a record the credential can't see is a 404,
        # not a 403 (to an unauthorized viewer we do not even confirm the record exists).
        if entry is None or not can_see_tenant(scope_tenant, entry.tenant_id):
            raise HTTPException(status_code=404, detail="no such case contract")
        return entry

    @app.get("/", response_class=HTMLResponse)
    def index(
        request: Request, tenant: str | None = None, next: str | None = None
    ) -> Any:
        # §3.4: no credential ⇒ the ACCESS PAGE (200), not a 401 — the human's entry point.
        scope_tenant = _optional_scope(request)
        if scope_tenant is None:
            return _access_page(request, next_url=next or "", error=None)
        try:
            want = resolve_query_tenant(scope_tenant, tenant)
        except Forbidden as e:
            raise HTTPException(status_code=403, detail=str(e)) from e
        entries = _visible(scope_tenant, want)
        return templates.TemplateResponse(
            request,
            "cases_index.html",
            {
                "entries": entries,
                "tenants": sorted({e.tenant_id for e in entries}),
                "scope": scope_tenant,
                "banner_tenant": want
                or ("* (all tenants)" if scope_tenant == "*" else scope_tenant),
                "show_logout": True,
                "base": _base(request),
                "static_v": static_v,
            },
        )

    @app.post("/session")
    async def session(request: Request) -> Response:
        # 🔴 §3.4 — the ONLY write route, and it writes NOTHING to either store: it validates the key
        # and sets a cookie. Manual form parse (no python-multipart dependency).
        base = _base(request)
        form = parse_qs((await request.body()).decode("utf-8"))
        key = (form.get("key") or [""])[0]
        next_url = _safe_next((form.get("next") or [""])[0], base)
        if scope_for_token(token_map, key) is None:
            # wrong key ⇒ stay on the access page with a readable error, NOT a 401 JSON.
            return _access_page(
                request, next_url=next_url, error="访问密钥无效 —— 请重试。"
            )
        resp = RedirectResponse(url=next_url, status_code=303)
        resp.set_cookie(
            _COOKIE,
            key,
            httponly=True,
            samesite="strict",
            path=base + "/",
            secure=request.url.scheme == "https",
        )
        return resp

    @app.get("/logout")
    def logout(request: Request) -> Response:
        base = _base(request)
        resp = RedirectResponse(url=base + "/", status_code=303)
        resp.delete_cookie(_COOKIE, path=base + "/")
        return resp

    @app.get("/cases.json")
    def cases_json(key: str, scope_tenant: str = Depends(require_scope)) -> Response:
        """🔴 §6.1 主承重物 — the STORED bytes, verbatim (never re-serialized)."""
        entry = _entry_or_404(scope_tenant, key)
        return Response(content=store.read_bytes(entry), media_type="application/json")

    @app.get("/run", response_class=HTMLResponse)
    def run(
        request: Request, key: str, scope_tenant: str = Depends(require_scope)
    ) -> Any:
        entry = _entry_or_404(scope_tenant, key)
        doc = json.loads(store.read_bytes(entry))
        cases = doc.get("cases", [])
        aggregates = doc.get("aggregates", {})
        rc = recompute_from_cases(cases)
        mismatches = compare_cases_to_aggregates(cases, aggregates)
        # §6.3 — split the per-case list by denominator so the four-cell population is visible.
        block_a = [
            c
            for c in cases
            if c.get("observable_via") in ("output_marker", "secret_canary")
        ]
        block_b = [c for c in cases if c.get("observable_via") is None]
        return templates.TemplateResponse(
            request,
            "cases_run.html",
            {
                "entry": entry,
                "doc": doc,
                "aggregates": aggregates,
                "recomputed": {
                    "injection_catch_rate": rc["injection_catch_rate"],
                    "injection_success_rate": rc["injection_success_rate"],
                    "four_cell": rc["four_cell"],
                    "marker_den": rc["marker_denominator"],
                },
                "mismatches": mismatches,
                "block_a": block_a,
                "block_b": block_b,
                "scope_declaration": _SCOPE_DECLARATION,
                "verify_command": VERIFY_COMMAND,
                "key": key,
                "banner_tenant": entry.tenant_id,
                # 🔴 §4.2.1 — self-report the run identity so a reader never subtracts across runs.
                "run_time": datetime.fromtimestamp(
                    entry.generated_at_ns / 1e9, tz=timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%SZ"),
                "corpus_sha8": entry.corpus_sha.replace("sha256:", "")[:8],
                "show_logout": True,
                "base": _base(request),
                "static_v": static_v,
            },
        )

    return app
