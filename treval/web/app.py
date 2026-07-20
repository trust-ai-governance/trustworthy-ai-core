"""treval-web — the read-only registry + report viewer (EV-W0 + EV-W1).

  GET /api/registry  → the EV-W0 §1 JSON contract (serialized live registry)
  GET /reports       → the report-store index, newest first (powers the selectors)
  GET /              → Dashboard SSR (?tenant=&window=; default = newest report)
  GET /detail        → 报告详情 SSR (same params)
  GET /report.json   → the STORED bundle, byte-for-byte (same params)
  /static/*          → CSS/assets

**Read-only by construction.** There is no POST/PUT/DELETE/PATCH route and no code path
that grades, re-runs, or mutates: the service only reads bundles the `treval report
--self-contained` producer already wrote. 重新评测 is a link, never an action (D5).

**No `/evidence` route (D3).** The UI renders aggregates, rules and outcomes — it never
drills to request level, so this service never reads or renders a request body and cannot
leak PII. The bundle's `evidence_refs` stay in the JSON for anyone verifying against the
WAL themselves.

**Auth (D4) — operator-scoped, NOT a multi-tenant portal.** Core has no identity system
and this must not grow one. Default posture: bind loopback (see `__main__`) + an optional
shared token (`TREVAL_WEB_TOKEN`). `/reports` lists exactly what is in THIS deployment's
store and `?tenant=` selects among them. **Per-viewer tenant ACLs are not provided** —
anyone deploying this multi-tenant MUST front it with their own authz. That is a real gap,
stated plainly rather than implied away.

FastAPI/uvicorn/Jinja2 are imported here only — never by the core library — so they stay
in the optional `treval[web]` extra.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from treval.registry import load_registry, serialize_registry
from treval.report_store import ReportStore, window_key
from treval.web.view import build_context, window_label

_HERE = Path(__file__).resolve().parent
_TEMPLATES = _HERE / "templates"
_STATIC = _HERE / "static"


def _static_version(static_dir: Path) -> str:
    """A short content hash of the static assets, appended to their URLs as ?v=… .

    Starlette's StaticFiles sends `last-modified`/`etag` but no `Cache-Control`, so browsers
    heuristically cache style.css/*.js and reuse a STALE copy without revalidating — a CSS
    change then doesn't take (a ? button renders as an unstyled square, a hidden popover shows
    flat). Versioning the URL by content makes any change mint a new URL, forcing a refetch."""
    h = hashlib.sha256()
    for f in sorted(static_dir.glob("*")):
        if f.is_file():
            h.update(f.read_bytes())
    return h.hexdigest()[:8]


# O1 (EV-W1 §8) ruling (a): no eval-execution surface exists, so 重新评测 shows the exact
# CLI command — honest about how evaluation is actually run today. One line to swap when
# an execution page lands.
RERUN_COMMAND = (
    "python -m treval.cli collect --gateway $GATEWAY --wal $WAL --out bundle.json"
)


def create_app(
    registry_path: str | Path | None = None,
    store_dir: str | Path | None = None,
    token: str | None = None,
) -> FastAPI:
    """Build the read-only viewer. `store_dir` defaults to `$TREVAL_REPORT_STORE`;
    `token`, when set (or `$TREVAL_WEB_TOKEN`), is required on every route."""
    registry = serialize_registry(load_registry(registry_path))
    objective_count = sum(
        len(objs) for dim in registry["dimensions"] for objs in dim["levels"].values()
    )
    store_path = store_dir or os.environ.get("TREVAL_REPORT_STORE") or "reports/store"
    store = ReportStore(store_path)
    required_token = token if token is not None else os.environ.get("TREVAL_WEB_TOKEN")
    static_v = _static_version(_STATIC)  # cache-bust token for /static links

    def auth(request: Request) -> None:
        if not required_token:
            return  # loopback-only posture; no token configured
        supplied = request.headers.get("x-treval-token") or ""
        header = request.headers.get("authorization") or ""
        if header.lower().startswith("bearer "):
            supplied = supplied or header[7:]
        if supplied != required_token:
            raise HTTPException(status_code=401, detail="unauthorized")

    app = FastAPI(
        title="treval-web — registry + report viewer",
        docs_url=None,
        redoc_url=None,
        dependencies=[Depends(auth)],
    )
    app.mount("/static", StaticFiles(directory=_STATIC), name="static")
    templates = Jinja2Templates(directory=str(_TEMPLATES))

    def _entry_or_404(tenant: str | None, window: str | None):
        entry = store.resolve(tenant, window)
        if entry is None:
            # Never fall back to another tenant's report, never leak a stack trace.
            raise HTTPException(status_code=404, detail="no such report")
        return entry

    def _selectors(current) -> dict[str, Any]:
        entries = store.list()
        return {
            "entries": entries,
            "tenants": sorted({e.tenant_id for e in entries}),
            # Filter FIRST, then number. Enumerating the global list and filtering inside the
            # comprehension made `newest` mean "newest across all tenants", so every tenant
            # except the globally-newest one got no (最新) marker at all. Invisible while all
            # fixtures shared one tenant — which is exactly the case the selector exists for.
            "windows": [
                {
                    "key": window_key(e.window),
                    "window": e.window,
                    # EV-PIN §1.5-3: LABEL only. `key` stays the raw ns pair because it is
                    # the selection key — deep links and the switcher depend on it.
                    "label": window_label(e.window),
                    "generated_at_ns": e.generated_at_ns,
                    "newest": i == 0,
                }
                for i, e in enumerate(
                    [
                        e
                        for e in entries
                        if current is None or e.tenant_id == current.tenant_id
                    ]
                )
            ],
            "current": current,
            "current_window": window_key(current.window) if current else None,
        }

    def _page(request: Request, template: str, tenant, window):
        entry = _entry_or_404(tenant, window)
        bundle = json.loads(store.read_bytes(entry))
        ctx = build_context(bundle)
        ctx.update(
            {
                "entry": entry,
                "scope": _selectors(entry),
                # The Dashboard/详情 nav links must carry the CURRENT scope, so switching view
                # keeps the tenant the user picked. Without it the links were bare "/" and
                # "/detail" (qs was undefined → empty), so every view switch fell back to the
                # globally-newest report — i.e. jumped to another tenant. Scope sits ABOVE the
                # view: the tenant is the entry's own, not the request param (which may be None).
                "qs": urlencode(
                    {"tenant": entry.tenant_id, "window": window_key(entry.window)}
                ),
                "rerun_command": RERUN_COMMAND,
                "levels_meta": registry["levels_meta"],
                "static_v": static_v,
            }
        )
        return templates.TemplateResponse(request, template, ctx)

    @app.get("/api/registry", response_class=JSONResponse)
    def get_registry() -> dict[str, Any]:
        """The EV-W0 §1 contract — serialized live registry. Read-only, no params."""
        return registry

    @app.get("/reports", response_class=JSONResponse)
    def get_reports() -> list[dict[str, Any]]:
        """The store index, newest first — powers the tenant + window selectors."""
        return [e.as_dict() for e in store.list()]

    @app.get("/report.json")
    def get_report_json(
        tenant: str | None = None, window: str | None = None
    ) -> Response:
        """The STORED bytes, verbatim — never a re-serialization. The bundle's whole value
        is being the exact artifact the engine produced; re-encoding would silently break
        byte-identity with the customer's copy and with registry_fingerprint verification."""
        entry = _entry_or_404(tenant, window)
        return Response(content=store.read_bytes(entry), media_type="application/json")

    @app.get("/", response_class=HTMLResponse)
    def dashboard(
        request: Request, tenant: str | None = None, window: str | None = None
    ) -> Any:
        if not store.list():
            return templates.TemplateResponse(
                request,
                "registry.html",
                {
                    "levels_meta": registry["levels_meta"],
                    "dimensions": registry["dimensions"],
                    "objective_count": objective_count,
                    "static_v": static_v,
                },
            )
        return _page(request, "dashboard.html", tenant, window)

    @app.get("/detail", response_class=HTMLResponse)
    def detail(
        request: Request, tenant: str | None = None, window: str | None = None
    ) -> Any:
        return _page(request, "detail.html", tenant, window)

    return app
