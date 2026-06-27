"""treval-web — the read-only registry / maturity-model viewer (EV-W0).

A thin FastAPI app over EV-6's `DimensionRegistry`:

  GET /api/registry  → the §1 JSON contract (serialized live registry)
  GET /              → server-rendered 5×5 dimension × level grid (Jinja2)
  /static/*          → CSS/assets

Read-only: no route mutates anything. The registry is loaded once at app
creation and reused (deterministic, no per-request I/O). FastAPI/uvicorn/Jinja2
are imported here only — never by the core library — so they live in the optional
`treval[web]` extra (see requirements-web.txt). EV-W1 will extend this same app
with the report view.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from treval.registry import load_registry
from treval.web.serialize import serialize_registry

_HERE = Path(__file__).resolve().parent
_TEMPLATES = _HERE / "templates"
_STATIC = _HERE / "static"


def create_app(registry_path: str | Path | None = None) -> FastAPI:
    """Build the read-only viewer app over the registry at `registry_path`
    (default: the repo's `registry/dimensions/`, per EV-6's loader)."""
    registry = serialize_registry(load_registry(registry_path))
    objective_count = sum(
        len(objs) for dim in registry["dimensions"] for objs in dim["levels"].values()
    )

    app = FastAPI(title="treval-web — registry viewer", docs_url=None, redoc_url=None)
    app.mount("/static", StaticFiles(directory=_STATIC), name="static")
    templates = Jinja2Templates(directory=str(_TEMPLATES))

    @app.get("/api/registry", response_class=JSONResponse)
    def get_registry() -> dict[str, Any]:
        """The §1 contract — serialized live registry. Read-only, no params."""
        return registry

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> Any:
        return templates.TemplateResponse(
            request,
            "registry.html",
            {
                "levels_meta": registry["levels_meta"],
                "dimensions": registry["dimensions"],
                "objective_count": objective_count,
            },
        )

    return app
