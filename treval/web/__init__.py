"""treval-web — read-only registry / maturity-model viewer (EV-W0).

The registry serializer lives in `treval.registry.serialize` (it is pure registry → dict
and the engine needs it too — see EV-R1); it is re-exported here for the web layer's
convenience. The FastAPI app factory (`create_app`) is exposed lazily via `__getattr__`,
so importing `treval.web` does not pull in FastAPI/Jinja2 — those stay in the optional
`treval[web]` extra. Dependency direction is one-way: `treval.web → treval.registry`; the
core library NEVER imports `treval.web` (guarded by tests/test_layering.py).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from treval.registry.serialize import (
    DIMENSION_ORDER,
    LEVELS,
    LEVELS_META,
    serialize_registry,
)

if TYPE_CHECKING:
    from treval.web.app import create_app

__all__ = [
    "serialize_registry",
    "LEVELS",
    "LEVELS_META",
    "DIMENSION_ORDER",
    "create_app",
]


def __getattr__(name: str) -> Any:
    if name == "create_app":
        from treval.web.app import create_app

        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
