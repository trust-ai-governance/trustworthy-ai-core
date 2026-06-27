"""treval-web — read-only registry / maturity-model viewer (EV-W0).

The serializer (`serialize_registry`) is pure and imported eagerly. The FastAPI
app factory (`create_app`) is exposed lazily via `__getattr__`, so importing
`treval.web` does not pull in FastAPI/Jinja2 — those stay in the optional
`treval[web]` extra. Use `from treval.web import create_app` only in the web
environment; the core library never touches it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from treval.web.serialize import (
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
