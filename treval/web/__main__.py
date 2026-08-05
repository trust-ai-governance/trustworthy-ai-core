"""Run the read-only registry viewer: `python -m treval.web` (serves on :8090).

Port 8090 keeps clear of the gateway (8080) / admin (8081) — EV-W0 §4.

UI-3 §4.3 — SINGLE-ENTRY is an opt-in DEPLOYMENT posture, expressed ONLY here: set
`TREVAL_CASES_MOUNT=/cases` and the case service is mounted under the report app. 🔴 `create_app()`
itself never mounts (a library function stays pure) — otherwise any test/embed that imports it would
grow case routes. Default (unset) ⇒ the case service is NOT reachable here (run it standalone on
:8091). The mounted sub-app keeps its OWN auth: `TREVAL_WEB_TOKEN` never opens `/cases/*` (a mount is
a separate app, so the report token does not descend into it).
"""

from __future__ import annotations

import os

import uvicorn

from treval.web.app import create_app


def main() -> None:
    mount = os.environ.get("TREVAL_CASES_MOUNT")
    # Tell the report app the case service's URL ONLY when we actually mount it here, so the
    # 「用例明细」 nav item appears exactly when the link resolves (not merely when the env var is set).
    app = create_app(cases_url=mount if mount else None)
    if mount:
        from treval.web.cases_app import create_cases_app

        app.mount(mount, create_cases_app())
    uvicorn.run(app, host="127.0.0.1", port=8090)


if __name__ == "__main__":
    main()
