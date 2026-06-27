"""Run the read-only registry viewer: `python -m treval.web` (serves on :8090).

Port 8090 keeps clear of the gateway (8080) / admin (8081) — EV-W0 §4.
"""

from __future__ import annotations

import uvicorn

from treval.web.app import create_app


def main() -> None:
    uvicorn.run(create_app(), host="127.0.0.1", port=8090)


if __name__ == "__main__":
    main()
