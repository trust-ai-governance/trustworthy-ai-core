"""Run the UI-3a case-level Tier-0 recompute service: `python -m treval.web.cases` (serves :8091).

Port 8091 = the report service's 8090 + 1 (§4). 🔴 `TREVAL_CASES_TOKENS` (a JSON file path holding
`{token: tenant}`, `"*"` = admin) is REQUIRED — no map ⇒ create_cases_app refuses to start
(fail-closed; a bypass-map service has no "no token = allow" posture). `TREVAL_CASE_STORE` is the
case store dir (NEVER the report store).
"""

from __future__ import annotations

import uvicorn

from treval.web.cases_app import create_cases_app


def main() -> None:
    uvicorn.run(create_cases_app(), host="127.0.0.1", port=8091)


if __name__ == "__main__":
    main()
