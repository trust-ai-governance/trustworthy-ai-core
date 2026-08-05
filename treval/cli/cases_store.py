"""EV-R2 / UI-3 §5.3 — `treval cases store <cases.json> --store DIR`: the FAIL-CLOSED ingest gate.

A separate command, not a flag on the producer (§5.3): the gate must stop ANY contract entering the
store, not only ones our own producer wrote, and two steps mean a file can be audited / `cases
verify`'d BEFORE it enters the store. The store dir comes from `--store` or `$TREVAL_CASE_STORE` —
🔴 NEVER a fallback to the report store's default (`reports/store`), which would write case data
straight into the report store.
"""

from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from treval.case_store import CaseStoreError, write_case_bundle

EXIT_OK = 0
EXIT_REFUSED = 2  # the ingest gate refused — a real refusal, never a silent admit
EXIT_IO = 3


def run_cases_store(args: argparse.Namespace) -> int:
    store_dir = args.store or os.environ.get("TREVAL_CASE_STORE")
    if not store_dir:
        # 🔴 No default: a case store must be chosen explicitly. Falling back to the report store's
        # `reports/store` would write case data into the report store — the exact thing we separate.
        print(
            "🔴 no --store and no $TREVAL_CASE_STORE — refusing. A case store must be explicit; it is "
            "NEVER the report store (do not point it at reports/store).",
            flush=True,
        )
        return EXIT_IO
    try:
        text = Path(args.cases_file).read_text(encoding="utf-8")
    except OSError as e:
        print(f"🔴 cannot read {args.cases_file}: {e}", flush=True)
        return EXIT_IO
    try:
        entry = write_case_bundle(store_dir, text, generated_at_ns=time.time_ns())
    except CaseStoreError as e:
        print(f"🔴 {e}", flush=True)
        return EXIT_REFUSED
    print(
        f"✅ stored — tenant={entry.tenant_id}  key={entry.key}  → {Path(store_dir) / entry.file}"
    )
    return EXIT_OK
