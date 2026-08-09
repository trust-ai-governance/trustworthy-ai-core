"""Case access log — 件C 访问留痕 (UI-3-AUTH §4), the ONE new data-to-disk path this ticket adds.

🔴 This is the whole reason the ticket exists (§4): a case record is a BYPASS MAP — "which technique
punches through this gateway" — and an operator_only bypass map with NO record of who read it is a
demo, not a product. Every authenticated request appends one JSONL line: a SUCCESS carries
`label / at / action / run_key / tenant`; a FAILURE carries ONLY `{"at", "ok": false, "reason":
"rejected"}` — 🔴 never the submitted key, what it resembled, or a fine-grained reason (that would
write a key dictionary to disk, §4.1).

🔴 It is NOT an audit chain and must not be mistaken for one (§4.3): the FIRST line is a self-
describing `_note` stating verbatim that it is not a hash chain, has no tamper-proofing, and cannot
prove no-one accessed (only the WAL does chains — whoever can write this file can also delete it).

Pure stdlib — like `case_store.py`, and in the SAME isolation domain (the case-store side): it imports
NEITHER the engine NOR a WAL reader (UI-3 §5.1), and writes ONLY under the case store dir — 🔴 never
the report store, never any outbound artifact (§4.2/§5.3).

Write failure ⇒ fail-closed (`AccessLogError`): the caller must REFUSE to serve the request rather
than degrade to "visible but no trace" (§4.5) — the exact state this ticket kills.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ACCESS_LOG_NAME = "access.jsonl"

# 🔴 §4.3 — the effect-boundary the artifact carries with it. Contains, verbatim, the two lines
# acceptance 10 greps for: "不是哈希链" and "不能证明无人访问".
ACCESS_LOG_NOTE = (
    "访问记录 access log —— 运维可读的“谁看过这份绕过地图”的记录。"
    "🔴 它不是哈希链、没有防篡改保证（防篡改是 WAL 的事）；它能回答“谁访问过”，"
    "但不能证明无人访问 —— 能写它的人也能删它。not a hash chain, no tamper-proofing."
)
_NOTE: dict[str, str] = {"_note": ACCESS_LOG_NOTE}


class AccessLogError(Exception):
    """The access line could not be appended — fail-closed (§4.5): refuse to serve, never serve
    untraced."""


def access_log_path(store_dir: str | Path) -> Path:
    """`$TREVAL_CASES_ACCESS_LOG`, else `access.jsonl` under the case store dir (§4.2). 🔴 It lives on
    the case-store side of the isolation boundary — never the report store, never an outbound
    artifact."""
    env = os.environ.get("TREVAL_CASES_ACCESS_LOG")
    if env:
        return Path(env)
    return Path(store_dir) / ACCESS_LOG_NAME


def log_access(
    store_dir: str | Path,
    *,
    ok: bool,
    label: str | None = None,
    scope: str | None = None,
    action: str | None = None,
    run_key: str | None = None,
    tenant: str | None = None,
    at: str | None = None,
) -> None:
    """Append one JSONL line (§4.1). A SUCCESS records who/what/which-run; a FAILURE records ONLY that
    one happened. 🔴 There is no `key` parameter — the function structurally CANNOT write a submitted
    key. Fail-closed: a write error raises AccessLogError so the caller can refuse to serve (§4.5)."""
    ts = at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if ok:
        record: dict[str, Any] = {
            "at": ts,
            "label": label,
            "scope": scope,
            "action": action,
            "run_key": run_key,
            "tenant": tenant,
            "ok": True,
        }
    else:
        # 🔴 §4.1 — a failure is one opaque line: never the key, what it resembled, or why it failed.
        record = {"at": ts, "ok": False, "reason": "rejected"}
    path = access_log_path(store_dir)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        header_needed = not path.exists() or path.stat().st_size == 0
        with path.open("a", encoding="utf-8") as fh:
            if header_needed:
                fh.write(json.dumps(_NOTE, ensure_ascii=False) + "\n")
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError as e:
        raise AccessLogError(f"cannot append to access log {path}: {e}") from e


def read_access(store_dir: str | Path) -> list[dict[str, Any]]:
    """Every DATA record, oldest first (the `_note` header and any malformed line are skipped). The
    CALLER applies scope filtering — admin sees all, a scoped tenant sees only its own tenant's rows
    (§4.4). No file yet ⇒ empty list."""
    path = access_log_path(store_dir)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as e:
        raise AccessLogError(f"cannot read access log {path}: {e}") from e
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            rec = json.loads(s)
        except json.JSONDecodeError:
            continue
        if isinstance(rec, dict) and "_note" not in rec:
            out.append(rec)
    return out
