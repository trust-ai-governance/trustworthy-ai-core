"""UI-3-AUTH §4 — 件C 访问留痕, the case access log. Acceptance 7–10, 13, each with the input that
turns it red.

Pure stdlib, no HTTP: the log module must be single-testable off the service (§9), and it must stay
in the case-store isolation domain — it imports NEITHER the engine NOR a WAL reader (§5.1)."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from test_case_store import module_imports_wal_reader  # reuse the AST check
from treval.case_access_log import (
    ACCESS_LOG_NAME,
    AccessLogError,
    access_log_path,
    log_access,
    read_access,
)

_ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# 7 — a success line carries label + run_key
# --------------------------------------------------------------------------- #


def test_success_appends_a_line_with_label_and_run_key(tmp_path):
    """🔴 acceptance 7: one success ⇒ the log gains a line with `label` and `run_key`. RED input:
    drop the write (no line), or a record without label/run_key."""
    log_access(
        tmp_path,
        ok=True,
        label="auditor-acme",
        scope="acme",
        action="view_run",
        run_key="9de2dfde",
        tenant="acme",
    )
    records = read_access(tmp_path)
    assert len(records) == 1
    rec = records[0]
    assert rec["label"] == "auditor-acme" and rec["run_key"] == "9de2dfde"
    assert rec["action"] == "view_run" and rec["tenant"] == "acme" and rec["ok"] is True
    assert rec["at"].endswith("Z")  # ISO-8601 Z


# --------------------------------------------------------------------------- #
# 8 — a failure line never carries the key (or what it resembled, or why)
# --------------------------------------------------------------------------- #


def test_failure_line_records_only_that_one_happened(tmp_path):
    """🔴 acceptance 8: a failure is one opaque line — the submitted key appears 0 times. RED input:
    a `key`/`reason`-detail field that echoes the attempt (a key dictionary written to disk)."""
    sentinel = "sentinel-key-should-never-be-logged"
    for _ in range(4):
        log_access(tmp_path, ok=False)
    raw = access_log_path(tmp_path).read_text(encoding="utf-8")
    assert sentinel not in raw  # the function has no `key` param — it CANNOT write one
    fails = read_access(tmp_path)
    assert len(fails) == 4
    assert all(set(f) == {"at", "ok", "reason"} and f["ok"] is False for f in fails)
    assert all(f["reason"] == "rejected" for f in fails)  # never a fine-grained reason


# --------------------------------------------------------------------------- #
# 9 — write failure ⇒ fail-closed
# --------------------------------------------------------------------------- #


def test_write_failure_is_fail_closed(tmp_path, monkeypatch):
    """🔴 acceptance 9: if the line cannot be written, raise (the caller then refuses to serve). RED
    input: swallow the OSError and return (visible but untraced). Point the log at a DIRECTORY so the
    append fails regardless of the running user (a chmod check would pass as root)."""
    a_dir = tmp_path / "iam-a-directory"
    a_dir.mkdir()
    monkeypatch.setenv("TREVAL_CASES_ACCESS_LOG", str(a_dir))
    with pytest.raises(AccessLogError):
        log_access(tmp_path, ok=True, label="a", action="view_run", run_key="k")


# --------------------------------------------------------------------------- #
# 10 — self-describing effect boundary
# --------------------------------------------------------------------------- #


def test_first_line_is_the_self_describing_note(tmp_path):
    """🔴 acceptance 10: the FIRST line states verbatim it is not a hash chain and cannot prove no-one
    accessed. RED input: drop the header, or a header missing either phrase."""
    log_access(
        tmp_path, ok=True, label="a", action="view_run", run_key="k", tenant="acme"
    )
    first = access_log_path(tmp_path).read_text(encoding="utf-8").splitlines()[0]
    note = json.loads(first)
    assert "_note" in note
    assert "不是哈希链" in note["_note"] and "不能证明无人访问" in note["_note"]
    # the header is NOT a data record — read_access skips it
    assert all("_note" not in r for r in read_access(tmp_path))


# --------------------------------------------------------------------------- #
# 13 — isolation: case-store side only, no engine / no WAL reader
# --------------------------------------------------------------------------- #


def test_log_lives_under_the_case_store_dir(tmp_path):
    """acceptance 13: the default path is `access.jsonl` UNDER the case store dir — the case-store
    side of the isolation boundary, never the report store or an outbound artifact (§4.2)."""
    p = access_log_path(tmp_path)
    assert p.name == ACCESS_LOG_NAME
    assert p.parent == Path(tmp_path)


def test_report_store_cannot_see_the_access_log(tmp_path):
    """🔴 acceptance 13: the report export path (ReportStore reads `index.json`) surfaces NOTHING from
    a case store — the access log next to it is invisible. RED input: put the log where the report
    store would enumerate it."""
    from treval.report_store import ReportStore

    log_access(
        tmp_path, ok=True, label="a", action="view_run", run_key="k", tenant="acme"
    )
    assert access_log_path(tmp_path).is_file()
    assert ReportStore(tmp_path).list() == []


def test_module_imports_no_engine():
    """🔴 acceptance 13 / §5.1: importing the log module must not pull the active-eval harness — it
    cannot fire a probe."""
    code = (
        "import sys; import treval.case_access_log; "
        "bad = [m for m in sys.modules if m.startswith('treval.active_eval')]; "
        "assert not bad, bad"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=_ROOT
    )
    assert proc.returncode == 0, proc.stderr


def test_module_source_imports_no_wal_reader():
    """🔴 acceptance 13 / §5.1: the log module never imports a WAL reader in its OWN source."""
    import treval.case_access_log as mod

    assert not module_imports_wal_reader(mod)
    # and it is pure stdlib + no treval.* engine imports at all
    src = Path(mod.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    treval_imports = [
        n.module
        for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and n.module and n.module.startswith("treval")
    ]
    assert treval_imports == []


def test_read_access_skips_malformed_lines(tmp_path):
    """A crash mid-append can leave a partial line; read_access skips it (and the header) rather than
    failing the page."""
    p = access_log_path(tmp_path)
    log_access(
        tmp_path, ok=True, label="a", action="view_run", run_key="k", tenant="acme"
    )
    with p.open("a", encoding="utf-8") as fh:
        fh.write("{ half a line\n")
    records = read_access(tmp_path)
    assert len(records) == 1 and records[0]["label"] == "a"


def test_read_access_no_file_is_empty(tmp_path):
    assert read_access(tmp_path) == []
