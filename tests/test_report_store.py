"""EV-W1 — the report store: content-addressed, atomic, append-only, byte-faithful."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from treval.report_store import (
    INDEX_NAME,
    ReportStore,
    ReportStoreError,
    window_key,
    write_bundle,
)

_FIXTURES = (
    Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "report" / "valid"
)


def _load_all(store_dir) -> ReportStore:
    for i, f in enumerate(sorted(_FIXTURES.glob("*.json"))):
        write_bundle(store_dir, f.read_text(encoding="utf-8"), generated_at_ns=1000 + i)
    return ReportStore(store_dir)


# --------------------------------------------------------------------------- #
# §7.8 — store E2E over the six EV-R1 fixtures
# --------------------------------------------------------------------------- #


def test_six_fixtures_index_resolve_and_round_trip(tmp_path):
    store = _load_all(tmp_path)
    entries = store.list()
    assert len(entries) == 6  # index lists 6
    for e in entries:
        assert store.read_bytes(e) == (tmp_path / e.file).read_bytes()  # byte-identical
        assert json.loads(store.read_bytes(e))["schema_version"] == 2


def test_index_is_newest_first(tmp_path):
    store = _load_all(tmp_path)
    gens = [e.generated_at_ns for e in store.list()]
    assert gens == sorted(gens, reverse=True)


def test_resolve_defaults_to_newest(tmp_path):
    store = _load_all(tmp_path)
    assert store.resolve() == store.list()[0]


def test_resolve_unknown_is_none_never_another_report(tmp_path):
    store = _load_all(tmp_path)
    assert store.resolve("no-such-tenant") is None
    assert store.resolve(None, "1-2") is None
    # a wrong window under a real tenant must NOT fall back to that tenant's other report
    real = store.list()[0]
    assert store.resolve(real.tenant_id, "999-999") is None


def test_bundle_is_content_addressed_no_tenant_in_path(tmp_path):
    """tenant_id is untrusted WAL input — it must never reach a filesystem path."""
    doc = json.loads((_FIXTURES / "rich.json").read_text(encoding="utf-8"))
    doc["report"]["tenant_id"] = "../../etc/passwd"
    entry = write_bundle(tmp_path, json.dumps(doc), generated_at_ns=1)
    assert entry.tenant_id == "../../etc/passwd"  # preserved as DATA
    assert ".." not in entry.file and entry.file.startswith("bundles/")
    assert (tmp_path / entry.file).is_file()
    assert ReportStore(tmp_path).read_bytes(entry)  # still resolvable


def test_store_is_append_only_and_re_store_is_idempotent(tmp_path):
    """Same bytes → one entry (idempotent). Different bytes for the same (tenant, window)
    → BOTH kept (§9 append-only); resolve returns the newest."""
    rich = (_FIXTURES / "rich.json").read_text(encoding="utf-8")
    write_bundle(tmp_path, rich, generated_at_ns=1)
    write_bundle(tmp_path, rich, generated_at_ns=2)
    assert len(ReportStore(tmp_path).list()) == 1  # idempotent

    other = (_FIXTURES / "over_claim_gaps.json").read_text(encoding="utf-8")
    write_bundle(tmp_path, other, generated_at_ns=3)
    entries = ReportStore(tmp_path).list()
    assert len(entries) == 2  # append-only: nothing replaced
    assert entries[0].generated_at_ns == 3  # newest first


def test_generated_at_ns_is_stored_not_mtime(tmp_path):
    write_bundle(
        tmp_path,
        (_FIXTURES / "rich.json").read_text(encoding="utf-8"),
        generated_at_ns=424242,
    )
    assert ReportStore(tmp_path).list()[0].generated_at_ns == 424242


def test_index_written_atomically_and_parsable(tmp_path):
    _load_all(tmp_path)
    doc = json.loads((tmp_path / INDEX_NAME).read_text(encoding="utf-8"))
    assert isinstance(doc, list) and len(doc) == 6
    assert set(doc[0]) == {
        "tenant_id",
        "window",
        "generated_at_ns",
        "registry_fingerprint",
        "file",
    }


def test_window_key_round_trips(tmp_path):
    store = _load_all(tmp_path)
    e = store.list()[0]
    assert store.resolve(e.tenant_id, window_key(e.window)) is not None


# --------------------------------------------------------------------------- #
# fail-closed
# --------------------------------------------------------------------------- #


def test_missing_store_lists_empty_but_read_is_explicit(tmp_path):
    assert ReportStore(tmp_path / "nope").list() == []


def test_malformed_index_raises(tmp_path):
    (tmp_path / INDEX_NAME).write_text("{not json", encoding="utf-8")
    with pytest.raises(ReportStoreError, match="not valid JSON"):
        ReportStore(tmp_path).list()


def test_non_bundle_rejected(tmp_path):
    with pytest.raises(ReportStoreError, match="not an EV-R1 envelope"):
        write_bundle(tmp_path, json.dumps({"nope": 1}), generated_at_ns=1)


def test_escaping_bundle_path_is_refused(tmp_path):
    """The index is a file on disk — treat it as input (defence in depth)."""
    _load_all(tmp_path)
    doc = json.loads((tmp_path / INDEX_NAME).read_text(encoding="utf-8"))
    doc[0]["file"] = "../../../etc/passwd"
    (tmp_path / INDEX_NAME).write_text(json.dumps(doc), encoding="utf-8")
    store = ReportStore(tmp_path)
    with pytest.raises(ReportStoreError, match="escapes the store"):
        store.read_bytes(store.list()[0])
