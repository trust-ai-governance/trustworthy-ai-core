"""UI-3 §5.3 / C3 — the case store + its fail-closed ingest gate. The teeth (acceptance 1,2,4–7):

1 — the two stores mutually refuse: a case contract → report_store (existing), an EV-R1 report →
    case_store (new). 2 — ReportStore(<case dir>).list() is empty (distinct index name). 4 —
    disclosure fail-closed. 5 — don't-trust-the-label: operator_only but a row has response_text ⇒
    still refused. 6 — a v2 contract is refused with "re-run" (not "hand-add"). 7 — a tampered row
    is refused (does-not-re-add). Plus: the store never pulls the engine or a WAL reader (§7).
"""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from test_ev_r2 import _case, _probe
from treval.active_eval import serialize_case_contract
from treval.case_store import (
    CaseStore,
    CaseStoreError,
    case_ingest_gate,
    write_case_bundle,
)
from treval.report_store import ReportStore, ReportStoreError, write_bundle
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_ROOT = Path(__file__).resolve().parents[1]


def _contract(*, tenant="acme", include_response_content=False):
    cases = [
        _case("s", technique="role_override"),
        _case("h", technique="delim"),
        _case("f", technique="fuzz"),
    ]
    results = [
        _probe("s", decision=_ALLOW, followed=True),
        _probe("h", decision=_BLOCK),
        _probe("f", decision=_ALLOW, hint=True),
    ]
    return serialize_case_contract(
        cases,
        results,
        target_kind="gateway",
        tenant_id=tenant,
        generated_at_ns=1,
        include_response_content=include_response_content,
    )


# --------------------------------------------------------------------------- #
# happy path + acceptance 2 (separation by index name)
# --------------------------------------------------------------------------- #


def test_store_and_read_round_trip(tmp_path):
    entry = write_case_bundle(tmp_path, json.dumps(_contract()), generated_at_ns=7)
    assert entry.tenant_id == "acme"
    store = CaseStore(tmp_path)
    assert store.get(entry.key) == entry
    assert store.read_bytes(entry) == (tmp_path / entry.file).read_bytes()


def test_report_store_cannot_see_case_records(tmp_path):
    """🔴 acceptance 2: the case store's index is `cases_index.json`, so ReportStore(<case dir>) —
    which reads `index.json` — lists NOTHING. Rename it back to index.json and this goes red."""
    write_case_bundle(tmp_path, json.dumps(_contract()), generated_at_ns=1)
    assert (tmp_path / "cases_index.json").is_file()
    assert not (tmp_path / "index.json").exists()
    assert ReportStore(tmp_path).list() == []  # the report export path gets nothing


# --------------------------------------------------------------------------- #
# acceptance 1 — the two gates are symmetric
# --------------------------------------------------------------------------- #


def test_two_stores_mutually_refuse(tmp_path):
    contract = json.dumps(_contract())
    # a case contract → report store: refused (existing)
    with pytest.raises(ReportStoreError, match="disclosure_class"):
        write_bundle(tmp_path / "rep", contract, generated_at_ns=1)
    # an EV-R1 report envelope → case store: refused (new, symmetric)
    report_envelope = json.dumps(
        {"schema_version": 4, "report": {"window": [0, 0], "tenant_id": "acme"}}
    )
    with pytest.raises(CaseStoreError, match="EV-R1 report envelope"):
        write_case_bundle(tmp_path / "cs", report_envelope, generated_at_ns=1)


# --------------------------------------------------------------------------- #
# acceptance 4,5,6,7 — the ingest gate, each fail-closed check
# --------------------------------------------------------------------------- #


def test_disclosure_class_fail_closed():
    """acceptance 4: missing class ⇒ refused (not defaulted public); internal_handoff ⇒ refused."""
    doc = _contract()
    doc.pop("disclosure_class")
    assert any("disclosure_class" in r for r in case_ingest_gate(doc))
    assert case_ingest_gate(
        _contract(include_response_content=True)
    )  # internal_handoff refused


def test_shape_over_label_operator_only_with_content_is_refused():
    """🔴 acceptance 5: a contract LABELLED operator_only but whose rows carry response_text is
    refused anyway — the label is a claim, the field is the fact (P2-4)."""
    doc = _contract()
    assert doc["disclosure_class"] == "operator_only"
    doc["cases"][0]["response_text"] = (
        "smuggled body"  # a Tier-1 field hidden under a Tier-0 label
    )
    reasons = case_ingest_gate(doc)
    assert any("response_text" in r and "shape" in r for r in reasons)


def test_v2_contract_is_refused_with_rerun_not_handadd():
    """🔴 acceptance 6 (store side): a v2 contract (no tenant) is refused, and the message says
    RE-RUN — never 'add a tenant field' (hand-adding a tenant is exactly what we prevent)."""
    doc = _contract()
    doc["schema_version"] = 2
    doc.pop("tenant_id")
    reasons = " ".join(case_ingest_gate(doc))
    assert "re-run" in reasons.lower()
    assert "hand-add" in reasons.lower()  # names the anti-pattern explicitly


def test_tampered_row_is_refused_does_not_readd():
    """acceptance 7: flip a verdict so the rows no longer re-add ⇒ refused (not silently stored)."""
    doc = _contract()
    doc["cases"][1]["verdict"] = "declined_by_model"  # was hard_blocked
    doc["cases"][1]["governance_reacted"] = False
    reasons = case_ingest_gate(doc)
    assert any("re-add" in r for r in reasons)


def test_clean_v3_contract_passes_the_gate():
    assert case_ingest_gate(_contract()) == []


def test_empty_contract_is_refused():
    """🔴 acceptance 15 (store side): an all-errored run (gateway unreachable) yields a contract whose
    three aggregates are all n=0. It self-re-adds (0=0), so the recompute check can't catch it — but
    it measured NOTHING. The store refuses it, pointing at gateway/identity readiness (§5.4)."""
    cases = [_case(f"c{i}", technique="t") for i in range(3)]
    results = [_probe(f"c{i}", decision=None, error="ReadTimeout") for i in range(3)]
    doc = serialize_case_contract(
        cases, results, target_kind="gateway", tenant_id="acme", generated_at_ns=1
    )
    reasons = case_ingest_gate(doc)
    assert any("empty contract" in r and "GATE-LASTMILE P4" in r for r in reasons)


# --------------------------------------------------------------------------- #
# §7 — the store never pulls the engine or a WAL reader
# --------------------------------------------------------------------------- #


def module_imports_wal_reader(module) -> bool:
    """True iff the MODULE's own source imports a WAL reader (AST, not a substring in a comment — the
    `'ci' in getsource` anti-pattern the egress gate warns about). The package __init__ pulls a reader
    for every `import treval.X`, so a sys.modules check is meaningless here; this checks the module's
    OWN import statements, which is what "app never imports a WAL reader" (acceptance 9) means."""
    src = Path(module.__file__).read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.ImportFrom) and node.module:
            if "readers" in node.module or "wal_reader" in node.module:
                return True
        elif isinstance(node, ast.Import):
            if any("readers" in n.name or "wal_reader" in n.name for n in node.names):
                return True
    return False


def test_case_store_pulls_no_engine():
    """§7: importing the store must not pull the active-eval harness — it cannot fire a probe. (The
    active_eval harness is NOT in the package baseline, so this sys.modules check is meaningful.)"""
    code = (
        "import sys; import treval.case_store; "
        "bad = [m for m in sys.modules if m.startswith('treval.active_eval')]; "
        "assert not bad, bad"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=_ROOT
    )
    assert proc.returncode == 0, proc.stderr


def test_case_store_source_imports_no_wal_reader():
    """🔴 §7/acceptance 9: the store never imports a WAL reader in its OWN source — add a
    `from treval.readers import ...` to case_store and this goes red."""
    import treval.case_store as mod

    assert not module_imports_wal_reader(mod)
