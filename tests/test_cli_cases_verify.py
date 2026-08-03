"""EV-R2 §9 — `treval cases verify <cases.json>`. The teeth:

§9.8 — a tampered row OR a tampered aggregate ⇒ RED naming the aggregate; a v1 file ⇒ "predates
       aggregates" (NOT "fork"); the PASS output MUST carry the §9.4 scope declaration verbatim.
§9.3 — (b)/(e) content-free: a Tier-1 file's response body never appears in the output;
       (d) the per-case list labels the CELL, never a `!= hard_blocked` binary.
§9.10 — a Tier-1 (internal_handoff) file is accepted with a WARN, not rejected.
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from test_ev_r2 import _case, _probe
from treval.active_eval import serialize_case_contract
from treval.cli.cases_verify import _SCOPE_DECLARATION
from treval.cli.main import main

_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW


def _run(path) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["cases", "verify", str(path)])
    return rc, buf.getvalue()


def _write_contract(tmp_path, *, include_response_content=False, response=""):
    cases = [
        _case("succ", technique="role_override"),
        _case("hard", technique="delimiter_break"),
        _case("soft", technique="base64_smuggle"),
        _case("declined", technique="obfuscation"),
    ]
    results = [
        _probe("succ", decision=_ALLOW, followed=True, response_text=response or None),
        _probe("hard", decision=_BLOCK),
        _probe("soft", decision=_ALLOW, hint=True),
        _probe("declined", decision=_ALLOW),
    ]
    contract = serialize_case_contract(
        cases,
        results,
        target_kind="gateway",
        generated_at_ns=1,
        include_response_content=include_response_content,
    )
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(contract, indent=2), encoding="utf-8")
    return path, contract


def test_pass_prints_the_scope_declaration_verbatim(tmp_path):
    """🔴 §9.8(a): a clean file PASSes (exit 0) and the §9.4 scope block is PRINTED — deleting it
    makes this red. The point: an auditor reading green must SEE 'self-consistent ≠ true'."""
    path, _ = _write_contract(tmp_path)
    rc, out = _run(path)
    assert rc == 0
    assert "✅ self-consistent" in out and "4 case rows re-add" in out
    assert _SCOPE_DECLARATION in out  # the whole mandatory block, verbatim
    assert "does NOT prove the probes ever ran" in out
    assert "wal_verify.py" in out  # points the reader at the real end-to-end check


def test_per_case_list_labels_the_cell_not_a_binary(tmp_path):
    """🔴 §9.3(d)/§9.8(d): the per-case list names the cell each case landed in; the void
    `!= hard_blocked` binary appears nowhere."""
    path, _ = _write_contract(tmp_path)
    rc, out = _run(path)
    assert rc == 0
    assert "succeeded (1):" in out and "hard_blocked (1):" in out
    assert "soft_flag_declined (1):" in out and "declined_by_model (1):" in out
    assert "!= hard_blocked" not in out and "hard_blocked" in out


def test_per_case_list_is_split_by_denominator(tmp_path):
    """🔴 architect review: the flat list re-surfaced the cross-denominator fallacy — the four-cell
    aggregate counts the output_marker subset (declined_by_model=0) while the FULL list showed 3
    declined cases, reading as "the tool is broken / hiding something". The fix (option b) SPLITS the
    list: the marker block matches the aggregate (declined=0), the 3 detection-only misses sit in
    their OWN block — both populations visible on the page. Mirrors §9.7's live evidence: the
    gateway-missed evasive cases are exactly the unobservable ones."""
    cases = [
        _case("s1", technique="role_override"),  # marker → succeeded
        _case("h1", technique="delim"),  # marker → hard_blocked
        _case("h2", technique="delim2"),  # marker → hard_blocked
        _case("f1", technique="fuzz"),  # marker → soft_flag_declined
        _case(
            "base64_smuggle", technique="base64_smuggle", marker=""
        ),  # detection-only
        _case(
            "lang_switch", technique="language_switch_override", marker=""
        ),  # detection-only
        _case(
            "translate", technique="translate_then_leak", marker=""
        ),  # detection-only
    ]
    results = [
        _probe("s1", decision=_ALLOW, followed=True),
        _probe("h1", decision=_BLOCK),
        _probe("h2", decision=_BLOCK),
        _probe("f1", decision=_ALLOW, hint=True),
        # the 3 evasive misses: allowed, no marker ⇒ declined_by_model, observable_via=None
        _probe("base64_smuggle", decision=_ALLOW, marker=""),
        _probe("lang_switch", decision=_ALLOW, marker=""),
        _probe("translate", decision=_ALLOW, marker=""),
    ]
    contract = serialize_case_contract(
        cases, results, target_kind="gateway", generated_at_ns=1
    )
    # 🔴 the aggregate the reader would otherwise think contradicts the list:
    assert contract["aggregates"]["four_cell"]["declined_by_model"] == 0
    path = tmp_path / "cases.json"
    path.write_text(json.dumps(contract), encoding="utf-8")
    rc, out = _run(path)
    assert rc == 0
    # both denominators are headed structurally
    assert "output_marker subset (4)" in out and "detection-only (3)" in out
    assert "the four-cell aggregate (n=4)" in out
    # the 3 declined misses live in the detection-only block, not contradicting declined_by_model=0
    marker_hdr = out.index("output_marker subset")
    detonly_hdr = out.index("detection-only (3)")
    assert marker_hdr < detonly_hdr  # marker block first
    assert (
        "declined_by_model (3):" in out[detonly_hdr:]
    )  # the 3 misses, in the detection block
    for cid in ("base64_smuggle", "lang_switch", "translate"):
        assert (
            out.index(cid) > detonly_hdr
        )  # each miss sits AFTER the detection-only header


def test_tampering_a_verdict_row_is_caught(tmp_path):
    """🔴 §9.8: flip one verdict so the rows no longer re-add ⇒ RED naming the aggregate, exit 2."""
    path, contract = _write_contract(tmp_path)
    doc = json.loads(path.read_text())
    row = next(c for c in doc["cases"] if c["case_id"] == "hard")
    row["verdict"] = (
        "declined_by_model"  # was hard_blocked; also drops governance_reacted's meaning
    )
    row["governance_reacted"] = False
    path.write_text(json.dumps(doc), encoding="utf-8")
    rc, out = _run(path)
    assert rc == 2
    assert "NOT self-consistent" in out
    assert "injection_catch_rate" in out or "four_cell.hard_blocked" in out


def test_tampering_an_aggregate_number_is_caught(tmp_path):
    """🔴 §9.8: edit a number in `aggregates` (rows untouched) ⇒ RED. Self-consistency is two-sided."""
    path, _ = _write_contract(tmp_path)
    doc = json.loads(path.read_text())
    doc["aggregates"]["injection_catch_rate"]["value"] = 0.999
    path.write_text(json.dumps(doc), encoding="utf-8")
    rc, out = _run(path)
    assert rc == 2
    assert "NOT self-consistent" in out and "injection_catch_rate" in out


def test_v1_file_reports_predates_aggregates_not_fork(tmp_path):
    """🔴 §9.8: a schema_version 1 file (no aggregates) ⇒ 'predates aggregates', NOT 'fork' (the
    EV-CIGATE F1 version discipline — never call an OLD shape broken)."""
    path, contract = _write_contract(tmp_path)
    doc = json.loads(path.read_text())
    doc["schema_version"] = 1
    doc.pop("aggregates")
    path.write_text(json.dumps(doc), encoding="utf-8")
    rc, out = _run(path)
    assert rc == 2
    assert "predates" in out and "aggregates" in out
    assert (
        "fork" not in out.lower() or "NOT a fork" in out
    )  # never mis-diagnosed as a fork


def test_tier1_file_is_accepted_with_a_warning_and_stays_content_free(tmp_path):
    """🔴 §9.3(b)/(e) + §9.10: a Tier-1 (internal_handoff) file re-adds fine (Tier-0 fields only),
    prints a WARN that it should not circulate, and 🔴 the response body NEVER appears in the
    output — verify reads no content."""
    secret = "SECRET-BODY-do-not-echo-7f3a"
    path, contract = _write_contract(
        tmp_path, include_response_content=True, response=secret
    )
    assert contract["disclosure_class"] == "internal_handoff"
    assert secret in json.dumps(contract)  # it IS in the file...
    rc, out = _run(path)
    assert rc == 0  # accepted, not rejected
    assert "internal_handoff" in out and "should not be circulating" in out
    assert secret not in out  # 🔴 ...but NOT in verify's output


def test_missing_disclosure_class_is_refused(tmp_path):
    """§7/§9: a file with no disclosure_class fails closed — verify won't validate it."""
    path, _ = _write_contract(tmp_path)
    doc = json.loads(path.read_text())
    doc.pop("disclosure_class")
    path.write_text(json.dumps(doc), encoding="utf-8")
    rc, out = _run(path)
    assert rc == 2 and "cannot verify" in out
