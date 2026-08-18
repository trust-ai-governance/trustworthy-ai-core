"""序8 件3 — final_terminal is a FREE proto string; read it by WHITELIST membership (never substring),
classify the no-verdict states (REJECTED/PENDING/ERROR/TIMEOUT/"") as a THIRD state that EXITS the
denominator (not a silent allow/miss), and RAISE on an unregistered value. Acceptance ①–⑤ + the shared
reliability whitelist (terminal_error_ratio).
"""

from __future__ import annotations

import pytest
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval import InjectionCatchRate
from treval.active_eval.checks import (
    _caught_at_response,
    hard_blocked,
    response_no_verdict,
)
from treval.active_eval.target import ProbeResult
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus
from treval.terminal import (
    UnknownTerminalError,
    is_error_terminal,
    response_terminal_class,
)

_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW


def _ev(cid, ctx):
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=0, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="__eval__",
        received_at_ns=0,
        record=ctx,
    )


def _decision(cid, final):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.decision.final_decision = final  # type: ignore[assignment]
    r = ctx.decision.rules_evaluated.add()  # a rule ran ⇒ NOT gateway_undecided
    r.rule_id = "inj-1"  # injection prefix ⇒ a decision BLOCK is an attributable catch
    r.matched = final == _BLOCK
    return _ev(cid, ctx)


def _response(cid, terminal):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.response.final_terminal = terminal
    return _ev(cid, ctx)


def _probe(cid, *, final=_ALLOW, terminal=None):
    resp = _response(cid, terminal) if terminal is not None else None
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="",
        response_text="x",
        evidence=_decision(cid, final),
        response_evidence=resp,
        attack_class="direct_prompt_injection",
    )


def _catch(probes):
    (m,) = InjectionCatchRate().measure(probes)
    return m


# --------------------------------------------------------------------------- #
# the classifier — whitelist membership, three states, raise on unknown
# --------------------------------------------------------------------------- #
def test_terminal_classifier_whitelist_three_states():
    assert response_terminal_class("BLOCKED") == "block"
    assert response_terminal_class("ALLOWED") == "allow"
    for t in ("REJECTED", "PENDING", "ERROR", "TIMEOUT", ""):
        assert response_terminal_class(t) == "no_verdict"
    assert response_terminal_class("  blocked  ") == "block"  # strip + case-insensitive


def test_unknown_terminal_raises_acceptance1():
    # ① "NOT_BLOCKED" — the substring `"BLOCK" in x` USED to read this as a block; now it RAISES.
    with pytest.raises(UnknownTerminalError, match="未登记取值"):
        response_terminal_class("NOT_BLOCKED")
    with pytest.raises(UnknownTerminalError):
        _caught_at_response(_response("x", "NOT_BLOCKED"))


def test_blocked_terminal_still_a_block_acceptance4():
    # ④ regression — BLOCKED must still read as a block at the response stage.
    assert response_terminal_class("BLOCKED") == "block"
    assert _caught_at_response(_response("x", "BLOCKED")) is True
    assert hard_blocked(_probe("x", final=_ALLOW, terminal="BLOCKED")) is True


def test_response_no_verdict_predicate():
    assert response_no_verdict(_probe("x", terminal="REJECTED")) is True
    assert (
        response_no_verdict(_probe("x", terminal="")) is True
    )  # "" = no response observation
    assert response_no_verdict(_probe("x", terminal="ALLOWED")) is False  # clean allow
    assert (
        response_no_verdict(_probe("x", terminal="BLOCKED")) is False
    )  # caught IS a verdict
    assert (
        response_no_verdict(_probe("x", terminal=None)) is False
    )  # no response record


# --------------------------------------------------------------------------- #
# the denominator — no-verdict terminals EXIT (never a silent allow/miss)
# --------------------------------------------------------------------------- #
def test_catch_no_verdict_terminals_exit_denominator_acceptance2_3():
    # ② "" and ③ REJECTED/ERROR exit the denominator + are counted; only the real catch remains.
    caught = _probe(
        "c", final=_BLOCK
    )  # decision BLOCK, inj-1 matched ⇒ attributable catch
    probes = [
        caught,
        _probe("nv1", final=_ALLOW, terminal=""),  # ②
        _probe("nv2", final=_ALLOW, terminal="REJECTED"),  # ③
        _probe("nv3", final=_ALLOW, terminal="ERROR"),  # ③
    ]
    m = _catch(probes)
    assert m.sample_size == 1  # 3 no-verdict exited ⇒ denominator is 1, NOT 4
    assert m.value == 1.0
    assert "3 no-verdict" in m.notes  # counted + readable


def test_catch_all_no_verdict_is_not_measured_acceptance5():
    # ⑤ flagship — all probes no-verdict ⇒ not_measured (n=0), NEVER a pretty "catch 0%".
    probes = [
        _probe(f"nv{i}", final=_ALLOW, terminal=t)
        for i, t in enumerate(("", "REJECTED", "ERROR", "PENDING"))
    ]
    m = _catch(probes)
    assert m.sample_size == 0 and m.value == 0.0  # insufficient_data, not 0%
    assert "no-verdict" in m.notes


# --------------------------------------------------------------------------- #
# the shared reliability whitelist (terminal_error_ratio)
# --------------------------------------------------------------------------- #
def test_is_error_terminal_membership_not_substring():
    assert is_error_terminal("ERROR") and is_error_terminal("TIMEOUT")
    assert not is_error_terminal("BLOCKED") and not is_error_terminal("ALLOWED")
    assert not is_error_terminal("")  # no_verdict, but not an ERROR terminal
    # 🔴 substring regression: "NOT_AN_ERROR" contains "ERROR" but is UNREGISTERED ⇒ raise, not match
    with pytest.raises(UnknownTerminalError):
        is_error_terminal("NOT_AN_ERROR")


# --------------------------------------------------------------------------- #
# 序8 件2 — the imaginary TIMEOUT/TIMED_OUT/FAIL are UNREGISTERED: classified by historical
# convention (so terminal_error_ratio's tests hold) but FLAGGED in the number's notes; a truly
# unknown value still RAISES.
# --------------------------------------------------------------------------- #
from treval.indicators.terminal_error_ratio import TerminalErrorRatio  # noqa: E402
from treval.terminal import is_unregistered_terminal  # noqa: E402

_RESP = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED


def _brec(cid, terminal):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.record_type = _RESP  # type: ignore[assignment]
    ctx.response.final_terminal = terminal
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=0, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="t",
        received_at_ns=0,
        record=ctx,
    )


def _terr(records):
    (m,) = TerminalErrorRatio().measure(records)
    return m


def test_is_unregistered_terminal():
    assert is_unregistered_terminal("TIMEOUT") and is_unregistered_terminal("timed_out")
    assert not is_unregistered_terminal("ALLOWED") and not is_unregistered_terminal("")
    assert not is_unregistered_terminal(
        "FOO"
    )  # truly-unknown ⇒ False (it RAISES in the classifier)
    # still classified (historical) — no raise, and still an error terminal for reliability
    assert response_terminal_class("TIMEOUT") == "no_verdict"
    assert is_error_terminal("TIMED_OUT") is True


def test_terminal_error_ratio_flags_unregistered_in_notes_acceptance1():
    # ① TIMED_OUT ⇒ classification unchanged (counts as an error) AND notes carries the warning
    m = _terr([_brec("a", "ALLOWED"), _brec("b", "TIMED_OUT")])
    assert m.value == 0.5  # 1 error of 2 — classification unchanged
    assert (
        "未登记取值" in m.notes and "TIMED_OUT" in m.notes
    )  # rides WITH the number, not stderr


def test_terminal_error_ratio_no_warning_when_all_declared_acceptance3():
    # ③ all declared values ⇒ NO unregistered warning (never unconditionally attached)
    m = _terr([_brec("a", "ALLOWED"), _brec("b", "BLOCKED"), _brec("c", "ERROR")])
    assert "未登记取值" not in m.notes


def test_terminal_error_ratio_truly_unknown_still_raises_acceptance2():
    # ② a truly-unknown value (FOO) still RAISES — 件2 must not relax this
    with pytest.raises(UnknownTerminalError):
        _terr([_brec("a", "FOO")])
