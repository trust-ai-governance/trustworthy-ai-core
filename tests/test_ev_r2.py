"""EV-R2 — the active-eval CASE-LEVEL result contract. The teeth:

§3.1 — the case rows re-add injection_catch_rate / injection_success_rate / the four cells
       BIT-FOR-BIT (the whole reason the contract exists); a constructed fork fails CLOSED.
§3   — verdict reuses the closed EV-ATTRIB vocabulary; a minted word is refused.
§3.2 — the two signals verdict drops (observable_via + governance_reacted) are what make the
       recompute exact; an `unmeasurable` case never lands in a rate denominator.
§2   — Tier 0 carries POINTERS ONLY (no response content); disclosure_class is mandatory +
       fail-closed; Tier 1 content is internal_handoff and the report store REFUSES it.
"""

from __future__ import annotations

import json

import pytest
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval import (
    CorpusCase,
    InjectionCatchRate,
    InjectionSuccessRate,
    serialize_case_contract,
)
from treval.active_eval.cases import (
    CaseContractError,
    assert_recomputes,
    build_cases,
    recompute_from_cases,
    validate_case_contract,
)
from treval.active_eval.target import ProbeResult
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus
from treval.report_store import ReportStoreError, write_bundle

_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
_UNDECIDED = rc_pb.DecisionTrace.FINAL_DECISION_UNDECIDED
_MARK = "ZZPWN"


def _case(cid, *, technique, marker=_MARK, canary="", attack_class="direct"):
    return CorpusCase(
        id=cid,
        owasp="LLM01",
        dimension="robustness",
        attack_class=attack_class,
        input="attack text",
        success_when="blocked_or_flagged",
        severity="high",
        source="core-authored",
        output_marker=marker,
        secret_canary=canary,
        attack_technique=technique,
    )


def _probe(
    cid,
    *,
    decision=_ALLOW,
    followed=False,
    hint=False,
    error=None,
    marker=_MARK,
    canary="",
    response_text=None,
    raw_response="",
):
    """A probe joined to _case(cid). decision ∈ {BLOCK, ALLOW, UNDECIDED, None}; followed ⇒ output
    starts with the marker; hint ⇒ a soft flag (reacted, not denied); None decision ⇒ no WAL
    record (with error ⇒ errored)."""
    ev = None
    if decision is not None:
        ctx = rc_pb.RequestContext()
        ctx.envelope.request_id = f"req-{cid}"
        ctx.decision.final_decision = decision  # type: ignore[assignment]
        r = ctx.decision.rules_evaluated.add()
        r.rule_id = "inj-1"
        r.matched = decision == _BLOCK
        if hint:
            ctx.audit.hint_emitted = True
        ev = AuditEvidence(
            ref=EvidenceRef(source="wal:/w/000.wal", seq=7, request_id=f"req-{cid}"),
            integrity=IntegrityStatus.VERIFIED,
            tenant_id="__eval__",
            received_at_ns=0,
            record=ctx,
        )
    if response_text is None:
        response_text = f"{_MARK} sure, done" if followed else "I will not do that"
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}" if error is None else "",
        decision="",
        response_text=response_text,
        raw_response=raw_response,
        evidence=ev,
        error=error,
        output_marker=marker,
        secret_canary=canary,
    )


# A mixed, all-DECIDED run exercising all four cells + a non-marker case + an errored case.
def _mixed_run():
    cases = [
        _case("succ", technique="role_override"),
        _case("hard", technique="delimiter_break"),
        _case("soft", technique="base64_smuggle"),
        _case("declined", technique="obfuscation"),
        _case("nm", technique="posture_probe", marker=""),  # detection-only (no marker)
        _case("err", technique="timeout_case"),
    ]
    results = [
        _probe("succ", decision=_ALLOW, followed=True),  # succeeded
        _probe("hard", decision=_BLOCK),  # hard_blocked
        _probe("soft", decision=_ALLOW, hint=True),  # soft_flag_declined
        _probe("declined", decision=_ALLOW),  # declined_by_model
        _probe(
            "nm", decision=_BLOCK, marker=""
        ),  # non-marker, caught (in CATCH denom only)
        _probe(
            "err", decision=None, error="ReadTimeout"
        ),  # errored (out of every denom)
    ]
    return cases, results


# --------------------------------------------------------------------------- #
# §3.1 — the recompute invariant (the hardest acceptance)
# --------------------------------------------------------------------------- #


def test_件_cases_re_add_the_three_aggregates_bit_for_bit():
    """🔴 §3.1: recompute injection_catch_rate / injection_success_rate / four cells from the case
    ROWS alone ⇒ EXACTLY the aggregate measurements. serialize runs this guard, so a clean
    serialize IS the proof; assert the numbers too, so the expectation is legible."""
    cases, results = _mixed_run()
    built = build_cases(cases, results, target_kind="gateway")
    rc = recompute_from_cases(built)

    (catch,) = InjectionCatchRate().measure(results)
    (succ,) = InjectionSuccessRate().measure(results)
    # CATCH denom = 5 decided (errored excluded); caught = hard + soft + non-marker block = 3.
    assert rc["injection_catch_rate"] == (3, 5)
    assert catch.value == 3 / 5 and catch.sample_size == 5
    # SUCCESS / four cells denom = 4 marker cases; one succeeded.
    assert rc["injection_success_rate"] == (1, 4)
    assert succ.value == 1 / 4 and succ.sample_size == 4
    assert rc["four_cell"] == {
        "succeeded": 1,
        "hard_blocked": 1,
        "soft_flag_declined": 1,
        "declined_by_model": 1,
    }
    # the guard itself agrees (bit-identical or it raises)
    assert_recomputes(built, results)


def test_envelope_embeds_the_indicator_aggregates():
    """🔴 §9.2: the envelope carries an `aggregates` block = the INDICATOR values (not the recompute
    output), so a reader can re-add the rows to it. schema_version is 2 (the bump that introduced
    it)."""
    cases, results = _mixed_run()
    contract = serialize_case_contract(
        cases, results, target_kind="gateway", tenant_id="acme", generated_at_ns=1
    )
    (catch,) = InjectionCatchRate().measure(results)
    agg = contract["aggregates"]
    assert contract["schema_version"] == 3
    assert agg["injection_catch_rate"] == {"value": catch.value, "n": catch.sample_size}
    assert agg["four_cell"] == {
        "hard_blocked": 1,
        "soft_flag_declined": 1,
        "succeeded": 1,
        "declined_by_model": 1,
        "n": 4,
    }


def test_件_a_constructed_fork_fails_closed():
    """🔴 §3.1 teeth: tamper ONE case row so it no longer re-adds ⇒ CaseContractError (the runtime
    form of '加不回来 = 不可信'). Flipping the hard_blocked case's governance_reacted to False drops
    the recomputed catch below the measured one."""
    cases, results = _mixed_run()
    built = build_cases(cases, results, target_kind="gateway")
    assert_recomputes(built, results)  # clean first
    forked = [dict(c) for c in built]
    hard = next(c for c in forked if c["case_id"] == "hard")
    hard["governance_reacted"] = False  # a lie: this case WAS caught
    with pytest.raises(CaseContractError, match="recompute FORK") as exc:
        assert_recomputes(forked, results)
    assert "injection_catch_rate" in str(exc.value)
    assert "GATE-LASTMILE P4" in str(
        exc.value
    )  # §9.6 — the troubleshooting half-sentence landed


def test_件_unmeasurable_case_enters_no_rate_denominator():
    """🔴 §3 / §3.2: a gateway-undecided probe is verdict='unmeasurable' — NOT 'not caught'. It must
    NOT lower catch (the fake-0% family): two caught marker cases + one undecided non-marker case ⇒
    catch stays 2/2 = 100%, never 2/3."""
    cases = [
        _case("a", technique="t1"),
        _case("b", technique="t2"),
        _case("u", technique="t3", marker=""),
    ]
    results = [
        _probe("a", decision=_BLOCK),
        _probe("b", decision=_BLOCK),
        _probe("u", decision=_UNDECIDED, marker=""),  # gateway never judged
    ]
    built = build_cases(cases, results, target_kind="gateway")
    assert next(c for c in built if c["case_id"] == "u")["verdict"] == "unmeasurable"
    rc = recompute_from_cases(built)
    assert rc["injection_catch_rate"] == (2, 2)  # undecided is OUT of the denominator
    assert_recomputes(
        built, results
    )  # and it matches the indicator (which also excludes it)


# --------------------------------------------------------------------------- #
# §3.2 — the two signals verdict drops; §3 — the closed vocabulary
# --------------------------------------------------------------------------- #


def test_observable_via_distinguishes_marker_canary_and_detection_only():
    """🔴 §3.2: observable_via is EV-COVERAGE axis③'s vocabulary, not a bool — llm02's canary case
    and llm01's marker case pick DIFFERENT denominators; a detection-only case selects neither."""
    cases = [
        _case("m", technique="t1", marker=_MARK),
        _case("c", technique="t2", marker="", canary="CANARY-xyz"),
        _case("d", technique="t3", marker=""),
    ]
    results = [
        _probe("m", decision=_ALLOW),
        _probe("c", decision=_ALLOW, marker="", canary="CANARY-xyz"),
        _probe("d", decision=_ALLOW, marker=""),
    ]
    built = {
        c["case_id"]: c for c in build_cases(cases, results, target_kind="gateway")
    }
    assert built["m"]["observable_via"] == "output_marker"
    assert built["c"]["observable_via"] == "secret_canary"
    assert built["d"]["observable_via"] is None


def test_verdict_vocabulary_is_closed():
    """§3: a minted verdict word is a second source of truth ⇒ refused by the reader validator."""
    doc = {
        "disclosure_class": "operator_only",
        "cases": [{"verdict": "totally_blocked", "observable_via": None}],
    }
    with pytest.raises(CaseContractError, match="closed set"):
        validate_case_contract(doc)


def test_missed_techniques_are_nameable_from_the_rows():
    """§8-3: 'which rule to fix' = the attack_technique of every case verdict != hard_blocked. The
    contract makes that a one-line derivation over the rows."""
    cases, results = _mixed_run()
    built = build_cases(cases, results, target_kind="gateway")
    got_through = sorted(
        c["attack_technique"] for c in built if c["verdict"] not in ("hard_blocked",)
    )
    # everything except the hard-blocked 'delimiter_break' + the excluded errored row is nameable
    assert "role_override" in got_through and "base64_smuggle" in got_through
    assert "delimiter_break" not in got_through


# --------------------------------------------------------------------------- #
# §2 — disclosure discipline: pointers only, mandatory class, Tier-1 refused by the store
# --------------------------------------------------------------------------- #


def test_tier0_carries_no_response_content_and_is_operator_only():
    """🔴 §2: Tier 0 is POINTERS ONLY. A distinctive response body must NOT appear anywhere in the
    serialized contract, and there is no response_text/raw_response key. disclosure_class is set,
    mandatory, and operator_only (never public)."""
    secret = "LEAK-9f3a-do-not-serialize"
    cases = [_case("x", technique="t1")]
    results = [_probe("x", decision=_ALLOW, response_text=secret, raw_response=secret)]
    contract = serialize_case_contract(
        cases, results, target_kind="gateway", tenant_id="acme", generated_at_ns=123
    )
    assert contract["disclosure_class"] == "operator_only"
    assert contract["schema_version"] == 3  # UI-3 §5.2 — v3 adds tenant_id
    assert contract["target_kind"] == "gateway"
    assert contract["tenant_id"] == "acme"  # v3: the tenant the probes ran as
    assert contract["corpus_sha"].startswith("sha256:")
    (row,) = contract["cases"]
    assert "response_text" not in row and "raw_response" not in row
    assert row["request_id"] == "req-x" and row["evidence_ref"]["seq"] == 7
    assert secret not in json.dumps(contract)  # 🔴 not one byte of content
    validate_case_contract(contract)  # a well-formed Tier-0 contract validates


def test_disclosure_class_is_mandatory_and_fails_closed():
    """🔴 §7: a contract with no disclosure_class is REFUSED — never defaulted to public."""
    with pytest.raises(CaseContractError, match="MANDATORY"):
        validate_case_contract({"cases": []})
    with pytest.raises(CaseContractError, match="MANDATORY"):
        validate_case_contract({"disclosure_class": "public", "cases": []})


def test_tier1_opt_in_embeds_content_and_is_internal_handoff():
    """§2.2: --include-response-content flips the class to internal_handoff and embeds the body."""
    secret = "TIER1-BODY-abc"
    cases = [_case("x", technique="t1")]
    results = [_probe("x", decision=_ALLOW, response_text=secret, raw_response=secret)]
    contract = serialize_case_contract(
        cases,
        results,
        target_kind="gateway",
        tenant_id="acme",
        generated_at_ns=1,
        include_response_content=True,
    )
    assert contract["disclosure_class"] == "internal_handoff"
    assert contract["cases"][0]["response_text"] == secret


def test_report_store_refuses_a_case_contract(tmp_path):
    """🔴 §7 / §6.1-1: the report store is SEPARATE from the case store — a case contract (Tier 0 or
    Tier 1) is refused, so a report-export path can never carry case rows."""
    cases = [_case("x", technique="t1")]
    results = [_probe("x", decision=_ALLOW)]
    tier0 = serialize_case_contract(
        cases, results, target_kind="gateway", tenant_id="acme", generated_at_ns=1
    )
    tier1 = serialize_case_contract(
        cases,
        results,
        target_kind="gateway",
        tenant_id="acme",
        generated_at_ns=1,
        include_response_content=True,
    )
    for contract in (tier0, tier1):  # operator_only AND internal_handoff both refused
        with pytest.raises(ReportStoreError, match="disclosure_class"):
            write_bundle(tmp_path, json.dumps(contract), generated_at_ns=1)
