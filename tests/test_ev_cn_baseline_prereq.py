"""EV-CN-BASELINE Batch A (前置1 + 前置2) — the measurement-correctness prerequisites that MUST land
before any Chinese FPR is taken.

前置1 (§3.0) — false_positive_rate attributes a DECISION-stage block to the injection detector via the
gateway's own `decided_by`; a block by a NON-injection rule (e.g. a PII / number-shape rule, which CN
traffic hits more) is NOT an injection false positive — it exits the numerator, stays in the denominator,
and is counted (the F1 mirror the benign side never had).

前置2 (§3.0) — the runtime canary is digit-free (see test_ev_canary), and the FPR determinism claim is
split into two: ① the decision FUNCTION is deterministic; ② the INPUT is NOT bit-reproducible (canary
re-cast per run).
"""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval import FalsePositiveRate
from treval.active_eval.target import ProbeResult
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

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


def _benign_block(cid, *, decided_by=(), rules=()):
    """A benign case the gateway DECISION-stage BLOCKED. `rules` = [(rule_id, tags_dict)] (all matched);
    `decided_by` = the rule ids the gateway says MADE the block."""
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.decision.final_decision = _BLOCK  # type: ignore[assignment]
    for rid, tags in rules:
        r = ctx.decision.rules_evaluated.add()
        r.rule_id = rid
        r.matched = True
        for k, v in tags.items():
            r.tags[k] = v
    for rid in decided_by:
        ctx.decision.decided_by.append(rid)
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="",
        response_text="ok",
        evidence=_ev(cid, ctx),
        attack_class="benign_hard_negative",
    )


def _benign_allow(cid):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.decision.final_decision = _ALLOW  # type: ignore[assignment]
    r = (
        ctx.decision.rules_evaluated.add()
    )  # a rule ran ⇒ a GOVERNED allow (not decision_undecided)
    r.rule_id = "r"
    r.matched = False
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="",
        response_text="ok",
        evidence=_ev(cid, ctx),
        attack_class="benign_hard_negative",
    )


def _fpr(probes):
    (m,) = FalsePositiveRate().measure(probes)
    return m


# --------------------------------------------------------------------------- #
# 前置1 — injection-attributed blocks ARE FPs; non-injection blocks are NOT
# --------------------------------------------------------------------------- #
def test_injection_block_is_a_false_positive():
    m = _fpr([_benign_block("i", decided_by=["inj-1"], rules=[("inj-1", {})])])
    assert m.sample_size == 1 and m.value == 1.0  # blocked by injection ⇒ injection FP


def test_non_injection_block_exits_numerator_acceptance_prereq1():
    # 🔴 §7-1 — a benign blocked by a NON-injection (PII) rule is NOT an injection FP: exits the
    # numerator, STAYS in the denominator (a measured benign injection did not wrongly block), counted.
    m = _fpr(
        [_benign_block("pii", decided_by=["pii-phone-1"], rules=[("pii-phone-1", {})])]
    )
    assert m.sample_size == 1  # stays in the denominator
    assert m.value == 0.0  # 🔴 NOT in the numerator (counting it here ⇒ red)
    assert "non-injection-blocked" in m.notes  # counted separately, readable


def test_decided_by_is_precise_pii_decides_injection_only_evaluated():
    # 🔴 decided_by names the PII rule; an injection rule merely EVALUATED (did not decide) ⇒ non-injection
    m = _fpr(
        [_benign_block("x", decided_by=["pii-1"], rules=[("pii-1", {}), ("inj-2", {})])]
    )
    assert m.value == 0.0 and "non-injection-blocked" in m.notes


def test_attribution_by_tag_attack_class_and_owasp():
    a = _fpr(
        [
            _benign_block(
                "a",
                decided_by=["r1"],
                rules=[("r1", {"attack_class": "prompt_injection"})],
            )
        ]
    )
    b = _fpr(
        [_benign_block("b", decided_by=["r2"], rules=[("r2", {"owasp": "LLM01"})])]
    )
    assert (
        a.value == 1.0 and b.value == 1.0
    )  # ①② the gateway's own tags, not just the prefix


def test_mixed_injection_and_non_injection_blocks():
    probes = [
        _benign_block("i", decided_by=["inj-1"], rules=[("inj-1", {})]),  # FP
        _benign_block("p", decided_by=["pii-1"], rules=[("pii-1", {})]),  # not FP
        _benign_allow("ok"),  # clean allow
    ]
    m = _fpr(probes)
    assert m.sample_size == 3  # all three in the denominator
    assert m.value == 1 / 3  # only the injection block is an FP
    assert "1 non-injection-blocked" in m.notes


# --------------------------------------------------------------------------- #
# 前置2 — the FPR notes split determinism into TWO statements
# --------------------------------------------------------------------------- #
def test_fpr_notes_split_determinism_into_two_acceptance_prereq3():
    m = _fpr([_benign_allow("ok")])
    # ① decision FUNCTION deterministic …
    assert "deterministic" in m.notes and "FUNCTION" in m.notes
    # ② … BUT the INPUT is NOT bit-reproducible (canary re-cast) — the claim the old wording dropped
    assert "NOT bit-reproducible" in m.notes and "canary re-cast" in m.notes
