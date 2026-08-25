"""EV-CN-TIER2 — the JUDGE side on Chinese: what it BUYS (recall lift, combined recall) and what it
COSTS (benign flag rate). Each test names what reds it AND what it measures."""

from __future__ import annotations

import pytest
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval import (
    BenignShadowFlagRate,
    InjectionCombinedRecall,
    Tier2ShadowRecallLift,
)
from treval.active_eval.indicators import ProbeResult
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus

_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW

_CN_TIER2_IDS = {
    "tier2_shadow_recall_lift",
    "injection_combined_recall",
    "benign_shadow_flag_rate",
}


def _decision(cid, *, blocked):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.decision.final_decision = _BLOCK if blocked else _ALLOW
    r = ctx.decision.rules_evaluated.add()
    r.rule_id = "inj-1"
    r.matched = blocked
    r.tags["family"] = "injection"
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=0, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="t",
        received_at_ns=0,
        record=ctx,
    )


def _governance(cid, *, hinted):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.record_type = rc_pb.AUDIT_RECORD_TYPE_GOVERNANCE_OBSERVED
    ctx.audit.hint_emitted = hinted
    r = ctx.decision.rules_evaluated.add()
    r.rule_id = "t2-judge"
    r.matched = hinted
    r.tags["tier"] = "2"
    return AuditEvidence(
        ref=EvidenceRef(source="wal:g", seq=1, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="t",
        received_at_ns=0,
        record=ctx,
    )


def _cn_attack_probes(*, drained=True, n=10, tier1=4, tier2=3):
    """🔴 Shaped like the REAL CN attack arm: NO canary, NO output_marker (the arm has zero of both)."""
    out = []
    for i in range(n):
        t1 = i < tier1
        t2 = (not t1) and i < tier1 + tier2
        out.append(
            ProbeResult(
                case_id=f"a{i}",
                request_id=f"req-a{i}",
                decision="",
                response_text="",
                evidence=_decision(f"a{i}", blocked=t1),
                governance_evidence=_governance(f"a{i}", hinted=True) if t2 else None,
                tier2_drain_executed=drained,
                attack_class="direct_prompt_injection",
            )
        )
    return out


# --------------------------------------------------------------------------- #
# 件1 — the three producers are wired, and the ENGLISH run is bit-identical
# --------------------------------------------------------------------------- #
def test_jian1_the_three_tier2_producers_are_in_CURATION_CN_with_the_zh_subject():
    # WHAT IT MEASURES: that the judge side is actually collected on Chinese. What reds it: remove a
    # producer ⇒ that number is never produced, and a missing number reads like a measured absence.
    from treval.cli.collect import CURATION_CN

    got = {p.indicator_id for p in CURATION_CN}
    assert _CN_TIER2_IDS <= got
    assert all(
        p.subject == "language:zh" for p in CURATION_CN
    )  # never binds a rubric objective


def test_jian1_the_english_run_is_untouched():
    # 🔴 件2 的老验收，别退化: adding CN rows must not make the English run probe one extra directory.
    # What reds it: put a CN producer into CURATION ⇒ every English run starts reading Chinese corpora.
    from treval.cli.collect import CURATION

    assert sorted({p.corpus_subdir for p in CURATION}) == [
        "llm01_benign_holdout",
        "llm01_prompt_injection",
        "llm01_speech_act",
        "llm02_sensitive_disclosure",
        "llm05_improper_output",
        "llm06_tool_scope",
        "llm07_system_prompt_leak",
    ]
    assert not any(p.corpus_subdir.startswith("llm01_cn_") for p in CURATION)


def test_jian1_the_tier2_producers_read_the_right_arms():
    # buy-side on the attack arm; cost-side on the HOLDOUT benign arm (never the calib/fit arm).
    from treval.cli.collect import CURATION_CN

    by = {p.indicator_id: p.corpus_subdir for p in CURATION_CN}
    assert by["tier2_shadow_recall_lift"] == "llm01_cn_injection"
    assert by["injection_combined_recall"] == "llm01_cn_injection"
    assert by["benign_shadow_flag_rate"] == "llm01_cn_benign_holdout"


# --------------------------------------------------------------------------- #
# 件2 (施工单②) — the canary question, settled BEFORE wiring
# --------------------------------------------------------------------------- #
def test_jian2_combined_recall_computes_WITHOUT_canaries_or_markers():
    # 🔴 the blocking question: the CN attack arm carries ZERO canaries and ZERO output markers, and
    # "wired but incomputable" is this repo's recurring defect. `caught_by_tier2` reads the hint at τ and
    # combined recall sums the aggregate catch with the lift — neither reads a canary.
    # What reds it: base either half on the marker-only subset ⇒ n collapses to 0 on this arm.
    probes = _cn_attack_probes()
    assert all(not p.output_marker and not p.secret_canary for p in probes)
    (lift,) = Tier2ShadowRecallLift().measure(probes)
    (combined,) = InjectionCombinedRecall().measure(probes)
    assert lift.sample_size == 10 and combined.sample_size == 10
    assert combined.value == pytest.approx(
        0.7
    )  # 4 Tier-1 + 3 Tier-2 rescues over ONE denominator


def test_jian2_combined_recall_refuses_when_the_halves_do_not_share_a_denominator(
    monkeypatch,
):
    # 🔴 门 — the two halves MUST share one denominator; a sum of numbers that do not add is worse than no
    # number, because it looks addable. The disagreement is forced here (rather than hoped for from a
    # probe shape) so the test exercises the REFUSAL BRANCH itself, deterministically.
    # What reds it: drop the n-equality check ⇒ the mismatched halves get summed anyway.
    from treval.models import Measurement

    probes = _cn_attack_probes()
    real = Tier2ShadowRecallLift.measure

    def divergent(self, results):
        (m,) = real(self, list(results))
        return (
            Measurement(
                indicator_id=m.indicator_id,
                dimension=m.dimension,
                value=m.value,
                unit=m.unit,
                sample_size=m.sample_size + 1,  # the halves now disagree
                evidence_refs=m.evidence_refs,
                notes=m.notes,
            ),
        )

    monkeypatch.setattr(Tier2ShadowRecallLift, "measure", divergent)
    (combined,) = InjectionCombinedRecall().measure(probes)
    assert (
        combined.sample_size == 0
    )  # 🔴 n=0 ⇒ insufficient_data, never a confident number
    assert "denominator mismatch" in combined.notes


# --------------------------------------------------------------------------- #
# 件3 — no drain ⇒ not_measured, never a confident 0
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "indicator", [Tier2ShadowRecallLift, InjectionCombinedRecall, BenignShadowFlagRate]
)
def test_jian3_without_the_drain_every_tier2_number_is_not_measured_not_zero(indicator):
    # 🔴 验收 — collect does not drain by itself. WHAT IT MEASURES: whether the async judge was actually
    # observed. A 0 here would say "the judge bought nothing"; the truth is "we never looked".
    # What reds it: drop the drain guard ⇒ an unobserved judge reports as a judge that did nothing.
    (m,) = indicator().measure(_cn_attack_probes(drained=False))
    assert m.sample_size == 0
    assert "n/a" in m.notes and "NOT a zero" in m.notes


def test_jian3_with_the_drain_the_numbers_appear():
    (m,) = Tier2ShadowRecallLift().measure(_cn_attack_probes(drained=True))
    assert m.sample_size == 10 and m.value > 0


# --------------------------------------------------------------------------- #
# 件4 — the co-report gate is TELLING THE TRUTH on CN; it must not be softened
# --------------------------------------------------------------------------- #
def test_jian4_cn_tier2_numbers_are_not_citable_because_CN_has_no_mention_arm():
    # 🔴 WHAT IT MEASURES: that a judge-movable number published without the mention arm says so. On CN
    # this fires because Chinese genuinely has no use/mention twins yet — the gate is reporting a real
    # gap, not malfunctioning. ⚠️ Making it green by editing the gate would be tuning the gate to the
    # data; the only honest route to green is writing the Chinese mention arm (件5, another slice).
    # 🔴 And the cost of this not_citable is ZERO here: CN is a diagnostic batch whose scope already
    # says 不可对外引用 — the gate takes away nothing the batch ever had.
    from treval.citability import JUDGE_MOVABLE_IDS, derive_judge_coreport

    cn_product = {"injection_catch_rate", "false_positive_rate"} | _CN_TIER2_IDS
    blocked = derive_judge_coreport(cn_product)
    assert blocked == JUDGE_MOVABLE_IDS & cn_product
    assert (
        "tier2_shadow_recall_lift" in blocked and "benign_shadow_flag_rate" in blocked
    )
    # the Chinese mention arm landing is what clears it — not a change to the gate
    assert (
        derive_judge_coreport(cn_product | {"speech_act_shadow_separation_rate"})
        == frozenset()
    )


def test_jian4_the_cost_side_is_measurable_today_without_a_mention_arm():
    # 🔴 §1 — benign_shadow_flag_rate counts how many Chinese benign cases the judge flagged and needs NO
    # mention arm. What is missing is the use/mention SLICE of the cost, not the cost itself.
    benign = [
        ProbeResult(
            case_id=f"b{i}",
            request_id=f"req-b{i}",
            decision="",
            response_text="",
            evidence=_decision(f"b{i}", blocked=False),
            governance_evidence=_governance(f"b{i}", hinted=i < 2) if i < 2 else None,
            tier2_drain_executed=True,
            attack_class="benign_hard_negative",
        )
        for i in range(10)
    ]
    (m,) = BenignShadowFlagRate().measure(benign)
    assert m.sample_size == 10 and m.value == pytest.approx(0.2)


# --------------------------------------------------------------------------- #
# 追加① — the raw judge score rides in the case table. WHAT IT MEASURES: nothing on its own — it is a
# DIAGNOSTIC FACT. Its value is that one read of a read-once arm yields the whole curve instead of one point.
# --------------------------------------------------------------------------- #
def test_add1_the_case_tables_carry_the_raw_judge_score():
    # 🔴 IRREVERSIBLE if skipped: the holdout arm is read-once, so a run without this column can only ever
    # be one point at the pre-registered τ — recovering the curve later means re-reading a spent arm.
    # What reds it: drop the column ⇒ the certification run buys a single point and cannot buy more.
    from treval.active_eval.cases import build_benign_cases, build_cases
    from treval.active_eval.corpus import CorpusCase

    def case(cid, klass):
        return CorpusCase(
            id=cid,
            owasp="LLM01",
            dimension="robustness",
            attack_class=klass,
            input="x",
            success_when="allowed" if "b" in cid else "blocked_or_flagged",
            severity="info",
            source="core-authored",
        )

    attack_probes = _cn_attack_probes(n=2, tier1=1, tier2=1)
    for pr, sc in zip(attack_probes, (0.91, 0.12)):
        if pr.governance_evidence is not None:
            pr.governance_evidence.record.decision.scores["injection_score"] = sc
    rows = build_cases(
        [case(p.case_id, "direct_prompt_injection") for p in attack_probes],
        attack_probes,
        target_kind="gateway",
    )
    assert all("injection_score" in r for r in rows)

    benign = [
        ProbeResult(
            case_id="b0",
            request_id="req-b0",
            decision="",
            response_text="",
            evidence=_decision("b0", blocked=False),
            governance_evidence=_governance("b0", hinted=True),
            tier2_drain_executed=True,
            attack_class="benign_hard_negative",
        )
    ]
    benign[0].governance_evidence.record.decision.scores["injection_score"] = 0.55
    brows = build_benign_cases(
        [case("b0", "benign_hard_negative")], benign, target_kind="gateway"
    )
    assert brows[0]["injection_score"] == pytest.approx(0.55)


def test_add1_the_raw_score_is_a_FACT_never_a_criterion():
    # 🔴 emit-vs-interpret: the catch signal is the hint the gateway emitted AT ITS OWN τ. Core must never
    # COMPARE this score against anything — a Core-side cut would be us grading the judge against a line we
    # chose after seeing its scores, and the gateway would no longer own its own threshold.
    # Checked by AST (not by grepping prose): any comparison whose operand is an injection_score() call.
    # What reds it: add `if injection_score(pr) > 0.5:` anywhere in the engine.
    import ast
    import inspect

    from treval.active_eval import cases as cases_mod
    from treval.active_eval import checks, indicators

    def _is_score_call(node):
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "injection_score"
        )

    offenders = []
    for mod in (checks, indicators, cases_mod):
        tree = ast.parse(inspect.getsource(mod))
        for node in ast.walk(tree):
            if isinstance(node, ast.Compare):
                operands = [node.left, *node.comparators]
                if any(_is_score_call(o) for o in operands):
                    offenders.append((mod.__name__, getattr(node, "lineno", "?")))
    assert not offenders, f"Core re-thresholded the raw judge score at {offenders}"


# --------------------------------------------------------------------------- #
# 追加② — the curve's citability, pre-registered BEFORE the run
# --------------------------------------------------------------------------- #
def test_add2_only_the_preregistered_tau_is_citable_every_other_point_is_in_sample():
    # 🔴 THE mutation that matters: remove the "other points are not citable" sentence and the next reader
    # picks the best-looking τ off the curve — at which moment the holdout arm has become a calibration
    # arm. That is not hypothetical; it is how the previous round died.
    from treval.citability import TAU_PREREGISTRATION_NOTE

    assert "预注册" in TAU_PREREGISTRATION_NOTE
    assert "只验这一个点" in TAU_PREREGISTRATION_NOTE
    assert (
        "in-sample" in TAU_PREREGISTRATION_NOTE
        and "不可引用" in TAU_PREREGISTRATION_NOTE
    )
    assert (
        "变成标定臂" in TAU_PREREGISTRATION_NOTE
    )  # names the failure, not just the rule
    assert (
        "4df97413" in TAU_PREREGISTRATION_NOTE
    )  # bound to the calib arm that produced τ


def test_add2_the_preregistration_travels_inside_the_curve_file():
    # the table now IS the curve, so the rule about quoting off it must ride in the same file.
    # What reds it: keep the note only in citability ⇒ whoever opens the table sees the curve, not the rule.
    import inspect

    from treval.active_eval import cases

    assert '"tau_preregistration"' in inspect.getsource(cases.serialize_case_contract)


# --------------------------------------------------------------------------- #
# 追加③ — the INVERSE assertion: no type-3 record ≠ a miss
# --------------------------------------------------------------------------- #
def test_add3_a_tier1_block_with_no_type3_record_counts_as_CAUGHT():
    # 🔴 WHAT IT MEASURES: that absence of a judge record is read as "the judge never had to look", not as
    # "the judge missed it". A Tier-1 hard block means the request never reached the judge — reading the
    # missing hint as a miss would charge Tier-1's success to Tier-2's failure.
    # What reds it: treat "no hint" as a miss ⇒ this probe drops out of the caught count.
    probes = [
        ProbeResult(
            case_id="t1only",
            request_id="req-t1only",
            decision="",
            response_text="",
            evidence=_decision("t1only", blocked=True),
            governance_evidence=None,  # 🔴 no type-3 record at all
            tier2_drain_executed=True,
            attack_class="direct_prompt_injection",
        )
    ]
    (combined,) = InjectionCombinedRecall().measure(probes)
    assert combined.sample_size == 1
    assert combined.value == pytest.approx(
        1.0
    )  # caught by Tier-1; the absent judge record is not a miss


# --------------------------------------------------------------------------- #
# 追加④ — the CN FPR is a Tier-1 quantity and must not be read as a judge-threshold gate
# --------------------------------------------------------------------------- #
def test_add4_the_cn_fpr_citation_says_it_is_a_TIER1_rate():
    # 🔴 under shadow the judge is not on the decision path, so this number cannot move with τ. Reading it
    # as a Tier-2 gate would let a judge threshold be "validated" by a rate that is blind to it.
    # What reds it: drop the note ⇒ the number reads as if it gated the judge.
    from treval.citability import CN_FPR_TIER1_SCOPE_NOTE, citation_form
    from treval.models import EvidenceRef, IntegrityStatus, Measurement

    def form(subject):
        m = Measurement(
            indicator_id="false_positive_rate",
            dimension="robustness",
            value=0.1,
            unit="ratio",
            sample_size=100,
            evidence_refs=(EvidenceRef(source="wal:x", seq=1),),
            subject=subject,
            ci_low=0,
            ci_high=1,
            integrity=IntegrityStatus.VERIFIED,
        )
        return citation_form(
            m,
            pinned=True,
            window=(1, 2),
            evidence_basis="wal_anchored",
            citable=True,
            first_blocker=None,
        )

    cn = form("language:zh")
    assert CN_FPR_TIER1_SCOPE_NOTE in cn
    assert "不得当作 Tier-2 的门" in cn and "benign_shadow_flag_rate" in cn
    assert CN_FPR_TIER1_SCOPE_NOTE not in form(
        ""
    )  # the English FPR has its own scope statement
