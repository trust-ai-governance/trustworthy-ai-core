"""EV-CN-BASELINE Batch B (§3.1 + 前置3) — the CN diagnostic-batch plumbing. Each test names the input
that reds it (§7 acceptance). Covers:
  件1  same-id/different-subdir producer set ⇒ raise (not silent overwrite)
  件2  CURATION_CN + --corpus-set (default en bit-identical)
  件3  carrier-rate arms per corpus-set (en arms never hold a CN dir)
  件4  benign case-level table (queryable by case_id, 拦截来源 via decision_injection_source, canary-safe)
  件5  corpus gates point out-of-repo + PRINT "本项未校验" on an empty pass (never silent)
  前置3 offline-recomputability marker — DERIVED from the corpus set, machine-gated, mix-without-label ⇒ red
  bonus unattributable ⇒ a LOUD warning (detection layer likely didn't run), not just a count
"""

from __future__ import annotations

import pytest
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval import InjectionCatchRate
from treval.active_eval.canary import CanaryLeakError
from treval.active_eval.cases import serialize_benign_case_table
from treval.active_eval.corpus import CorpusCase
from treval.active_eval.target import ProbeResult
from treval.cli.collect import (
    CURATION,
    CURATION_CN,
    Producer,
    _assert_no_id_subdir_collision,
    carrier_arm_dirs,
    curation_for,
)
from treval.cli.bundle import build_bundle
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus, Measurement
from treval.rubric.serialize import (
    OFFLINE_HOLDER_ONLY,
    OFFLINE_THIRD_PARTY,
    assert_offline_recomputable_derived,
    assert_recomputability_labeled,
    derive_offline_recomputable,
)

import tools.check_benign as check_benign
import tools.check_canary as check_canary

_BLOCK = rc_pb.DecisionTrace.FINAL_DECISION_BLOCK


# --------------------------------------------------------------------------- #
# 件1 — same indicator_id → two corpus_subdirs in one set ⇒ RAISE (§7-5)
# --------------------------------------------------------------------------- #
def test_jian1_same_id_different_subdir_raises():
    clash = (
        Producer("false_positive_rate", CURATION[0].factory, "llm01_benign"),
        Producer("false_positive_rate", CURATION[0].factory, "llm01_cn_benign"),
    )
    with pytest.raises(ValueError, match="two corpus_subdirs"):
        _assert_no_id_subdir_collision(clash)


def test_jian1_same_id_same_subdir_is_fine():
    # the aggregate + its disclosure rows share a subdir — that must NOT raise (only a SPLIT does).
    ok = (
        Producer("injection_catch_rate", CURATION[0].factory, "llm01_prompt_injection"),
        Producer(
            "injection_catch_rate",
            CURATION[0].factory,
            "llm01_prompt_injection",
            subject="outcome_observable",
        ),
    )
    _assert_no_id_subdir_collision(ok)  # no raise
    _assert_no_id_subdir_collision(CURATION)  # the real set is clean
    _assert_no_id_subdir_collision(CURATION_CN)


# --------------------------------------------------------------------------- #
# 件2 — CURATION_CN + corpus-set (default en bit-identical) (§7-4)
# --------------------------------------------------------------------------- #
def test_jian2_default_en_producer_set_is_unchanged():
    # 🔴 §7-4 — the DEFAULT (`en`) set IS CURATION, so the probed corpus dirs are byte-for-byte the
    # pre-change set. What reds it: point the default at CURATION_CN (the "默认改成 cn" mutation).
    assert curation_for("en") is CURATION
    en_dirs = {p.corpus_subdir for p in curation_for("en")}
    cn_dirs = {p.corpus_subdir for p in curation_for("cn")}
    assert en_dirs == {p.corpus_subdir for p in CURATION}
    assert cn_dirs == {"llm01_cn_injection", "llm01_cn_benign"}
    assert not (en_dirs & cn_dirs)  # the two sets share no corpus dir


def test_jian2_unknown_corpus_set_fails_closed():
    with pytest.raises(ValueError, match="unknown --corpus-set"):
        curation_for("de")


# --------------------------------------------------------------------------- #
# 件3 — carrier-rate arms per corpus-set; en arms never hold a CN dir (§7-6)
# --------------------------------------------------------------------------- #
def test_jian3_en_arms_hold_no_cn_dir():
    attack, benign = carrier_arm_dirs(CURATION)
    assert attack == ("llm01_prompt_injection",) and benign == ("llm01_benign",)
    assert not any("cn" in d for d in attack + benign)  # §7-6


def test_jian3_cn_arms_are_cn_dirs():
    attack, benign = carrier_arm_dirs(CURATION_CN)
    assert attack == ("llm01_cn_injection",) and benign == ("llm01_cn_benign",)


# --------------------------------------------------------------------------- #
# 件4 — benign case table: queryable by case_id, 拦截来源 readable, canary-safe (§7-11)
# --------------------------------------------------------------------------- #
def _ev(cid, ctx):
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=0, request_id=f"req-{cid}"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="__eval__",
        received_at_ns=0,
        record=ctx,
    )


def _benign_block(cid, rule_id, tags):
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = f"req-{cid}"
    ctx.decision.final_decision = _BLOCK  # type: ignore[assignment]
    r = ctx.decision.rules_evaluated.add()
    r.rule_id = rule_id
    r.matched = True
    ctx.decision.decided_by.append(rule_id)
    for k, v in tags.items():
        r.tags[k] = v
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="",
        response_text="ok",
        evidence=_ev(cid, ctx),
        attack_class="benign_hard_negative",
    )


def _benign_case(cid):
    return CorpusCase(
        id=cid,
        owasp="LLM01",
        dimension="robustness",
        attack_class="benign_hard_negative",
        input="x",
        success_when="allowed",
        severity="low",
        source="core-authored",
    )


def test_jian4_blocked_benign_is_queryable_with_block_source():
    pii = _benign_block(
        "b-pii", "pii-phone-1", {"owasp": "LLM02"}
    )  # non-injection block
    inj = _benign_block("b-inj", "inj-lexical-1", {"owasp": "LLM01"})  # injection FP
    tbl = serialize_benign_case_table(
        [_benign_case("b-pii"), _benign_case("b-inj")],
        [pii, inj],
        target_kind="gateway",
        tenant_id="__eval__",
        generated_at_ns=1,
    )
    by_id = {r["case_id"]: r for r in tbl["cases"]}
    # 🔴 §7-11 — queryable by case_id, AND 拦截来源 is readable (the A1 predicate, reused not re-minted):
    assert by_id["b-pii"]["denied_at_decision"] is True
    assert (
        by_id["b-pii"]["decision_block_source"] is None
    )  # NON-injection ⇒ not an injection FP
    assert by_id["b-inj"]["decision_block_source"] == "tag_owasp"  # injection ⇒ an FP
    assert by_id["b-pii"]["fired_rule_ids"] == ["pii-phone-1"]
    assert tbl["disclosure_class"] == "operator_only"


def test_jian4_canary_plaintext_is_refused():
    # 🔴 architect ② — a canary value must NEVER land in a circulated artifact. The same guard the attack
    # table守着 (assert_no_canary_plaintext) refuses it here. Plant a literal canary in the fired rule id.
    pr = _benign_block("b", "CANARY-abcdefghij-leaked", {"owasp": "LLM02"})
    with pytest.raises(CanaryLeakError):
        serialize_benign_case_table(
            [_benign_case("b")],
            [pr],
            target_kind="gateway",
            tenant_id="__eval__",
            generated_at_ns=1,
        )


# --------------------------------------------------------------------------- #
# 件5 — the gates announce "本项未校验" on an empty pass, never silently (§7-14)
# --------------------------------------------------------------------------- #
def test_jian5_check_benign_cn_absent_announces_not_verified(capsys):
    rc = check_benign.main(
        ["--corpus-set", "cn"]
    )  # CN corpus is out-of-repo ⇒ absent in-repo
    out = capsys.readouterr().out
    assert rc == 0
    assert "本批语料不在本仓" in out and "本项未校验" in out  # NEVER a silent pass


def test_jian5_check_benign_en_default_still_runs(capsys):
    rc = check_benign.main([])  # default en = the real in-repo benign corpus
    out = capsys.readouterr().out
    assert rc == 0
    assert (
        "llm01_benign" in out and "本项未校验" not in out
    )  # a real check, not the not-verified path


def test_jian5_check_canary_cn_absent_announces_not_verified(capsys):
    rc = check_canary.main(["--corpus-set", "cn"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "本批语料不在本仓" in out and "carrier-rate 本项未校验" in out


# --------------------------------------------------------------------------- #
# 前置3 — offline-recomputability: DERIVED, machine-gated, mix-without-label ⇒ red (§7-3b)
# --------------------------------------------------------------------------- #
def test_prereq3_marker_is_derived_from_corpus_set():
    assert derive_offline_recomputable("en") == OFFLINE_THIRD_PARTY
    assert derive_offline_recomputable("cn") == OFFLINE_HOLDER_ONLY
    with pytest.raises(ValueError):
        derive_offline_recomputable("xx")


def test_prereq3_derived_gate_rejects_independent_storage():
    # 🔴 architect ① — the marker may NOT be stored independently; a hand-set value that disagrees with
    # derive(corpus_set) fails the machine gate (same shape as assert_evidence_basis_derived).
    with pytest.raises(ValueError, match="never stored independently"):
        assert_offline_recomputable_derived("en", OFFLINE_HOLDER_ONLY)
    assert_offline_recomputable_derived(
        "cn", OFFLINE_HOLDER_ONLY
    )  # the derived value passes


def test_prereq3_mixed_classes_without_label_is_red():
    # 🔴 §7-3b — a report mixing recomputable + holder-only WITHOUT labelling every row ⇒ red.
    with pytest.raises(ValueError, match="mixes offline-recomputable classes"):
        assert_recomputability_labeled([OFFLINE_HOLDER_ONLY, None])
    # a single class, or a FULLY-labelled mix, passes (the mix is annotated, not silent):
    assert_recomputability_labeled([OFFLINE_THIRD_PARTY, OFFLINE_THIRD_PARTY])
    assert_recomputability_labeled([OFFLINE_THIRD_PARTY, OFFLINE_HOLDER_ONLY])
    assert_recomputability_labeled([None, None])


def _measurement(iid="false_positive_rate", subject=""):
    return Measurement(
        indicator_id=iid,
        dimension="robustness",
        value=0.0,
        unit="ratio",
        sample_size=1,
        evidence_refs=(),
        subject=subject,
    )


def test_prereq3_bundle_stamps_the_marker_per_measurement_and_run():
    cn = build_bundle(
        (_measurement(),),
        tenant_id="__eval__",
        window=(0, 1),
        mode="x",
        corpus_set="cn",
    )
    assert cn["offline_recomputable"] == OFFLINE_HOLDER_ONLY  # run-level
    assert all(
        m["offline_recomputable"] == OFFLINE_HOLDER_ONLY for m in cn["measurements"]
    )  # 🔴 §1.3 逐 measurement 带
    en = build_bundle(  # default corpus_set='en'
        (_measurement(),), tenant_id="__eval__", window=(0, 1), mode="x"
    )
    assert en["offline_recomputable"] == OFFLINE_THIRD_PARTY


# --------------------------------------------------------------------------- #
# bonus ⑤ — a nonzero `unattributable` is a LOUD warning, not a bland count
# --------------------------------------------------------------------------- #
def test_bonus_unattributable_emits_a_loud_warning():
    # a benign-looking attack probe blocked purely by a PII rule, NO injection rule evaluated ⇒
    # unattributable. On a healthy gateway this branch is unreachable, so a hit is a serious event.
    pr = ProbeResult(
        case_id="u",
        request_id="req-u",
        decision="",
        response_text="",
        evidence=_benign_block("u", "pii-1", {"owasp": "LLM02"}).evidence,
        attack_class="direct_prompt_injection",
    )
    (m,) = InjectionCatchRate().measure([pr])
    assert "WARNING" in m.notes and "检测层很可能" in m.notes  # loud, not just a tally
    assert (
        "1 unattributable" in m.notes
    )  # the count is STILL there (计数 + notes + warning)


# --------------------------------------------------------------------------- #
# 🔴 件2 fix — a Producer's DECLARED `subject` must REACH the measurement row.
#
# It used to be pure documentation: `Producer.subject` said "MUST match what factory().measure()
# stamps" and NOTHING checked it, so the `cn` producers declared subject="language:zh" while the
# indicators stamped "". The CN rows came out as AGGREGATE rows — which BIND to rubric objectives.
# Observed live on the first CN baseline: the report graded rob.l2 off 54 diagnostic Chinese cases
# and printed "能力缺口 · 任何样本量都过不了线" for a batch declared NOT citable.
# 🔴 A declaration nobody enforces is not a declaration.
# --------------------------------------------------------------------------- #
def test_cn_producers_stamp_their_declared_subject_so_the_rows_never_bind() -> None:
    """Every `cn` producer declares a non-empty subject ⇒ its row must carry it (⇒ never binds)."""
    cn = curation_for("cn")
    assert cn, "the cn set must not be empty"
    for prod in cn:
        assert prod.subject, (
            f"{prod.indicator_id}: a cn producer with an EMPTY subject emits an AGGREGATE row, "
            "which binds to a rubric objective — a diagnostic batch would be graded"
        )


def test_declared_subject_is_applied_to_the_measurement_row() -> None:
    """走真代码 `_apply_declared_subject` —— 内联复刻逻辑的测试变异杀不掉，等于永远绿。"""
    from treval.cli.collect import _apply_declared_subject

    m = Measurement(
        indicator_id="injection_catch_rate",
        dimension="robustness",
        value=0.5,
        unit="ratio",
        sample_size=10,
        evidence_refs=(),
        subject="",
    )
    prod = curation_for("cn")[0]
    assert _apply_declared_subject(prod, m).subject == "language:zh", (
        "the declared subject did not reach the row — the CN rows would bind to grading"
    )
    # an indicator that stamps its OWN subject still wins (the two must never fight)
    from dataclasses import replace as _replace

    own = _replace(m, subject="outcome_observable")
    en_agg = next(p for p in curation_for("en") if not p.subject)
    assert _apply_declared_subject(en_agg, own).subject == "outcome_observable"


def test_declared_subject_that_does_not_reach_the_row_raises() -> None:
    """🔴 守卫分支：声明了 subject 却没落到行上 ⇒ 必须 raise，不许静默。

    只有"填空"那一半而没有这道守卫，一个自己盖了【别的】subject 的指标会悄悄绕过声明 ——
    而声明存在的全部理由就是"这一行不许绑定评级"。没人检查的声明不是声明。"""
    from dataclasses import replace as _replace

    from treval.cli.collect import Producer, _apply_declared_subject

    prod = Producer(
        "injection_catch_rate", InjectionCatchRate, "x", subject="language:zh"
    )
    conflicting = Measurement(
        indicator_id="injection_catch_rate",
        dimension="robustness",
        value=0.5,
        unit="ratio",
        sample_size=10,
        evidence_refs=(),
        subject="something_else",
    )
    with pytest.raises(ValueError, match="declares subject"):
        _apply_declared_subject(prod, conflicting)
    # 同一条路径上，声明为空时不得误报
    _apply_declared_subject(_replace(prod, subject=""), conflicting)
