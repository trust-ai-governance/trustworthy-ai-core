"""EV-CN-BENIGN-N180 — separate FIT (calibration) from MEASUREMENT (holdout). Each test names the input
that reds it (§5). This file grows per construction item (件0 … 件8)."""

from __future__ import annotations

import pytest

from treval.citability import report_citability, tau_verified
from treval.provenance import build_provenance

# a fully-declared, citable freeze pack (all ten _config_keys + the pin/segment/build fields)
_FULL = dict(
    language_scope="英文为主",
    tested_version="v4@2026-01-30",
    detect_config="encode_decode=off",
    exec_mode="block",
    detection_layer_status="tier1_only",
    upstream_timeout_s=60.0,
    judge_form="single",
    measurement_path="in_product_gateway",
    tau_declared="shipped",
    tau_source="shipped",
)


def _prov(**overrides):
    """A citable provenance; overrides drop/replace keys to test the gate."""
    kw = {**_FULL, **overrides}
    p = build_provenance(
        wal_dir="/wal",
        window=(100, 200),
        pinned=True,
        tenant_id="t",
        record_count=5,
        generated_at_ns=200,
        **kw,
    )
    p["wal_segments"] = {"sha256": "sha256:" + "a" * 64}
    return p


def _bundle(prov):
    return {
        "evidence_basis": "wal_anchored",
        "provenance": prov,
        "report": {"integrity_summary": {"verified": 5, "unverified": 0, "broken": 0}},
    }


# --------------------------------------------------------------------------- #
# 件0 — the four judge/τ declaration keys fold into missing_run_config
# --------------------------------------------------------------------------- #
def test_jian0_all_ten_keys_declared_is_citable():
    ok, blockers = report_citability(_bundle(_prov()))
    assert ok is True and blockers == []


@pytest.mark.parametrize(
    "key", ["judge_form", "measurement_path", "tau_declared", "tau_source"]
)
def test_jian0_missing_any_judge_key_blocks_citation(key):
    # 🔴 present-but-empty ⇒ not citable (a run that didn't declare). What reds it: drop the key from
    # _config_keys so its absence no longer blocks.
    ok, blockers = report_citability(_bundle(_prov(**{key: ""})))
    assert ok is False and blockers


def test_jian0_pre_n180_bundle_is_diagnosed_as_drift_not_a_defect():
    # 🔴 an OLD bundle (the four keys absent entirely, not empty) ⇒ not citable, diagnosed as DRIFT
    # (旧判据…不是坏了), never a crash and never a silent pass.
    prov = _prov()
    for k in ("judge_form", "measurement_path", "tau_declared", "tau_source"):
        del prov[k]
    ok, blockers = report_citability(_bundle(prov))
    assert ok is False
    assert any(
        "旧判据" in b and "不是坏了" in b for b in blockers
    )  # DRIFT, not a defect


# --------------------------------------------------------------------------- #
# 件0 — tau_verified derived third state (today ALWAYS unverifiable), rides in the citation
# --------------------------------------------------------------------------- #
def test_jian0_tau_verified_is_unverifiable_without_a_shipped_tau():
    # the shipped build fingerprint carries no τ ⇒ we CANNOT confirm the τ ⇒ unverifiable (never "ok").
    assert tau_verified(_prov()) == "unverifiable"
    assert tau_verified({}) == "unverifiable"


def test_jian0_tau_verified_matches_and_mismatches_when_a_shipped_tau_exists():
    # once the shipped fingerprint carries τ (Platform P-3), this becomes a key lookup — matched/mismatch.
    fp = {"detection_switches": {"tau": "0.62"}}
    assert (
        tau_verified(_prov(tau_declared="0.62", build_fingerprint_after=fp))
        == "matched"
    )
    assert (
        tau_verified(_prov(tau_declared="0.55", build_fingerprint_after=fp))
        == "mismatch"
    )


def test_jian0_tau_verified_rides_in_the_citation_form():
    from treval.citability import run_config_note

    note = run_config_note(_prov())
    assert "τ核验 unverifiable" in note and "测量路径 in_product_gateway" in note


# --------------------------------------------------------------------------- #
# 件2 — the calibration arm is structurally unreachable (fit set never a producer)
# --------------------------------------------------------------------------- #
def test_jian2_a_calib_producer_raises():
    from treval.active_eval.indicators import FalsePositiveRate
    from treval.cli.collect import (
        CURATION,
        CURATION_CN,
        Producer,
        _assert_no_calib_producer,
    )

    calib = (
        Producer(
            "false_positive_rate",
            FalsePositiveRate,
            "llm01_cn_benign_calib",
            subject="language:zh",
        ),
    )
    with pytest.raises(ValueError, match="CALIBRATION arm"):
        _assert_no_calib_producer(calib)  # 🔴 §5-1 — 把标定臂塞进集里 ⇒ 必须红
    _assert_no_calib_producer(CURATION)  # the real sets are clean
    _assert_no_calib_producer(CURATION_CN)


def test_jian2_benign_producers_are_the_holdout_arm_never_calib_or_merged():
    from treval.cli.collect import CURATION, CURATION_CN

    benign = [
        p
        for p in CURATION_CN
        if p.indicator_id in ("false_positive_rate", "benign_flag_rate")
    ]
    # 🔴 §5-2 — the benign producers measure the HOLDOUT arm, NOT the old merged llm01_cn_benign
    assert benign and all(p.corpus_subdir == "llm01_cn_benign_holdout" for p in benign)
    # 🔴 §5-1 / 门 — no producer in EITHER set binds a _calib dir
    for prods in (CURATION, CURATION_CN):
        assert not any(p.corpus_subdir.endswith("_calib") for p in prods)


# --------------------------------------------------------------------------- #
# 件6 — a non-shipped τ ⇒ not_citable (a BLOCK, not a warning)
# --------------------------------------------------------------------------- #
def test_jian6_shipped_tau_is_citable():
    ok, blk = report_citability(_bundle(_prov(tau_source="shipped")))
    assert ok is True and blk == []


@pytest.mark.parametrize("src", ["fitted", "other"])
def test_jian6_non_shipped_tau_blocks_citation(src):
    # 🔴 §5-9 — a fitted/other τ ⇒ calibration diagnostic ⇒ not citable. What reds it: change the gate to
    # "only warn" (append nothing) ⇒ the fitted-τ bundle would come back citable.
    ok, blk = report_citability(_bundle(_prov(tau_source=src)))
    assert ok is False
    assert any("非发货阈值" in b and "tau_source != shipped" in b for b in blk)


def test_jian6_is_a_new_criteria_identity():
    # 件6 bumped 3→4 for `tau_not_shipped`; the ABSOLUTE version is pinned by 件5's test (it bumped 4→5),
    # so here we assert only that 件6's identity landed in the set.
    from treval.citability import CRITERIA_BLOCKERS

    assert "tau_not_shipped" in CRITERIA_BLOCKERS


# --------------------------------------------------------------------------- #
# 件5 — the SYMMETRIC value-gate on measurement_path: a declared but NON-PRODUCT path ⇒ not_citable
# (件0 only checks the field is PRESENT; this checks the VALUE is the product). §5-17: naked-citable ⇒ red.
# --------------------------------------------------------------------------- #
def test_jian5_in_product_path_is_citable():
    ok, blk = report_citability(_bundle(_prov(measurement_path="in_product_gateway")))
    assert ok is True and blk == []


def test_jian5_offline_judge_harness_path_blocks_citation():
    # 🔴 §5-17 — an honestly-declared offline_judge_harness bundle measures the JUDGE on raw corpus, not
    # the PRODUCT ⇒ not citable. What reds it: drop the value-gate (append nothing) ⇒ it comes back citable
    # — the exact "能裸引即红" the acceptance names. "字段在不在" (件0) cannot catch this "值对不对".
    ok, blk = report_citability(
        _bundle(_prov(measurement_path="offline_judge_harness"))
    )
    assert ok is False
    assert any(
        "非产品装配" in b and "measurement_path != in_product_gateway" in b for b in blk
    )


def test_jian5_path_value_is_new_identity_bumped_to_5():
    from treval.citability import CRITERIA_BLOCKERS, CRITERIA_VERSION

    # 🔴 a DISTINCT identity from tau_not_shipped, on the other axis ⇒ its own bump (4→5), not merged into 4.
    assert "path_not_product" in CRITERIA_BLOCKERS and CRITERIA_VERSION == 5


# --------------------------------------------------------------------------- #
# 件7 — the CN FPR's denominator口径 rides in citation_form (NOT notes)
# --------------------------------------------------------------------------- #
def _fpr_form(subject):
    from treval.citability import citation_form
    from treval.models import EvidenceRef, IntegrityStatus, Measurement

    # 🔴 obviously-SYNTHETIC fixture values (not tested-party measurements): a [0, 100%] CI is the vacuous
    # placeholder interval, so no disclosure marker is needed — the data itself reads as fake (件④).
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


def test_jian7_cn_fpr_carries_the_denominator_kojing_in_citation_form():
    form = _fpr_form("language:zh")
    # 🔴 §5-8 — the four things ride together; the key clauses + the Wilson clause are present
    assert "贴近治理边界" in form and "留出臂" in form and "不可外推" in form
    assert (
        "Wilson 区间只涵盖" in form and "分母构成误差" in form
    )  # the amendment sentence


def test_jian7_composition_is_attributed_in_two_layers_not_all_to_the_source():
    # 🔴 件7 修（架构 ③）— the per-workflow COUNT is OUR even split (no weight basis), only the workflow
    # LIST is the source's (attested). What reds it: revert to a single-layer note that books the whole
    # composition on 取材人的先验. Also states n=110 is the Wilson k≤1 floor, unrelated to workflow count.
    form = _fpr_form("language:zh")
    assert "两层归因" in form and "均分" in form and "无权重依据" in form
    assert "attested" in form  # the workflow LIST is attested by the source
    assert (
        "巧合" in form and "Wilson 的 k≤1 下限" in form
    )  # 110÷10=11 is coincidence, not design


def test_jian7_english_fpr_does_not_get_the_cn_note():
    # the English FPR (subject="") must NOT carry the CN denominator口径 (it has its own §2.2.4 notes).
    form = _fpr_form("")
    assert "N180" not in form and "贴近治理边界" not in form


def test_jian7_the_kojing_is_in_citation_form_not_a_stripped_notes_field():
    # 🔴 §5-8 / 件7 — writing it to `notes` (which gets stripped) instead of citation_form ⇒ red. Here we
    # assert it lives in the paste-whole citation_form string.
    from treval.citability import N180_FPR_DENOMINATOR_NOTE

    assert N180_FPR_DENOMINATOR_NOTE in _fpr_form("language:zh")


# --------------------------------------------------------------------------- #
# 件1 — two arms = two corpus ids = TWO separate registration entries. Mechanism built now, entries
# arrive with the freeze pack: absent ⇒「未登记·未校验」(NOT PASS); unparseable/merged ⇒ fail-closed.
# --------------------------------------------------------------------------- #
_SHA_A = "sha256:" + "a" * 64
_SHA_B = "sha256:" + "b" * 64


def _reg_block(*records: str) -> str:
    """Wrap registration records in a fenced code block inside a doc-shaped string."""
    body = "\n\n".join(records)
    return f"# doc\n\nsome prose\n\n```\n{body}\n```\n\nmore prose\n"


def _entry(cid: str, n: str, sha: str) -> str:
    return f"corpus id : {cid}\nn         : {n}\ncorpus_sha: {sha}"


_CALIB = "llm01_cn_benign_calib"
_HOLDOUT = "llm01_cn_benign_holdout"


def test_jian1_no_block_at_all_is_unregistered_not_pass():
    from tools.check_registration import check_registration

    r = check_registration("# doc\n\nno registration block here\n")
    assert r.status == "unregistered"
    out = "\n".join(r.lines)
    # 🔴 the deferred state must NEVER emit a PASS verdict (§6.1 — a green that parsed nothing is worse).
    assert "未登记·未校验" in out and "登记门：PASS" not in out


def test_jian1_arms_absent_from_an_existing_block_is_unregistered():
    from tools.check_registration import check_registration

    # a block that registers only the OLD baseline ids — the two N180 arms are still absent ⇒ unregistered.
    text = _reg_block(_entry("llm01_cn_injection", "69", _SHA_A))
    r = check_registration(text)
    assert r.status == "unregistered"
    out = "\n".join(r.lines)
    assert _CALIB in out and _HOLDOUT in out  # names which arms are missing


def test_jian1_two_distinct_entries_is_ok():
    from tools.check_registration import check_registration

    text = _reg_block(_entry(_CALIB, "70", _SHA_A), _entry(_HOLDOUT, "110", _SHA_B))
    r = check_registration(text)
    assert r.status == "ok" and "PASS" in "\n".join(r.lines)


def test_jian1_two_arms_sharing_one_sha_reds():
    # 🔴 §5-5 — a merged entry wearing two hats: same corpus_sha for both arms ⇒ the fit/measure split is
    # fake. What reds it: drop the shared-sha check ⇒ this passes. (合成一条即红)
    from tools.check_registration import check_registration

    text = _reg_block(_entry(_CALIB, "70", _SHA_A), _entry(_HOLDOUT, "110", _SHA_A))
    r = check_registration(text)
    assert r.status == "fail" and "共用同一 corpus_sha" in "\n".join(r.lines)


def test_jian1_malformed_sha_fails_closed():
    # 🔴 解析不了 ⇒ 失败关闭. What reds it: turn the `raise RegistrationError` into a skip ⇒ a corrupt block
    # would fall through to unregistered/ok instead of failing.
    from tools.check_registration import check_registration

    text = _reg_block(
        _entry(_CALIB, "70", "sha256:not-a-real-hash"),
        _entry(_HOLDOUT, "110", _SHA_B),
    )
    r = check_registration(text)
    assert r.status == "fail" and "失败关闭" in "\n".join(r.lines)


def test_jian1_missing_field_fails_closed():
    from tools.check_registration import check_registration

    # an entry that names a corpus id but omits corpus_sha ⇒ fail-closed, never a silent skip.
    text = _reg_block(
        f"corpus id : {_CALIB}\nn         : 70", _entry(_HOLDOUT, "110", _SHA_B)
    )
    r = check_registration(text)
    assert r.status == "fail"


def test_jian1_shipped_calib_arm_is_validated_while_holdout_pends():
    # 🔴 标定臂先交（架构）— calib registered alone, holdout deferred to §6.3. A SHIPPED arm must be
    # validated against the actual corpus EVEN before its pair lands: matching ⇒ unregistered(pending) but
    # "已登记，已与实跑核对一致"; a moved calib sha ⇒ FAIL even though holdout is absent.
    from tools.check_registration import check_registration

    text = _reg_block(_entry(_CALIB, "70", _SHA_A))  # only calib
    ok = check_registration(text, actual={_CALIB: (70, _SHA_A)})
    assert ok.status == "unregistered"
    out = "\n".join(ok.lines)
    assert (
        "已与实跑核对一致" in out and _HOLDOUT in out
    )  # calib validated, holdout named as missing
    # 🔴 a shipped arm whose sha moved reds even with the pair still pending.
    bad = check_registration(text, actual={_CALIB: (70, "sha256:" + "e" * 64)})
    assert bad.status == "fail" and "实跑" in "\n".join(bad.lines)


def test_jian1_registered_sha_disagreeing_with_actual_run_reds():
    # 🔴 §4 两条登记条目 — 跑完删/改一件, the actual corpus_sha moves; a stale registered sha must red.
    from tools.check_registration import check_registration

    text = _reg_block(_entry(_CALIB, "70", _SHA_A), _entry(_HOLDOUT, "110", _SHA_B))
    actual = {
        _CALIB: (70, _SHA_A),
        _HOLDOUT: (110, "sha256:" + "c" * 64),
    }  # holdout sha moved
    r = check_registration(text, actual=actual)
    assert r.status == "fail" and "实跑" in "\n".join(r.lines)


# --------------------------------------------------------------------------- #
# 件3.1 — three DEPTH proxies, FIRST ROUND MEASURE-ONLY (no gate). The count floor cannot catch a corpus
# that is all-hard yet all-shallow (两个模子印 110 遍). Each test names the input that reds it.
# --------------------------------------------------------------------------- #
def test_jian3_mother_pattern_reads_the_NAMED_signatures_not_auto_clusters():
    # 🔴 THE severe correction: 母形态覆盖 must measure "did they use the two NAMED §8.3 molds", NOT the
    # near-duplicate rate of auto-clustered skeletons. Here every case has a DISTINCT exact skeleton (so an
    # auto top-2 would report ~0.2 — reassuringly low), yet 8/10 carry mother-pattern ①「…为准」⇒ the NAMED
    # coverage is 0.8. What it MEASURES: the delivery side's named say-forms. What reds it: point the
    # signature at a literal the corpus does not use (the tooth stops biting the thing it must bite).
    from tools.check_cn_depth import mother_pattern_coverage

    texts = [
        f"甲{i}方口径以附件第{i}版为准，别用你那版" for i in range(8)
    ]  # ① 以…为准, all distinct
    texts += ["今天天气不错", "周一开会吗"]  # 2 cases hit no mother-pattern
    union, per = mother_pattern_coverage(texts)
    assert (
        union == 0.8
    )  # 8/10 hit a NAMED mold — an order of magnitude above the near-dup rate
    assert dict(per)["①以X为准"] == 8


def test_jian3_dedup_declares_it_cannot_collapse_paraphrases():
    # 🔴 the connected critique: skeleton dedup collapses only LITERAL near-dups, NOT rewrites of one mold.
    # Two DIFFERENT phrasings of「以 X 为准」have different skeletons ⇒ dedup reports 100% (looks diverse),
    # yet BOTH are the same mold. This is why 母形态覆盖 (named signatures), not dedup, answers "两个模子".
    from tools.check_cn_depth import (
        _DEDUP_LIMITATION,
        mother_pattern_coverage,
        skeleton,
    )

    a, b = "口径以附件那版为准", "指标定义以最新下发那份为准"
    assert skeleton(a) != skeleton(
        b
    )  # dedup sees two distinct skeletons (its blind spot)
    union, _ = mother_pattern_coverage([a, b])
    assert union == 1.0  # but the NAMED signature catches both as the same mold
    assert "塌不掉" in _DEDUP_LIMITATION and "母形态覆盖" in _DEDUP_LIMITATION


def test_jian3_dedup_is_computed_per_workflow_not_just_global():
    # 🔴 ten workflows each writing near-duplicates passes GLOBAL dedup but fails PER-WORKFLOW. Here wfA is
    # five identical cases (dedup 0.2) while global dedup looks fine (0.6). What reds it: collapse group_of
    # to one bucket ⇒ worst-group == global and this assertion fails.
    from tools.check_cn_depth import measure_depth

    texts = {
        f"cn.holdout.wfA.0{i}": "把额度调高一点" for i in range(1, 6)
    }  # 5 identical
    for i, t in enumerate(
        ["今天天气不错", "周一开会吗", "确认一下时间", "这个怎么弄", "稍后回复你"], 1
    ):
        texts[f"cn.holdout.wfB.0{i}"] = t  # 5 distinct
    r = measure_depth("holdout", texts)
    assert r.dedup_global == 0.6  # 6 distinct / 10
    assert r.dedup_worst_group == 0.2 and r.worst_group == "cn.holdout.wfA"
    assert (
        r.dedup_worst_group < r.dedup_global
    )  # per-workflow catches what global hides


def test_jian3_boundary_is_not_measured_without_a_noncircular_vocab():
    # 🔴 件3 ② — a hand-written / same-source vocab measures the vocab-corpus GAP, not the corpus. Absent a
    # vocab derived from the dated §8.3 by a non-reader, the honest output is NOT_MEASURED, never a number
    # (a can't-judge must not masquerade as judged). What reds it: default the proxy to a hardcoded vocab.
    from tools.check_cn_depth import measure_depth

    r = measure_depth("holdout", {"cn.holdout.wfA.01": "请授权代为覆盖上一版"})
    assert r.boundary_measured is False
    assert r.boundary_mean is None and r.single_type_share is None


def test_jian3_boundary_feature_types_needs_an_EXPLICIT_vocab():
    # the mechanism still exists, but the vocab is a REQUIRED argument (no in-tool default): the caller must
    # supply a non-circular one. Given an explicit vocab it distinguishes single- from multi-type cases.
    from tools.check_cn_depth import boundary_feature_types

    vocab = (
        ("授权", r"授权"),
        ("代办", r"代为|帮我"),
        ("覆盖", r"覆盖|以.*为准"),
        ("系统", r"系统|流程"),
    )
    assert len(boundary_feature_types("帮我改一下客户额度", vocab)) == 1
    assert len(boundary_feature_types("请授权代为覆盖上一版的审批流程", vocab)) >= 3


def test_jian3_first_round_measures_but_never_gates(tmp_path):
    # 🔴 measure-only: even a pathological corpus never yields a threshold FAIL this round, and the number
    # must APPEAR labeled「无门槛·首测」(a gate-less number absent reads as "passed"). Corpus absent here
    # ⇒ empty-measure path, which must still return 0 and print the banner.
    from tools.check_cn_depth import _FIRST_MEASUREMENT_BANNER, main

    assert "无门槛·首测" in _FIRST_MEASUREMENT_BANNER
    rc = main(["--corpus", str(tmp_path)])
    assert rc == 0  # never a FAIL


def test_jian3_measure_depth_on_all_one_mold_is_measured_not_raised():
    # a corpus that is all one mold (mother coverage 100%, dedup 0.2) is a NUMBER, not an exception, not a
    # gate — measure-only reports it for the human to read.
    from tools.check_cn_depth import measure_depth

    texts = {f"cn.holdout.wfA.0{i}": "以最新政策为准" for i in range(1, 6)}
    r = measure_depth("holdout", texts)
    assert r.mother_union == 1.0 and r.dedup_global == 0.2  # reported, not enforced


# --------------------------------------------------------------------------- #
# 件4 — the holdout arm is READ-ONCE. A second FPR on the same holdout corpus_sha (by a different run) is
# not_citable. The registration entry's holdout_consumed marker is the state; empty ⇒ first read ⇒ citable.
# --------------------------------------------------------------------------- #
_HSHA = "sha256:" + "d" * 64


def _fpr_bundle(sha=_HSHA, gen_ns=100, subject="language:zh"):
    return {
        "evidence_basis": "wal_anchored",
        "provenance": {"generated_at_ns": gen_ns},
        "measurements": [
            {
                "indicator_id": "false_positive_rate",
                "subject": subject,
                "corpus_sha": sha,
            }
        ],
    }


def test_jian4_first_read_is_citable():
    from treval.citability import holdout_reread_blocker

    # holdout_consumed empty (未读) ⇒ this is the first read ⇒ no blocker.
    assert holdout_reread_blocker(_fpr_bundle(), consumed={}) is None


def test_jian4_second_read_same_sha_by_a_different_run_is_not_citable():
    # 🔴 §5-4 — the same holdout sha, first consumed by run "100", read again by run "200" ⇒ not_citable.
    # What reds it: drop the reread check (return None) ⇒ the second read comes back citable.
    from treval.citability import holdout_reread_blocker

    blk = holdout_reread_blocker(_fpr_bundle(gen_ns=200), consumed={_HSHA: "100"})
    assert blk is not None and "第二次读同一条留出臂" in blk


def test_jian4_same_run_reserialize_is_not_a_reread():
    # re-serializing the SAME run's bundle (marker matches consumed) is idempotent, not a second read.
    from treval.citability import holdout_reread_blocker

    assert (
        holdout_reread_blocker(_fpr_bundle(gen_ns=100), consumed={_HSHA: "100"}) is None
    )


def test_jian4_english_fpr_is_not_a_holdout_consumption():
    # the EN FPR (subject="") is not the CN holdout arm ⇒ no consumption, never blocked by this gate.
    from treval.citability import holdout_consumption_marker, holdout_reread_blocker

    assert holdout_consumption_marker(_fpr_bundle(subject="")) is None
    assert (
        holdout_reread_blocker(_fpr_bundle(subject=""), consumed={_HSHA: "100"}) is None
    )


def test_jian4_marker_records_sha_and_run():
    from treval.citability import holdout_consumption_marker

    assert holdout_consumption_marker(_fpr_bundle(gen_ns=100)) == (_HSHA, "100")


def test_jian4_reread_gate_runs_through_the_registration_gate_production_path():
    # 🔴 件4 修（架构 ③）— a function-level test cannot kill "no one calls it". This goes through the REAL
    # caller: check_registration holds the registry (holdout_consumed), so IT runs holdout_reread_blocker.
    # What reds it: delete the `if bundle is not None:` block in check_registration ⇒ the gate never fires.
    from tools.check_registration import check_registration

    holdout_entry = f"corpus id : {_HOLDOUT}\nn         : 110\ncorpus_sha: {_HSHA}\nholdout_consumed: 100"
    text = _reg_block(_entry(_CALIB, "70", _SHA_A), holdout_entry)
    # a fresh FPR (run 200) re-reading a holdout already consumed by run 100 ⇒ the registration gate reds.
    reread = check_registration(text, bundle=_fpr_bundle(gen_ns=200))
    assert reread.status == "fail" and "第二次读同一条留出臂" in "\n".join(reread.lines)
    # the same run (marker 200 == consumed 200) is idempotent ⇒ not a reread ⇒ ok.
    same = check_registration(
        text.replace("holdout_consumed: 100", "holdout_consumed: 200"),
        bundle=_fpr_bundle(gen_ns=200),
    )
    assert same.status == "ok"


# --------------------------------------------------------------------------- #
# 件8 — operator-only (Tier-0) family diagnostics: single-case leverage table (zero detection results),
# two-arm hardness comparison, and a comparison that drives no threshold-gated action.
# --------------------------------------------------------------------------- #
def test_jian8_leverage_table_uses_only_counts_and_weights():
    from treval.cn_family_leverage import leverage_table

    # family A: high prior (0.8), few cases (10); B: low prior (0.2), many cases (90). N=100, K=2.
    rows = leverage_table({"A": 10, "B": 90}, {"A": 0.8, "B": 0.2})
    a = next(r for r in rows if r.family == "A")
    assert a.natural == pytest.approx(0.01)  # 1/N — same for every family
    assert a.prior == pytest.approx(0.08)  # ŵ_A / n_A = 0.8/10
    assert a.equal == pytest.approx(0.05)  # 1/(K·n_A) = 1/20
    assert rows[0].family == "A"  # sorted by prior leverage, highest first


def test_jian8_leverage_swing_is_max_prior_over_natural():
    # 🔴 the magnitude PM wants: reweighting can move the number up to 8× the natural口径. What reds it:
    # drop the /n_f in the prior口径 ⇒ the swing changes.
    from treval.cn_family_leverage import leverage_swing, leverage_table

    rows = leverage_table({"A": 10, "B": 90}, {"A": 0.8, "B": 0.2})
    assert leverage_swing(rows) == pytest.approx(8.0)  # 0.08 / 0.01


def test_jian8_leverage_row_carries_no_detection_result():
    # 🔴 §5 验收 — the table's fields are counts + the three口径 ONLY; no observed mis-block / FPR field.
    # Any detection result in the table ⇒ red (it would be a boundary map, not our denominator's shape).
    from treval.cn_family_leverage import FamilyLeverage

    assert set(FamilyLeverage.__dataclass_fields__) == {
        "family",
        "n",
        "natural",
        "prior",
        "equal",
    }


def test_jian8_holdout_below_floor_fails_per_arm():
    # 🔴 §5-3 — 留出臂易例超限 ⇒ 红, even though a HARD calib sits beside it (arms are never merged).
    from treval.cn_family_leverage import two_arm_comparison

    r = two_arm_comparison((100, 100), (80, 100), floor=0.84, margin=0.05)
    assert r.status == "fail"


def test_jian8_merged_denominator_cannot_rescue_a_soft_holdout():
    # merging (180/200 = 0.90 ≥ floor) would falsely pass; per-arm judgement fails on the holdout (0.80).
    from treval.cn_family_leverage import two_arm_comparison

    merged_ratio = (100 + 80) / (100 + 100)
    assert merged_ratio >= 0.84  # a merge WOULD have passed
    assert (
        two_arm_comparison((100, 100), (80, 100), floor=0.84, margin=0.05).status
        == "fail"
    )


def test_jian8_holdout_much_softer_than_calib_warns_not_silent():
    # 🔴 件8.3 — both clear the floor, but the holdout is softer than the calib by > margin ⇒ WARN (the
    # 下意识少找难件 signal), never swallowed. What reds it: drop the relative-softness branch.
    from treval.cn_family_leverage import two_arm_comparison

    r = two_arm_comparison((100, 100), (90, 100), floor=0.84, margin=0.05)
    assert r.status == "warn"
    assert any("下意识少找难件" in ln for ln in r.lines)


def test_jian8_comparable_arms_are_ok():
    from treval.cn_family_leverage import two_arm_comparison

    r = two_arm_comparison((90, 100), (88, 100), floor=0.84, margin=0.05)
    assert r.status == "ok"


def test_jian8_pending_item_is_identical_in_both_directions():
    # 🔴 件8.2 — no action hangs on the comparison threshold: BOTH outcomes record the SAME pending item;
    # only the urgency wording differs. What reds it: return a different item on one branch.
    from treval.cn_family_leverage import family_prior_pending_item

    agree_item, agree_urg = family_prior_pending_item(True)
    disagree_item, disagree_urg = family_prior_pending_item(False)
    assert agree_item == disagree_item  # the pending item is threshold-independent
    assert agree_urg != disagree_urg
    # 🔴 agree must NOT claim the prior was validated; disagree escalates to the backlog.
    assert "不得据此宣称先验被验证" in agree_urg
    assert "backlog" in disagree_urg


def test_jian8_family_field_scan_flags_a_family_key_in_yaml(tmp_path):
    # 🔴 §4 族标签不落语料 — the loader silently drops unknown fields, so this scans RAW yaml.
    from tools.check_cn_two_arm import family_field_hits

    (tmp_path / "a.yaml").write_text("id: x\nfamily: f3\ninput: hi\n", encoding="utf-8")
    (tmp_path / "b.yaml").write_text("id: y\ninput: hi\n", encoding="utf-8")
    hits = family_field_hits(tmp_path)
    assert hits == [("a.yaml", "family")]


def test_jian8_two_arm_tool_absent_corpus_empty_passes(tmp_path, capsys):
    from tools import check_cn_two_arm

    assert check_cn_two_arm.main(["--corpus", str(tmp_path)]) == 0
    assert "未校验" in capsys.readouterr().out


def test_jian8_leverage_tool_prints_the_swing(tmp_path, capsys):
    import json

    from tools import cn_leverage_table

    inp = tmp_path / "t.json"
    inp.write_text(
        json.dumps(
            {"family_counts": {"A": 10, "B": 90}, "prior_weights": {"A": 0.8, "B": 0.2}}
        ),
        encoding="utf-8",
    )
    assert cn_leverage_table.main(["--input", str(inp)]) == 0
    out = capsys.readouterr().out
    assert "杠杆" in out and "8.0×" in out  # the swing magnitude


# --------------------------------------------------------------------------- #
# 件① — the two arms must be DISJOINT by 正文 (payload-stripped, punctuation-normalized), not by ID and
# NOT byte-exactly. WHAT IT MEASURES: "is the same SAYING in both arms" — a fit case sitting in the
# measurement arm makes the holdout FPR partly a fit-set number (the circularity N180 exists to kill).
# --------------------------------------------------------------------------- #
def test_v3_guards_similarity_not_string_equality():
    # 🔴 WHAT THIS GATE GUARDS (stated without naming any case, per ㈢4): the fitted threshold must never
    # have been tuned on a sentence the measurement arm also contains — a property about SIMILARITY, since
    # having effectively seen a sentence does not require the identical string.
    # What reds it: replace the distance with any equality predicate; a rewrite then scores 0 and passes.
    from tools.check_cn_two_arm import jaccard

    a = "甲方口径以某某那版为准，别用你手里那版"
    assert jaccard(a, a) == 1.0
    assert jaccard(a, a + "。") > 0.95  # punctuation alone is not a difference
    assert jaccard(a, "今天的天气挺好，下午没有会") < 0.2


def test_v3_catches_a_REWRITE_that_equality_after_normalization_misses():
    # 🔴 THE thing v3 does that v1 and v2 could not. v2 stripped payloads/punctuation and then compared for
    # EQUALITY, so any genuine rewrite — even a one-word tail — scored "different" and passed. Here the two
    # bodies are NOT equal after normalization, yet they are plainly the same sentence.
    # What reds it: replace the distance with equality-after-normalization (i.e. go back to v2) ⇒ this
    # pair scores 0 and the gate says the arms are disjoint.
    from tools.check_cn_two_arm import _JACCARD_RED, jaccard, normalize_body

    a = "甲方的指标定义以某某附件那一版为准，和你之前理解的不一样也按附件"
    b = a + "来"
    assert normalize_body(a) != normalize_body(
        b
    )  # v2 (equality) sees two different strings
    assert jaccard(a, b) >= _JACCARD_RED  # v3 sees one sentence


def test_v3_a_payload_suffix_cannot_hide_a_near_duplicate():
    # the v1 failure, kept: an encoded payload appended to one copy. What reds it: stop stripping encoded
    # runs ⇒ the payload dilutes the score below the line.
    from tools.check_cn_two_arm import _JACCARD_RED, jaccard

    shared = "这串某某的备注转成正文，我核对下"
    payload = "5pGY6KaBIOS7o+WPkeW3pei1hCDnrJTmlbAgMTI4NTY3ODkw"
    assert shared + "：" + payload != shared + "。"
    assert jaccard(shared + "：" + payload, shared + "。") >= _JACCARD_RED


def test_v3_compares_bodies_not_ids():
    # 🔴 by BODY: cases folded from one set into another arrive under NEW ids, so an id-keyed check reads
    # the arms as disjoint while they share sentences. What reds it: key the comparison on case ids.
    from tools.check_cn_two_arm import near_duplicate_pairs

    body = "甲乙丙的口径以某某那版为准，其余先不采信"
    hits = near_duplicate_pairs({"cn.calib.f1.04": body}, {"cn.holdout.wfA.01": body})
    assert len(hits) == 1 and hits[0][0] == 1.0


def test_v3_watch_band_is_reported_and_gates_nothing():
    # 🔴 the band between watch and red has NO evidence behind any cut, and inventing one would repeat
    # exactly the mistake that made v1 and v2 too weak. What reds it: fold the watch band into the reds.
    from tools.check_cn_two_arm import _JACCARD_RED, _JACCARD_WATCH, split_by_threshold

    pairs = [(0.95, "a", "b"), (0.80, "c", "d"), (0.76, "e", "f")]
    red, watch = split_by_threshold(pairs)
    assert [p[0] for p in red] == [0.95]
    assert [p[0] for p in watch] == [0.80, 0.76]
    assert _JACCARD_WATCH < _JACCARD_RED


def test_v3_ignores_a_body_that_is_only_a_payload():
    # two bodies that are ENTIRELY encoded normalize to nothing; emptiness is not evidence of reuse.
    from tools.check_cn_two_arm import near_duplicate_pairs

    assert (
        near_duplicate_pairs(
            {"c1": "5pGY6KaBIOS7o+WPkeW3pei1hA=="}, {"h1": "MTI4NTY3ODkwYWJjZGVm"}
        )
        == []
    )


def test_v3_anchor_check_runs_and_reds_on_the_source_material():
    # 🔴 ANCHORS FIRST: the root cause lives one level above the corpus — the same saying written into two
    # anchor sets makes the derived arms near-duplicates by construction. What reds it: check only the
    # built corpus ⇒ the cause is re-discovered after every build and paid for every time.
    from tools.check_cn_two_arm import anchor_near_duplicates

    same = "甲方口径以某某那版为准"
    red, _watch = anchor_near_duplicates(
        {
            "calib_anchors_8_2": {"f1": [same]},
            "wf_anchors_8_3": {"wfA": {"sayings": [same]}},
        }
    )
    assert len(red) == 1
    # 🔴 a material file missing either set is NOT a pass — nothing was compared.
    assert anchor_near_duplicates({"calib_anchors_8_2": {"f1": [same]}}) is None


# --------------------------------------------------------------------------- #
# 件③ — the FOURTH depth proxy: 语用行为集中度, measured RELATIVE TO the delivery anchors, per group.
# WHAT IT MEASURES: "what is the sentence DOING" — the other three measure which words and how repeated,
# and none of them can see a corpus that varies its nouns perfectly while performing one speech act.
# --------------------------------------------------------------------------- #
def test_jian_acts_catches_what_the_other_three_proxies_are_blind_to():
    # 🔴 the raison d'être, as a test: a corpus with DISTINCT skeletons (dedup ~100%) and ZERO mother-pattern
    # hits — it passes the other proxies cleanly — yet every case performs the SAME act (a bare directive).
    # What reds it: drop the act proxy ⇒ this monotone corpus reads as fully healthy on all measures.
    from tools.check_cn_depth import (
        act_concentration,
        dedup_rate,
        mother_pattern_coverage,
        skeleton,
    )

    monotone = [
        "把这条诉求登记进台账",
        "把那笔冲正录入系统",
        "把检查意见登记到底稿",
        "把客户诉求录入工单",
    ]
    assert mother_pattern_coverage(monotone)[0] == 0.0  # proxy ① sees nothing
    assert dedup_rate([skeleton(t) for t in monotone]) == 1.0  # proxy ② sees nothing
    assert act_concentration(monotone) == 1.0  # 🔴 proxy ④ sees it: one act, every case


def test_jian_acts_distinguishes_speech_acts():
    from tools.check_cn_depth import speech_acts

    assert "interrogative" in speech_acts("这批重跑用原参数还是用默认参数？")
    assert "prohibitive" in speech_acts("配置里现在这版先别用")
    assert "directive" in speech_acts("把这句原文登记进底稿")
    assert speech_acts("差额落在这几笔") == frozenset(
        {"assertive"}
    )  # a plain statement


def test_jian_acts_concentration_falls_when_acts_vary():
    from tools.check_cn_depth import act_concentration

    varied = [
        "把这条诉求登记进台账",
        "这批重跑用原参数还是默认参数？",
        "差额落在这几笔",
    ]
    assert act_concentration(varied) < 1.0


def test_jian_acts_compares_per_group_against_anchors_only_where_anchors_exist():
    # 🔴 relative to the DELIVERY ANCHORS (the non-circular reference), per group; a group the anchors do
    # not cover has no reference and is skipped — never compared against an invented absolute threshold.
    from tools.check_cn_depth import speech_act_vs_anchors

    rows = speech_act_vs_anchors(
        {"wfA": ["把这条登记进台账", "把那条录入系统"], "wfZ": ["无锚点组"]},
        {"wfA": ["把这句原文登记进底稿", "这条按哪版口径算？"]},
    )
    assert [r[0] for r in rows] == ["wfA"]  # wfZ has no anchors ⇒ not compared
    group, corpus_conc, anchor_conc, n = rows[0]
    assert (
        corpus_conc == 1.0 and anchor_conc == 0.5 and n == 2
    )  # corpus flatter than source


def test_jian_acts_is_not_measured_without_anchors():
    # 🔴 no delivery anchors ⇒ not_measured. An absolute threshold would be another 拍脑袋 number; a
    # can't-judge must not masquerade as judged (same discipline as the boundary vocab).
    from tools.check_cn_depth import measure_depth

    r = measure_depth("holdout", {"cn.holdout.wfA.01": "把这条登记进台账"})
    assert r.act_rows is None


# --------------------------------------------------------------------------- #
# 件④ · 件⑨ — the fingerprint ALGORITHM is versioned, and a new sha is a NEW entry (not a revision)
# --------------------------------------------------------------------------- #
def test_jian4algo_sha_mismatch_under_a_changed_algo_reads_as_algo_drift():
    # 🔴 件④ — a sha mismatch has TWO causes and conflating them is the whole problem: the CORPUS changed,
    # or the ALGORITHM changed (an algo bump moves every sha at once). WHAT IT MEASURES: which of the two.
    # What reds it: drop sha_algo from the entry ⇒ an algo bump reads as "someone edited the corpus".
    from tools.check_registration import check_registration

    stale_algo = f"corpus id : {_CALIB}\nn         : 70\ncorpus_sha: {_SHA_A}\nsha_algo  : cfp-v0"
    r = check_registration(
        _reg_block(stale_algo), actual={_CALIB: (70, "sha256:" + "f" * 64)}
    )
    assert r.status == "fail"
    out = "\n".join(r.lines)
    assert "算法漂移" in out and "不是【语料被改】" in out


def test_jian4algo_same_algo_mismatch_reads_as_corpus_changed():
    from tools.check_registration import check_registration

    cur = f"corpus id : {_CALIB}\nn         : 70\ncorpus_sha: {_SHA_A}\nsha_algo  : cfp-v1"
    r = check_registration(_reg_block(cur), actual={_CALIB: (70, "sha256:" + "f" * 64)})
    assert r.status == "fail" and "语料被改过" in "\n".join(r.lines)


def test_jian9_a_second_entry_for_one_arm_is_history_not_a_silent_drop():
    # 🔴 件⑨ — the 第八族 landing makes a NEW entry; the old one stays (already-fitted numbers bind to it).
    # The gate must validate the CURRENT (last) entry and SAY the history exists. What reds it: keep the
    # dict-comprehension that silently collapses duplicate ids ⇒ one of two entries vanishes unremarked.
    from tools.check_registration import check_registration

    old = f"corpus id : {_CALIB}\nn         : 70\ncorpus_sha: {_SHA_A}\nsha_algo  : cfp-v1"
    new = f"corpus id : {_CALIB}\nn         : 80\ncorpus_sha: {_SHA_B}\nsha_algo  : cfp-v1"
    r = check_registration(_reg_block(old, new), actual={_CALIB: (80, _SHA_B)})
    out = "\n".join(r.lines)
    assert "2 条条目" in out and "1 历史" in out  # the history is stated, not dropped
    assert r.status != "fail"  # the CURRENT entry matches the corpus ⇒ no mismatch


def test_jian4algo_version_constant_is_exported():
    from treval.active_eval.corpus import (
        CORPUS_FINGERPRINT_ALGO,
        CORPUS_FINGERPRINT_VERSION,
    )

    assert CORPUS_FINGERPRINT_ALGO == f"cfp-v{CORPUS_FINGERPRINT_VERSION}"


# --------------------------------------------------------------------------- #
# 件⑧ — the material-landing → run-start ruleset pin. WHAT IT MEASURES: whether the ruleset MOVED during
# the window in which the holdout material was readable. 「我们相信没人看」是自述；「指纹说它没动」是测量。
# --------------------------------------------------------------------------- #
def _fp(sha):
    return {"runtime": {"ruleset_sha256": sha}}


def test_jian8pin_matched_when_the_ruleset_did_not_move():
    from treval.citability import material_window_verified

    prov = {"material_ruleset_sha256": "r1", "build_fingerprint_before": _fp("r1")}
    assert material_window_verified(prov) == "matched"


def test_jian8pin_mismatch_is_visible_not_silently_fine():
    # 🔴 a moved ruleset across the visible window is NOT automatically a defect and NOT automatically
    # fine — it is a question a human must answer, so it must be VISIBLE. What reds it: fold mismatch
    # into "matched"/None ⇒ the window silently reads as clean.
    from treval.citability import material_window_verified

    prov = {"material_ruleset_sha256": "r1", "build_fingerprint_before": _fp("r2")}
    assert material_window_verified(prov) == "mismatch"


def test_jian8pin_unverifiable_never_reads_as_no_problem():
    from treval.citability import material_window_verified

    assert material_window_verified({}) == "unverifiable"  # pre-件⑧ pack
    assert material_window_verified({"material_ruleset_sha256": "r1"}) == "unverifiable"


def test_jian8pin_rides_in_the_citation_note():
    from treval.citability import run_config_note

    note = run_config_note(
        _prov(material_ruleset_sha256="r1", build_fingerprint_before=_fp("r2"))
    )
    assert "素材窗口 mismatch" in note  # a question nobody sees is not asked


# --------------------------------------------------------------------------- #
# 件④ 加载规则 — the merged predecessor and the calib arm must never be loaded together
# --------------------------------------------------------------------------- #
def test_jian4_double_load_of_predecessor_and_calib_raises():
    # 🔴 the 25 originals were folded into calib under NEW ids ⇒ loading both counts them twice, and
    # because the IDS DIFFER no duplicate-id check can see it. What reds it: drop the pair table.
    from tools.check_cn_two_arm import assert_no_double_load

    with pytest.raises(ValueError, match="不得同时加载"):
        assert_no_double_load(["llm01_cn_benign", "llm01_cn_benign_calib"])
    # each alone is fine, and the holdout never collides with either
    assert_no_double_load(["llm01_cn_benign_calib", "llm01_cn_benign_holdout"])
    assert_no_double_load(["llm01_cn_benign", "llm01_cn_benign_holdout"])


# --------------------------------------------------------------------------- #
# 批一 — deviation from the source is TWO-SIDED. WHAT IT MEASURES: 偏离素材源, in EITHER direction —
# above the anchors = 偷懒套模子; below = 造了交付方没给的语言. Reporting only the high side is half a criterion.
# --------------------------------------------------------------------------- #
def test_pi1_a_corpus_far_BELOW_the_anchors_is_reported_not_passed():
    # 🔴 the acceptance: a corpus significantly LOWER than the anchors. A one-sided ("must not exceed")
    # criterion PASSES it silently; the two-sided one must name the direction. What reds it: drop the
    # `delta < -band` branch ⇒ 'below' collapses into 'aligned' and the deviation disappears.
    from tools.check_cn_depth import drift_direction

    assert (
        drift_direction(0.10, 0.60) == "below"
    )  # far more diverse than the delivered material
    assert (
        drift_direction(0.90, 0.60) == "above"
    )  # far more concentrated — the mold-copying failure
    assert drift_direction(0.62, 0.60) == "aligned"


def test_pi1_both_directions_are_readable_in_the_output():
    from tools.check_cn_depth import _DRIFT_LABEL

    assert "偷懒套模子" in _DRIFT_LABEL["above"]
    assert "造了交付方没给的语言" in _DRIFT_LABEL["below"]  # the half that was missing


def test_pi1_mother_drift_is_measured_against_covering_anchors_only():
    # 🔴 an arm built from a DIFFERENT anchor set must read not_measured, never a fake finding: comparing
    # the calib arm (§8.2-built) against the holdout's §8.3 anchors is apples-to-oranges dressed as a result.
    from tools.check_cn_depth import measure_depth

    anchors = {"wfA": ["口径以附件那版为准", "这条按哪版算？"]}
    covered = measure_depth(
        "holdout", {"cn.holdout.wfA.01": "把这条登记进台账"}, anchors=anchors
    )
    assert covered.mother_drift in ("above", "below", "aligned")
    uncovered = measure_depth(
        "calib", {"cn.calib.f1.01": "把这条登记进台账"}, anchors=anchors
    )
    assert uncovered.mother_drift is None and uncovered.mother_anchor is None


def test_pi1_drift_stays_measure_only_never_a_gate(tmp_path):
    # the band has NO evidence behind it, so it makes the direction readable and nothing else.
    from tools.check_cn_depth import main

    assert main(["--corpus", str(tmp_path)]) == 0


# --------------------------------------------------------------------------- #
# 批一.2 — 承重宾语 / 侧 must be a COLUMN in the Tier-0 side table, never a VALUE. A case can be BOTH
# f1 AND object-bearing (§13.2②: an orthogonal axis); storing it as a value squashes the axis back into
# a single label — the exact thing §13.2② says breaks f1's composition.
# --------------------------------------------------------------------------- #
def test_pi1_object_bearing_is_a_column_not_a_family_value():
    from tools.check_cn_two_arm import assert_orthogonal_axis_is_a_column

    # ✅ correct shape: family and object_bearing are SEPARATE columns; one row carries both.
    assert_orthogonal_axis_is_a_column(
        [{"case_id": "c1", "family": "f1", "object_bearing": True, "side": "行使"}]
    )
    # 🔴 what reds it: the axis squashed into the family VALUE ⇒ the case is no longer also f1.
    with pytest.raises(ValueError, match="正交轴"):
        assert_orthogonal_axis_is_a_column(
            [{"case_id": "c1", "family": "object_bearing"}]
        )
    with pytest.raises(ValueError, match="布尔列"):
        assert_orthogonal_axis_is_a_column(
            [{"case_id": "c1", "object_bearing": "行使"}]
        )


def test_pi1_the_real_side_table_has_the_column_shape():
    # 🔴 the side table lives OUT OF REPO with the corpus, and this repo never names that path (§0). The
    # precheck points at it via TREVAL_CN_SIDE_TABLE; absent ⇒ skip LOUDLY, never a silent green.
    import json
    import os

    from tools.check_cn_two_arm import assert_orthogonal_axis_is_a_column

    p = os.environ.get("TREVAL_CN_SIDE_TABLE", "")
    if not p or not os.path.exists(p):
        pytest.skip(
            "TREVAL_CN_SIDE_TABLE unset — the CN side table is out-of-repo, not checked here"
        )
    with open(p, encoding="utf-8") as fh:
        d = json.load(fh)
    assert_orthogonal_axis_is_a_column(d.get("holdout", []) + d.get("calib", []))


# --------------------------------------------------------------------------- #
# 追加④ — superseded_by. WHAT IT MEASURES: which entry is CURRENT — read from the pointer, not from file
# position. A superseded entry is RETIRED, never deleted: old numbers stay recomputable against it.
# --------------------------------------------------------------------------- #
def test_add4_current_entry_is_chosen_by_the_pointer_not_by_position():
    # 🔴 the historical entry is written LAST here. Position-based "last wins" would pick the retired one.
    # What reds it: go back to `by_id[id] = en` for every entry (last-in-file wins).
    from tools.check_registration import check_registration

    current = f"corpus id : {_CALIB}\nn         : 80\ncorpus_sha: {_SHA_B}\nsha_algo  : cfp-v1"
    retired = (
        f"corpus id : {_CALIB}\nn         : 70\ncorpus_sha: {_SHA_A}\nsha_algo  : cfp-v1\n"
        f"superseded_by: {_SHA_B}"
    )
    r = check_registration(_reg_block(current, retired), actual={_CALIB: (80, _SHA_B)})
    assert (
        r.status != "fail"
    )  # validated against the CURRENT (n=80) entry, not the retired one
    assert "仍可复算" in "\n".join(r.lines)  # the retired entry is kept, not dropped


def test_add4_a_retired_entry_is_parsed_and_kept_not_dropped():
    from tools.check_registration import parse_registration

    retired = (
        f"corpus id : {_CALIB}\nn         : 70\ncorpus_sha: {_SHA_A}\n"
        f"superseded_by: {_SHA_B}"
    )
    entries = parse_registration(_reg_block(retired))
    assert len(entries) == 1 and entries[0].superseded_by == _SHA_B


def test_jian6_output_carries_the_kojing_label(capsys, tmp_path):
    # 🔴 件6 §3.2.4 — the output must SAY it measures 词面 (surface form), not 语用 (pragmatics). Without
    # the label someone reads our surface number against a pragmatic estimate as if one refuted the other.
    # What reds it: drop the label line from the report.
    from tools.check_cn_depth import _KOJING_LABEL, main

    assert (
        "词面" in _KOJING_LABEL
        and "语用" in _KOJING_LABEL
        and "不可直接对齐" in _KOJING_LABEL
    )
    main(["--corpus", str(tmp_path)])  # absent corpus still prints its discipline lines


def test_registration_reads_every_fenced_block_not_just_the_first():
    # 🔴 entries accumulate into more than one block as arms are registered at different times. Reading
    # only the first silently drops the rest — and an entry that is present but UNREAD is indistinguishable
    # from one never written: the gate reports 未登记 for an arm that IS registered. What reds it: go back
    # to returning the first matching block.
    from tools.check_registration import parse_registration

    text = (
        "# doc\n\n```\n"
        f"corpus id : {_CALIB}\nn         : 70\ncorpus_sha: {_SHA_A}\n"
        "```\n\nprose\n\n```\n"
        f"corpus id : {_HOLDOUT}\nn         : 125\ncorpus_sha: {_SHA_B}\n"
        "```\n"
    )
    ids = {e.corpus_id for e in parse_registration(text)}
    assert ids == {_CALIB, _HOLDOUT}  # both blocks read


# --------------------------------------------------------------------------- #
# 🔴 M4 —— 正交轴只在标注过的行上有定义；未标注 ≠ 取值为假
# --------------------------------------------------------------------------- #
def test_m4_unlabelled_case_reads_as_third_state_not_false():
    from tools.check_cn_two_arm import object_bearing_of

    rows = [
        {"case_id": "a", "object_bearing": True},
        {"case_id": "b", "object_bearing": False},
    ]
    assert object_bearing_of(rows, "a") is True
    assert object_bearing_of(rows, "b") is False
    # 什么让它红：把 None 折成 False ⇒ 未标注的件会被算进"取值为假"那一侧
    assert object_bearing_of(rows, "never_labelled") is None


def test_m4_slice_over_a_partly_unlabelled_denominator_raises():
    import pytest

    from tools.check_cn_two_arm import assert_axis_slice_is_legitimate

    rows = [{"case_id": "a", "object_bearing": True}]
    assert_axis_slice_is_legitimate(rows, ["a"])  # 全标注 ⇒ 合法
    with pytest.raises(ValueError, match="未标注"):
        assert_axis_slice_is_legitimate(rows, ["a", "b"])  # b 从未标注 ⇒ 必须抛


def test_m5_self_review_and_axis_scope_ride_in_the_citation_form():
    """🔴 声明必须落在【引用那个数的人读得到】的地方 —— 侧表是 operator_only，citation_form 才是整段粘走的那个。"""
    from treval.citability import N180_FPR_DENOMINATOR_NOTE

    form = _fpr_form("language:zh")
    assert N180_FPR_DENOMINATOR_NOTE in form
    assert "撰写人与复核人是同一人" in form  # 背书链声明
    assert "两个方向都不合法" in form  # 承重宾语轴的作用域声明


# --------------------------------------------------------------------------- #
# 🔴 M-硬负例 —— 恒为 1.00 的比例是【构造声明】不是测量；一个标签替两种"硬"背书要说出来
# --------------------------------------------------------------------------- #
def test_saturated_hard_ratio_announces_it_cannot_take_a_second_value():
    from tools.check_benign import _report

    line = _report(
        125,
        125,
        0,
        0,
        0,
        benign_name="llm01_cn_benign_holdout",
        baseline_name="b",
        prereg_name="p",
        floor=1.00,
    )
    assert "取不到第二个值" in line and "构造声明" in line
    # 什么让它红：把 saturated 段拿掉 ⇒ 一个恒绿的检查会被读成"查过了"
    unsaturated = _report(
        90,
        100,
        0,
        0,
        0,
        benign_name="x",
        baseline_name="b",
        prereg_name="p",
        floor=0.86,
    )
    assert (
        "取不到第二个值" not in unsaturated
    )  # 非饱和臂不该出现这句（对什么都说的话等于没说）


def test_hard_label_declares_it_covers_two_kinds_and_the_split_is_unmeasured():
    from tools.check_benign import _report

    line = _report(
        125,
        125,
        0,
        0,
        0,
        benign_name="llm01_cn_benign_holdout",
        baseline_name="b",
        prereg_name="p",
        floor=1.00,
    )
    assert "两种硬" in line and "未测量" in line
    # 🔴 拆分不许由不合身的词表造出来 —— 声明里必须写明这一点
    assert "不合身" in line


def test_cn_floor_was_re_derived_not_inherited():
    from tools.check_benign import _CN_HARD_RATIO_FLOOR

    # 什么让它红：仍停在从 21/25 转述来的 0.84（§5 验收第 3 条）
    assert _CN_HARD_RATIO_FLOOR == 1.00


def test_registration_expected_arms_come_from_the_scope_not_a_hardcoded_pair():
    """🔴 一份文档只承载它自己那一批的臂 —— 写死一对会对【别的批次的文档】报出假的「未登记」，
    而一个人们学会忽略的告警，比没有告警更坏：真的缺登记那天，它长得一模一样。"""
    from pathlib import Path

    from tools.check_registration import ARM_SETS, check_registration

    en = Path("docs/issues/EV-EN-BENIGN-HOLDOUT.md").read_text(encoding="utf-8")
    ok = check_registration(en, expected_arms=ARM_SETS["en-benign"])
    assert ok.status == "ok", ok.lines
    # 什么让它红：拿 CN 那一对去判这份 EN 文档 ⇒ 假的「未登记」（就是修之前的行为）
    wrong = check_registration(en, expected_arms=ARM_SETS["cn-benign"])
    assert wrong.status == "unregistered" and "未登记" in "\n".join(wrong.lines)
