"""EV-EN-BENIGN-HOLDOUT — the English benign arm's FIT/MEASURE split, its replay gate, and the arm
repoint. Each test names what reds it AND what it measures."""

from __future__ import annotations

import glob

import pytest
import yaml

from treval.en_arm_split import (
    EN_ARM_ID_SET_SHA12,
    EN_CALIB_N,
    EN_CALIB_SUBDIR,
    EN_HOLDOUT_SUBDIR,
    EN_SPLIT_SEED,
    EN_TOTAL_N,
    SplitReplayError,
    assert_split_matches_registration,
    id_set_sha12,
)


def _arm_ids(subdir: str) -> list[str]:
    return [
        yaml.safe_load(open(f, encoding="utf-8"))["id"]
        for f in glob.glob(f"corpus/{subdir}/*.yaml")
    ]


# --------------------------------------------------------------------------- #
# 件1 — the split is a REPLAYABLE artifact. WHAT IT MEASURES: that the arms on disk are exactly the ones
# the recorded seed produces — i.e. that "which cases τ was fitted on" is a fact anyone can recompute,
# not one recoverable only by running someone else's code.
# --------------------------------------------------------------------------- #
def test_jian1_both_arms_keep_their_seed_membership_intact_as_they_grow():
    # BOTH arms grow (族 C lands 8 into each), so neither whole-arm digest matches any more — and neither
    # should. What must stay exact is each arm's SEED membership: the record of which cases τ was fitted on.
    from treval.en_arm_split import assert_seed_subset_replays, seed_members

    seed = seed_members()
    assert len(seed[EN_CALIB_SUBDIR]) == EN_CALIB_N == 87
    assert len(seed[EN_HOLDOUT_SUBDIR]) == EN_TOTAL_N - EN_CALIB_N == 86
    assert id_set_sha12(seed[EN_CALIB_SUBDIR]) == EN_ARM_ID_SET_SHA12[EN_CALIB_SUBDIR]
    assert (
        id_set_sha12(seed[EN_HOLDOUT_SUBDIR]) == EN_ARM_ID_SET_SHA12[EN_HOLDOUT_SUBDIR]
    )
    assert_seed_subset_replays(_arm_ids(EN_CALIB_SUBDIR), _arm_ids(EN_HOLDOUT_SUBDIR))


def test_jian1_a_grown_arm_still_audits_via_its_SEED_SUBSET():
    # 🔴 裁定② path D — an arm legitimately GROWS (new families are authored into it). Two properties were
    # conflated by one whole-arm digest: CONTAMINATION ("nothing here was used to fit τ" — newly authored
    # cases satisfy it by construction, growth cannot break it) and AUDIT ("the seed-derived part still
    # replays" — the one growth does break). Separating them is the fix.
    # What reds it: go back to hashing the whole arm ⇒ every legitimate addition reds, and a gate that
    # reds on legitimate work is a gate someone switches off.
    from treval.en_arm_split import assert_seed_subset_replays

    calib, holdout = _arm_ids(EN_CALIB_SUBDIR), _arm_ids(EN_HOLDOUT_SUBDIR)
    assert len(holdout) > EN_TOTAL_N - EN_CALIB_N  # it grew
    assert_seed_subset_replays(calib, holdout)  # and it still audits


def test_jian1_a_seed_case_moved_between_arms_is_caught():
    # 🔴 the contamination this片 exists to prevent: a case that fitted τ turning up in the measurement arm.
    # What reds it: drop the cross-arm check ⇒ a rehomed fit case passes as ordinary growth.
    from treval.en_arm_split import assert_seed_subset_replays, seed_members

    seed = seed_members()
    calib = list(seed[EN_CALIB_SUBDIR])
    holdout = list(seed[EN_HOLDOUT_SUBDIR]) + [
        calib.pop()
    ]  # a calib seed case lands in holdout
    with pytest.raises(SplitReplayError, match="拟合件跑到测量臂"):
        assert_seed_subset_replays(calib, holdout)


def test_jian1_a_deleted_seed_case_is_caught():
    # dropping a seed case silently shrinks the audited set; the digest must not be satisfiable by a subset.
    from treval.en_arm_split import assert_seed_subset_replays, seed_members

    seed = seed_members()
    holdout = list(seed[EN_HOLDOUT_SUBDIR])[:-1]
    with pytest.raises(SplitReplayError, match="缺失"):
        assert_seed_subset_replays(seed[EN_CALIB_SUBDIR], holdout)


def test_jian1_RESPLITTING_A_GROWN_SET_IS_REFUSED():
    # 🔴 the road explicitly closed (裁定②-B): re-running the split over the grown id list to "make the
    # digest match again" reshuffles ALL ids, washing already-fitted calib cases into the holdout arm —
    # the exact contamination, arriving disguised as a fix. A stale digest is VISIBLE; a quietly rehomed
    # fit case is not. What reds it: drop the guard ⇒ the tempting one-liner becomes available again.
    from treval.en_arm_split import assert_never_resplit

    assert_never_resplit(
        [f"case.{i:03d}" for i in range(EN_TOTAL_N)]
    )  # the original set is fine
    with pytest.raises(SplitReplayError, match="拒绝在"):
        assert_never_resplit([f"case.{i:03d}" for i in range(EN_TOTAL_N + 24)])


def test_jian1_a_wrong_split_fails_closed():
    # 🔴 fail-CLOSED, never a warning: one case swapped between arms ⇒ raise.
    calib, holdout = _arm_ids(EN_CALIB_SUBDIR), _arm_ids(EN_HOLDOUT_SUBDIR)
    swapped_calib = calib[:-1] + [holdout[0]]
    swapped_holdout = holdout[1:] + [calib[-1]]
    with pytest.raises(SplitReplayError, match="失败关闭"):
        assert_split_matches_registration(swapped_calib, swapped_holdout)


def test_jian1_digest_fingerprints_membership_not_shuffle_order():
    # the digest sorts INSIDE: membership is the fact worth pinning, the emitted order is not.
    assert id_set_sha12(["b", "a", "c"]) == id_set_sha12(["c", "b", "a"])
    assert id_set_sha12(["a", "b"]) != id_set_sha12(["a", "c"])


def test_jian1_the_seed_is_recorded_in_repo_not_only_upstream():
    # 🔴 只有跑别人代码才知道的切分等于没有切分 —— the seed/algorithm/digests live HERE.
    assert EN_SPLIT_SEED == 20260823 and EN_CALIB_N == 87
    assert set(EN_ARM_ID_SET_SHA12) == {EN_CALIB_SUBDIR, EN_HOLDOUT_SUBDIR}


# --------------------------------------------------------------------------- #
# 件2 — the calib arm is structurally unreachable; FPR reads the HOLDOUT arm
# --------------------------------------------------------------------------- #
def test_jian2_en_fpr_producers_read_the_holdout_arm():
    # 🔴 验收 — FPR 语料必须是留出臂. What reds it: point them back at the merged/calib dir.
    from treval.cli.collect import CURATION

    benign = [
        p
        for p in CURATION
        if p.indicator_id in ("false_positive_rate", "benign_flag_rate")
    ]
    assert benign and all(p.corpus_subdir == EN_HOLDOUT_SUBDIR for p in benign)


def test_jian2_no_producer_may_bind_the_english_calib_arm():
    # 🔴 验收 — 把英文标定臂塞进 CURATION ⇒ 必须红. The EXISTING guard covers it (no new mechanism).
    from treval.active_eval.indicators import FalsePositiveRate
    from treval.cli.collect import CURATION, Producer, _assert_no_calib_producer

    _assert_no_calib_producer(CURATION)  # the real set is clean
    with pytest.raises(ValueError, match="CALIBRATION arm"):
        _assert_no_calib_producer(
            (Producer("false_positive_rate", FalsePositiveRate, EN_CALIB_SUBDIR),)
        )


def test_jian2_the_merged_arm_is_gone_so_nothing_can_silently_read_it():
    # the pre-split dir must not linger: a stale reference would keep reading fit+measure merged.
    assert not glob.glob("corpus/llm01_benign/*.yaml")


# --------------------------------------------------------------------------- #
# 族 C — in the FPR denominator, reported on its OWN line, carrying its own contamination marker.
# WHAT IT MEASURES: whether the new signature cost us anything on legitimate traffic — a question the
# whole-arm number alone cannot answer, and which the family's originating eval set cannot answer at all.
# --------------------------------------------------------------------------- #
def _fpr(subject="", notes=""):
    from treval.models import EvidenceRef, IntegrityStatus, Measurement

    return Measurement(
        indicator_id="false_positive_rate",
        dimension="robustness",
        value=0.1,
        unit="ratio",
        sample_size=100,
        evidence_refs=(EvidenceRef(source="wal:x", seq=1),),
        subject=subject,
        notes=notes,
        ci_low=0,
        ci_high=1,
        integrity=IntegrityStatus.VERIFIED,
    )


def _serialize(measurements):
    from treval import load_registry
    from treval.active_eval import EVIDENCE_REQUIREMENTS
    from treval.provenance import build_provenance
    from treval.rubric.engine import evaluate
    from treval.rubric.serialize import serialize_self_contained_bundle

    prov = build_provenance(
        wal_dir="/wal",
        window=(100, 200),
        pinned=True,
        tenant_id="__eval__",
        record_count=5,
        generated_at_ns=200,
        language_scope="英文",
        tested_version="v4",
        detect_config="x",
        exec_mode="block",
        detection_layer_status="tier1_only",
        upstream_timeout_s=60.0,
        judge_form="single",
        measurement_path="in_product_gateway",
        tau_declared="shipped",
        tau_source="shipped",
    )
    prov["wal_segments"] = {"sha256": "sha256:" + "a" * 64}
    reg = load_registry()
    report = evaluate(reg, measurements, [], window=(100, 200), tenant_id="__eval__")
    return serialize_self_contained_bundle(
        report, measurements, reg, prov, evidence_requirements=EVIDENCE_REQUIREMENTS
    )


def _row(bundle, subject):
    return next(
        r
        for r in bundle["measurements"]
        if r["indicator_id"] == "false_positive_rate" and r["subject"] == subject
    )


def test_family_c_in_the_denominator_without_its_row_makes_the_fpr_not_citable():
    # 🔴 同报门 — family C measured (its marker rides in the notes) but NO family:phonetic row ⇒ the
    # whole-arm FPR is not citable. What reds it: drop the co-report block in serialize.
    from treval.citability import FAMILY_C_MARKER

    bundle = _serialize([_fpr(notes=f"...{FAMILY_C_MARKER}...")])
    assert "NOT CITABLE" in _row(bundle, "")["citation_form"]
    assert "分行" in _row(bundle, "")["citation_form"]


def test_family_c_row_present_clears_the_block():
    from treval.citability import FAMILY_C_MARKER, FAMILY_C_SUBJECT

    bundle = _serialize(
        [
            _fpr(notes=f"...{FAMILY_C_MARKER}..."),
            _fpr(subject=FAMILY_C_SUBJECT, notes=f"k_C ...{FAMILY_C_MARKER}..."),
        ]
    )
    assert "NOT CITABLE" not in _row(bundle, "")["citation_form"]


def test_a_product_without_family_c_is_unaffected():
    # no family-C case measured ⇒ nothing to co-report ⇒ the gate must not fire (a gate that reds on
    # everything gets switched off).
    bundle = _serialize([_fpr()])
    assert "NOT CITABLE" not in _row(bundle, "")["citation_form"]


def test_k_c_is_documented_as_a_COUNT_not_a_rate():
    # 🔴 字段说明写死 — the misreading is one division away: 8 cases, one mis-block = 12.5pp.
    from treval.citability import FAMILY_C_COUNT_NOTE

    assert (
        "【计数】不是【率】" in FAMILY_C_COUNT_NOTE and "12.5pp" in FAMILY_C_COUNT_NOTE
    )


def test_combined_power_is_read_across_both_sides_but_the_denominator_is_holdout_only():
    # 🔴 BOTH reasons must be stated, not just the first: (1) the calib side is the fit set; (2) more
    # fundamentally the NATO signature is Tier-1 and is not the same measurement as a judge FPR.
    from treval.citability import FAMILY_C_COUNT_NOTE

    assert "合读" in FAMILY_C_COUNT_NOTE and "只算留出侧 8" in FAMILY_C_COUNT_NOTE
    assert "拟合集" in FAMILY_C_COUNT_NOTE  # reason (1)
    assert (
        "Tier-1" in FAMILY_C_COUNT_NOTE and "不是同一次测量" in FAMILY_C_COUNT_NOTE
    )  # reason (2)


def test_family_c_carries_its_contamination_marker():
    # 件5 — 族 C 由评测件催生; the original batch is a REGRESSION item, never capability evidence.
    from treval.citability import FAMILY_C_COUNT_NOTE, FAMILY_C_MARKER

    assert FAMILY_C_MARKER == "motivated_by_eval_set"
    assert (
        FAMILY_C_MARKER in FAMILY_C_COUNT_NOTE and "只作【回归】" in FAMILY_C_COUNT_NOTE
    )


def test_the_whole_english_benign_arm_declares_it_is_authored_not_sampled():
    # 🔴 ③ — the property was ALWAYS true of the existing 173 and had never been declared; the new families
    # only made us notice. So it attaches to the whole English arm, and it says WHERE IT IS WEAKER than the
    # CN one. What reds it: drop the append (or attach it only to the new families).
    from treval.citability import EN_BENIGN_AUTHORED_NOTE

    bundle = _serialize([_fpr()])
    form = _row(bundle, "")["citation_form"]
    assert EN_BENIGN_AUTHORED_NOTE in form
    assert "全部为我方自撰" in form and "非按真实流量抽样" in form
    assert "比中文那条更弱" in form  # symmetry must not be assumed by the reader


def test_the_cn_stratum_does_not_get_the_english_provenance_note():
    # the CN FPR is domain-sourced and carries its own denominator口径 — pasting the weaker English
    # statement onto it would be wrong.
    from treval.citability import EN_BENIGN_AUTHORED_NOTE, FAMILY_C_SUBJECT

    bundle = _serialize([_fpr(), _fpr(subject="language:zh")])
    assert EN_BENIGN_AUTHORED_NOTE not in _row(bundle, "language:zh")["citation_form"]
    assert FAMILY_C_SUBJECT  # (imported for the sibling tests)


def test_w2_anchor_note_attaches_only_where_the_denominator_holds_w2_cases():
    """🔴 W2 锚点来源只挂在【分母含 W2 件】的分层上。

    什么让它红：把它挂进 `EN_BENIGN_AUTHORED_NOTE` 那一行（条件是「不是中文分层」，作用域是**整个**
    英文良性臂）—— 那会把「本臂件按领域侧锚点生成」盖到从未见过锚点的分层头上。
    两条说明的**条件不同**，同处同行是把二者当成了同一个条件。
    """
    from treval.citability import (
        EN_BENIGN_P1_POOLED_SUBJECT,
        EN_BENIGN_P1_UNLISTED_STRATUM_EXAMPLE,
        EN_BENIGN_P1_W2_SUBJECT,
        W2_ANCHOR_PROVENANCE_NOTE,
    )

    subjects = (
        EN_BENIGN_P1_POOLED_SUBJECT,
        EN_BENIGN_P1_W2_SUBJECT,
        EN_BENIGN_P1_UNLISTED_STRATUM_EXAMPLE,
    )
    bundle = _serialize([_fpr(subject=s) for s in subjects])
    for s in (EN_BENIGN_P1_POOLED_SUBJECT, EN_BENIGN_P1_W2_SUBJECT):
        assert W2_ANCHOR_PROVENANCE_NOTE in _row(bundle, s)["citation_form"]
    # 🔴 不在白名单里的分层必须【拿不到】这条 —— 这是本文件里那条通用性质唯一在跑的实例
    assert (
        W2_ANCHOR_PROVENANCE_NOTE
        not in _row(bundle, EN_BENIGN_P1_UNLISTED_STRATUM_EXAMPLE)["citation_form"]
    )


def test_every_p1_stratum_is_whitelisted():
    """🔴 +56 落地时新加了两个分层（批 1 / 批 2）。**新增分层却忘了加进白名单**，
    `W2_ANCHOR_PROVENANCE_NOTE` 就会静默停止挂在它上面 —— 声明没了，而没有任何门会红。

    什么让它红：加一个 `EN_BENIGN_P1_*_SUBJECT` 却不把它放进 `W2_DENOMINATOR_SUBJECTS`。

    ⚠️ 它不覆盖什么：**同时**忘了登记表和白名单仍然不红。这条把两处遗漏里的一处变成红，不是两处。
    （真正的 derive-not-store 要从 producer 的 subject 推，而今天没有任何 producer 发这些 subject。）"""
    from treval.citability import EN_BENIGN_P1_SUBJECTS, W2_DENOMINATOR_SUBJECTS

    missing = EN_BENIGN_P1_SUBJECTS - W2_DENOMINATOR_SUBJECTS
    assert not missing, f"p1 分层未入白名单，锚点来源声明会静默丢失：{sorted(missing)}"


def test_both_batches_are_separately_reportable():
    """🔴 批 1 必须【始终可单独报】—— 合池 171 的 FPR 与旧的 115 FPR **不可比**：数会因【构成】
    而动，不因【系统】而动（本臂从"纯 IT 运营层"变成"IT 运营层 115 + 其他四类 56"）。
    没有批 1 分层，「改前 vs 改后」这个比较永远做不了，而合池数会被当成同一个数的延续。

    什么让它红：把两个批次分层合并掉，只留合池 —— 那正是构成变更被读成系统变化的入口。"""
    from treval.citability import (
        EN_BENIGN_P1_BATCH1_SUBJECT,
        EN_BENIGN_P1_BATCH2_SUBJECT,
        EN_BENIGN_P1_POOLED_SUBJECT,
        W2_ANCHOR_PROVENANCE_NOTE,
    )

    assert EN_BENIGN_P1_BATCH1_SUBJECT != EN_BENIGN_P1_BATCH2_SUBJECT
    assert EN_BENIGN_P1_POOLED_SUBJECT not in (
        EN_BENIGN_P1_BATCH1_SUBJECT,
        EN_BENIGN_P1_BATCH2_SUBJECT,
    )
    # 两个批次分层都在分母里含 W2 件（甲案：批 2 也是新撰）⇒ 两者都该拿到锚点来源声明
    bundle = _serialize(
        [
            _fpr(subject=EN_BENIGN_P1_BATCH1_SUBJECT),
            _fpr(subject=EN_BENIGN_P1_BATCH2_SUBJECT),
        ]
    )
    for s in (EN_BENIGN_P1_BATCH1_SUBJECT, EN_BENIGN_P1_BATCH2_SUBJECT):
        assert W2_ANCHOR_PROVENANCE_NOTE in _row(bundle, s)["citation_form"]


def test_w2_anchor_note_is_a_positive_whitelist_not_a_negation():
    """🔴 正列 vs 否定：**否定条件的作用域随世界增长**。

    若接点写成「不是幸存子集」，那么明天新增的任何分层（另一条臂、另一个族）都会自动被卷进来、
    声称自己用了领域锚点，而没有任何东西会红。正列不会。

    什么让它红：把 `W2_DENOMINATOR_SUBJECTS` 的成员判断换成任何形式的「不等于某个分层」。
    """
    from treval.citability import (
        EN_BENIGN_P1_UNLISTED_STRATUM_EXAMPLE,
        W2_ANCHOR_PROVENANCE_NOTE,
        W2_DENOMINATOR_SUBJECTS,
    )

    assert EN_BENIGN_P1_UNLISTED_STRATUM_EXAMPLE not in W2_DENOMINATOR_SUBJECTS
    # 一个与本臂无关的、将来才会出现的分层 —— 正列下它拿不到这条说明
    future = "arm:some_future_stratum"
    assert future not in W2_DENOMINATOR_SUBJECTS
    bundle = _serialize([_fpr(subject=future)])
    assert W2_ANCHOR_PROVENANCE_NOTE not in _row(bundle, future)["citation_form"]
    # 未分层的默认值 subject="" 同样不该拿到 —— 它是【任何】未分层测量的默认，不是"本臂合池"
    bundle = _serialize([_fpr()])
    assert W2_ANCHOR_PROVENANCE_NOTE not in _row(bundle, "")["citation_form"]


def test_jian1_the_digest_guards_the_MANIFEST_itself_not_just_the_arms():
    # 🔴 Found by a surviving mutation: with set semantics, if no seed id is MISSING then the intersection
    # equals the seed set, so the digest can never differ — the digest branch is unreachable via the arms.
    # What it actually guards is the MANIFEST: edit the recorded seed membership and the digest is the only
    # thing that notices. What reds it: drop the digest comparison ⇒ the audit record becomes editable
    # without anything objecting, which is the one file whose integrity the whole audit rests on.
    from treval import en_arm_split as m

    seed = m.seed_members()
    tampered = {
        m.EN_CALIB_SUBDIR: seed[m.EN_CALIB_SUBDIR],
        m.EN_HOLDOUT_SUBDIR: seed[m.EN_HOLDOUT_SUBDIR][:-1]
        + ["benign.hard.not_a_real_seed.999"],
    }
    original = m.seed_members
    m.seed_members = lambda: tampered  # type: ignore[assignment]
    try:
        arms_calib = list(tampered[m.EN_CALIB_SUBDIR])
        arms_holdout = list(
            tampered[m.EN_HOLDOUT_SUBDIR]
        )  # arms agree with the TAMPERED manifest
        with pytest.raises(SplitReplayError, match="种子子集重放"):
            m.assert_seed_subset_replays(arms_calib, arms_holdout)
    finally:
        m.seed_members = original  # type: ignore[assignment]


# --------------------------------------------------------------------------- #
# 携带率 —— WHAT IT MEASURES: whether the canary's mere PRESENCE separates the arms. The 20pp gap is a
# TOLERANCE around that criterion, not the criterion; both arms are built to ONE DECLARED rate instead.
# --------------------------------------------------------------------------- #
def test_carrier_rate_is_built_to_a_DECLARED_target_not_to_the_other_arm():
    # 🔴 chasing the other arm makes the benign rate a function of whatever the attack corpus incidentally
    # is, so every change to either arm restarts the chase. A declared rate both arms are built to is what
    # ends it. What reds it: delete the declared constant and compare arms to each other again.
    from treval.active_eval.canary import (
        DECLARED_CARRIER_RATE,
        carrier_rate,
        rate_deviation,
    )
    from treval.active_eval import load_corpus

    benign = list(load_corpus(f"corpus/{EN_HOLDOUT_SUBDIR}"))
    carriers, total = carrier_rate(benign)
    assert DECLARED_CARRIER_RATE == 0.45
    assert (
        abs(rate_deviation(carriers, total)) < 0.02
    )  # built TO the spec, not squeezed under a tolerance


def test_the_gate_separates_not_implanted_from_mix_imbalance():
    # 🔴 two different faults wear the same number. A bare "gap 22.6pp" sends someone to review cases; the
    # actual cause can be that the arm grew while the carrier COUNT stood still — nothing wrong with any
    # case. Same gap, opposite fix. What reds it: report only the gap.
    from treval.active_eval.canary import CarrierRateGap, carrier_diagnosis

    grew_but_not_implanted = CarrierRateGap(
        attack_rate=0.451,
        benign_rate=0.225,
        gap=0.226,
        exceeds=True,
        attack=(69, 153),
        benign=(32, 142),
    )
    assert carrier_diagnosis(grew_but_not_implanted) in ("not_implanted", "both")

    both_on_target = CarrierRateGap(
        attack_rate=0.451,
        benign_rate=0.451,
        gap=0.0,
        exceeds=False,
        attack=(69, 153),
        benign=(64, 142),
    )
    assert carrier_diagnosis(both_on_target) == "ok"


def test_the_diagnosis_names_the_fix_not_only_the_symptom():
    from treval.active_eval.canary import CarrierRateGap, carrier_diagnosis_note

    note = carrier_diagnosis_note(
        CarrierRateGap(
            attack_rate=0.451,
            benign_rate=0.225,
            gap=0.226,
            exceeds=True,
            attack=(69, 153),
            benign=(32, 142),
        )
    )
    assert "新件没植入" in note and "不要去逐条复核语料" in note


def test_the_carrier_set_was_drawn_by_a_RECORDED_SEED_not_hand_picked():
    # 🔴 hand-picking which benign cases carry the line is us deciding which benign cases look like attack
    # cases — the class signal the criterion forbids, re-entering by the back door. What reds it: drop the
    # seed record ⇒ the draw stops being reproducible and "we sampled it" becomes unfalsifiable.
    import json

    rec = json.loads(open("treval/en_canary_implant.json", encoding="utf-8").read())
    assert isinstance(rec["implant_seed"], int)
    assert rec["declared_carrier_rate"] == 0.45
    assert len(rec["implanted"]) == len(set(rec["implanted"])) > 0


def test_implanting_the_canary_leaves_the_user_sentence_untouched():
    # the line lives in system_prompt, so the case still measures exactly what it measured before —
    # which is why fixing the collinearity is cheap and does not disturb the FPR denominator's meaning.
    import json

    from treval.active_eval import load_corpus

    rec = json.loads(open("treval/en_canary_implant.json", encoding="utf-8").read())
    implanted = set(rec["implanted"])
    for c in load_corpus(f"corpus/{EN_HOLDOUT_SUBDIR}"):
        if c.id in implanted:
            assert "{{canary}}" in (c.system_prompt or "")
            assert c.input or c.messages  # the user's own turn is still there, unedited


# --------------------------------------------------------------------------- #
# 🔴 工单 3 · 共报门 —— 「只给合池数」会被现有机制处理成什么
#
# 这一格是【判断】不是实现。结论写在这里，就是给 PM 的裁定材料：
#
#   现有机制是【声明即强制】，不是无条件强制，也不只是命名。三档实测（下面三条测试）：
#     ① 合池数【声明了】子集在自己分母里（notes 带 marker）而缺分层行 ⇒ 🔴 **拒绝**（NOT CITABLE）；
#     ② 分层行补上 ⇒ 放行；
#     ③ 合池数【什么都不声明】⇒ 放行，一个字都不加。
#
#   ⇒ 强制的那一半真的存在（不是仅命名，`citation_form` 的 `@subject` 只是命名那一半）。
#     但它挂在**发数的人自己写下的那个声明**上。不声明的产物照旧通行。
#
# 🔴 这正好落在 PM 关心的那件事上：这条规矩的执行者是出对客材料的人，而他的激励与规矩相反。
#   现有机制拦得住"声明了却只报一个数"，拦不住"干脆不声明"。是否把触发条件从【声明】改成
#   【语料构成】（子集在臂里就必须共报，与 notes 无关）——那是 PM 的裁定，不是实现选择，本轮不做。
# --------------------------------------------------------------------------- #
def test_coreport_is_enforced_on_declaration_not_unconditionally():
    """🔴 三档一次跑完，供 PM 对照。什么让它红：把拒绝改成加注，或把触发条件从 notes 挪走。"""
    from treval.citability import FAMILY_C_MARKER, FAMILY_C_SUBJECT

    declared_only = _serialize([_fpr(notes=f"...{FAMILY_C_MARKER}...")])
    declared_with_row = _serialize(
        [
            _fpr(notes=f"...{FAMILY_C_MARKER}..."),
            _fpr(subject=FAMILY_C_SUBJECT, notes=f"k_C ...{FAMILY_C_MARKER}..."),
        ]
    )
    undeclared = _serialize([_fpr()])

    # ① 声明了、缺分层行 ⇒ 拒绝
    assert "NOT CITABLE" in _row(declared_only, "")["citation_form"]
    # ② 补上分层行 ⇒ 放行
    assert "NOT CITABLE" not in _row(declared_with_row, "")["citation_form"]
    # ③ 🔴 什么都不声明 ⇒ 照样放行，且【不加任何提示】—— 这一条是给 PM 看的那一格
    plain = _row(undeclared, "")["citation_form"]
    assert "NOT CITABLE" not in plain
    assert FAMILY_C_SUBJECT not in plain


def test_a_stratified_row_always_names_its_stratum():
    """命名那一半：分层数必须写明自己是哪一层（`citation_form` 的 `@subject`）——
    否则一个子集上的数读起来像整臂的数。什么让它红：去掉 `@subject` 拼接。"""
    from treval.citability import FAMILY_C_MARKER, FAMILY_C_SUBJECT

    bundle = _serialize(
        [
            _fpr(notes=f"...{FAMILY_C_MARKER}..."),
            _fpr(subject=FAMILY_C_SUBJECT, notes=f"k_C ...{FAMILY_C_MARKER}..."),
        ]
    )
    assert (
        f"false_positive_rate@{FAMILY_C_SUBJECT}"
        in _row(bundle, FAMILY_C_SUBJECT)["citation_form"]
    )


# --------------------------------------------------------------------------- #
# 🔴 PM 2026-09-06 —— 两条随数走的声明（与 benign_session_disruption_rate 同一处：citation_form）
#
# 🔴 两条的【作用域不同】，这是本节存在的理由：
#   B 分母不含敏感形态 —— 与臂无关（三条臂逐条扫过，六种形态零命中）⇒ 按 indicator_id 挂即可。
#   A 分母构成 171 = 115 + 56 —— **只对 p1 臂成立**。同一个 indicator_id 也可能跑在【旧臂
#     llm01_benign_holdout（142 件）】上（臂名由 --benign-arm 选），那时 A 是一句**假话**。
#     ⇒ A 必须同时按【臂】键控，而臂名此前**不进 provenance** —— 产物答不出 A 自己要求的
#     「先答出它出自哪一条臂」。补 provenance.benign_arm 是让 A 成立的前提，不是附赠。
# --------------------------------------------------------------------------- #
def _fpr_bundle(*, benign_arm: str = "", indicator_id: str = "false_positive_rate"):
    from dataclasses import replace

    from treval import load_registry
    from treval.active_eval import EVIDENCE_REQUIREMENTS
    from treval.provenance import build_provenance
    from treval.rubric.engine import evaluate
    from treval.rubric.serialize import serialize_self_contained_bundle

    m = replace(_fpr(), indicator_id=indicator_id)
    prov = build_provenance(
        wal_dir="/wal",
        window=(100, 200),
        pinned=True,
        tenant_id="__eval__",
        record_count=5,
        generated_at_ns=200,
        language_scope="英文",
        tested_version="v4",
        detect_config="x",
        exec_mode="block",
        detection_layer_status="tier1_only",
        upstream_timeout_s=60.0,
        judge_form="single",
        measurement_path="in_product_gateway",
        tau_declared="shipped",
        tau_source="shipped",
        benign_arm=benign_arm,
    )
    prov["wal_segments"] = {"sha256": "sha256:" + "a" * 64}
    reg = load_registry()
    report = evaluate(reg, [m], [], window=(100, 200), tenant_id="__eval__")
    bundle = serialize_self_contained_bundle(
        report, [m], reg, prov, evidence_requirements=EVIDENCE_REQUIREMENTS
    )
    return next(r for r in bundle["measurements"] if r["indicator_id"] == indicator_id)[
        "citation_form"
    ]


def test_declaration_b_rides_with_the_benign_rates():
    """声明 B —— 分母不含敏感信息形态，且那句「未测量，不是测得为零」必须在。
    什么让它红：不挂，或把末句写成「未发现」。"""
    from treval.citability import BENIGN_PII_ABSENT_NOTE

    for iid in ("false_positive_rate", "benign_flag_rate"):
        body = _fpr_bundle(indicator_id=iid)
        assert BENIGN_PII_ABSENT_NOTE in body
    for shape in (
        "掩码卡号",
        "掩码手机号",
        "姓名",
        "内网 IP",
        "网点名",
        "统一社会信用代码",
    ):
        assert shape in BENIGN_PII_ABSENT_NOTE
    assert (
        "未测量" in BENIGN_PII_ABSENT_NOTE
        and "不是【测得为零】" in BENIGN_PII_ABSENT_NOTE
    )


def test_declaration_b_carries_the_invalidation_condition():
    """🔴 PM 新加的那条反面：一旦加入任何请求侧 PII 规则，本数对新配置【不成立】，必须重测。
    什么让它红：只写「未测量」不写「加了规则本数作废」—— 前者说的是今天，后者说的是明天。"""
    from treval.citability import BENIGN_PII_ABSENT_NOTE

    assert "请求侧 PII 规则" in BENIGN_PII_ABSENT_NOTE
    assert "重测" in BENIGN_PII_ABSENT_NOTE


def test_declaration_a_rides_only_on_the_p1_arm():
    """🔴 声明 A 只对 p1 臂成立。什么让它红：只按 indicator_id 挂 —— 那样一个跑在【旧臂 142 件】
    上的 FPR 会带着「分母构成 = 115 + 56 = 171」出门，而那是假话。"""
    from treval.citability import P1_COMPOSITION_NOTE

    assert P1_COMPOSITION_NOTE in _fpr_bundle(benign_arm="llm01_benign_holdout_p1")
    assert P1_COMPOSITION_NOTE not in _fpr_bundle(benign_arm="llm01_benign_holdout")
    # 🔴 臂名未记 ⇒ 不许猜、也不许默认挂上：说不出是哪条臂时，这条声明本身就不成立
    assert P1_COMPOSITION_NOTE not in _fpr_bundle(benign_arm="")


def test_declaration_a_keeps_both_statements_alive():
    """🔴 A 的要害是【两条并存】：四类未覆盖对旧臂仍成立、对 p1 不再成立。
    什么让它红：只留新臂那半 —— 旧臂的既有数就没人提醒它仍缺那四类。"""
    from treval.citability import P1_COMPOSITION_NOTE

    assert "旧臂" in P1_COMPOSITION_NOTE and "仍成立" in P1_COMPOSITION_NOTE
    assert "不可直接比" in P1_COMPOSITION_NOTE
    assert "先答出它出自哪一条臂" in P1_COMPOSITION_NOTE


def test_the_arm_name_reaches_the_artifact():
    """🔴 A 靠 provenance.benign_arm 键控，而它此前【不进 provenance】。
    什么让它红：把 benign_arm 从 build_provenance 拿掉 —— A 就只能靠猜，或者一律挂上。"""
    from treval.provenance import build_provenance

    prov = build_provenance(
        wal_dir="/wal",
        window=(1, 2),
        pinned=True,
        tenant_id="__eval__",
        record_count=1,
        benign_arm="llm01_benign_holdout_p1",
    )
    assert prov["benign_arm"] == "llm01_benign_holdout_p1"
    # 未声明 ⇒ 空串，不是缺键：缺键与"跑在默认臂上"在下游读起来一样
    assert (
        build_provenance(
            wal_dir="/wal",
            window=(1, 2),
            pinned=True,
            tenant_id="__eval__",
            record_count=1,
        )["benign_arm"]
        == ""
    )
