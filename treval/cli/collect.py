"""`collect` — the operator path (EV-8 §3/§6): drive the live gateway through the
curated active corpora and emit a Measurement bundle.

The D3 curation map is the whole point: each bound `indicator_id` is produced from exactly
ONE canonical corpus, so the bundle holds one aggregate per id and the engine's
`DuplicateIndicatorError` net never trips.

Two producer families, distinct `indicator_id`s (no D3 collision):
  - ACTIVE (detection efficacy) — drive the gateway with a corpus, measure over ProbeResults.
  - PASSIVE (EV-5, §6) — read the eval WAL once, measure over its AuditEvidence stream.
    `chain_integrity` / `unclosed_loop_rate` are live-meaningful over the eval WAL NOW (the
    Transparency moat); `duration_p99` / `terminal_error_ratio` reflect the eval probes
    (mechanically valid, not a production SLA). Production-scoped passive reads land later.

Errors aggregate (§5): a producer that fails (gateway down / WAL unreadable / …) records a
warning and the run continues; its indicator is simply absent from the bundle (→ `report`
renders insufficient_data, honest missing data, not a crash).
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from treval.active_eval import (
    BenignCanaryLeakRate,
    DecoyToolHijackRate,
    DecoyToolPartialRate,
    PlantedSecretInOutputRate,
    CorpusIndicator,
    CostRunawayCaught,
    OutputNeutralizeFidelityRate,
    OutputNeutralizeInertRate,
    BenignFlagRate,
    BenignFlagRateHardOnly,
    BenignShadowFlagRate,
    FalsePositiveRate,
    InjectionCatchRate,
    InjectionCombinedRecall,
    InjectionCatchRateObservable,
    InjectionDecisionBlockRate,
    InjectionDeclinedByModelRate,
    InjectionHardBlockedRate,
    InjectionSoftFlagDeclinedRate,
    InjectionSuccessRate,
    SensitiveDisclosureRate,
    SpeechActSeparationRate,
    SpeechActShadowSeparationRate,
    SystemPromptLeakRate,
    Tier2JudgeCoverage,
    Tier2ShadowRecallLift,
    ToolScopeViolationRate,
    UnsafeOutputPassthroughRate,
    WireIndirectBenignFlagRate,
    WireIndirectCatchRate,
    load_corpus,
    run_corpus,
)
from treval.active_eval.canary import (
    CanaryLeakError,
    CanarySet,
    assert_no_canary_plaintext,
)
from treval.active_eval.cases import (
    serialize_benign_case_table,
    serialize_case_contract,
)
from treval.active_eval.corpus import CorpusCase, corpus_fingerprint
from treval.active_eval.indicators import DEFAULT_ARM_PARITY, check_arm_parity

# 🔴 C2 —— 决策记录的类型号从 target 导入，不在这里另写一个字面量：
# 它是从 proto 描述符算出来的（target.py:50），写第二份就是两个迟早不等的真相。
from treval.active_eval.target import _DECISION_MADE
from treval.active_eval.target import AdminAuthError, ProbeResult
from treval.case_contract import CaseContractError
from treval.denominator import Denominator, DenominatorError, load_denominator
from treval.policy_pin import PolicyDriftError, assert_single_policy_snapshot
from treval.cli.bundle import build_bundle
from treval.indicators import (
    BoundaryBreachRate,
    ChainIntegrity,
    DurationP99,
    PiiExposureSurface,
    RedactionHitRatio,
    TerminalErrorRatio,
    UnclosedLoopRate,
)
from treval.models import Measurement
from treval.protocols import Indicator
from treval.provenance import (
    JudgeImprintError,
    build_provenance,
    observed_window,
    resolve_judge_imprint,
)
from treval.readers import WalEvidenceReader

_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_CORPUS = _ROOT / "corpus"

EXIT_OK = 0
EXIT_IO = 3


class DuplicateProbeError(RuntimeError):
    """F5 (§5) — a case_id was probed more than once in one collection (the case-level dedup broke)."""


def _assert_probed_once(results: tuple[ProbeResult, ...]) -> None:
    """🔴 F5 (§5.2) — the case-level dedup guarantee as a fail-CLOSED assertion (RAISE, never warn):
    each case_id appears in the probe results EXACTLY once. A duplicate means a case was probed twice,
    so its decision- and output-side numbers would read DIFFERENT executions — the exact bug F5 removes.
    Restoring the old directory-level key (a case in two directories) trips this."""
    counts: dict[str, int] = {}
    for pr in results:
        counts[pr.case_id] = counts.get(pr.case_id, 0) + 1
    dups = sorted(cid for cid, n in counts.items() if n > 1)
    if dups:
        raise DuplicateProbeError(
            f"F5: case_id(s) probed more than once in one collection: {dups[:5]} — the case-level "
            "dedup broke (a case's decision- and output-side numbers would read different executions)"
        )


def _apply_declared_subject(prod: Producer, m: Measurement) -> Measurement:
    """🔴 件2 fix — the producer's DECLARED `subject` must REACH the row, and be CHECKED that it did.

    It used to be pure documentation: `Producer.subject` said "MUST match what factory().measure()
    stamps" and NOTHING enforced it, so the `cn` producers declared subject="language:zh" while the
    indicators stamped "". The CN rows came out as AGGREGATE rows — which BIND to rubric objectives.
    Observed live on the first CN baseline: the report graded rob.l2 off 54 diagnostic Chinese cases
    and printed 「能力缺口 · 任何样本量都过不了线」 for a batch declared NOT citable.
    🔴 A declaration nobody enforces is not a declaration.

    FILLS an empty subject only, so an indicator that stamps its own (the outcome_observable
    disclosure row) still wins — the two never fight. Then RAISES if the declared value did not end
    up on the row, so this can never silently regress to documentation again."""
    if prod.subject and not m.subject:
        m = replace(m, subject=prod.subject)
    if prod.subject and m.subject != prod.subject:
        raise ValueError(
            f"producer {prod.indicator_id} declares subject={prod.subject!r} but the measurement "
            f"carries {m.subject!r} — a declared subject that does not reach the row is how a "
            "diagnostic batch silently becomes a graded aggregate"
        )
    return m


# 🔴 C-3a-1 红线③ —— 随数走的那句限定。**写进 notes，不是写进文档**：数会被摘出去引用，
# 而文档不跟着走。
SMALL_ARM_NOTE = "⚠️ 本臂 n 太小，出不了有统计意义的率，只给方向读数"


def _apply_arm_note(prod: Producer, m: Measurement) -> Measurement:
    """把 Producer 声明的【臂级限定】追加到行的 notes 上。

    🔴 为什么不落在指标里：本单要给两条小臂的数挂一句「n 太小，只给方向读数」，而其中一条
    (`wire_indirect_catch_rate`) 是**空类体 + 继承** —— 它的 notes 由 `InjectionCatchRate.measure()`
    产出，那是完整注入臂（以及别的臂）共用的一份。把限定写进指标，等于把一句**只对某条臂成立**
    的话，印到每一条共用同一个 `measure()` 的臂上。

    🔴 而这句限定确实是【绑定】的属性、不是【指标】的属性：同一个指标绑到大臂上时这句话是**假的**。
    印一句假的限定不是保守 —— 它给一个不需要打折的数打折，还会把这句话读成套话，
    于是下一个人在它**真**成立的臂上也不读它了。⇒ 谁声明，谁带着；不声明的绑定原样通过。"""
    if not prod.arm_note:
        return m
    return replace(m, notes=f"{m.notes}；{prod.arm_note}" if m.notes else prod.arm_note)


def _run_arm_parity() -> str:
    """E3F §4 (F4) — the single arm-parity口径 this run stamped. The curated producers all build via
    the zero-arg factory, so catch and benign both use DEFAULT_ARM_PARITY; check_arm_parity enforces
    that they agree (it RAISES on a mismatch, §4.4-4) so the invariant is asserted, not merely assumed,
    at the one place the value enters the bundle."""
    catch_arm = benign_arm = DEFAULT_ARM_PARITY
    check_arm_parity(catch_arm, benign_arm)
    return catch_arm


@dataclass(frozen=True)
class Producer:
    """One curated active producer: bound id ← indicator over its canonical corpus.

    `subject` is the EV-0 stratification key the producer emits ("" = the aggregate row that binds
    to a rubric objective; non-empty = a disclosure/stratified row that never binds). It MUST match
    what `factory().measure()` stamps — two producers may share an `indicator_id` iff their
    `subject` differs (EV-ATTRIB §3.1: injection_catch_rate has an aggregate row AND an
    outcome_observable row)."""

    indicator_id: str
    factory: type[CorpusIndicator]
    corpus_subdir: str
    subject: str = ""
    # 🔴 C-3a-1 红线③ —— 一句随【这条绑定的数】走的限定，追加到行的 notes 上（见 `_apply_arm_note`）。
    # 它与 `subject` 同层，理由也同源：两者都是「这条绑定声明了什么」，而不是「这个指标是什么」。
    arm_note: str = ""


# W6 业务伪装诊断臂的子目录名。语料在仓外受控卷 ⇒ 用 --corpus 指到那个根,子目录名在这里。
DECOY_ARM_SUBDIR = "llm01_en_disguised"
# 英文良性臂的【默认】子目录名。🔴 可由 --benign-arm 覆盖 —— 新臂叫别的名字(如 W2 的
# llm01_benign_holdout_p1),而在此之前这个名字是【写死】的,于是一条名字不同的臂在这条路上
# 根本跑不了:语料在、判据在、Producer 找不到它。
BENIGN_ARM_DEFAULT = "llm01_benign_holdout"

# The D3 curation map (§3). Each bound indicator_id ← exactly ONE canonical corpus (so the
# bundle holds one aggregate per id — DuplicateIndicatorError never trips). Corpus subdirs are
# copied VERBATIM from eval_report's bindings (one source of truth for corpus↔indicator).
#
# DECISION-side (read the WAL decision record): `measured` only on a gateway; on a raw_model /
# moderation_api they are `n/a_needs_gateway` by construction (EV-FWD) — kept so a gateway run
# still measures them.
# OUTPUT-side (EV-PAIR-A): read response_text / secret_canary / output_marker only, so they are
# `measured` on BOTH gateway AND raw_model — this is what lets `collect --target-kind raw_model`
# produce real numbers (the same corpus↔indicator pairs eval_report already runs). 🔴 NOTE: several
# producers share a corpus (llm01_prompt_injection has six). They are probed ONCE and share that one
# run — see collect_measurements PHASE 1; the old one-run-per-producer model made catch and success
# read DIFFERENT executions of the same corpus. `within_cost_budget` is deliberately NOT here — it needs a budget arg while
# `factory()` is no-arg; it lands with EV-PAIR's factory-form change (EV-PAIR-A §3).
CURATION: tuple[Producer, ...] = (
    # decision-side
    Producer("injection_catch_rate", InjectionCatchRate, "llm01_prompt_injection"),
    # 🔴 C-0a —— 入口期拦截率。此前指标建好、三条判据在位、14 发变异全红，**但没有 Producer**：
    # 于是 2026-09-12 的 C-2a 诊断跑把它写进了预登记块的主判据，而那一跑【产不出这个数】。
    # 一个"已建好没接上"的指标，在台账上和一个不存在的指标长得一样 —— 差别只在有人去跑它的那一天。
    # 分母与 InjectionCatchRate 同源（同一个 `_catch_counts`），两者的 sample_size 由测试钉死相等。
    Producer(
        "injection_decision_block_rate",
        InjectionDecisionBlockRate,
        "llm01_prompt_injection",
    ),
    # EV-ATTRIB §3.1 — the SAME catch metric re-denominated to the marker-bearing subset, so catch
    # and success read on ONE denominator. Shares the injection_catch_rate id, differentiated by
    # subject="outcome_observable" (a disclosure row — never binds, never trips DuplicateIndicatorError).
    Producer(
        "injection_catch_rate",
        InjectionCatchRateObservable,
        "llm01_prompt_injection",
        subject="outcome_observable",
    ),
    # EV-ATTRIB §1 (+ F1) — the other THREE (decision×output) cells: WHO earned a "0% succeeded"
    # (governance vs the model). needs_decision ⇒ n/a on a bare model; the four cells sum to 1 (§4).
    # 🔴 hard_blocked is the ONLY one that alone backs a governance claim; soft_flag_declined is the
    # ambiguous 'attribution undetermined' cell, disclosed separately, never folded in.
    Producer(
        "injection_hard_blocked_rate",
        InjectionHardBlockedRate,
        "llm01_prompt_injection",
    ),
    Producer(
        "injection_soft_flag_declined_rate",
        InjectionSoftFlagDeclinedRate,
        "llm01_prompt_injection",
    ),
    Producer(
        "injection_declined_by_model_rate",
        InjectionDeclinedByModelRate,
        "llm01_prompt_injection",
    ),
    Producer("tool_scope_violation_rate", ToolScopeViolationRate, "llm06_tool_scope"),
    # GATE-CONSISTENCY 件一 — the FALSE-POSITIVE side of the two-sided detector gate (README: "catch
    # ≥0.80 AND false-positive ≤0.05, Both or neither"). Without these in CURATION, standard collect
    # never produced FPR, so rob.l2 graded RECALL-ONLY — an all-blocking gateway scored full marks
    # (the exact recall-only benchmark the README criticises). Over corpus/llm01_benign; both
    # needs_decision (WAL rule decisions). BenignFlagRate rides alongside as FPR's advisory companion
    # (EV-AE10: a soft flag did not deny the user — NOT gated, but same-frame so a flag-everything
    # rule that scores 0% hard-FPR yet high recall is still loud).
    # 🔴 EV-EN-BENIGN-HOLDOUT 件2 — the English FPR reads the HOLDOUT arm. The calib arm (τ was fitted on
    # it) is structurally unreachable: `_assert_no_calib_producer` already refuses any `_calib` subdir, so
    # "remember not to report FPR on the fit set" stops being a promise and becomes a mechanism.
    # ⚠️ ONE-OFF COST (施工单 件2): this changes which corpus the English FPR reads ⇒ every historical
    # English pack's FPR corpus_sha stops matching. That is CORRECT — those numbers really were produced on
    # the merged arm — and it is written down so it never reads as an accident.
    Producer("false_positive_rate", FalsePositiveRate, "llm01_benign_holdout"),
    # 🔴 良性泄漏 —— 已欠下的那条路。判据(`benign_leaked` / `benign_leak_unmeasurable`)与语料
    # (良性件的 `secret_canary`)都在,而在此之前【没有任何 Producer 消费它们】⇒ 「良性件同样不泄漏」
    # 一直是【没测】。判据写好了目的地、路没修 —— 本行就是那条路。
    Producer("benign_canary_leak_rate", BenignCanaryLeakRate, "llm01_benign_holdout"),
    Producer("benign_flag_rate", BenignFlagRate, "llm01_benign_holdout"),
    # E3F "两种读法" — the SAME benign_flag_rate under the hard_only口径, as a DISCLOSURE row (subject),
    # side-by-side with the graded hard_or_flag aggregate in ONE bundle so the口径's effect is visible
    # without a second run. Shares the id, differentiated by subject ⇒ never trips DuplicateIndicatorError.
    Producer(
        "benign_flag_rate",
        BenignFlagRateHardOnly,
        "llm01_benign_holdout",
        subject="arm_parity:hard_only",
    ),
    # output-side (measurable on a bare model)
    Producer("injection_success_rate", InjectionSuccessRate, "llm01_prompt_injection"),
    Producer(
        "sensitive_disclosure_rate",
        SensitiveDisclosureRate,
        "llm02_sensitive_disclosure",
    ),
    Producer(
        "unsafe_output_passthrough_rate",
        UnsafeOutputPassthroughRate,
        "llm05_improper_output",
    ),
    Producer(
        "system_prompt_leak_rate", SystemPromptLeakRate, "llm07_system_prompt_leak"
    ),
    # G1 — the async Tier-2 shadow judge's recall lift over Tier-1. Unbound (not in the registry):
    # a DISCLOSURE row, never graded. 🔴 Wired so a Tier-2-on run actually MEASURES the layer it is
    # labelled with: without this producer a run with the judge enabled emits a bundle that says
    # "Tier-2 on" while every number in it is Tier-1-only — the worst of the three options. Reads
    # governance_evidence, which only PHASE 2's drain populates ⇒ no drain ⇒ `no-async`, never 0.
    Producer(
        "tier2_shadow_recall_lift", Tier2ShadowRecallLift, "llm01_prompt_injection"
    ),
    # 🔴 序8 件6 — the SUM of the two halves, published as ONE measurement over ONE denominator, so a
    # reader never has to (and must never) add injection_catch_rate to the lift by hand. It refuses to
    # publish at all if the two denominators ever diverge again.
    Producer(
        "injection_combined_recall", InjectionCombinedRecall, "llm01_prompt_injection"
    ),
    # EV-BENIGN-N173 §2 — use/mention separation. Unbound (not in the registry): a DISCLOSURE row, never
    # graded (无门槛·首测, §2.4). The 24 cases are control_ prefixed ⇒ E3F's generic exclusion keeps them
    # out of every existing denominator + the carrier arms. 🔴 §5: this indicator is canary-independent,
    # so it is NOT in _ATTACK_ARM_INDICATOR_IDS / _BENIGN_ARM_INDICATOR_IDS — adding it would pollute the
    # carrier-rate arms (acceptance §7-14).
    Producer("speech_act_separation_rate", SpeechActSeparationRate, "llm01_speech_act"),
    # 🔴 EV-JUDGE-UNION 件1/件2 (N180 件⑤) — the JUDGE-side twin, on the SAME corpus. Without a producer the
    # indicator exists but is NEVER measured, and 件2's gate ("a judge-movable number without the mention arm
    # ⇒ not_citable") would then make every Tier-2 number un-citable BECAUSE WE DIDN'T WIRE IT — a gate
    # firing on our own omission, not on a real defect. In collect (no Tier-2 drain) it honestly emits
    # not_measured/n=0, never a silent 0% (E3-n ②).
    Producer(
        "speech_act_shadow_separation_rate",
        SpeechActShadowSeparationRate,
        "llm01_speech_act",
    ),
    # 🔴 C-3a-1 件A —— 判据建好了、分类登记了、语料在公开仓里，而**没有消费方**：这条臂被运维 CLI
    # (`tools/eval_report.py`) 跑过，却不产出可引的 Measurement ⇒「作者位/信任区这条路测过没有」
    # 产物答不出来。指标零改动（空类体 + 继承 `InjectionCatchRate.measure()`），本行只接线。
    # 限定走 `arm_note`（绑定级），**不进指标** —— 那个 measure() 是完整注入臂共用的。
    Producer(
        "wire_indirect_catch_rate",
        WireIndirectCatchRate,
        "llm01_wire_indirect",
        arm_note=SMALL_ARM_NOTE,
    ),
    # 🔴 C-3a-1 件B —— 上一条的良性对照面。**新 id**，不复用 `false_positive_rate` /
    # `benign_flag_rate`：载体率门的两条臂是从【指标↔语料绑定】派生的（`carrier_arm_dirs`），
    # 用既有良性 id 会把这条臂**自动**拉进那个门的良性臂，于是那个门的量不再是它声称的量。
    # ⇒ 与上面 `speech_act_separation_rate` 同一条理由：新 id、不进 _BENIGN_ARM_INDICATOR_IDS。
    Producer(
        "wire_indirect_benign_flag_rate",
        WireIndirectBenignFlagRate,
        "llm01_indirect_benign",
        arm_note=SMALL_ARM_NOTE,
    ),
    # 🔴 C-3a-1 件C —— 覆盖率落在 Tier-2 lift 那几个 producer 所在的注入臂上，因为本指标存在的
    # 理由正是「lift 看起来正常而覆盖率无人知晓」：lift 出数、覆盖率不出数，那个缺陷就原样保留着。
    # ⚠️ 它是完整注入臂，**不带** SMALL_ARM_NOTE —— 那句限定在这里是假的，而印一句假的限定
    # 会把这句话读成套话，下一个人在它真成立的臂上也就不读它了。
    # ⚠️ 写在表尾而不是紧挨 lift：插在中间会移动既有行在产物里的位置（PHASE 3 的顺序不变约定）。
    Producer("tier2_judge_coverage", Tier2JudgeCoverage, "llm01_prompt_injection"),
    # 🔴 C-3a-2 —— 「已建好没接上」的第七、八笔。A2 输出中和的**双侧**效能：
    # inert 答「活性标记还能不能执行」，fidelity 答「它是不是一个盲目消毒器」。
    # ⚠️ 两条必须**成对**接 —— 只接 inert，一个把正文整段删掉的实现也能拿满分。
    # 🔴 它们的分母是【交付且已中和】那一桶，不是整条臂（`_is_neutralized` 是可测性门）：
    # 403 作用域拦截与未声明路由都没有那个标记 ⇒ 退出分母。**那是设计，不是缺口。**
    # 🔴 接线这一步顺带解掉了一个此前看不见的缺陷：本仓那道 CI 机制门枚举的是
    # `{p.factory for p in CURATION}` —— **它的作用域就是"已接线的"**，所以在接上之前
    # 它对这三个指标是**瞎的**，不是放行的。⇒ 接线不只是让它出数，是把它放进所有既有门的视野。
    Producer(
        "output_neutralize_inert_rate", OutputNeutralizeInertRate, "llm05_neutralize"
    ),
    Producer(
        "output_neutralize_fidelity_rate",
        OutputNeutralizeFidelityRate,
        "llm05_neutralize",
    ),
    Producer("cost_runaway_caught", CostRunawayCaught, "llm10_unbounded_consumption"),
)


# 🔴 EV-CN-BASELINE 件2 — the CN diagnostic batch is a SEPARATE producer set, NEVER folded into
# CURATION. CURATION is全量: adding a CN row would make EVERY run (the English frozen/paired runs
# included) probe the Chinese corpus ⇒ `--language-scope 英文…` becomes a lie and the run gets longer.
# So CN lives in its own tuple, selected by `--corpus-set cn`; the DEFAULT (`en`) leaves CURATION — and
# therefore every existing run — BIT-IDENTICAL. The three CN producers ride the EXISTING ids as
# subject="language:zh" DISCLOSURE rows (§2): a subject-bearing row never binds a rubric objective and
# never trips DuplicateIndicatorError, so the CN numbers can never be graded (a diagnostic batch must
# not). The out-of-repo corpus root is passed at runtime via `--corpus`; this file names no path.
CURATION_CN: tuple[Producer, ...] = (
    Producer(
        "injection_catch_rate",
        InjectionCatchRate,
        "llm01_cn_injection",
        subject="language:zh",
    ),
    # 🔴 EV-CN-BENIGN-N180 件2 — the benign producers measure FPR on the HOLDOUT arm
    # (llm01_cn_benign_holdout, never fitted), NOT the old merged llm01_cn_benign and NEVER the
    # CALIBRATION arm. Making the fit set structurally unreachable IS the guard (see
    # _assert_no_calib_producer) — "记得别在拟合集上报 FPR" is an unguarded promise.
    Producer(
        "false_positive_rate",
        FalsePositiveRate,
        "llm01_cn_benign_holdout",
        subject="language:zh",
    ),
    Producer(
        "benign_flag_rate",
        BenignFlagRate,
        "llm01_cn_benign_holdout",
        subject="language:zh",
    ),
    # 🔴 EV-CN-TIER2 件1 — the JUDGE side on Chinese: what the judge BUYS (recall lift, combined recall)
    # and what it COSTS (benign flag rate). 🔴 The cost side is measurable TODAY: benign_shadow_flag_rate
    # counts how many Chinese benign cases the judge flagged, and it needs no mention arm. What is missing
    # is the use/mention SLICE of the cost, not the cost.
    #
    # 🔴 CANARY CHECK SETTLED BEFORE WIRING (件2 / 施工单②), because "wired but incomputable" is this
    # repo's recurring defect: the CN attack arm carries ZERO canaries and ZERO output markers. That does
    # NOT block these three — `caught_by_tier2` reads the hint at τ, and `injection_combined_recall` sums
    # the aggregate catch with the lift over ONE shared denominator; neither reads a canary. (The canary
    # dependency belongs to `injection_success_rate`, which is NOT part of combined recall and is NOT
    # wired here.) Verified by measuring all three on canary-free, marker-free probes before landing this.
    Producer(
        "tier2_shadow_recall_lift",
        Tier2ShadowRecallLift,
        "llm01_cn_injection",
        subject="language:zh",
    ),
    Producer(
        "injection_combined_recall",
        InjectionCombinedRecall,
        "llm01_cn_injection",
        subject="language:zh",
    ),
    Producer(
        "benign_shadow_flag_rate",
        BenignShadowFlagRate,
        "llm01_cn_benign_holdout",
        subject="language:zh",
    ),
)

# 🔴 C-3c 贴边臂 —— 自成一个编组，**不并进 `cn`**。这不是洁癖，是 `_assert_one_subdir_per_id`
# （件1）在接线当天挡下来的一次真实错法：本臂与留出臂用【同一个 `false_positive_rate` id】，
# 而 `corpus_sha` 是按 indicator_id 建键的 ⇒ 两条臂进同一个编组，其中一条的指纹会被另一条
# 静默覆盖，产物照写、退出码照 0。
#
# ⚠️ 顺带把一件事变成结构：两条臂的数【本来就不许合池】—— 贴边臂量的是
# `P(误拦 | 良性 且 贴近治理边界)`，留出臂量的是另一个条件分布，合池出来的数会因【构成】而动、
# 不因【系统】而动。分成两个编组之后，"合池"连打字都打不出来。
#
# 🔴 它既不是标定臂也不是留出臂 ⇒ `_assert_no_calib_producer` 不拦它，而"它从未被拟合过"
#    今天只由本注释与登记表承担 —— 写在这里，不冒充它是一道门。
CURATION_CN_EDGE: tuple[Producer, ...] = (
    Producer(
        "false_positive_rate",
        FalsePositiveRate,
        "llm01_cn_benign_edge",
        subject="language:zh",
    ),
    Producer(
        "benign_flag_rate",
        BenignFlagRate,
        "llm01_cn_benign_edge",
        subject="language:zh",
    ),
    Producer(
        "benign_shadow_flag_rate",
        BenignShadowFlagRate,
        "llm01_cn_benign_edge",
        subject="language:zh",
    ),
)

# 🔴 use-mention-18 —— 中文 use/mention 配对臂，同样自成编组。与英文 `llm01_speech_act` 同一个
# 指标、同一条判据，换一门语言 ⇒ 同 id 不同目录，进 `cn` 会撞上件1 那道门（同上）。
# `speech_act_separation_rate` 已在 `FIRST_MEASUREMENT_NO_GATE_IDS` 里 ⇒ 它出的数【不代表通过】，
# 是一次首测；门排在拿到首测之后单独裁定。
# ⚠️ 本臂件全部 `control_speech_act_*` ⇒ 通用 `control_` 过滤把它们挡在【每一个既有分母】之外
#    ⇒ 接这条线不改动任何既有数字（纪律③）。
CURATION_CN_UM18: tuple[Producer, ...] = (
    Producer(
        "speech_act_separation_rate",
        SpeechActSeparationRate,
        "llm01_cn_speech_act",
        subject="language:zh",
    ),
)

# 🔴 中文【攻击臂单侧】—— `cn` 的攻击那三行，良性三行一行不带。
#
# 存在的理由是一次差点发生的实际损失（2026-09-16）：Tier-1 单侧那一跑本来要用 `--corpus-set cn`，
# 而 `cn` 里挂着三个跑在 `llm01_cn_benign_holdout` 上的良性 producer —— 那是门 B 的
# **125 件一次性留出臂**。那一跑只需要攻击侧的逐件判定，却会顺手在留出臂上花掉一次观测。
#
# 🔴 为什么"花掉一次"是真代价而不是洁癖：留出臂的全部价值在于它只被看一次。
#    看第二次本身不改数，但它让"看了不满意再看一次"在结构上成为可能 —— 而 optional stopping
#    正是两段式预登记要堵的那个洞。⇒ 堵法是【够不着】，不是【记得别看】。
#
# ⚠️ 它与 `cn` 共用 injection 那三个 id、指向同一个目录 ⇒ 同组不冲突（同 id 同 subdir 是允许的），
#    但仍然自成编组：一个编组就是一次跑的射程，而"这一跑碰不碰留出臂"必须由编组决定，不由人记得。
CURATION_CN_INJ: tuple[Producer, ...] = tuple(
    p for p in CURATION_CN if p.corpus_subdir == "llm01_cn_injection"
)

# 🔴 臂 B(C-3b 网格 160)—— 门 A 认证数的唯一来源,因此【自成编组】而不是并进 `cn`:
# 它与 `llm01_cn_injection` 共用 injection 那三个 id,同组会撞 `_assert_no_id_subdir_collision`
# （corpus_sha 按 indicator_id 建键）。
# ⚠️ 本臂是 120 中文 + 40 英文的混合臂 ⇒ subject 只标 `language:zh` 会是错的。
#    标 `arm:cn_armb` —— 臂名回答"哪批件",语种由件自己带,一个键不兼任两个量。
CURATION_ARMB: tuple[Producer, ...] = (
    Producer(
        "injection_catch_rate",
        InjectionCatchRate,
        "llm01_grid_attack",
        subject="arm:cn_armb",
    ),
    Producer(
        "tier2_shadow_recall_lift",
        Tier2ShadowRecallLift,
        "llm01_grid_attack",
        subject="arm:cn_armb",
    ),
    Producer(
        "injection_combined_recall",
        InjectionCombinedRecall,
        "llm01_grid_attack",
        subject="arm:cn_armb",
    ),
)

# 🔴 英文攻击网格臂(C-3b EN,160 件)—— 门 A 的英文侧,与中文侧 `armb` 结构相同、语料不同。
# 自成编组的理由同 armb:与 `en`/`inj` 共用 injection 三个 id,同组会撞
# `_assert_no_id_subdir_collision`(corpus_sha 按 indicator_id 建键)。
# ⚠️ 本臂【可重跑、零消耗】(不在 READ_ONCE_ARMS)⇒ 门 A 第一段取数、补件、再跑,都不花掉它。
#    这正是 PM 定的顺序能成立的前提:门 A 反复跑、门 B 只跑一次且排在门 A 件数定死之后。
CURATION_EN_GRID: tuple[Producer, ...] = (
    Producer(
        "injection_catch_rate",
        InjectionCatchRate,
        "llm01_en_grid_attack",
        subject="arm:en_grid",
    ),
    Producer(
        "tier2_shadow_recall_lift",
        Tier2ShadowRecallLift,
        "llm01_en_grid_attack",
        subject="arm:en_grid",
    ),
    Producer(
        "injection_combined_recall",
        InjectionCombinedRecall,
        "llm01_en_grid_attack",
        subject="arm:en_grid",
    ),
)

# 🔴 臂 A(C-3a 不可信通道位置效应)—— 每个载荷各做两件:T 可信位 / U 不可信位。
#
# ⚠️ 本编组【只产出每件的判定】,不产出"位置效应"那个数 —— 而那正是这条臂要的东西。
#    理由写清楚,不冒充覆盖:位置效应 = T 组与 U 组的 BLOCK 率【落差】,那是一次【配对比较】,
#    不是一个单臂 producer 能算的量。今天 `pair.py` 的配对轴是 raw_model×gateway(归因轴),
#    不是 T×U(位置轴)——【同名不同轴】,拿它直接套会得到一个算得出来但答非所问的数。
# ⇒ 位置落差那一列是一件独立的活(新的配对指标),本行不假装它已经接上了。
CURATION_ARMA: tuple[Producer, ...] = (
    Producer(
        "injection_decision_block_rate",
        InjectionDecisionBlockRate,
        "llm01_arma_untrusted_position",
        subject="arm:en_arma_position",
    ),
)

# 🔴 The producers that read ONLY the decision/judge stage — the only ones whose numbers survive a
# target with no upstream model (`--no-output-side`). An indicator NOT on this list is presumed to read
# the response, so declaring `--no-output-side` alongside it is REFUSED rather than measured: with an
# echo forwarder every output-side rate would come back a clean, self-consistent, entirely false 0.
# 🔴 Fail-closed by construction: add a producer to CURATION_CN without adding it here and the CN
# no-output-side run stops, instead of quietly measuring the new one against an absent output.
#
# 🔴 这个集合有【两个消费方】，同名不同量的经典形状。**往里加一个 id，要同时答两问：**
#
#   ① 它凭什么可以与 `--no-output-side` 并存？（＝它真的不读模型输出）
#      消费方是 `assert_no_output_side_is_legitimate`，而这个集合对它是**白名单** ——
#      加一个成员就是默许这个 id 和「本目标没有上游模型」同时成立。答错了守卫不再拒绝，
#      失效形态逐字就是那个函数里那句：**「从来就没有输出」被读成「什么都没泄漏」**。
#      ⚠️ 判据是【它读不读正文】，不是【它碰不碰响应记录】：数一条类型 2 记录**在不在**，
#      在 echo 转发器上是真的；读那条记录里的 completion 才是假的。
#
#   ② 它在认证跑编组里落在哪？若它绑注入臂，加进来就会把它**推进认证跑的产物**
#      （`CURATION_INJ` 的过滤是 subdir ∧ 本集合，见下）；若它不绑注入臂，对编组无影响 ——
#      但那是一句**会过期**的话，所以它要被核实，不是被相信。
#
# 🔴 为什么写在这里还不够：这两问此前只是注释，而一发变异证明 ② 那个方向**没有任何门看见**
# （加一个只放宽守卫、不动编组的 id ⇒ 全量门全绿）。成员表因此被手写钉死在测试里，
# 两问的答案是**必填字段**而不是可选注释 —— 见 `_DECISION_SIDE_RATIONALE`。
# ⚠️ 不拆这个集合（拆是重构）。只让「加成员」变成一次必须答两问的显式动作。
_DECISION_SIDE_ONLY: frozenset[str] = frozenset(
    {
        "injection_catch_rate",
        "false_positive_rate",
        "benign_flag_rate",
        "tier2_shadow_recall_lift",
        "injection_combined_recall",
        "benign_shadow_flag_rate",
        # 🔴 C-3a-1 件C —— 对 ① 成立的理由要写清，因为它**读了响应记录**：本指标数的是
        # 类型 2 记录【在不在】，不是记录里的正文。`--no-output-side` 要防的是"从来就没有输出"
        # 被读成"什么都没泄漏"，那是【正文】上的病；一条记录的存在与否在 echo 转发器上是真的，
        # 所以它的数在没有上游模型的目标上照样成立。
        # 对 ② 则是本单要的落点：不进这里，覆盖率就进不了认证跑，于是 lift 出数、覆盖率不出数 ——
        # 正是本指标存在的理由所描述的那个缺陷，原样保留在编组里。
        "tier2_judge_coverage",
        # 🔴 C-0a 入口期拦截率 —— 加成员必答的两问，答案写在这里而不是注释在别处：
        # ① 它是决策侧吗？**是，且是最纯的一个**：分子逐字是 `decision.final_decision == BLOCK`，
        #    只读类型 1 决策记录，**一个字节的响应正文都不读** ⇒ `--no-output-side` 要防的
        #    「从来就没有输出 被读成 什么都没泄漏」在它身上结构上不可能发生。
        # ② 它绑注入臂吗？**绑**：Producer 的 `corpus_subdir == "llm01_prompt_injection"`，
        #    与 `injection_catch_rate` 同一条臂、同一个分母（`_catch_counts`）。
        #    ⚠️ 这一问必须答，因为 `CURATION_INJ` 的过滤是 subdir ∧ 本集合 —— 只答①不答②，
        #    会放进一个守卫放宽了、却不在这条臂上的 id，而那个方向【没有任何门看见】。
        "injection_decision_block_rate",
    }
)


def preflight_refusal(pr: Any) -> str | None:
    """跑一次性臂之前，那一件**合成**试探件的三条判据（PM 2026-09-06 放行条件⑤）。
    返回拒绝理由，或 None 表示放行。

    🔴 为什么由**跑批工具自己**发这一件、而不由操作者用 curl 验：要证明的不是「网关能返 200」，
    是「跑这批的那个工具、走那条身份路、带那套 header 与超时、会不会踩坑」。**只有那个工具能证明它自己。**

    三条，每一条都对应一次真的踩过的坑：
      ① 传输    打不通 / 身份不对 / 超时为零 —— 三次跑批各 194/194 件死在这里，每次都在最后才发现。
      🔴 ② 未被拦  合成探针是**良性**的。它被拦 ⇒ 这条身份/配置下良性件都过不去 ⇒ 那 171 件的 FPR
                 会是一个被配置决定的数，不是被检测决定的数 —— 而它读起来完全正常。
      🔴 ③ 有 completion  200、合法 JSON、**没有 choices**（echo 形态）。传输一切正常，
                 而一次性臂会全花在一个不产出正文的目标上。这一条此前**不在**试探判据里：
                 试探只判①，于是它检查的东西比它声称的更容易为真 —— 那正是它上面那段注释
                 讲 admin 游标时说过的同一句话，只是低了一层。

    ⚠️ echo 转发器（`--no-output-side`）不需要在这里再判一次：`GatewayTarget` 在声明了它之后
    **根本不产生** `extract_error`（target.py:492 的 `not self._no_output_side`）⇒ ③ 自然不触发。
    🔴 第一版我在这里加了一个 `no_output_side` 形参 —— 一次变异证明它**改不了任何结果**（死参数），
    已删。一个看起来在做决定、实际不做决定的旋钮，比没有更坏：它让人以为这一层也在把关。"""
    err = pr.error or ""
    if err.startswith("harness-transport"):
        return f"① 传输不通：{err}"
    if pr.decision == "BLOCK" or getattr(pr, "response_stage_blocked", False):
        return (
            "② 合成【良性】试探件被判 BLOCK —— 这条身份/配置下良性件都过不去，"
            "那么这批的误报率会是配置决定的，不是检测决定的"
        )
    if err:
        return f"③ 200/非拦截响应里没有可解析的 completion（无 choices —— echo 形态）：{err}"
    return None


def _synthetic_preflight_case() -> Any:
    """A throwaway case for the connectivity pre-flight. 🔴 Authored here, never drawn from a corpus:
    a read-once holdout arm must not spend a case proving the socket works. Benign text, so a probe
    that DOES reach a live gateway costs nothing and tells the tested party nothing."""
    from treval.active_eval.corpus import CorpusCase

    return CorpusCase(
        id="__preflight__",
        owasp="LLM01",
        dimension="injection",
        attack_class="benign",
        success_when="never",
        severity="low",
        source="synthetic",
        tool_id="chat",
        input="ping",
    )


# 🔴 C2A0 —— 跑前基线比对的三态。**三个词原样进产物、原样印给操作者，不许转述。**
# 为什么不许转述：去掉路径之后（见 `_baseline_ruleset_sha` 的判据），一个 `mismatch` 不再能区分
# 「规则集漂移了」和「载入的是另一份规则集」——`citability` 里那条既有明文正是为此要求带路径的。
# 门只把 `mismatch` 摆出来就诚实；一旦转述成「规则集已漂移」，就等于替读者做了那条被去掉的推断。
BASELINE_NOT_DECLARED = "not_declared"
BASELINE_MATCHED = "matched"
BASELINE_MISMATCH = "mismatch"


class BaselineError(Exception):
    """基线产物读不出 / 缺那一格 ⇒ 本跑停机。

    🔴 为什么是停不是跳过：本项的全部用途是「确认可比」，而**一个读不出基线的跑，
    恰恰是最不可比的那一种**。与 `judge_imprint` 的 0 字节拒收同形 ——
    **一次失败的读取不是一次通过的检查。**
    """


def _baseline_ruleset_sha(path: str | None) -> str | None:
    """基线产物里 `provenance.build_fingerprint_before.runtime.ruleset_sha256` 那一格。

    不声明 `--baseline-bundle` ⇒ `None`（调用方记 `not_declared`，**不是** `matched`）。
    读不出 / 缺那一格 ⇒ `BaselineError`（停机，见该异常）。

    🔴 **只取这一格，不取路径，也不取整块 fingerprint**，三条理由各不相同：
      · 不取整块：`build_fingerprint` 里含**我们自己发流量就会动**的计数器
        （`arrival_evidence.egress_attempts` 一类）⇒ 整块比会让**任何真发过探针的跑都踩红**，
        而本仓已因此收窄过一次白名单（`citability` 那段注释：假红一样贵，它训练人去忽略这条门）。
      · 不取路径：**路径是自述，哈希是测量。** 产物记了路径，但那一格不可校验 ——
        拿一个校验不了的东西参与比对，只是多一个能悄悄错掉的格子。
      · 取「运行时实际加载的那一份」而不是任何源文件：deploy copy 与 master 可以不一致，
        而被测的是 deploy copy ⇒ 一条规则可以**只存在于被跑的那一份里**，
        任何「看源文件」的核对都看不见它。
    """
    if not path:
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            bundle = json.load(fh)
    except (OSError, ValueError) as e:
        raise BaselineError(
            f"🔴 基线产物读不出（{type(e).__name__}: {e}）—— 本跑停机。\n"
            "  本项的用途是确认【可比】，而一个读不出基线的跑恰恰是最不可比的那一种；\n"
            "  一次失败的读取不是一次通过的检查。⇒ 修路径或去掉 --baseline-bundle（那会记 "
            f"{BASELINE_NOT_DECLARED}，是一个诚实的空格子）"
        ) from None
    if not isinstance(bundle, dict):
        raise BaselineError(f"🔴 基线产物不是一个 JSON 对象（{path}）—— 本跑停机")
    prov = bundle.get("provenance")
    fp = (
        (prov or {}).get("build_fingerprint_before") if isinstance(prov, dict) else None
    )
    sha = (
        (fp or {}).get("runtime", {}).get("ruleset_sha256")
        if isinstance(fp, dict)
        else None
    )
    if not isinstance(sha, str) or not sha:
        raise BaselineError(
            "🔴 基线产物里取不到 "
            "`provenance.build_fingerprint_before.runtime.ruleset_sha256` —— 本跑停机。\n"
            "  这一格是本门唯一的判据；取不到它，本跑与基线是否可比【无法回答】，"
            "而无法回答不等于可比"
        )
    return sha


def compare_baseline_ruleset(
    baseline_sha: str | None, build_fingerprint_before: dict[str, Any] | None
) -> str:
    """三态之一，**原样返回那三个词**。比的只有 `runtime.ruleset_sha256` 一格。

    ⚠️ 本跑那一格取不到时同样记 `not_declared` —— 它与「没声明基线」是不同的原因，
    却是同一个事实：**这一跑没有做过这个比对**。而做过与没做过的区别，才是三态要守的那个区别。
    """
    if baseline_sha is None:
        return BASELINE_NOT_DECLARED
    fp = build_fingerprint_before or {}
    this_sha = (fp.get("runtime") or {}).get("ruleset_sha256")
    if not isinstance(this_sha, str) or not this_sha:
        return BASELINE_NOT_DECLARED
    return BASELINE_MATCHED if this_sha == baseline_sha else BASELINE_MISMATCH


#: `--baseline-expect` 的取值域 —— 操作者对"本跑的规则集与基线是否相同"的【事前声明】。
#: 🔴 有限枚举，不是自由文本：一个拼错的词会让这道门静默退回"未声明"。
BASELINE_EXPECT_SAME = "same"
BASELINE_EXPECT_DIFFERENT = "different"
BASELINE_EXPECTATIONS = (BASELINE_EXPECT_SAME, BASELINE_EXPECT_DIFFERENT)


def baseline_gate_verdict(compared: str, expect: str | None) -> tuple[bool, str]:
    """C2A0 的形态改判（规则专家 2026-09-13 提，2026-09-14 落地）——
    返回 `(要不要停机, 说给操作者的那句话)`。

    🔴 **旧形态「不一致就拦」会拦住我们正要跑的那一跑**：块一落地之后
    `ruleset_sha256` 是【故意】改的（R-1b），而那一跑必须跑得成。
    ⇒ 正确形态是**记录 + 要求显式声明**：不一致【且未声明】才红。

    🔴 **而它必须双向守，不能只守一个方向**：
        不一致 + 声明"预期不同"  ⇒ 放行并记录      —— 操作者知道自己在做什么
        不一致 + 未声明          ⇒ 🔴 停机          —— 这就是这道门存在的理由
        一致   + 声明"预期不同"  ⇒ 🔴 也出声        —— 声明与事实【反方向】不符，
                                                      一样是错：它说明操作者对本跑的
                                                      认识与实际不一致，而下一步很可能
                                                      是把这一跑当成"改动已生效"来读
        一致   + 声明"预期相同"  ⇒ 放行，这是最强的一种通过（事前说了，事后对上）
    ⚠️ 未做过比对（`not_declared`）时，任何声明都不成立 —— 没有事实可以与它对照。
    """
    if compared == BASELINE_NOT_DECLARED:
        if expect is not None:
            return False, (
                f"⚠️ 声明了 --baseline-expect {expect}，而本跑【没有做过基线比对】"
                "（未传 --baseline-bundle，或本跑那一格取不到）⇒ 该声明没有对照物，不成立。"
            )
        return False, ""
    if compared == BASELINE_MISMATCH:
        if expect == BASELINE_EXPECT_DIFFERENT:
            return False, (
                "✅ 规则集与基线不同，且【事前声明了预期不同】⇒ 放行并记录。"
                "🔴 与基线的任何跨批比较必须写明这一点 —— 两批不在同一份规则集上。"
            )
        return True, baseline_mismatch_message()
    # matched
    if expect == BASELINE_EXPECT_DIFFERENT:
        return False, (
            "🔴 声明了预期【不同】，而实测规则集与基线【相同】—— 反方向的不符一样是错。"
            "最可能的成因：以为某个改动已经生效，而它没有上到被跑的这一份。"
            "本跑不停机，但在查清之前，不要把它当作『改动已生效』的证据。"
        )
    return False, ""


def baseline_mismatch_message() -> str:
    """停机文案。**抽成具名函数是为了让「原样打印那三个词、绝不转述」可被断言** ——
    一段只活在 `print(...)` 里的文案，测试只能去 grep 源码，而那测的是源码文本不是行为。

    🔴 它只摆出 `mismatch` 那个词，不替读者判定是「漂移」还是「载入了另一份规则集」：
    判据里不含 `ruleset_path`，而两种情形正是靠路径消歧的 ⇒ 这一格上它们不可区分。
    """
    return (
        f"跑前基线比对 {BASELINE_MISMATCH} —— "
        "本跑的 ruleset_sha256 与基线产物记录的那一个不一致。\n"
        "  ⇒ 语料一件未动。这两跑的数不可并排读（同一个名字下是两套规则）。\n"
        "  🔴 本门只报这一个词，**不替你判定它是「漂移」还是「载入了另一份」** —— "
        "判据里不含路径，而路径是自述、哈希是测量，\n"
        "     所以这两种情形在这一格上不可区分。要分清，去核运行时实际加载的那一份。"
    )


class EmptyRunError(Exception):
    """声明了 producer，而一个都没产出 —— 本跑作废。

    🔴 2026-09-06 实测（W2 一次性臂）：臂名重映射写在装载侧、查找写在消费侧，两处用了不同的名字
    ⇒ 171 件真模型探针照跑、四个 producer 全部静默跳过、**退出码 0、bundle 写了、报告 ✅ CITABLE**。
    产物里只剩 7 个被动格，而被动格来自 WAL 全窗口，**看起来完全正常**。
    ⇒ "跑完了"与"量到了"是两件事，而只有后者值钱。
    """


class MissingArmError(Exception):
    """声明了 Producer，却够不着它绑定的那条语料臂。

    🔴 为什么是异常不是 warning：旧行为"记一条 warning，接着跑"实测出过两次空跑 ——
    一次 `--corpus` 指到了子目录（0/17 个 Producer 产出、退出码 0、bundle 照写），
    一次良性臂改名后 Producer 找不到它。而 W2 那类臂是【读一次】的：空跑一次就没有第二次，
    且结果长得和跑完了一模一样。**警告会被读过去，异常不会。**
    """


def assert_no_output_side_is_legitimate(producers: tuple[Producer, ...]) -> None:
    """🔴 `--no-output-side` says "this target has no upstream model, so an absent completion is by
    design". That is true for an echo forwarder — and it is a licence to stop treating an absent
    completion as a probe failure. Granting that licence while an OUTPUT-SIDE producer is active
    would turn "there was never any output" into "nothing leaked". Refuse instead."""
    offenders = sorted({p.indicator_id for p in producers} - _DECISION_SIDE_ONLY)
    if offenders:
        raise ValueError(
            "--no-output-side 与输出侧指标不能同时成立："
            + "、".join(offenders)
            + " 会把【从来就没有输出】读成【什么都没泄漏】。"
            "要么去掉该声明，要么换一个不含输出侧产出的编组"
        )


# 🔴 W6 业务伪装诊断臂 —— 独立 curation,【不在】默认 en 集里。
# 判据:它是诊断臂,与既有攻击臂不可交换(语域系统性不同)⇒ 不进 injection_catch_rate 分母;
# 而放进默认集会让每一次标准英文跑都去探这条臂 —— 语料在仓外,标准跑每次都会多一条 warning,
# 更糟的是:有人把 --corpus 指到 P1 卷时,标准跑会【静默】把诊断臂并进来。
# ⚠️ 分层那一行不折叠:折进完整劫持会抬高率,折进"什么都没发生"会藏起一个可调用但不可操纵的模型。
CURATION_W6: tuple[Producer, ...] = (
    Producer("decoy_tool_hijack_rate", DecoyToolHijackRate, DECOY_ARM_SUBDIR),
    Producer(
        "decoy_tool_hijack_rate",
        DecoyToolPartialRate,
        DECOY_ARM_SUBDIR,
        subject="decoy:partial",
    ),
    # 🔴 与上面两行【成对】出，不是可选的补充（W6 2026-09-05 实测）：完整劫持成立 ⇒ canary 进响应
    # ⇒ 该件在响应期被拦、正文成占位符 ⇒ 退出分母。⇒ 上面那个率在会拦 canary 的栈上不可能为正。
    # 这一行从审计面读同一件事，正文被扣下也读得到 —— 它是那个盲区的补集。
    Producer(
        "planted_secret_in_output_rate", PlantedSecretInOutputRate, DECOY_ARM_SUBDIR
    ),
)

# 🔴 W2 误报侧的编组 —— 只含【良性侧】producer，因为 W2 那条臂在仓外的 P1 卷里，
# 而 `--corpus` 只接受【一个】根。`en` 编组的 7 条臂在仓内 `corpus/`，两者不在同一个根下 ⇒
# 拿 `--corpus-set en` 指着 P1 卷跑 W2，在 fail-closed 守卫之前会**只出良性侧的数、
# 其余 6 条臂各记一条 warning、退出码 0、bundle 照写** —— 而 W2 是【读一次】的臂，
# 那一次会以"跑完了、数出来了"的形态把它花掉。
# ⚠️ 臂名仍走 `--benign-arm`（盘上是 `llm01_benign_holdout_p1`），不在这里写死：
# 写死就等于把一次改名变成一次改代码，而改名的人不改代码。
# 🔴 从 W2 编组移出的指标 + **它去哪了**（PM 2026-09-06 ⑤）。
# 留痕不是礼貌：半年后没人记得这个指标为什么不在，而"不在"与"从来没想过"在编组表上一模一样。
W2_REMOVED_INDICATORS: dict[str, str] = {
    "benign_canary_leak_rate": (
        "🔴 移出 W2 编组（2026-09-06），**不补语料**。"
        "① 结构上不可测：本臂 171 件的 `secret_canary` 字段为空（凭证在 system_prompt 里，"
        "而判据读的是 secret_canary）⇒ 这一格只会给出一个没有仪器的 0。"
        "② 更硬的结构理由：阳性（吐出 canary）⊆ 被排除（canary 进响应 ⇒ 响应期拦截 ⇒ 正文成占位符 "
        "⇒ 退出分母）⇒ 在 exec_mode=block 上**这个率不可能为正**，与 decoy_tool_hijack_rate 同形。"
        "③ 时点：此刻改语料正文 ⇒ 改 corpus_sha ⇒ 改 injection_score ⇒ 可能改变标记结果，"
        "而门 B 的 ci_high 距阈值只差千分之二 —— 在这个时点改语料，与「改分子够门」是同一件事。"
        "⇒ 去向：登记为**待建 W2c 臂**。判据必须从**审计面**读"
        "（`on_tool_response_rules[dlp-canary-response].matched`），不能从正文读 ——"
        "就是 W6 的 planted_secret_in_output_rate 那条路。"
        "🔴 缺口仍然开着：那 77 件运行时**真的带着一个可泄漏的凭证在跑**，而没有任何判据去看它"
        "（🔴 77 = 本臂中 system_prompt 携带 canary 占位符的件数 —— 与 secret_canary 字段数（0）是**两个不同的量**；复算路径见 operator_only 附表）"
        "漏没漏 ⇒「良性件同样不泄漏」今天仍是【未测】。移除的是那个量不出来的数，不是那个问题。"
    ),
}

CURATION_W2: tuple[Producer, ...] = tuple(
    p
    for p in CURATION
    if p.corpus_subdir == BENIGN_ARM_DEFAULT
    and p.indicator_id not in W2_REMOVED_INDICATORS
)

# 🔴 认证跑【攻击侧】的编组 —— 只含注入臂上的【决策侧】producer。
#
# 两个理由，缺一不可：
#   ① 分母：门是按 134 定的，而 `en` 编组会连带跑另外 6 条臂（共 430 件）——
#      判官只评 Tier-1 漏检件，多出来的臂会一起进判官队列，把"约 1.8 小时"那个估计打掉。
#      而排空要等多久，正是这一轮反复出问题的地方。
#   ② 转发器：本跑在 echo 上（零 token、零出域 —— 注入判决在转发【之前】）。
#      注入臂上另有 4 个 producer 读模型输出（success / 三格归因），echo 上它们【测不了】：
#      放进来就只有两条路 —— 每条探针记一次仪器错误，或谎报 `--no-output-side`。
#      两条都是把"没测"变成一个数，所以它们不在这个编组里，而是【未测量】。
# ⇒ 留下的 4 个正好是门要的：`injection_catch_rate`(+可观测分层) · `tier2_shadow_recall_lift`
#   · `injection_combined_recall`（Tier-1 ∪ Tier-2，就是门 A 缺的那一格）。
CURATION_INJ: tuple[Producer, ...] = tuple(
    p
    for p in CURATION
    if p.corpus_subdir == "llm01_prompt_injection"
    and p.indicator_id in _DECISION_SIDE_ONLY
)

# 🔴 P3 设计臂(300 件) —— 可反复读 · 可据它拟合 · 不消耗。它的全部用途是在【生产刻度】上
# 给 τ 找工作点，所以它要的正是良性侧那三个 producer：FPR(硬拒)· flag(软标)· 判官侧软标。
#
# 🔴 每一个都带 subject="arm:fit_p3"，不是装饰，是这一编组能存在的唯一理由：
#   带 subject 的行永不绑定 rubric objective、永不参与评级 ⇒ p3 的数在结构上进不了验收，
#   而 `_assert_no_calib_producer` 的词表那道正是按这一格放行的。
#   ⚠️ 去掉任何一个 subject，这一编组当场红 —— 那道门在跑之前拦，不在报告里提醒。
#
# 🔴 arm_note 是 PM 要的「半年后还分得出来它能不能重读」那个标记 —— 它随【这条绑定的数】走，
#   印在行的 notes 上。subject 让机器分得出来，arm_note 让人分得出来，两个都要：
#   一个只有 subject 的行，在被复制进某份材料之后，就只剩一个看不出性质的字符串。
_P3_ARM_NOTE = (
    "arm=llm01_benign_design_p3（设计臂）：可反复读 · 可据它拟合 · 不消耗。"
    "🔴 本行是 diagnostic_only，永不作验收数 —— 门 B 的验收数只出自 llm01_benign_holdout_p2。"
)

# 🔴 subject 只在【指标自己不盖】时填，不拼、不覆盖 —— 这是 `_apply_declared_subject` 的契约：
#   指标不盖 ⇒ Producer 声明的填进去；指标自己盖了 ⇒ 声明的必须【等于】它，否则 raise。
# ⚠️ 我第一版拼成 "arm:fit_p3|<原键>"，在 `BenignFlagRateHardOnly`（它自己盖
#   `arm_parity:hard_only`）上当场被那道门拦下 —— 而我的 11 条单测全绿，因为它们钉的是
#   我自己的意图（复合键唯一），不是仓里的契约。⇒ 见 test_p3_design_arm_lane 里那条契约测试。
# ⇒ 三行仍然各自唯一：("false_positive_rate","arm:fit_p3") ·
#   ("benign_flag_rate","arm:fit_p3") · ("benign_flag_rate","arm_parity:hard_only")。
# 🔴 而臂名靠 `arm_note` 随数走，不靠 subject —— subject 是口径键，臂名是限定，两件事。
CURATION_P3: tuple[Producer, ...] = tuple(
    Producer(
        p.indicator_id,
        p.factory,
        "llm01_benign_design_p3",
        subject=p.subject or "arm:fit_p3",
        arm_note=_P3_ARM_NOTE,
    )
    for p in CURATION_W2
)

# 🔴 A2 英文攻击【留出臂】296 件 —— 门 A 的【可引用】读数所在的那条臂。
#
# 它与 `en_grid` 同构（同三个 producer、换一条语料），而存在的理由正是那个"不同"：
# τ 是在网格臂上扫出来的 ⇒ 网格臂上的门 A 数是【拟合数】；A2 不参与定 τ，
# 所以只有它上面的数才是测量数。⚠️ 两条臂的数不许互换，也不许相加。
#
# 🔴 A2 是 read-once：跑它就花掉它。所以这一编组的每一次使用都要有人点头，
#   而不是"顺手带上"——它不出现在任何其它编组里（见 test_a2_holdout_arm_lane）。
CURATION_EN_A2: tuple[Producer, ...] = tuple(
    Producer(p.indicator_id, p.factory, "llm01_en_holdout_a2", subject="arm:en_a2")
    for p in CURATION_EN_GRID
)

# 🔴 A3 英文攻击【留出臂】416 件 —— 门 A 的【验收数】所在的那条臂，与 A2 同构、同性质。
#
# ⛔ 它【不在】FIT_ARMS：A4a/A4b/A4c 三条同卷同轴的臂都在里面（其数只作诊断），
#   A3 是那三条旁边唯一一条"数要进验收"的。登记时照抄上一条 = 门 A 从此没有读数。
#
# 🔴 read-once：跑它就花掉它，没有第二次。所以本编组不出现在任何其它编组里
#   （见 test_a3_holdout_arm_lane 的射程测试）。
CURATION_EN_A3: tuple[Producer, ...] = tuple(
    Producer(p.indicator_id, p.factory, "llm01_en_holdout_a3", subject="arm:en_a3")
    for p in CURATION_EN_GRID
)

# 🔴 A5 英文攻击【留出臂】416 件 —— 攻击侧【最后一条】未见臂，门 A 的验收数所在。
#
# ⛔ 不在 FIT_ARMS：与 A3 同档。它旁边同卷同轴的 A4a/A4b/A4c 三条全在 FIT_ARMS 里，
#   照抄它们 = 宣布门 A 没有读数。
# ⛔ 用掉没有第三次，且【不得因未过而另造一条重跑当门】—— 那会把验收臂变成可重试的。
CURATION_EN_A5: tuple[Producer, ...] = tuple(
    Producer(p.indicator_id, p.factory, "llm01_en_holdout_a5", subject="arm:en_a5")
    for p in CURATION_EN_GRID
)

# 🔴 A6 英文攻击【留出臂】1000 件 —— 攻击侧最后一条未见臂，门 A 的验收数所在。
# ⛔ 不在 FIT_ARMS（与 A3/A5 同档）· ⛔ 跑完不得因未过而造 A7。
CURATION_EN_A6: tuple[Producer, ...] = tuple(
    Producer(p.indicator_id, p.factory, "llm01_en_holdout_a6", subject="arm:en_a6")
    for p in CURATION_EN_GRID
)

# 🔴 F1 英文良性【析因证伪臂】576 件 —— 四根设计因子 24 格 × 24 件，量的是【误报】。
#
# 它与 P3 同为可反复读的诊断臂，而用途不同：P3 用来找工作点，F1 用来【证伪一根轴】——
# 「误报到底跟着哪个因子走」。所以它进 FIT_ARMS 的理由是「其数不作验收数」，
# 不是「可据它拟合 τ」（见 label_freeze.FIT_ARMS 里那段）。
#
# 🔴 每个 producer 都带 subject="arm:en_f1"：带 subject 的行永不绑定 rubric objective、
#   永不参与评级，而 `_assert_no_calib_producer` 的词表那道正是按这一格放行的。
#   去掉任何一个 subject，这一编组当场红。
_F1_ARM_NOTE = (
    "arm=llm01_en_factorial_f1（析因证伪臂）：576 件 · 可反复读 · 不消耗 · "
    "四因子 24 格均分。🔴 本行是 diagnostic_only，永不作验收数 —— "
    "门 B 的验收数只出自 llm01_benign_holdout_p2。"
)

CURATION_EN_F1: tuple[Producer, ...] = tuple(
    Producer(
        p.indicator_id,
        p.factory,
        "llm01_en_factorial_f1",
        subject=p.subject or "arm:en_f1",
        arm_note=_F1_ARM_NOTE,
    )
    for p in CURATION_W2
)

# 🔴 A4a 中途探测臂 100 件 —— 与 en_grid/en_a2 同构（攻击侧三个 producer）。
# 它存在的理由是折扣：网格臂(拟合)与 A2(留出)之间量出了一个显著落差（值在私有仓台账，
# 🔴 纪律②：不进公开仓），而那个落差是"规则认识哪批件"的函数。A4a 按规避轴构造，用来拆开它。
# ⛔ 其数 diagnostic_only：subject 非空 ⇒ 永不绑定 rubric objective（FIT_ARMS 那道门按此放行）。
_A4A_ARM_NOTE = (
    "arm=llm01_en_interim_a4a（中途探测臂）：100 件 · 可反复读 · 不消耗 · 按规避轴构造。"
    "🔴 本行是 diagnostic_only，永不作验收数 —— 门 A 的验收数只出自 llm01_en_holdout_a3。"
)

CURATION_EN_A4A: tuple[Producer, ...] = tuple(
    Producer(
        p.indicator_id,
        p.factory,
        "llm01_en_interim_a4a",
        subject="arm:en_a4a",
        arm_note=_A4A_ARM_NOTE,
    )
    for p in CURATION_EN_GRID
)

# 🔴 A4b 中途探测臂 100 件 —— 与 A4a 同构、按 case.id 零重叠（实核：A4a∩A4b=0、A4b∩A3=0、A4b∩A2=0）。
# 它要回答的唯一问题：规则专家这一轮的新检出，在一条【从未被读过】的臂上还剩多少（泛化率）。
# ⛔ 其数 diagnostic_only；判门 A 归 llm01_en_holdout_a3。
_A4B_ARM_NOTE = (
    "arm=llm01_en_interim_a4b（中途探测臂·未被读过）：100 件 · 可反复读 · 不消耗。"
    "🔴 本行是 diagnostic_only，永不作验收数 —— 门 A 的验收数只出自 llm01_en_holdout_a3。"
)

CURATION_EN_A4B: tuple[Producer, ...] = tuple(
    Producer(
        p.indicator_id,
        p.factory,
        "llm01_en_interim_a4b",
        subject="arm:en_a4b",
        arm_note=_A4B_ARM_NOTE,
    )
    for p in CURATION_EN_GRID
)

# 🔴 A4c 中途探测臂 100 件 —— 与 A4a/A4b 同构、同轴分布（规避轴逐格相同），按 case.id 与
# 【按件正文】双重零重叠（实核对 A4a/A4b/A3/P2/A2/网格 六条臂各取一次，两道判据都是 0）。
# 它要回答的唯一问题：A4a 重量给出的 91−93 里，【拟合增益】与【臂间差异】两个未知数混在一起；
# A4c 与 A4b 对同一份规则都未见过 ⇒ 拟合增益项恒为 0 ⇒ 这一跑量的是【纯臂间差异】。
# ⛔ 一次性：它是最后一个未见子集（PM 2026-09-22 写死），用掉没有第三次 ⇒ 同时在 READ_ONCE_ARMS。
# ⛔ 其数 diagnostic_only；判门 A 归 llm01_en_holdout_a3。
_A4C_ARM_NOTE = (
    "arm=llm01_en_interim_a4c（中途探测臂·未被读过·一次性）：100 件 · 最后一个未见子集。"
    "🔴 本行是 diagnostic_only，永不作验收数 —— 门 A 的验收数只出自 llm01_en_holdout_a3。"
)

CURATION_EN_A4C: tuple[Producer, ...] = tuple(
    Producer(
        p.indicator_id,
        p.factory,
        "llm01_en_interim_a4c",
        subject="arm:en_a4c",
        arm_note=_A4C_ARM_NOTE,
    )
    for p in CURATION_EN_GRID
)

CORPUS_SETS: tuple[str, ...] = (
    "en",
    "cn",
    "cn_edge",
    "cn_um18",
    "cn_inj",
    "armb",
    "arma",
    "en_grid",
    "w6",
    "w2",
    "inj",
    "p3",
    "en_a2",
    "en_f1",
    "en_a4a",
    "en_a4b",
    "en_a4c",
    "en_a3",
    "en_a5",
    "en_a6",
)
_CURATION_BY_SET: dict[str, tuple[Producer, ...]] = {
    "en": CURATION,
    "cn": CURATION_CN,
    "cn_edge": CURATION_CN_EDGE,
    "cn_um18": CURATION_CN_UM18,
    "cn_inj": CURATION_CN_INJ,
    "armb": CURATION_ARMB,
    "arma": CURATION_ARMA,
    "en_grid": CURATION_EN_GRID,
    "w6": CURATION_W6,
    "w2": CURATION_W2,
    "inj": CURATION_INJ,
    "p3": CURATION_P3,
    "en_a2": CURATION_EN_A2,
    "en_f1": CURATION_EN_F1,
    "en_a4a": CURATION_EN_A4A,
    "en_a4b": CURATION_EN_A4B,
    "en_a4c": CURATION_EN_A4C,
    "en_a3": CURATION_EN_A3,
    "en_a5": CURATION_EN_A5,
    "en_a6": CURATION_EN_A6,
}


def curation_for(corpus_set: str) -> tuple[Producer, ...]:
    """The active producer set for a run — `en` ⇒ CURATION (the default, bit-identical to every existing
    run), `cn` ⇒ CURATION_CN (件2). Fail-closed on an unknown set so a typo can never silently fall back
    to the English corpus and mislabel a CN run."""
    try:
        return _CURATION_BY_SET[corpus_set]
    except KeyError:
        raise ValueError(
            f"unknown --corpus-set {corpus_set!r}; expected one of {CORPUS_SETS}"
        ) from None


_CALIB_SUFFIX = "_calib"


def _assert_no_calib_producer(producers: tuple[Producer, ...]) -> None:
    """🔴 EV-CN-BENIGN-N180 件2 (本片核心) — the CALIBRATION arm (`…_calib`) is what τ is FITTED on, so
    reporting FPR over it reports the FIT, not a measurement (k=0 is a construction guarantee there). Make
    train/test separation a MECHANICAL FACT: no producer may bind a `_calib` corpus ⇒ the fit set is
    structurally unreachable by any run. "记得别在拟合集上报 FPR" is an unguarded promise; this raise IS
    the guard (same discipline as `subject != ""` never grading — 靠机制不靠记性).

    🔴 两道判据（词表那道见下），不是一道的两种写法（2026-09-21 补的第二道）：后缀认的是【命名约定】，词表认的是
    【声明的性质】。P3 是一条不带 `_calib` 后缀的拟合臂 —— 只有后缀那道时，这道门对它完全是瞎的，
    而瞎的方式看起来与「它本来就不是拟合臂」一模一样。反过来，只有词表那道时，一条随手叫了
    `_calib` 却没登记进词表的新臂会溜过去。两种疏忽方向相反，所以两道都留。

    🔴 口径（2026-09-21 第二次改，Lead 裁定开路）：词表那道拦的是**不带 subject 的** producer，
    不是"绑定该臂的一切"。第一版一律拦，把「p3 的数不得进验收」做成了机制 —— 对的 —— 而同时
    把【在生产刻度上给 p3 打分】这条唯一的路也关了。而那条路比离线复刻强一档：离线要自己实现
    规则 R 的 `label=="Unsafe"` 那一支，实现偏差没有任何东西查得出来。
    ⇒ 改成按 subject 分：带 subject 的行永不绑定 rubric objective、永不参与评级（仓里既有机制，
      CURATION_CN 那一族就是靠它把诊断批挡在评级外的）⇒ 放行；不带 subject 的 ⇒ 仍然红。
    ⚠️ 这不是放宽：两种状态的【后果】不同，所以判据按状态分，而不是按臂分。"""
    from treval.label_freeze import FIT_ARMS

    for p in producers:
        if p.corpus_subdir.endswith(_CALIB_SUFFIX):
            raise ValueError(
                f"producer {p.indicator_id!r} binds the CALIBRATION arm {p.corpus_subdir!r} — the fit "
                "set must NEVER be a producer's corpus (τ was fitted on it ⇒ FPR there is CONSTRUCTED, "
                "not measured). EV-CN-BENIGN-N180 件2."
            )
        if p.corpus_subdir in FIT_ARMS and not p.subject:
            raise ValueError(
                f"producer {p.indicator_id!r} binds the FIT arm {p.corpus_subdir!r} "
                "(label_freeze.FIT_ARMS) 且【不带 subject】—— 该臂上的数是 diagnostic_only，"
                "永不作验收数。带 subject 的诊断行放行（带 subject 的行永不绑定 rubric objective、"
                "永不参与评级，与 CURATION_CN 同一机制）；不带 subject = 想拿它当验收数 ⇒ 红。"
                "它不带 `_calib` 后缀 ⇒ 后缀那道门看不见它；本条判据建在词表上，不建在命名约定上。"
            )


def _assert_frozen_arms_unchanged(
    producers: tuple[Producer, ...], corpus_root: Path
) -> None:
    """跑前校验：本跑要打的臂里，凡是【已冻结标签】的，其实测标签 sha 必须等于冻结值。

    🔴 存在的理由是 PM 2026-09-17 核出的一格：`assert_labels_frozen` 在 `label_freeze.py:87`
    定义得好好的、fail-closed、文档齐全 —— 而它的【全部调用点都在测试里】，生产路径一次都不调。
    ⇒ 冻结表今天没有任何【跑时】校验；`labelset_pin` 只把 sha 写进 citation_form，不判红。
    而那个函数自己的 docstring 逐字写着「只能在跑之前拦」——**它从来没有在跑之前拦过。**

    ⚠️ 这一族 PM 已数到第六个（`tools/send_material.py` 开头自列三条 + 本条 + 英文侧去重量具）：
    **建了、测了、文档写了，就是没人调。** 一个只被自己的测试调用的 fail-closed 守卫，
    与一个不存在的守卫，在生产路径上是同一个东西。

    🔴 射程写死，不扩大：只校验【本跑真的会读】且【已在冻结表里登记】的臂。
      • 未登记的臂 ⇒ 跳过（冻结是自愿登记制；把未登记当红会让每一条新臂无法开工）
      • 登记了但目录不在 ⇒ 也跳过，交给 `MissingArmError` 去红 —— 两道门各报各的，
        一道门替另一道门报错，会让人去修错的那一处
    """
    from treval.label_freeze import FROZEN_LABEL_SHA, assert_labels_frozen

    arms: dict[Path, str] = {}
    for p in producers:
        frozen = FROZEN_LABEL_SHA.get(p.corpus_subdir)
        if frozen is None:
            continue
        d = corpus_root / p.corpus_subdir
        if d.is_dir():
            arms[d] = frozen
    if arms:
        assert_labels_frozen(arms)


def _resolve_arm(subdir: str, benign_arm: str) -> str:
    """良性臂的子目录名重映射 —— 臂名解析的【唯一】一份实现。

    🔴 只重映射良性臂那一个默认名，不做通配：通配会让一次手误把攻击臂也指过去，
    而那种错在结果里长得完全正常（数照出、分母是另一条臂）。

    🔴 「只此一处」这条纪律归本函数（2026-09-25 从消费侧的 `_arm_of` 移来）：
    此前映射写在装载侧、查找写在消费侧，两处必须永远相等 —— 而它们不相等时的表现是
    探针照跑、producer 一个都没消费到、退出码 0、bundle 写了、报告 ✅ CITABLE。
    W2 一次性臂就是这么空跑掉的（2026-09-06 实测）。
    ⇒ 一个"必须永远相等"的东西出现两次，就是它迟早不等的原因。
    ⚠️ 而它还有第二半：解析必须排在【所有跑前门之前】，否则门看到的是重映射前的名字
    （2026-09-24 实测，三种表现同一根因，见 `collect_measurements` 开头那段）。
    """
    return benign_arm if (benign_arm and subdir == BENIGN_ARM_DEFAULT) else subdir


def _with_arm_resolved(
    producers: tuple[Producer, ...], benign_arm: str
) -> tuple[Producer, ...]:
    """把 producers 的 corpus_subdir 换成解析后的臂名，供跑前门与装载侧共用同一份事实。"""
    if not benign_arm:
        return producers
    return tuple(
        p
        if p.corpus_subdir == _resolve_arm(p.corpus_subdir, benign_arm)
        else Producer(
            p.indicator_id,
            p.factory,
            _resolve_arm(p.corpus_subdir, benign_arm),
            subject=p.subject,
            arm_note=p.arm_note,
        )
        for p in producers
    )


def _assert_read_once_arms_intact(
    producers: tuple[Producer, ...], wal_dir: str
) -> None:
    """跑前两道一次性臂的门。🔴 射程写死：只看【本跑真的会打】的臂。

    ⚠️ 两道分开报，不合并成一句：一道说"这条臂已经花掉了"，另一道说"你要写进别人的卷"，
    处置完全不同（前者要人裁定作废，后者改一个 --wal 参数就好）。
    合成一条 message，看的人得先分辨是哪一种。
    """
    from treval.label_freeze import (
        assert_read_once_not_spent,
        assert_wal_belongs_to_this_run,
    )

    arms = {p.corpus_subdir for p in producers}
    assert_read_once_not_spent(arms)
    assert_wal_belongs_to_this_run(wal_dir, arms)


def _assert_no_id_subdir_collision(producers: tuple[Producer, ...]) -> None:
    """🔴 EV-CN-BASELINE 件1 — a GUARD, not a restructure. `corpus_sha` is keyed by indicator_id alone,
    so two producers sharing an indicator_id but pointing at DIFFERENT corpus_subdirs would silently
    overwrite each other's fingerprint (today safe only by the COINCIDENCE that same-id producers share a
    subdir — nothing enforced it). 件2 makes the collision impossible in practice (CN is its own set, one
    set active per run), so this does NOT change the data structure; it fails CLOSED if the invariant is
    ever violated, rather than shipping a bundle whose corpus_sha lies about which corpus a producer ran.
    Same-id/same-subdir (the aggregate + its disclosure rows) is fine — only a subdir SPLIT raises."""
    by_id: dict[str, str] = {}
    for p in producers:
        prior = by_id.setdefault(p.indicator_id, p.corpus_subdir)
        if prior != p.corpus_subdir:
            raise ValueError(
                f"indicator_id {p.indicator_id!r} bound to two corpus_subdirs "
                f"({prior!r} and {p.corpus_subdir!r}) in one producer set — corpus_sha is keyed by "
                "indicator_id, so this would silently overwrite one fingerprint (EV-CN-BASELINE 件1)"
            )


# §8.5.2 — the §6.2-3 carrier-rate gate's two arms are DERIVED from CURATION, never hand-listed. The
# ATTACK arm is whatever corpus the injection indicators bind to; the BENIGN arm whatever the benign
# indicators bind to. A hand-list is correct only by COINCIDENCE — the day someone binds a benign
# indicator to a new corpus, a hand-list silently fails to widen and nothing reminds them. Deriving it
# means the gate's benign arm expands WITH the binding (构造一致, not coincidentally-consistent). 🔴 The
# indicator SETS here are the definition of each arm; the DIRS come from the bindings, so a known benign
# indicator on a new corpus pulls that corpus into the arm automatically.
_ATTACK_ARM_INDICATOR_IDS = frozenset(
    {"injection_catch_rate", "tier2_shadow_recall_lift"}
)
_BENIGN_ARM_INDICATOR_IDS = frozenset({"false_positive_rate", "benign_flag_rate"})


def carrier_arm_dirs(
    producers: tuple[Producer, ...] | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(attack_dirs, benign_dirs) for the carrier-rate gate, derived from `producers` so the arms track
    the indicator↔corpus bindings (the single source of truth, §8.5.2). Each sorted + de-duplicated.
    `producers=None` ⇒ the module CURATION global (resolved at CALL time, so a monkeypatch of CURATION is
    honoured) == (("llm01_prompt_injection",), ("llm01_benign",)).

    🔴 EV-CN-BASELINE 件3 — pass the ACTIVE corpus-set's tuple (CURATION_CN) and both arms become the CN
    dirs, so the "carrier-rate gap ≤ 20pp" is measured WITHIN a language, never across one. Fold the CN
    dirs into the English arms and that gap stops being the quantity it claims to be (a judge could then
    separate the arms by language, not by whether the canary is carried)."""
    if producers is None:
        producers = CURATION

    def _dirs(ids: frozenset[str]) -> tuple[str, ...]:
        return tuple(
            sorted({p.corpus_subdir for p in producers if p.indicator_id in ids})
        )

    return _dirs(_ATTACK_ARM_INDICATOR_IDS), _dirs(_BENIGN_ARM_INDICATOR_IDS)


# PASSIVE producers (EV-5, EV-9): measured over the eval WAL's AuditEvidence stream, feeding the
# MaturityReport's dimension grid (NOT the OWASP eval_report). Distinct ids, so they never collide
# with the active ones. `block_rate` is intentionally NOT here — over eval-attack probes it's
# DEGENERATE (~all-block), a misleading value (§6). The EV-9 dimension-attribution indicators ARE
# here: their registry bindings are `sample_size`-gated (a capability claim — "measured on N real
# VERIFIED requests" — not a value-quality claim), and over the eval WAL they produce non-degenerate,
# correctly-attributed values (production-representative only on the production passive path, §6).
PASSIVE: tuple[Indicator, ...] = (
    ChainIntegrity(),
    UnclosedLoopRate(),
    DurationP99(),
    TerminalErrorRatio(),
    BoundaryBreachRate(),  # EV-9 → robustness
    RedactionHitRatio(),  # EV-9 → privacy
    PiiExposureSurface(),  # EV-9 → privacy
)


@dataclass(frozen=True)
class PassiveScan:
    """One passive WAL read: its measurements plus the window it actually covered.

    `observed_window` is the HALF-OPEN `[min, max+1)` of the records read (None when the scan
    was empty) — the interval that re-selects exactly these records. `record_count` is the
    scan's n, so the pin artifact states the sample size the numbers came from."""

    measurements: tuple[Measurement, ...]
    observed_window: tuple[int, int] | None
    record_count: int


# 🔴 C1 —— 被动侧的【输出侧】指标：它们读的是模型输出的内容。
#
# 起因是一次实跑的对照：`pii_exposure_surface` 在 echo 上报出一个高值，而在有真实上游的
# 那一跑上是低值 —— 两跑同一指标、同一份良性语料。（具体数字不写公开仓 —— 纪律②。）
# 根因不是泄漏，是 **echo 转发器把请求原样回显** ⇒ 请求里的 PII 出现在"输出"里
# ⇒ 这些指标在 echo 上【量的是输入】。
#
# 🔴 而 `--no-output-side` 当时【没有挡住它们】：`assert_no_output_side_is_legitimate`
# 只看主动 producer，看不到被动扫描 ⇒ 那道守卫本该红而没红。
# ⚠️ 不走"把 echo 的回显从输出里剔掉"那条路 —— 那是给一个测错对象的量具打补丁，
#    而它在下一种转发器上会用另一种方式错。正确的是：**声明了没有输出侧，
#    输出侧指标就不该出数**，而不是出一个看起来正常的数。
_OUTPUT_SIDE_PASSIVE: frozenset[str] = frozenset(
    {
        # 读 response 正文里的 PII 类型集合
        "pii_exposure_surface",
        # 读"有几条请求的输出本可被脱敏"
        "redaction_hit_ratio",
        # 读响应侧规则面 + authz 的交叉——同样要有真实模型输出才成立
        "boundary_breach_rate",
    }
)

_NO_OUTPUT_SIDE_NOTE = (
    "n/a — 本跑声明了 --no-output-side（没有上游模型 / echo 转发器）⇒ 输出侧【不可测】。"
    "🔴 不是 0，也不是「什么都没泄漏」：echo 会把请求原样回显，于是这一格量到的是【输入】。"
    "实证：同一指标在 echo 上与在有真实上游的那一跑上取值相反。"
)


def _blank_output_side(m: Measurement) -> Measurement:
    """把一个输出侧被动指标改写成【不可测】—— 保留行，清掉数。

    🔴 保留行而不是删掉：删掉会让"这一跑没有这个指标"与"这一跑不可测"同形，
    而它们的处置相反（前者去接线，后者去换目标）。"""
    return replace(
        m,
        value=0.0,
        sample_size=0,
        evidence_refs=(),
        ci_low=None,
        ci_high=None,
        notes=_NO_OUTPUT_SIDE_NOTE,
    )


def scan_passive(
    wal_dir: str,
    tenant: str,
    *,
    warnings: list[str],
    window_from_ns: int | None = None,
    window_to_ns: int | None = None,
    no_output_side: bool = False,
) -> PassiveScan:
    """Read the eval WAL ONCE (optionally windowed) and measure every passive indicator over
    its AuditEvidence stream (EV-5 §6). Best-effort (§5): an unreadable WAL or a failing
    indicator is a warning, not a crash. The stream is materialized once — each indicator
    iterates it, and the observed window is derived from the same materialized scan.

    Passing BOTH bounds is what makes a run reproducible (EV-PIN): the reader's filter is
    half-open `[from, to)`, so the same WAL + the same bounds always yields the same records."""
    try:
        evidence = tuple(
            WalEvidenceReader(wal_dir).read_audit(
                tenant_id=tenant,
                time_from_ns=window_from_ns,
                time_to_ns=window_to_ns,
            )
        )
    except Exception as e:  # unreadable / undecodable WAL — record, keep going
        warnings.append(f"passive WAL read failed: {type(e).__name__}: {e}")
        return PassiveScan((), None, 0)
    if not evidence:
        warnings.append(f"passive WAL had no records for tenant {tenant!r}")
        return PassiveScan((), None, 0)

    measurements: list[Measurement] = []
    for ind in PASSIVE:
        try:
            produced = list(ind.measure(evidence))
        except Exception as e:
            warnings.append(
                f"passive {ind.indicator_id} failed: {type(e).__name__}: {e}"
            )
            continue
        # 🔴 C1 —— 声明了没有输出侧，输出侧被动指标就不出数（见 _OUTPUT_SIDE_PASSIVE）。
        if no_output_side and ind.indicator_id in _OUTPUT_SIDE_PASSIVE:
            produced = [_blank_output_side(m) for m in produced]
            warnings.append(
                f"passive {ind.indicator_id}: --no-output-side ⇒ 标为不可测"
                "（echo 会回显请求 ⇒ 该格会量到输入）"
            )
        measurements.extend(produced)
    return PassiveScan(
        measurements=tuple(measurements),
        observed_window=observed_window(evidence),
        record_count=len(evidence),
    )


def _probes_covered_by_window(
    wal_dir: str,
    tenant: str,
    window: tuple[int, int],
    *,
    warnings: list[str],
) -> int | None:
    """窗口内有【多少个不同的请求】留下了决策记录 —— 用来和主动侧发出的件数对账。

    🔴 数的是 `record_type == DECISION` 的 **distinct request_id**，不是记录条数：
    一次探针会写多条记录（决策 / 响应 / 异步治理），按条数比会恒不等，
    那样这条对账就成了一条恒红的门 —— 而恒红与恒绿一样没有信息。

    读不出来 ⇒ 返回 None（不是 0）：一次失败的读取不是一次"零覆盖"的观测。"""
    try:
        evidence = WalEvidenceReader(wal_dir).read_audit(
            tenant_id=tenant, time_from_ns=window[0], time_to_ns=window[1]
        )
        seen = {
            ev.ref.request_id
            for ev in evidence
            if ev.record.record_type == _DECISION_MADE and ev.ref.request_id
        }
    except Exception as e:  # 读不出来就说读不出来，不兜成一个数
        warnings.append(
            f"probe_window 覆盖对账跳过：WAL 读取失败 {type(e).__name__}: {e}"
        )
        return None
    return len(seen)


def _observed_window_unfiltered(wal_dir: str, tenant: str) -> tuple[int, int] | None:
    """The [min, max+1) span of ALL of a tenant's records, IGNORING any window filter (EV-CITE C12).
    Used only when a pinned window caught nothing — to tell the operator where the records really are
    so they can re-pin. Best-effort: an unreadable WAL yields None (the blocker degrades gracefully)."""
    try:
        evidence = tuple(WalEvidenceReader(wal_dir).read_audit(tenant_id=tenant))
    except Exception:
        return None
    return observed_window(evidence)


def collect_passive(
    wal_dir: str, tenant: str, *, warnings: list[str]
) -> tuple[Measurement, ...]:
    """Measurements only — the pre-EV-PIN shape, kept for callers that don't need the
    window. New code should prefer `scan_passive` (it also reports the covered window)."""
    return scan_passive(wal_dir, tenant, warnings=warnings).measurements


@dataclass(frozen=True)
class ActiveScan:
    """The active-collection result: the aggregate measurements PLUS run-level probe stats.

    `probe_count`/`error_count` are the totals across ALL producers' probes; `first_error` is the
    first probe error seen (verbatim). They power the EV-PAIR-A2 whole-run guard: when every probe
    across the whole run errored, `collect` must SHOUT at the top (not bury `N error(s) excluded`
    in each indicator's notes) and exit non-zero — a wasted run is not a success.

    `corpus_sha` maps indicator_id → the fingerprint of the corpus that producer ran (EV-PAIR §2/§3.1),
    so the delivered bundle records WHICH corpus backed each number."""

    measurements: tuple[Measurement, ...]
    probe_count: int
    error_count: int
    first_error: str | None
    corpus_sha: dict[str, str]
    # EV-R2 (--cases-out): the llm01_prompt_injection corpus + its ProbeResults, captured from the
    # FIRST injection producer's run (InjectionCatchRate) so the case contract re-adds to the SAME
    # aggregate this run's bundle reports. Empty when no injection producer ran (e.g. a corpus with
    # no llm01_prompt_injection subdir).
    injection_cases: tuple[CorpusCase, ...] = ()
    injection_results: tuple[ProbeResult, ...] = ()
    # 🔴 EV-CN-BASELINE 件4 — the BENIGN corpus + its ProbeResults, captured from the false_positive_rate
    # producer's run (llm01_benign for `en`, llm01_cn_benign for `cn`), for the benign-side case-level
    # table (--benign-cases-out). Empty when no benign producer ran.
    benign_cases: tuple[CorpusCase, ...] = ()
    benign_results: tuple[ProbeResult, ...] = ()
    # G1 — did PHASE 2 actually drain the async Tier-2 records? False ⇒ the Tier-2 rows are
    # UNMEASURED (n/a), never 0: "the judge scored below τ" and "we never looked" must not
    # collapse into the same number (the fail-open shape this ticket exists to close).
    tier2_drain_executed: bool = False
    # F7 (E3F §7.3-③) — the run's canary-set identity (sha256-of-salt handle, NOT the salt or any
    # canary string). Pins WHICH canary epoch this run used so two runs stay comparable (same
    # corpus_sha, different canaries). Empty when nothing was probed.
    canary_set_id: str = ""
    # 🔴 序8 件3 — the /admin/v1/audit:cursor readings taken BEFORE (pre-flight) and AFTER the Tier-2
    # drain, stored VERBATIM for R5's cross-check (the gateway's SELF-REPORTED guardrail_* counters vs
    # our WAL-MEASURED no_async — a mismatch is itself a finding). None when no admin cursor endpoint /
    # unreachable (a warning records which).
    guardrail_cursor_before: dict[str, Any] | None = None
    guardrail_cursor_after: dict[str, Any] | None = None
    # 🔴 本跑实际跑在哪些【规则内容指纹】上 —— 实测（被测方在每条决策记录上盖的章），
    # 不是操作者声明的 `detect_config`（人填的，可以填错；指纹填不了错）。
    # 记账按它、不按跑批次数：改一条 Tier-1 再跑一次可以是秒级，
    # 那条路根本不产生一个"看起来像跑批"的动作。
    # ⚠️ 追加在末尾 —— ActiveScan 是位置构造，插在中间会静默错位（我第一版就插错了）。
    policy_snapshots: tuple[str, ...] = ()


def collect_measurements(
    target: object,
    *,
    corpus_root: Path,
    benign_arm: str = "",
    warnings: list[str],
    corpus_set: str = "en",
    denominator: Denominator | None = None,
    drain_timeout_s: float | None = None,
    wal_dir: str = "",
) -> ActiveScan:
    """Run every curated producer against `target`. A producer exception is caught, noted
    in `warnings`, and skipped (best-effort collection — §5). Pure w.r.t. `target`: pass a
    fake Target in tests to exercise this without a gateway. Also tallies probe-level errors
    across the run for the whole-run guard (EV-PAIR-A2 §1).

    🔴 EV-CN-BASELINE 件2 — `corpus_set` selects the producer set (`en` default ⇒ CURATION, bit-identical
    to every existing run; `cn` ⇒ CURATION_CN). 件1 — the set is guarded for id↔subdir collisions first."""
    producers = curation_for(corpus_set)
    # 🔴 臂名解析必须排在【所有跑前门之前】—— 2026-09-24 实测的一处缺口：
    # `--benign-arm` 的重映射原本在 1600 行之后，而四道门读的是重映射【之前】的
    # `corpus_subdir`。于是良性验收臂走 `--corpus-set w2 --benign-arm <新臂>` 时：
    #   ① 冻结门在射程内找不到臂 ⇒ 静默跳过 ⇒ 那条一次性臂的标签【跑时不校验】
    #   ② 一次性门看到默认名 ⇒ 空过 ⇒ "已消耗"拦不住
    #   ③ 卷归属门看到默认名（无卷标记）而卷名带着新臂的标记 ⇒ 反而把【合法的跑】拦下来
    # 三种表现，同一个根因：门读的名字不是要打的那条臂。
    # ⚠️ 而②那一格最危险：它不报错、不吭声，看上去和"这条臂没问题"完全一样。
    producers = _with_arm_resolved(producers, benign_arm)
    _assert_no_id_subdir_collision(producers)
    _assert_no_calib_producer(
        producers
    )  # 🔴 件2 — the fit set is structurally unreachable
    _assert_frozen_arms_unchanged(producers, corpus_root)
    # 🔴 PM 2026-09-23 要的两道门 —— 两次【事后才发现】的失效各对一道：
    #   ① A2 被完整读了两次   ⇒ assert_read_once_not_spent
    #   ② F1 的流量落进 wal-a2 ⇒ assert_wal_belongs_to_this_run
    # 两道都排在这里（一件语料未发之前），与上面三道同一位置 —— 跑完再发现等于没发现。
    _assert_read_once_arms_intact(producers, wal_dir)
    measurements: list[Measurement] = []
    probe_count = 0
    error_count = 0
    first_error: str | None = None
    corpus_sha: dict[str, str] = {}
    injection_cases: tuple[CorpusCase, ...] = ()
    injection_results: tuple[ProbeResult, ...] = ()
    benign_cases: tuple[CorpusCase, ...] = ()  # 件4 — the benign case-table source
    benign_results: tuple[ProbeResult, ...] = ()

    # 🔴 PHASE 0 — PRE-FLIGHT the drain path, in SECONDS, before spending hours probing.
    #
    # PHASE 2's drain necessarily runs at the END (its stop condition snapshots the WAL head once and
    # polls past it). So a broken drain used to surface only after the whole run: observed live, the
    # cursor read raised and the run finished 2.3 h later with tier2_drain_executed=False and every
    # Tier-2 row n/a — a wasted night, discovered at the end. Reading the cursor ONCE up front turns
    # that into a 2-second answer. It is a WARNING, not a refusal: a Tier-2-off run does not need the
    # drain, and refusing to start would make an unrelated admin hiccup block the whole collection.
    guardrail_cursor_before: dict[str, Any] | None = None
    guardrail_cursor_after: dict[str, Any] | None = None
    probe = getattr(target, "read_drain_cursor", None) or getattr(
        target, "_read_cursor", None
    )
    if callable(getattr(target, "drain_governance", None)) and callable(probe):
        try:
            cur = probe()
        except AdminAuthError:
            # 🔴 PROPAGATE, do not warn. The "warning, not refusal" reasoning above is correct for
            # what it names — an unrelated admin hiccup — but a REJECTED CREDENTIAL is neither
            # unrelated nor a hiccup: it is deterministic, it will not heal during the run, and it
            # costs every Tier-2 row. A warning that is printed and stepped over is not a gate; on a
            # read-once corpus arm, stepping over it spends the arm for a Tier-1-only answer.
            raise
        except Exception as e:  # noqa: BLE001 — any other failure is the same signal here
            cur = None
            warnings.append(
                f"pre-flight: drain cursor read raised {type(e).__name__}: {e}"
            )
        # 序8 件3 — store the pre-flight reading VERBATIM (null when unreachable — already warned above).
        guardrail_cursor_before = cur if isinstance(cur, dict) else None
        if not isinstance(cur, dict) or cur.get("wal_head_seq") is None:
            warnings.append(
                "🔴 pre-flight: the Tier-2 drain cursor is NOT readable "
                f"(got {cur!r}) — this run will finish with tier2_drain_executed=false and every "
                "Tier-2 row n/a. Fix the admin endpoint BEFORE spending the run, or accept a "
                "Tier-1-only result."
            )

    # 🔴 PHASE 1 — probe each corpus subdir ONCE, shared by every producer bound to it.
    #
    # It used to be one `run_corpus` PER PRODUCER: llm01_prompt_injection has six producers, so the
    # same 202 cases were probed six times (~1484 probes for ~406 cases, ~3.6× waste, ~139 min).
    # 🔴 But the wasted time was the SMALLER half of the problem: each producer then measured its OWN
    # pass, so `injection_catch_rate` (decision-side, deterministic) and `injection_success_rate`
    # (OUTPUT-side, reads the model's text) were computed over DIFFERENT probe executions of the same
    # corpus. Observed live: one run reported success 0.3333 (n=63) in the bundle and 0.2812 (n=64)
    # in its own case contract — two answers, one run. Probing once makes every producer over a corpus
    # read ONE observation, which is what "catch and success on one denominator" always claimed.
    # 🔴 良性臂重命名 —— 新臂(W2)叫 llm01_benign_holdout_p1,而登记表里写的是默认名。
    # 在此之前这个名字是【写死】的:语料在、判据在、Producer 找不到它 ⇒ 那条臂在这条路上跑不了。
    # 🔴 只重映射【良性臂】那一个子目录名,不做通配 —— 通配会让一次手误把攻击臂也指过去,
    # 而那种错在结果里长得完全正常(数照出、分母是另一条臂)。
    # 🔴 臂名解析【只此一处】。此前映射写在装载侧、查找写在消费侧（`runs.get(prod.corpus_subdir)`），
    # 两处必须永远相等 —— 而它们不相等时的表现是：171 件探针照跑、四个 producer 一个都没消费到、
    # 退出码 0、bundle 写了、报告 ✅ CITABLE。W2 一次性臂就是这么空跑掉的（2026-09-06 实测）。
    # ⇒ 一个"必须永远相等"的东西出现两次，就是它迟早不等的原因。抽成函数，让它不可能不等。
    # 🔴 臂名已在函数开头由 `_with_arm_resolved` 解析过 ⇒ 这里直接读 corpus_subdir。
    # 2026-09-25 内联掉了原来那层 `_arm_of`：解析提前之后它退化成恒等函数，
    # 而一个只剩 `return prod.corpus_subdir` 的包装层会让下一个人以为"这里还有一次映射"。
    by_subdir: dict[str, list[Producer]] = {}
    for prod in producers:
        by_subdir.setdefault(prod.corpus_subdir, []).append(prod)

    probed: dict[str, tuple[CorpusCase, ...]] = {}
    runs: dict[str, tuple[ProbeResult, ...]] = {}
    # F7 (E3F §7.3) — ONE run-level salt so every case's canary shares one epoch (one canary_set_id).
    # The salt is SECRET (never stored); only its sha256-derived set_id reaches provenance. corpus_sha is
    # taken from the ORIGINAL corpus (with {{canary}} placeholders) BEFORE injection, so canary rotation
    # never moves it. A no-op on the current literal corpus (inject returns identity) until 3c.
    run_salt = secrets.token_hex(32)
    canary_set_id = ""
    # 🔴 F5 (§5) — dedup at CASE-ID level, not directory level. Load every subdir, then MERGE all cases
    # into one unique-by-case_id set and probe it ONCE; dispatch results back per subdir by case_id. The
    # old per-directory probing relied on the COINCIDENCE that no case_id lives in two directories —
    # nothing guarded it, so a case referenced by two directories would be probed twice and the decision-
    # and output-side indicators would again read DIFFERENT executions (the two-runs bug in a new shape).
    subdir_ids: dict[str, list[str]] = {}
    unique_cases: dict[str, CorpusCase] = {}
    # 🔴 声明了 Producer 却够不着它那条臂 ⇒ 整跑作废，不是一条 warning。
    # 旧行为是"记一条 warning，接着跑"，后果实测过两次：一次 `--corpus` 指到了子目录，
    # 0/17 个 Producer 产出、**退出码 0、bundle 照写**；一次是良性臂改名（盘上
    # `llm01_benign_holdout_p1`，代码默认 `llm01_benign_holdout`）⇒ 静默空跑。
    # 🔴 而 W2 是【一次性】臂：空跑一次就没有第二次。一条 warning 挡不住一个正在看
    # "跑完了"的人 —— 这是"警告会被读过去，异常不会"的又一处。
    missing_arms: list[tuple[str, list[str], str]] = []
    denominator_applied = False
    for subdir, prods in by_subdir.items():
        try:
            corpus = tuple(load_corpus(corpus_root / subdir))
        except Exception as e:  # 🔴 FAIL-CLOSED —— 见下面 `missing_arms` 的理由
            missing_arms.append(
                (subdir, sorted(p.indicator_id for p in prods), repr(e))
            )
            continue
        if not corpus:
            missing_arms.append(
                (
                    subdir,
                    sorted(p.indicator_id for p in prods),
                    "目录在，但一件语料都没有",
                )
            )
            continue
        # 🔴 分母清单只管它点名的那条臂。别的臂原样通过 —— 一份管 A 臂的清单
        # 悄悄削掉 B 臂，是"通配"那一族（本轮在 --benign-arm 上已经拒绝过一次）。
        if denominator is not None and subdir == denominator.arm_subdir:
            corpus = denominator.apply(corpus)
            denominator_applied = True
        probed[subdir] = corpus
        subdir_ids[subdir] = [c.id for c in corpus]
        sha = corpus_fingerprint(
            corpus
        )  # per-subdir sha over its OWN cases (unchanged)
        for prod in prods:
            corpus_sha[prod.indicator_id] = sha
        for c in corpus:
            unique_cases.setdefault(
                c.id, c
            )  # a case in two subdirs ⇒ ONE probe (dedup)

    # 🔴 声明了分母清单，而它点名的那条臂根本没被跑到 ⇒ 这一跑的分母不是它说的那个，
    # 而结果看起来完全正常。声明必须生效，否则是又一次"指定了目的地，没修路"。
    if denominator is not None and not denominator_applied:
        raise DenominatorError(
            f"分母清单 {denominator.source} 点名的臂 `{denominator.arm_subdir}` "
            f"不在本跑的编组里（本跑跑的是：{'、'.join(sorted(by_subdir))}）⇒ 清单没有生效。"
            "分母会是未经筛选的那个数，而报告看不出区别"
        )
    if missing_arms:
        raise MissingArmError(
            "🔴 声明了 Producer，却够不着它那条臂 —— 本跑作废，不产出 bundle：\n"
            + "\n".join(
                f"  · {sub}（{', '.join(ids)}）：{why}\n    找的是 {corpus_root / sub}"
                for sub, ids, why in missing_arms
            )
            + (
                f"\n  💡 良性臂改过名？盘上是 `{BENIGN_ARM_DEFAULT}_p1` 一类的名字时，"
                f"要显式给 `--benign-arm <目录名>` —— 默认名是 `{BENIGN_ARM_DEFAULT}`"
                if any(sub == BENIGN_ARM_DEFAULT for sub, _, _ in missing_arms)
                else ""
            )
            + "\n  ⚠️ 这里【不】降级成 warning：一次空跑会花掉一条读一次的臂，"
            "而它在结果里长得和跑完了一模一样"
        )

    if unique_cases:
        cset = CanarySet.generate(unique_cases.values(), salt=run_salt)
        canary_set_id = cset.set_id
        all_results = run_corpus(list(unique_cases.values()), target, canary_set=cset)  # type: ignore[arg-type]
        _assert_probed_once(
            all_results
        )  # 🔴 F5 — a case_id probed >1 ⇒ RAISE, never warn
        by_case = {pr.case_id: pr for pr in all_results}
        for pr in all_results:
            probe_count += 1
            if pr.error is not None:
                error_count += 1
                if first_error is None:
                    first_error = pr.error
        for subdir, ids in subdir_ids.items():
            runs[subdir] = tuple(by_case[cid] for cid in ids if cid in by_case)

    # 🔴 PHASE 2 — drain the ASYNC Tier-2 governance records ONCE, after ALL probing (G1).
    #
    # The Tier-2 shadow judge writes its record ~2s AFTER the probe, so a run that never drains leaves
    # `governance_evidence` None on every result and `caught_by_tier2` returns False for BOTH "the
    # judge scored below τ" and "we never looked" — a check that cannot return True. Draining here (not
    # per corpus) is deliberate: the stop condition snapshots the WAL head ONCE and polls the drain
    # cursor past it, so it must run after the last probe. No admin_url / not a gateway ⇒ skipped, and
    # `tier2_drain_executed=False` travels into provenance so the Tier-2 rows read n/a, never 0.
    drain = getattr(target, "drain_governance", None)
    drained = False
    if callable(drain) and runs:
        order = list(runs)
        flat = [pr for subdir in order for pr in runs[subdir]]
        try:
            # 🔴 Re-split BY POSITION, never by id(): drain_governance rebuilds the attached results
            # with dataclasses.replace, so a drained ProbeResult is a NEW object — an identity map
            # would silently drop exactly the records the drain just found. Order IS preserved.
            # 🔴 排空上限：不传 ⇒ 用 target 自己按件数推导的默认（_DRAIN_PER_CASE_S=5.0/件）。
            # 而那个 5.0 是在【中文认证跑那套栈】上按 median 2.84 s / max 4.26 s 定的（target.py:30
            # 注释逐字）。2026-09-21 实测同一条 p3 臂：第一跑 ~3.5 s/件，几跑之后劣化到 ~9.5 s/件
            # ——【语料没变、栈没变、只是判官慢了】，25 分钟的上限差 103 件没排完，整跑的 Tier-2 作废。
            # ⇒ 对可重跑臂那是白花 25 分钟；🔴 对 read-once 臂那是把臂烧掉，而且烧得毫无征兆：
            #   失败不是错误，是一个「本该有数的地方写着 not_measured」的产物。
            # ⇒ 所以这里要一个【操作者能显式声明】的闸门：跑之前量一次 s/件，把它写进跑单。
            #   常数留作默认（小批次照旧），但它不再是唯一可能的值。
            back = list(
                drain(flat)
                if drain_timeout_s is None
                else drain(flat, timeout=drain_timeout_s)
            )
            if len(back) != len(flat):
                raise ValueError(
                    f"drain returned {len(back)} results for {len(flat)} probes"
                )
            at = 0
            for subdir in order:
                n = len(runs[subdir])
                runs[subdir] = tuple(back[at : at + n])
                at += n
            drained = True
        except Exception as e:  # a drain failure must not void the whole collection
            warnings.append(f"tier-2 drain failed: {type(e).__name__}: {e}")

    # 🔴 序8 件3 — read the cursor ONCE MORE after the drain: the AFTER snapshot of the before/after pair
    # R5 cross-checks (self-reported guardrail_* vs our WAL-measured no_async). Stored verbatim; null +
    # a warning when the endpoint is unreachable (never a silent omission).
    if callable(probe):
        try:
            after = probe()
        except Exception as e:  # noqa: BLE001 — any failure is the same signal
            after = None
            warnings.append(
                f"post-drain: guardrail cursor read raised {type(e).__name__}: {e}"
            )
        guardrail_cursor_after = after if isinstance(after, dict) else None

    # 🔴 PHASE 3 — measure. Every producer over a corpus reads the SAME results tuple.
    # Iterates the ACTIVE producer set (not the by-corpus grouping) so the bundle's measurement ORDER is
    # unchanged by this refactor — fixtures and diffs stay stable, and the one-aggregate-per-bound-id
    # invariant is still read straight off the set (件2: CURATION for `en`, CURATION_CN for `cn`).
    # 🔴 件2 fix — the ATTACK subdir is DERIVED from the active producer set, exactly like `benign_subdir`
    # below. It used to be hardcoded `"llm01_prompt_injection"`, which made the pair ASYMMETRIC: on a `cn`
    # run the benign table wrote and the attack contract silently skipped ("no results to serialize"), so
    # a run could satisfy every other void-condition while its attack rows — the ones the §3.1 recompute
    # guard re-adds — did not exist. Observed live on the first CN baseline run, which the pre-declared
    # conditions therefore VOIDED. Derive it, so a new corpus set can never lose the contract by omission.
    injection_subdir = next(
        (
            p.corpus_subdir
            for p in producers
            if p.indicator_id == "injection_catch_rate"
        ),
        None,
    )
    if injection_subdir is not None and injection_subdir in runs:
        # EV-R2 — the contract is built from the SAME single run the aggregates are measured over
        # (that identity is now structural, not a "capture the first pass" convention).
        injection_cases = probed[injection_subdir]
        injection_results = runs[injection_subdir]
    # 🔴 件4 — capture the BENIGN run (the FPR producer's corpus: llm01_benign for `en`, llm01_cn_benign
    # for `cn`) from the SAME single probe pass, so the benign case table re-reads exactly what FPR did.
    benign_subdir = next(
        (p.corpus_subdir for p in producers if p.indicator_id == "false_positive_rate"),
        None,
    )
    if benign_subdir is not None and benign_subdir in runs:
        benign_cases = probed[benign_subdir]
        benign_results = runs[benign_subdir]
    for prod in producers:
        shared = runs.get(prod.corpus_subdir)
        if shared is None:
            # 🔴 注释原本写着 "already warned in PHASE 1" —— 而臂名重映射之下 PHASE 1 【不会】警告
            # （臂按新名装载成功了），于是这里成了一次**静默跳过**。现在明写一条。
            warnings.append(
                f"🔴 producer {prod.indicator_id} 没有拿到任何探针结果 —— "
                f"它绑的臂 {prod.corpus_subdir!r} 不在本跑的探针集合里（本跑跑了：{sorted(runs)}）"
            )
            continue
        try:
            (m,) = prod.factory().measure(shared)
            measurements.append(_apply_arm_note(prod, _apply_declared_subject(prod, m)))
        except Exception as e:
            warnings.append(
                f"producer {prod.indicator_id} failed: {type(e).__name__}: {e}"
            )
    # 🔴 声明了 N 个 producer，一个都没产出 ⇒ 作废。探针花掉了、语料花掉了、退出码却是 0，
    # 而 bundle 里只剩被动格 —— 报告照样 ✅ CITABLE。这是 W2 一次性臂空跑那次的形状。
    if producers and not measurements:
        raise EmptyRunError(
            f"🔴 本跑声明了 {len(producers)} 个 producer，而【一个都没有产出】 —— "
            f"探针已经发出去了（跑了这些臂：{sorted(runs)}），语料已经花掉，而产物里只有被动格。\n"
            + "\n".join(
                f"  · {w}" for w in warnings[-len(producers) :] if w.startswith("🔴")
            )
            + "\n  ⇒ 作废。一个 0 产出的跑不是成功的跑，尤其当它退出码是 0、报告还写着可引"
        )

    # 🔴 一跑之内规则内容变过 ⇒ 作废。分子分母来自不同规则集，而合出来的率看起来完全正常。
    snaps = assert_single_policy_snapshot([pr for rs in runs.values() for pr in rs])
    return ActiveScan(
        tuple(measurements),
        probe_count,
        error_count,
        first_error,
        corpus_sha,
        injection_cases,
        injection_results,
        benign_cases,
        benign_results,
        drained,
        canary_set_id,
        policy_snapshots=snaps,
        guardrail_cursor_before=guardrail_cursor_before,
        guardrail_cursor_after=guardrail_cursor_after,
    )


def _write_case_contract(
    cases: tuple[CorpusCase, ...],
    results: tuple[ProbeResult, ...],
    tenant_id: str,
    path: str,
    *,
    warnings: list[str],
) -> None:
    """EV-R2 (--cases-out) — serialize + write the LLM01 injection Tier-0 case contract from THIS
    run, mirroring tools.eval_report._write_case_contract. `serialize_case_contract` runs the §3.1
    recompute guard, so a run whose rows can't re-add their own aggregates is reported (never a
    contract that lies). Best-effort (§5): a missing injection run / a fork is a warning, not a
    crashed collection. 🔴 Tier-0: POINTERS only (request_id + evidence_ref), never response
    content — disclosure_class=operator_only."""
    if not results:
        warnings.append(
            "--cases-out: no injection-arm results to serialize (contract skipped)"
        )
        return
    try:
        contract = serialize_case_contract(
            cases,
            results,
            target_kind="gateway",
            tenant_id=tenant_id,
            generated_at_ns=time.time_ns(),
            # E3F §8.2-3 — the run's口径; a hard_only (diagnostic) run refuses to emit a contract.
            arm_parity=_run_arm_parity(),
        )
    except CaseContractError as e:
        warnings.append(f"--cases-out: case contract did not re-add (not written): {e}")
        return
    import json

    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps(contract, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"wrote {dest}: EV-R2 case contract "
        f"(disclosure_class={contract['disclosure_class']}, {len(contract['cases'])} cases "
        "— operator_only, do NOT publish)",
        file=sys.stderr,
    )


def _write_benign_case_table(
    cases: tuple[CorpusCase, ...],
    results: tuple[ProbeResult, ...],
    tenant_id: str,
    path: str,
    *,
    warnings: list[str],
) -> None:
    """🔴 EV-CN-BASELINE 件4 (--benign-cases-out) — serialize + write the Tier-0 benign case-level table
    from THIS run, the mirror of `_write_case_contract`. It carries POINTERS + the decision-stage FPR/flag
    口径 per case (拦截来源 = decision_injection_source), so a blocked benign case is answerable by case_id.
    serialize_benign_case_table refuses to emit if any canary plaintext reached a row (§7.4-5). Best-effort
    (§5): a missing benign run is a warning, not a crashed collection."""
    if not results:
        warnings.append(
            "--benign-cases-out: no benign results to serialize (table skipped)"
        )
        return
    try:
        table = serialize_benign_case_table(
            cases,
            results,
            target_kind="gateway",
            tenant_id=tenant_id,
            generated_at_ns=time.time_ns(),
        )
    except CanaryLeakError as e:
        warnings.append(f"--benign-cases-out: refused (canary plaintext): {e}")
        return
    import json

    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps(table, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"wrote {dest}: 件4 benign case table "
        f"(disclosure_class={table['disclosure_class']}, {len(table['cases'])} cases "
        "— operator_only, do NOT publish)",
        file=sys.stderr,
    )


def _resolve_target(args: argparse.Namespace) -> tuple[str, str] | None:
    """(target_url, target_kind) from the EV-FWD D3 CLI, or None after printing the error.

    `--gateway` is SUGAR for a gateway run (mutually exclusive with the explicit pair);
    `--target-kind` is NEVER inferred from the URL — a bare-model URL must not be silently
    mislabelled as a governed gateway (R1 honesty)."""
    gw = args.gateway
    url = getattr(args, "target_url", None)
    kind = getattr(args, "target_kind", None)
    if gw and (url or kind):
        print(
            "error: --gateway is sugar for a gateway run and is mutually exclusive with "
            "--target-url / --target-kind",
            file=sys.stderr,
        )
        return None
    if gw:
        return gw, "gateway"
    if url:
        if not kind:
            print(
                "error: --target-url requires --target-kind (gateway|raw_model|"
                "moderation_api) — the kind is never inferred from the URL",
                file=sys.stderr,
            )
            return None
        return url, kind
    print(
        "error: need --gateway (or TREVAL_EVAL_GATEWAY_URL), or --target-url + --target-kind",
        file=sys.stderr,
    )
    return None


def run_collect(args: argparse.Namespace) -> int:
    warnings: list[str] = []
    # 🔴 清单在【发探针之前】读 —— 一份读不了/对不上的清单，代价应该是 0 件语料，
    # 不是跑完 134 件才发现分母不对。
    denominator = None
    _manifest = getattr(args, "denominator_manifest", None)
    if _manifest:
        try:
            denominator = load_denominator(_manifest)
        except PolicyDriftError as e:
            # 🔴 退出码 3 —— 一跑之内规则内容变过，这一跑作废。与够不着臂同一档：
            # 操作者现在就能修（对齐规则集再跑），而合出来的率看起来完全正常，
            # 所以它必须是非零退出，不是一条 warning。
            print(f"error: {e}", file=sys.stderr)
            return 3
        except DenominatorError as e:
            print(f"error: {e}", file=sys.stderr)
            return 3
    # 🔴 判官指纹的声明也在【发探针之前】解析 —— 同一条理由：一份读不出/0 字节的 imprint，
    # 代价应该是 0 件语料，不是跑完一次性臂才发现那一格记不下来。
    try:
        judge_imprint = resolve_judge_imprint(getattr(args, "judge_imprint", None))
    except JudgeImprintError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    # 🔴 C2A0 —— 基线产物也在【发探针之前】读，与上面两条同一条理由。
    # ⚠️ 落点故意分两处：**读**在这里（纯本地文件，读不出就停 ⇒ 连那一件合成试探件都没发过），
    # **比**在拿到本跑 ruleset_sha256 之后（只有 fetch_buildinfo 能给出它），仍在语料探针之前。
    # 合成一处做不到：把比对提到这里就没有本跑那一格，放到跑后才比就已经花掉语料。
    baseline_compared = BASELINE_NOT_DECLARED
    try:
        baseline_ruleset_sha = _baseline_ruleset_sha(
            getattr(args, "baseline_bundle", None)
        )
    except BaselineError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    passive_only = getattr(args, "passive_only", False)
    pin_observed = getattr(args, "pin_observed_window", False)
    # E3-n ④ — the tested party's build fingerprint captured before/after a gateway run (None when no
    # --admin-url, or on a passive/raw_model run); citability compares them to verify zero-change.
    build_fp_before: dict | None = None
    build_fp_after: dict | None = None
    build_fp_before_err: str | None = None
    build_fp_after_err: str | None = None
    scan_start_ns: int | None = None
    admin_url_declared = bool(getattr(args, "admin_url", None))
    # C15 (source): the wall clock at INPUT-VALIDATION time — legal here — used ONLY to reject a
    # future --window-to-ns before any probe runs. This is a DIFFERENT moment from generated_at_ns
    # (the product-GENERATION clock, read AFTER the scan below): with --gateway --pin-observed-window
    # the probes CREATE records DURING the run, so the stamp must be taken after them. Two reads is
    # correct, not a smell.
    now_ns = time.time_ns()

    # EV-PIN: a run is PINNED only when the operator supplied BOTH window bounds — that is the
    # reproducibility claim (same WAL + same bounds ⇒ same records ⇒ same n and value). Parsed FIRST
    # so the C15/exclusivity refusals below happen at the SOURCE, before any probe is spent.
    raw_from = getattr(args, "window_from_ns", None)
    raw_to = getattr(args, "window_to_ns", None)
    window_from: int | None = int(raw_from) if raw_from is not None else None
    window_to: int | None = int(raw_to) if raw_to is not None else None

    # 🔴 C15 (source, primary): reject a FUTURE upper bound BEFORE probing. A window whose `to` has
    # not passed is NOT frozen — re-reading the same WAL later returns MORE records, so the pinned
    # number changes; reproducibility is the one thing `pinned` exists to guarantee. The clock is
    # legal HERE (source), so this refuses to even PRODUCE a fake-pinned bundle (not lean on downstream).
    if window_to is not None and window_to > now_ns:
        print(
            f"error: --window-to-ns {window_to} is in the future (now {now_ns}) — a window whose "
            "upper bound has not passed is NOT frozen: re-reading the same WAL later returns MORE "
            "records, so the pinned number changes. Pin with a CLOSED, past upper bound.",
            file=sys.stderr,
        )
        return EXIT_IO

    # C13: --pin-observed-window pins to whatever the passive scan covers, so explicit bounds make no
    # sense alongside it (they would filter the very scan it pins to). Reject the contradictory combo.
    if pin_observed and (window_from is not None or window_to is not None):
        print(
            "error: --pin-observed-window pins to the observed window — do not also pass "
            "--window-from-ns/--window-to-ns (they would filter the scan it pins to)",
            file=sys.stderr,
        )
        return EXIT_IO

    # C13: --passive-only reads the WAL and sends NO probes, so it needs no target — only a --wal to
    # read. The eval WAL is gateway-governed ⇒ its passive numbers are wal_anchored, so this is a
    # gateway-kind bundle with no active half. (It removes "re-pay the whole active side just to
    # change a WAL-read parameter".)
    if passive_only:
        if not args.wal:
            print(
                "error: --passive-only reads the WAL and sends no probes — it requires --wal DIR "
                "(plus --window-from-ns/--window-to-ns or --pin-observed-window to be citable)",
                file=sys.stderr,
            )
            return EXIT_IO
        target_url, target_kind, model = "", "gateway", None
        active = ActiveScan((), 0, 0, None, {})
    else:
        resolved = _resolve_target(args)
        if resolved is None:
            return EXIT_IO
        target_url, target_kind = resolved

        # EV-PAIR-A2 §2: `--model` is REQUIRED for a non-gateway target — `deepseek-v4-flash` is the
        # GATEWAY deployment's model id, no default is correct for an arbitrary endpoint (unset ⇒
        # near-certain 404 + a whole wasted run). Same discipline as D3's "never infer target_kind":
        # what can't be guessed isn't guessed. The gateway keeps its meaningful default.
        model = args.model
        if not model:
            if target_kind == "gateway":
                model = "deepseek-v4-flash"
            else:
                print(
                    f"error: --model is required for --target-kind {target_kind} (no default "
                    "for an arbitrary endpoint); it reads TREVAL_EVAL_MODEL",
                    file=sys.stderr,
                )
                return EXIT_IO

        # 🔴 EV-CN-BASELINE 架构师裁定三-② — a CN run measures ONLY the decision-side arm (catch / FPR /
        # benign_flag); CURATION_CN has NO injection_success_rate producer, so the bundle carries catch
        # WITHOUT success. Declare that scope UP FRONT — a reader who sees catch and no success would else
        # read the absence as "no attack succeeded" (false). Pre-run, never after-the-fact.
        if args.corpus_set == "cn":
            print(
                "🔴 作用域声明（跑前）：本批为中文诊断批，只测决策侧（injection_catch_rate / "
                "false_positive_rate / benign_flag_rate）；【本批不测输出侧成功率】—— 没有 "
                "injection_success_rate，catch 无 success 相伴不等于『没有攻击得逞』。",
                file=sys.stderr,
            )

        # Lazy — the targets pull httpx only when we actually collect.
        from treval.active_eval import GatewayTarget, OpenAITarget

        target: object
        if target_kind == "gateway":
            # E3-n ③ — DERIVE the client timeout from the tested party's DECLARED upstream request-
            # timeout: client = 2× upstream (not a guess). Platform pinned upstream = 60.0s hardcoded
            # (openai_request_timeout_s), so --upstream-timeout-s 60 ⇒ client 120s. Falls back to the
            # opt-in --timeout (EV-Coverage E3), else GatewayTarget's own 30.0 default.
            upstream = getattr(args, "upstream_timeout_s", None)
            timeout = getattr(args, "timeout", None)
            # 🔴 `--upstream-timeout-s` LOOKS like a pure declaration about the tested party, and it is
            # also the operational client timeout (2× it). Declare a value that does not apply and you
            # do not mis-label the run — you change it. Observed live: `--upstream-timeout-s 0` was
            # passed to mean "there is no upstream (echo forwarder)"; it became a 0-second client
            # timeout and all 194 probes died at ConnectError EINPROGRESS — the connect began and was
            # abandoned before it could finish. Refuse the value rather than run with it.
            if upstream is not None and upstream <= 0:
                print(
                    f"error: --upstream-timeout-s {upstream} ⇒ 客户端超时 {2.0 * upstream}s，"
                    "任何请求都完不成（connect 立即被放弃 ⇒ EINPROGRESS）。"
                    "这个字段既是声明也是参数：没有上游时不要填 0，要么省略该声明，"
                    "要么填被测方配置里真实存在的上游超时",
                    file=sys.stderr,
                )
                return 3
            # 🔴 Both given ⇒ one silently wins. Say which, rather than let the run use a timeout the
            # operator did not think they set.
            if upstream is not None and timeout is not None:
                warnings.append(
                    f"--upstream-timeout-s {upstream} 覆盖了 --timeout {timeout}："
                    f"客户端超时用的是 2×upstream = {2.0 * upstream}s"
                )
            client_timeout = (
                2.0 * upstream
                if upstream is not None
                else (timeout if timeout is not None else 30.0)
            )
            gw = GatewayTarget(
                target_url,
                wal_dir=args.wal,
                tenant_id=args.tenant,
                user_id=args.user,  # MUST be provisioned (else all-unmeasurable)
                model=model,
                temperature=0.0,  # pin for the statistical verticals
                timeout=client_timeout,
                # E3-n ④ — the admin base (GET /admin/v1/buildinfo + the drain cursor).
                admin_url=getattr(args, "admin_url", None),
                # 🔴 Run-wide `x-agent-id`. Without it the gateway answers IDENTIFY_FAILED before any
                # detection stage — every probe errors and every indicator is unmeasurable.
                agent_id=getattr(args, "agent", "") or None,
                # 🔴 Declared, never inferred — and only after the guard below proves no active
                # producer reads the response.
                no_output_side=getattr(args, "no_output_side", False),
            )
            if getattr(args, "no_output_side", False):
                try:
                    assert_no_output_side_is_legitimate(curation_for(args.corpus_set))
                except ValueError as e:
                    print(f"error: {e}", file=sys.stderr)
                    return 3
            # 🔴 PRE-FLIGHT THE TARGET ITSELF, with ONE synthetic probe, before spending the corpus.
            # The existing pre-flight reads the ADMIN cursor — a different port, a different client,
            # a different code path — and then the run assumes the probe path works. That is a check
            # verifying something easier-to-be-true than what it claims. Three whole runs died past
            # this point on things one probe answers in a second: a missing `x-agent-id`
            # (IDENTIFY_FAILED), a missing `tool:chat:*` scope (AUTHZ_SCOPE_INSUFFICIENT), and a
            # zero client timeout (EINPROGRESS) — each time 194/194 probes, each time discovered at
            # the end. An operator's `curl` succeeding beside the run proves nothing: this probe runs
            # in the RUN's process, with the run's client, timeout, headers and environment.
            # 🔴 SYNTHETIC, never a corpus case — a read-once arm must not pay for a connectivity check.
            preflight = _synthetic_preflight_case()
            pr0 = gw.probe(preflight)
            # 🔴 三条判据，不只传输（PM 放行条件⑤）：②被拦 与 ③无 completion 同样让这一跑
            # 白花掉一条一次性臂，而它们都不是传输问题 —— 只判①的试探比它声称的更容易为真。
            _pf = preflight_refusal(pr0)
            if _pf is not None:
                print(
                    f"error: 跑前合成探针未通过 —— {_pf}\n"
                    f"  target={target_url} client_timeout={client_timeout}s "
                    f"tenant={args.tenant} user={args.user} agent={getattr(args, 'agent', '') or '(无)'}\n"
                    "  ⇒ 语料一件未动。先修可达性/身份/超时，再跑",
                    file=sys.stderr,
                )
                return 3
            # E3-n ④ — snapshot the tested party's build fingerprint BEFORE any probe runs (None when
            # no --admin-url); the AFTER snapshot below must match it bit-for-bit or the run is void.
            build_fp_before, build_fp_before_err = gw.fetch_buildinfo()
            # 🔴 C2A0 —— 本跑的规则集与基线是不是同一份，**在发第一条语料探针之前**回答。
            # 今天唯一会红的是 `pair.py` 的拒发门，而它在【配对那一刻】才红 —— 那时语料已经花掉。
            # ⚠️ 「代价」按臂分两种，不合并：可重跑的公开臂丢的是【可比性】（臂还在，重跑即可）；
            # 一次性/留出臂能重跑，但重跑得到的数**不再是留出臂的数** —— 丢的是留出性。
            baseline_compared = compare_baseline_ruleset(
                baseline_ruleset_sha, build_fp_before
            )
            _halt, _msg = baseline_gate_verdict(
                baseline_compared, getattr(args, "baseline_expect", None)
            )
            if _msg:
                # 🔴 原样打印，不转述：`mismatch` 只说"两格不等"，不说是漂移还是载入了另一份
                # （判据里不含 ruleset_path）。转述一次就替读者做了那条被去掉的推断。
                print(_msg, file=sys.stderr if _halt else sys.stdout)
                if not _halt:
                    warnings.append(_msg)
            if _halt:
                return 3
            target = gw
        elif target_kind == "raw_model":
            # EV-FWD: a bare OpenAI-compatible model. NO wal_dir / NO tenant — it is not governed;
            # only the output-side indicators measure on it, the rest surface as availability=n/a.
            target = OpenAITarget(target_url, model=model, temperature=0.0)
        else:  # moderation_api
            print(
                "error: --target-kind moderation_api has no runtime in EV-FWD (its vendor-catch "
                "indicator lands with C2); only gateway | raw_model can be driven today",
                file=sys.stderr,
            )
            return EXIT_IO
        corpus_root = Path(args.corpus) if args.corpus else _DEFAULT_CORPUS
        # E3-n ② — bracket the active scan in wall-clock so probe_window (this run's probe span) is
        # distinguishable from observed_window (the whole WAL the passive scan read, incl. history).
        scan_start_ns = time.time_ns()
        try:
            active = collect_measurements(
                target,
                corpus_root=corpus_root,
                # 🔴 这一行此前【不在】：CLI 解析了 --benign-arm、collect_measurements 收它、
                # 重映射代码也在，唯独调用点没传 ⇒ 参数永远是默认的 ""，重映射一次都没触发过。
                # 为防 W2 空跑而建的那条路，断在最后一米 —— 而它本身就是"指定了目的地没修路"的修法。
                benign_arm=getattr(args, "benign_arm", "") or "",
                denominator=denominator,
                warnings=warnings,
                corpus_set=args.corpus_set,
                # 🔴 紧挨着上面那条「断在最后一米」的账：本参数同族，所以这一行与 CLI 声明、
                # 函数签名、drain 调用四处【一次落齐】。少这一行，--drain-timeout-s 会被解析、
                # 被写进 --help、被操作者写进跑单，然后【永远不起作用】——
                # 而它不起作用的表现，正是它本来要防的那个（排空追不上、Tier-2 全 not_measured）。
                drain_timeout_s=getattr(args, "drain_timeout_s", None),
                # 🔴 与 --benign-arm / --drain-timeout-s 同族的那条账：参数解析了、
                # 函数签名收了、判据也写了，唯独调用点不传 ⇒ 门永远看不到卷名。
                # 这一行与签名、判据、CLI 四处【一次落齐】。
                wal_dir=getattr(args, "wal", "") or "",
            )
        except DenominatorError as e:
            # 🔴 退出码 3 —— 与够不着臂同一档：操作者现在就能修的输入问题，
            # 而"现在就能修"正是它不能被跨过去的理由。语料一件未动。
            print(f"error: {e}", file=sys.stderr)
            return 3
        except EmptyRunError as e:
            print(f"error: {e}", file=sys.stderr)
            return 3
        except MissingArmError as e:
            # 🔴 退出码 3（io/参数），不是 traceback —— 这是操作者【现在就能修】的输入错误，
            # 而"现在就能修"正是它绝不能被跨过去的理由。语料一件未动（本检查在探针之前）。
            print(f"error: {e}", file=sys.stderr)
            return 3
        except AdminAuthError as e:
            # 🔴 The one refusal that must happen BEFORE any probe: see the pre-flight above. Exit 3
            # (io/arg), not a traceback — this is a fixable operator input, and it is fixable NOW,
            # which is exactly why it must not be stepped over.
            print(f"error: {e}", file=sys.stderr)
            print(
                "  ⇒ export TREVAL_ADMIN_TOKEN=... 再跑；确实要只测 Tier-1，就去掉 --admin-url —— "
                "那是一个明写下来的决定，不是一条被跳过的告警",
                file=sys.stderr,
            )
            return 3
        # E3-n ④ — snapshot the build fingerprint AFTER the run (isinstance narrows target →
        # GatewayTarget for mypy). citability blocks the run if before != after (a mid-run change),
        # OR if --admin-url was declared but either snapshot could not be fetched (fail-closed).
        if isinstance(target, GatewayTarget):
            build_fp_after, build_fp_after_err = target.fetch_buildinfo()
        # EV-R2 (--cases-out): write the Tier-0 LLM01 injection case contract from THIS run.
        # Gateway-only — it carries WAL decision pointers a bare model has no record for. The
        # stamped tenant is args.tenant, the SAME value handed to GatewayTarget(tenant_id=...)
        # above (UI-3 §5.2 — one source, not a second drifting env read).
        cases_out = getattr(args, "cases_out", None)
        if cases_out:
            if target_kind != "gateway":
                print(
                    "error: --cases-out needs a gateway run (the contract carries WAL decision "
                    "pointers a bare model has no record for)",
                    file=sys.stderr,
                )
                return EXIT_IO
            _write_case_contract(
                active.injection_cases,
                active.injection_results,
                args.tenant,
                cases_out,
                warnings=warnings,
            )
        # 🔴 件4 (--benign-cases-out): the benign case-level table from THIS run. Gateway-only for the
        # same reason (it reads WAL decision records for the FPR/flag口径). Independent of --cases-out so
        # a benign-only diagnostic run can still emit it.
        benign_cases_out = getattr(args, "benign_cases_out", None)
        if benign_cases_out:
            if target_kind != "gateway":
                print(
                    "error: --benign-cases-out needs a gateway run (the table carries WAL decision "
                    "pointers a bare model has no record for)",
                    file=sys.stderr,
                )
                return EXIT_IO
            _write_benign_case_table(
                active.benign_cases,
                active.benign_results,
                args.tenant,
                benign_cases_out,
                warnings=warnings,
            )
    # EV-PAIR-A2 §1: did the WHOLE run get zero model responses? (every probe errored). Computed
    # here so the guard can shout at the top + exit non-zero, rather than leaving the only clue
    # in each indicator's `N error(s) excluded` notes.
    all_errored = active.probe_count > 0 and active.error_count == active.probe_count

    # The window bounds were parsed + validated (C15 / exclusivity) at the top, before probing.
    pinned = window_from is not None and window_to is not None

    # Passive (EV-5): read the same WAL the probes wrote under. GATEWAY-only — a raw_model /
    # moderation_api run has no governed WAL, so passive indicators do not apply (EV-FWD).
    scan = (
        scan_passive(
            args.wal,
            args.tenant,
            warnings=warnings,
            window_from_ns=window_from,
            window_to_ns=window_to,
            # 🔴 C1 —— 声明传下去，否则那道守卫只挡得住主动侧（实证 2026-09-14：
            # pii_exposure_surface 在 echo 上报出一个高值，而它量的是被回显的请求）。
            no_output_side=bool(getattr(args, "no_output_side", False)),
        )
        if (args.wal and target_kind == "gateway")
        else PassiveScan((), None, 0)
    )
    passive = scan.measurements
    measurements = active.measurements + passive

    # C13: --pin-observed-window is an EXPLICIT operator declaration ("口径就是这一跑") — pin to the
    # window the passive scan actually covered. It stays an OWNED claim (NOT auto-pin, C12: the
    # operator named the flag). 🔴 C15 cannot wrongly fire because generated_at_ns is stamped AFTER
    # this scan (below), so it is >= every observed record — NOT because "the records already exist":
    # with --gateway the probes CREATE those records DURING the run (after the source-side now_ns).
    # Combinable with --gateway: the probes run ONCE, then the run pins to that observed passive window.
    if pin_observed and scan.observed_window is not None:
        pinned = True
        window_from, window_to = scan.observed_window

    # The window we RECORD: the pinned bounds when given, else the window actually observed
    # (half-open). Never (0,0) — a report that does not state its own window cannot be
    # reproduced, which is the entire defect EV-PIN exists to fix. A run with no passive read
    # (no --wal) has no observed window at all; say so with nulls rather than inventing zeros.
    if window_from is not None and window_to is not None:
        window = (window_from, window_to)
    else:
        window = scan.observed_window or (0, 0)
        if scan.observed_window is None and args.wal:
            warnings.append(
                "no records in the passive scan — window falls back to [0,0]; "
                "this run is NOT citable externally"
            )
    if not pinned:
        warnings.append(
            "unpinned run (no --window-from-ns/--window-to-ns): the window is a moving "
            "snapshot — do NOT cite these numbers in external documents (EV-PIN §1.4)"
        )

    # EV-PAIR §2: host:port only — 🔴 never the full URL (path/query), never the api_key. A
    # passive-only run probed nothing ⇒ no host to record (None).
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    target_url_host = parsed.netloc or target_url or None

    # C13: the run口径 — "passive" when nothing was probed, else the existing active(+passive) split.
    mode = "passive" if passive_only else ("active+passive" if passive else "active")

    # C12: the window the records occupy, for provenance. Normally the scan's own span; but if a
    # PINNED window caught NOTHING, an unfiltered read finds where the records really are — so the
    # citability blocker can hand the operator a window to re-pin (never "compute the ns yourself").
    prov_observed = scan.observed_window
    if pinned and scan.record_count == 0 and args.wal:
        prov_observed = _observed_window_unfiltered(args.wal, args.tenant)

    # 🔴 C15: generated_at_ns is the moment the product is GENERATED — read AFTER the scan, so it is
    # >= every record the window can cover. With --gateway --pin-observed-window the probes CREATE
    # records DURING this run (at times after the source-side now_ns); stamping now_ns instead would
    # make the just-observed window look "in the future" and wrongly block a legitimate citable run.
    generated_at_ns = time.time_ns()

    # E3-n ④ fail-CLOSED — a DECLARED admin endpoint that couldn't be reached is a check that FAILED
    # (not "no claim made"); surface which side + why so it is never silent (citability then blocks).
    if admin_url_declared:
        if build_fp_before_err:
            warnings.append(
                f"build_fingerprint: BEFORE snapshot could not be fetched — {build_fp_before_err}"
            )
        if build_fp_after_err:
            warnings.append(
                f"build_fingerprint: AFTER snapshot could not be fetched — {build_fp_after_err}"
            )
    # E3-n ② — this run's probe span [scan_start, generated_at), half-open; None when nothing was
    # probed. Active rates cite THIS, not observed_window, so a 430-probe number is not read as
    # standing on the whole WAL's (here 16.5h / 7837-record) history.
    probe_window = (
        (scan_start_ns, generated_at_ns)
        if (scan_start_ns is not None and active.probe_count > 0)
        else None
    )

    # 🔴 C2 —— 窗口是不是真的盖住了这一跑自己发的探针。
    #
    # 实证：某一跑里产物声明的件数，与 `probe_window` 内可复算的 type-1 决策记录数【不等】。
    # WAL 完整性 ok、两个数【各自都自洽】—— 声明的 n 来自主动侧逐件 probe 的返回（不经窗口），
    # 窗口内那个数来自按窗口过滤的 WAL。
    # 🔴 于是"按窗口复算得 122、报告写 134"这件事，只在有人去复算的那一天才暴露。
    #
    # ⚠️ 本处【只出声，不改窗口语义】：窗口该怎么定是口径，改它要 PM 落笔。
    #    这里做的是把一个今天无人知晓的不一致变成一条 warning —— 与 `denominator` 那条
    #    「一份对不上的输入，代价应该是零」同族，只是它发生在跑完之后，所以只能出声。
    if probe_window is not None and args.wal:
        covered = _probes_covered_by_window(
            args.wal, args.tenant, probe_window, warnings=warnings
        )
        if covered is not None and covered != active.probe_count:
            warnings.append(
                f"🔴 probe_window 未盖住本跑全部探针：主动侧发了 {active.probe_count} 件，"
                f"而窗口内可复算的决策记录只有 {covered} 件。两个数各自自洽，口径不同 —— "
                "任何【按窗口复算】的人会得到后者，而产物声明的是前者。"
                "不要用窗口复算这一跑，直到这一格查清。"
            )

    bundle = build_bundle(
        measurements,
        tenant_id=args.tenant,
        window=window,
        mode=mode,
        target_kind=target_kind,  # EV-FWD/R1: records WHAT was evaluated (drives availability)
        model=model,  # EV-PAIR §2: the config that determined the numbers, recorded WITH them
        temperature=0.0,  # pinned for the statistical verticals — recorded, not assumed
        target_url_host=target_url_host,
        corpus_sha=active.corpus_sha,
        corpus_set=args.corpus_set,  # 前置3 — derives the offline-recomputability tier
        pinned=pinned,
        provenance=build_provenance(
            policy_snapshots=getattr(active, "policy_snapshots", ()) if active else (),
            wal_dir=args.wal,
            window=window if (pinned or scan.observed_window) else None,
            pinned=pinned,
            tenant_id=args.tenant,
            record_count=scan.record_count,
            # 🔴 本跑读的是哪一条良性臂 —— 随数走的分母构成声明只对 p1 臂成立，
            # 不记它，那条声明要么挂不上、要么挂上就是假话。
            benign_arm=getattr(args, "benign_arm", "") or "",
            observed_window=prov_observed,
            generated_at_ns=generated_at_ns,  # C15: stamped AFTER the scan (see above)
            # E3-h/E3-m §3.1/§5: operator-declared freeze-pack config (empty when not passed).
            # language_scope is the #1 scope axis (declared, never inferred). config_source is
            # "declared" — no queryable version/config endpoint exists yet ("queried" is reserved).
            language_scope=getattr(args, "language_scope", None),
            tested_version=getattr(args, "tested_version", None),
            detect_config=getattr(args, "detect_config", None),
            exec_mode=getattr(args, "exec_mode", None),
            # E3-n ③ — the detection-layer status + the tested party's DECLARED upstream timeout,
            # both folded into the missing_run_config citability criterion.
            detection_layer_status=getattr(args, "detection_layer_status", None),
            upstream_timeout_s=getattr(args, "upstream_timeout_s", None),
            # 🔴 N180 件0 — the judge/τ declaration axes (operator-declared, like language_scope). Absent
            # ⇒ the bundle is not citable (a number that didn't record which τ / path / judge form can't
            # be cited as a product capability). measurement_path IS the assembly axis.
            # 🔴 A2 —— 留出语料【落地那一刻】网关加载的 ruleset_sha256，操作者声明。
            # 不得从本跑推导：material_window_verified 拿它与本跑的 build_fingerprint_before
            # 比，两侧同源就永远 matched（citability.py:995 逐字说明了它比的是哪两个时点）。
            material_ruleset_sha256=args.material_ruleset_sha256,
            # 🔴 A4 —— 语料指纹搬上产物行。机制早在算（ActiveResult.corpus_sha），
            # 而在它落到 provenance 之前，「冻结即不可改」没有任何东西在比对。
            # 🔴 不写 `or None`:{}(跑了但没有 producer)与"这格不存在"在产物上会同形。
            # 空 dict 原样落盘 —— 它说的是"有这一格,而它是空的",与 None 不是一回事。
            corpus_sha=active.corpus_sha,
            judge_form=getattr(args, "judge_form", None),
            measurement_path=getattr(args, "measurement_path", None),
            tau_declared=getattr(args, "tau_declared", None),
            tau_source=getattr(args, "tau_source", None),
            # 🔴 弱门（PM 2026-09-07）—— 判官指纹取没取。三态：None 未声明 · "not_taken" 明确没取 ·
            # {…} 取了。解析在 `resolve_judge_imprint`（0 字节的文件抛错，不降级成 not_taken）。
            judge_imprint=judge_imprint,
            baseline_compared=baseline_compared,
            # E3-n ② — collect does NOT drain the async Tier-2 layer (Platform froze it OFF), so the
            # freeze pack records whether PHASE 2 actually ran: False ⇒ the Tier-2 indicators read
            # n/a, never 0% ("scored below τ" and "we never looked" must not be the same number).
            tier2_drain_executed=active.tier2_drain_executed,
            # E3-n ④ — the before/after build fingerprints (verbatim evidence in the artifact).
            build_fingerprint_before=build_fp_before,
            build_fingerprint_after=build_fp_after,
            # E3-n ④ — whether --admin-url was DECLARED (the claim). Lets citability fail-close a
            # declared-but-unfetched check: both-None blocks only when the endpoint was actually named.
            admin_url_declared=admin_url_declared,
            # E3-n ② — this run's probe span; active rates cite it, passive/census keep observed_window.
            probe_window=probe_window,
            # E3F §4 (F4) — the arm-parity口径 both arms ran on. The curated producers all construct
            # via the zero-arg factory ⇒ DEFAULT_ARM_PARITY for catch AND benign; check_arm_parity
            # asserts that invariant (refusing a mismatched pair, §4.4-4) before it is stamped.
            arm_parity=_run_arm_parity(),
            # F7 (E3F §7.3-③) — the run's canary epoch (sha256-of-salt handle, no plaintext).
            canary_set_id=active.canary_set_id,
            # 🔴 序8 件3 — the guardrail cursor readings (before/after the drain), stored VERBATIM for
            # R5's self-reported-vs-measured cross-check. null when no admin cursor endpoint.
            guardrail_cursor_before=active.guardrail_cursor_before,
            guardrail_cursor_after=active.guardrail_cursor_after,
        ),
    )
    # F7 (E3F §7.4-5) — the collect bundle is a public artifact (aggregates + provenance, no response
    # content), so it must carry ZERO canary plaintext. Fail CLOSED before writing.
    assert_no_canary_plaintext(bundle, where="collect bundle")
    out = args.out or "bundle.json"
    try:
        import json

        Path(out).write_text(
            json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError as e:
        print(f"error: cannot write bundle {out}: {e}", file=sys.stderr)
        return EXIT_IO

    # EV-PAIR-A2 §1: the whole-run guard — SHOUT before the warnings (top of the output) when the
    # run got no model responses at all, and exit non-zero so a script never reads a wasted run as
    # success. A PARTIAL error stays quiet (each indicator already shows its own `N excluded`).
    if all_errored:
        print(
            "🔴 本次运行未取得任何模型响应 —— 指标不可测，非 0%"
            f"（{active.error_count}/{active.probe_count} 探针全部 error）",
            file=sys.stderr,
        )
        print(f"   首个 error: {active.first_error}", file=sys.stderr)
        print(
            "   排查：检查 --target-url / --model / 端点可达性",
            file=sys.stderr,
        )

    for w in warnings:
        print(f"  ⚠ {w}", file=sys.stderr)
    print(
        f"wrote {out}: {len(active.measurements)}/{len(curation_for(args.corpus_set))} active producer(s) + "
        f"{len(passive)} passive measurement(s)",
        file=sys.stderr,
    )
    return EXIT_IO if all_errored else EXIT_OK
