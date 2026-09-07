"""Deterministic JSON serialization of a MaturityReport bundle (EV-7 §1 / EV-R1).

Emits the report-bundle envelope defined in `docs/REPORT_JSON_SCHEMA.md`: the rubric
verdict PLUS the measurements that fed it (the report stores only pass/fail, the UI wants
both). Pure — `json`/`hashlib` + the frozen dataclasses + the canonical registry serializer
(`treval.registry.serialize`). The engine NEVER imports the web layer (tests/test_layering.py).

Determinism (the EV-7 byte-identical requirement): object keys sorted, and every array
has a DEFINED order independent of insertion — `dimensions`/`objectives` in the engine's
(registry) order, `measurements` by `(indicator_id, subject)`, `evidence_refs` by
`(source, seq)`, `gaps` already sorted by the engine.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

from treval.citability import (
    FPR_DISCLOSURE_IDS as _FPR_IDS,
    DECISION_STAGE_BLIND_IDS,
    FPR_PER_TENANT_ONLY,
    decision_fpr_measurability,
    ruleset_pin,
    decision_fpr_refusal,
    derive_family_c_coreport,
    CRITERIA_VERSION,
    FAMILY_C_MARKER,
    FAMILY_C_COREPORT_FIX,
    FAMILY_C_SUBJECT,
    JUDGE_COREPORT_FIX,
    assert_judge_coreport_derived,
    citation_form,
    derive_judge_coreport,
    report_citability,
    run_config_note,
)
from treval.models import (
    DimensionReport,
    EvidenceRef,
    MaturityReport,
    Measurement,
    ObjectiveResult,
)
from treval.registry import DimensionRegistry, serialize_registry

# 🔴 6: each measurement gains `excluded_count` / `arm_size` — 仪器损耗。Wilson 覆盖抽样、不覆盖
# 「臂丢了大半」;两者区间相同而处置相反,所以它必须是结构化字段,不能只活在 notes 的散文里。
# 🔴 7: `not_measured_count` / `stage_blocked_count` —— 缺口的另外两种理由。v6 只结构化了
# 仪器损耗那一种,于是修好 extract_error 后那批件挪进 stage_blocked,arm_size 缩成存活子集、
# excluded_count 归 0,报出来是一句自称量了整条臂的干净比率。缺口有几种理由就得有几个具名字段。
# 🔴 8: `sample_unit` —— 分母数的是请求还是会话。与 `unit`（值的量纲）是两根轴：
# 单轮件被软标记一次，一个 4 轮会话可能被标 4 次，两个率的差值没有意义，
# 而它们在一张表里长得一模一样 ⇒ 渲染面据此【分表】，不靠人记得那条禁令。
SCHEMA_VERSION = 8

# --- R1 — target_kind (report-level) + evidence_basis (DERIVED, single source of truth) ---
# target_kind names WHAT was evaluated; evidence_basis is its evidence strength and is NEVER
# stored independently — it is computed from target_kind here (R1 裁定 A). A new target_kind is
# ONE row below; do NOT invent an evidence_basis input. (`availability`/`evidence_requirement`
# are EV-FWD, not R1 — see R1 §1.5-A.)
TARGET_KINDS = ("raw_model", "gateway", "moderation_api")
DEFAULT_TARGET_KIND = "gateway"  # every current report is a gateway run (R1 §1.5-B)

_EVIDENCE_BASIS = {
    "gateway": "wal_anchored",  # WAL 锚定 · 可复算 · 最强
    "raw_model": "harness_observed",  # harness 自观测 · 中
    "moderation_api": "self_reported",  # 厂商自报 · 最弱 · 不可复算
}


def derive_evidence_basis(target_kind: str) -> str:
    """The evidence strength implied by a target_kind — the single source of truth for
    evidence_basis (R1 裁定 A). Fail-closed on an unknown target_kind so a typo cannot
    silently ship a bundle with no evidence tier."""
    try:
        return _EVIDENCE_BASIS[target_kind]
    except KeyError:
        raise ValueError(
            f"unknown target_kind {target_kind!r}; expected one of {TARGET_KINDS}"
        ) from None


def assert_evidence_basis_derived(target_kind: str, evidence_basis: str) -> None:
    """Machine gate (R1 §2): a bundle's evidence_basis MUST equal derive(target_kind). The
    serializers always compute it that way; this guards a future regression that reintroduces
    independent setting (a param / a stored field) — such a bundle FAILS here instead of
    silently shipping a mislabelled evidence tier. 靠门不靠人。"""
    expected = derive_evidence_basis(target_kind)
    if evidence_basis != expected:
        raise ValueError(
            f"evidence_basis {evidence_basis!r} != derive({target_kind!r})={expected!r} "
            "— evidence_basis is derived from target_kind, never stored independently "
            "(R1 裁定 A)"
        )


# --- EV-FWD — availability (indicator-level), DERIVED from (evidence_requirement × target_kind) ---
# `availability` answers "can this indicator be MEASURED in this mode?" (mechanism axis) — a
# SEPARATE, orthogonal axis from `evidence_basis`, which answers "how trustworthy / reproducible
# is what was measured?" (evidence axis). A "measurable-but-not-auditable" indicator is
# `measured` + a weaker `evidence_basis`, NEVER `n/a` (EV-FWD §0.1). Like `evidence_basis`,
# `availability` is a serialization overlay with a single source of truth — never stored
# independently, always derived. The rubric grading is untouched.
EVIDENCE_REQUIREMENTS = ("output_only", "needs_decision", "needs_wal")
# 🔴 `n/a_no_upstream` 是第四个值(2026-09-05)。此前这张表把 "gateway" 当成【一种】东西,
# 而它其实有两种:带真上游的、挂 echo 转发器的。后者【测不了】任何 output_only 指标 ——
# 模型根本不产出正文,`system_prompt_leak_rate` 之类会永久报 0.0 并盖 integrity: verified。
# 那正是 Platform 想把 compose 默认翻成 echo 时会造出的【永久空绿】,而根源不是缺一个新字段,
# 是这一格无条件写了 measured。⇒ 修在这里,不新增臂级的 requires_forwarder(那会是第三处说同一件事)。
AVAILABILITY_VALUES = (
    "measured",
    "n/a_needs_gateway",
    "n/a_self_reported",
    "n/a_no_upstream",
)
NO_UPSTREAM = "n/a_no_upstream"

# (evidence_requirement × target_kind) → availability (EV-FWD §5). For `gateway` EVERY
# requirement is `measured` (the governed path produces every kind of evidence). Under a
# non-gateway target, `output_only` still measures (harness reads the response itself), while
# `needs_decision` / `needs_wal` are architecturally absent: `n/a_needs_gateway` for a bare model
# (§5), `n/a_self_reported` for a moderation API (no WAL, and "缺网关" would misname a
# vendor-self-report absence — §5.1).
_AVAILABILITY: dict[tuple[str, str], str] = {
    ("output_only", "gateway"): "measured",
    ("output_only", "raw_model"): "measured",
    ("output_only", "moderation_api"): "measured",
    ("needs_decision", "gateway"): "measured",
    ("needs_decision", "raw_model"): "n/a_needs_gateway",
    ("needs_decision", "moderation_api"): "n/a_self_reported",
    ("needs_wal", "gateway"): "measured",
    ("needs_wal", "raw_model"): "n/a_needs_gateway",
    ("needs_wal", "moderation_api"): "n/a_self_reported",
}


def derive_availability(
    target_kind: str, evidence_requirement: str | None, *, has_upstream: bool = True
) -> str:
    """The availability of an indicator on a target — the single source of truth (EV-FWD §5).

    `evidence_requirement` is the indicator's declared need (see active_eval's
    EVIDENCE_REQUIREMENTS). `None` means "not one of the classified indicators": that must NEVER
    silently claim `measured` on a non-gateway target, so it defaults to the CONSERVATIVE
    `needs_wal` (a gateway run still resolves to `measured`; a standalone run to n/a). Fail-closed
    on an unknown target_kind so a typo cannot ship a bundle with a bogus availability."""
    req = evidence_requirement or "needs_wal"
    # 🔴 无上游(echo 转发器)⇒ output_only 指标【测不了】,不许判 measured。
    # 这是【声明】的,不从空响应体推断 —— 推断会让一个真坏了的上游把自己重贴成"哦,本来就没上游"。
    # 决策侧指标不受影响:它们在转发之前就判完了,那正是 echo 栈存在的理由。
    if not has_upstream and req == "output_only":
        return NO_UPSTREAM
    try:
        return _AVAILABILITY[(req, target_kind)]
    except KeyError:
        raise ValueError(
            f"cannot derive availability for (target_kind={target_kind!r}, "
            f"evidence_requirement={req!r}); target_kind must be one of {TARGET_KINDS} "
            f"and requirement one of {EVIDENCE_REQUIREMENTS}"
        ) from None


def assert_availability_derived(
    target_kind: str, evidence_requirement: str | None, availability: str
) -> None:
    """Machine gate (EV-FWD §5, mirrors assert_evidence_basis_derived): a serialized
    `availability` MUST equal derive(). Guards a future regression that stores it independently
    — such a bundle FAILS here rather than shipping a mislabelled availability. 靠门不靠人。"""
    expected = derive_availability(target_kind, evidence_requirement)
    if availability != expected:
        raise ValueError(
            f"availability {availability!r} != derive(target_kind={target_kind!r}, "
            f"requirement={evidence_requirement!r})={expected!r} — availability is derived, "
            "never stored independently (EV-FWD §5)"
        )


# --- EV-CN-BASELINE 前置3 — offline-recomputability (per-measurement), DERIVED from the corpus SET ---
# Can a THIRD PARTY re-run this measurement offline? It depends ONLY on where the corpus lives: the public
# in-repo corpus (`en`) is fetchable by anyone ⇒ third_party_recomputable; the out-of-repo controlled
# batch (`cn`) is not ⇒ holder_only. This is `corpus_sha`'s sibling (§1.3 "与 corpus_sha 同源"): the sha
# pins the CONTENT, this pins WHO CAN RE-RUN it. Like evidence_basis it is a DERIVED overlay with a SINGLE
# source (the corpus set), never a stored, independently-writable field — a second truth source would
# drift and no one would know which to trust (架构师裁定 ①). `ruleset_sha256` pins the rule and cannot
# pin the input; `corpus_sha` pins the content and cannot pin "who can re-run it" — capability claims must
# be split, never one field moonlighting for two (Platform 的同形理由).
OFFLINE_THIRD_PARTY = "third_party_recomputable"
OFFLINE_HOLDER_ONLY = "holder_only"
_OFFLINE_RECOMPUTABLE: dict[str, str] = {
    "en": OFFLINE_THIRD_PARTY,
    "cn": OFFLINE_HOLDER_ONLY,
    # 🔴 W6 业务伪装诊断臂在【仓外受控卷】⇒ holder_only,与 cn 同理由。
    # 本行是被这道门逼出来的:加 corpus-set 时只改了 CORPUS_SETS,出包时它 fail-closed 拦下 ——
    # 拦的正是"把一个仓外语料的数标成第三方可复现"。门做对了,漏的是加集合的人(我)。
    "w6": OFFLINE_HOLDER_ONLY,
    # 🔴 W2 英文良性留出臂同样在【仓外受控卷】⇒ holder_only。
    # 这道门第二次拦住同一个人（我）——它是本仓少数几处"加东西时逼你回答一个问题"的地方之一，
    # 而那个问题（第三方复算得了吗）恰恰是加集合的人最容易不想的。
    "w2": OFFLINE_HOLDER_ONLY,
    # 🔴 `inj` 跑的是【仓内】注入臂（corpus/llm01_prompt_injection），第三方拿到本仓就能复算
    # ⇒ third_party，与 `en` 同档。分母由 `--denominator-manifest` 的判据产生，而那份清单
    # 也可随产物给出（它自带 sha256）—— 复算所需的两样都在。
    "inj": OFFLINE_THIRD_PARTY,
}


def derive_offline_recomputable(corpus_set: str) -> str:
    """The offline-recomputability tier implied by a corpus SET — the single source of truth (前置3).
    Fail-closed on an unknown set so a typo cannot silently ship a number labelled reproducible when its
    corpus is out-of-repo (the exact mislabel §1.3 exists to prevent)."""
    try:
        return _OFFLINE_RECOMPUTABLE[corpus_set]
    except KeyError:
        raise ValueError(
            f"cannot derive offline_recomputable for corpus_set={corpus_set!r}; expected one of "
            f"{tuple(_OFFLINE_RECOMPUTABLE)}"
        ) from None


def assert_offline_recomputable_derived(corpus_set: str, marker: str) -> None:
    """Machine gate (前置3, mirrors assert_evidence_basis_derived): a stamped offline_recomputable MUST
    equal derive(corpus_set). Guards a future regression that stores it independently — such a bundle
    FAILS here rather than shipping a number whose 'a third party can re-run it' claim is a hand-written
    lie. 靠门不靠人。"""
    expected = derive_offline_recomputable(corpus_set)
    if marker != expected:
        raise ValueError(
            f"offline_recomputable {marker!r} != derive(corpus_set={corpus_set!r})={expected!r} — it "
            "is DERIVED from the corpus set, never stored independently (EV-CN-BASELINE 前置3)"
        )


def assert_recomputability_labeled(markers: Iterable[str | None]) -> None:
    """🔴 前置3 / §7-3b — a report that MIXES offline-recomputable classes (in-repo vs holder-only) must
    label EVERY measurement, or a reader takes the whole table as reproducible. RED iff the report mixes
    classes AND any measurement is UNLABELED (可复算与不可复算两类并排而无标注). A single-class report,
    or a FULLY-labelled mix, passes — the point is that the mix is never SILENT."""
    seen = list(markers)
    labeled = {m for m in seen if m}
    unlabeled = any(not m for m in seen)
    mixed = len(labeled) >= 2 or (bool(labeled) and unlabeled)
    if mixed and unlabeled:
        raise ValueError(
            "report mixes offline-recomputable classes but some measurements carry NO label "
            "(EV-CN-BASELINE 前置3 / §7-3b): 可复算与不可复算两类并排而无标注 ⇒ 读者会把整表当可复算"
        )


def _ref_sort_key(ref: EvidenceRef) -> tuple[str, bool, int, str]:
    """Total order over refs (seq may be None → sorts last within a source)."""
    return (ref.source, ref.seq is None, ref.seq or 0, ref.request_id or "")


def _serialize_ref(ref: EvidenceRef) -> dict[str, Any]:
    return {"source": ref.source, "seq": ref.seq, "request_id": ref.request_id}


def _serialize_refs(refs: tuple[EvidenceRef, ...]) -> list[dict[str, Any]]:
    return [_serialize_ref(r) for r in sorted(refs, key=_ref_sort_key)]


def _serialize_objective(obj: ObjectiveResult) -> dict[str, Any]:
    return {
        "objective_id": obj.objective_id,
        "kind": obj.kind,
        "status": obj.status,
        "evidence_refs": _serialize_refs(obj.evidence_refs),
    }


def _serialize_dimension(dim: DimensionReport) -> dict[str, Any]:
    return {
        "dimension": dim.dimension,
        "measured_ceiling": dim.measured_ceiling,
        "attested_ceiling": dim.attested_ceiling,
        "awarded_level": dim.awarded_level,
        # EV-CITE 件二: the kind of `None` + the fact that must ride with it (a null ceiling has two
        # very different meanings — "measured, below the line" vs "not produced this run").
        "measured_state": dim.measured_state,
        "measured_breakpoint": dim.measured_breakpoint,
        "measured_gap": list(dim.measured_gap),
        "objectives": [_serialize_objective(o) for o in dim.objectives],
        "gaps": list(dim.gaps),
    }


def serialize_report(report: MaturityReport) -> dict[str, Any]:
    """The `report` half of the bundle (REPORT_JSON_SCHEMA §2)."""
    return {
        "tenant_id": report.tenant_id,
        "window": list(report.window),
        "dimensions": [_serialize_dimension(d) for d in report.dimensions],
        "integrity_summary": dict(report.integrity_summary),
        "verification_basis": report.verification_basis,
    }


def serialize_measurement(
    m: Measurement,
    *,
    target_kind: str,
    evidence_requirements: Mapping[str, str] | None = None,
    has_upstream: bool = True,
) -> dict[str, Any]:
    """A `measurements[]` entry. `integrity` (EV-7 D1) rides along so the UI can show the
    trust basis of each value without a live call. `availability` (EV-FWD) is DERIVED from
    (this indicator's declared evidence_requirement × target_kind) — the honest per-indicator
    "does this dimension exist in this mode?" mark. `evidence_requirements` maps
    indicator_id → requirement; an id absent from it resolves conservatively (see
    derive_availability).

    🔴 `target_kind` is REQUIRED — no default. A DEFAULT here would turn "a caller forgot to
    thread target_kind" into "silently claims gateway ⇒ measured", which is exactly the EV-FWD
    live bug (cli/bundle.py forgot it and a raw_model run was mislabelled `measured`). Missing
    ⇒ TypeError, loud, at the call site — not a wrong availability shipped in a bundle."""
    req = None
    if evidence_requirements is not None:
        req = evidence_requirements.get(m.indicator_id)
    availability = derive_availability(target_kind, req, has_upstream=has_upstream)
    assert_availability_derived(
        target_kind, req, availability
    )  # single source of truth
    return {
        "indicator_id": m.indicator_id,
        "dimension": m.dimension,
        "value": m.value,
        "unit": m.unit,
        "sample_size": m.sample_size,
        "subject": m.subject,
        "notes": m.notes,
        "integrity": m.integrity.value,
        "availability": availability,
        # EV-CIGATE §7-A — the Wilson interval rides WITH the value so a consumer can see "point
        # estimate crossed the line, lower bound did not". 🔴 null (not 0/1) when the indicator is
        # not a binomial proportion — a `ci_low >= τ` gate over null RAISES, never silently grades.
        "ci_low": m.ci_low,
        "ci_high": m.ci_high,
        # EV-CITE 件一 (review): the interval MECHANISM must ride with the product, not just the
        # in-memory object — else the collect→report round-trip loses it and citation_form falls back.
        # "" (a detector / non-rate) is honest; a census / total_function declares its class.
        "interval_basis": m.interval_basis,
        # 🔴 仪器损耗必须随产物走,否则 collect→report 一个来回就只剩 notes 里的散文,
        # 而下游无法区分【小臂】与【大臂丢了大半】—— 两者的 Wilson 区间相同、处置相反。
        # null = 该指标未声明排除口径;0 = 量过没排除;>0 = value 的作用域是存活子集。
        "excluded_count": m.excluded_count,
        "arm_size": m.arm_size,
        # 🔴 v7 —— 缺口的另外两种理由。少了它们,arm_size 与 sample_size 之差就只是一个数,
        # 读者得自己猜是该补件、该换读法、还是该修仪器（三者处置相反）。
        "not_measured_count": m.not_measured_count,
        "stage_blocked_count": m.stage_blocked_count,
        # 🔴 v8 —— 样本单位必须随产物走：拒绝并表的门在【消费侧】，读不到它就没法拒绝。
        "sample_unit": m.sample_unit,
        "evidence_refs": _serialize_refs(m.evidence_refs),
    }


def serialize_bundle(
    report: MaturityReport,
    measurements: Iterable[Measurement],
    *,
    target_kind: str = DEFAULT_TARGET_KIND,
    evidence_requirements: Mapping[str, str] | None = None,
    has_upstream: bool = True,
) -> dict[str, Any]:
    """The full report bundle: `{schema_version, target_kind, evidence_basis, report,
    measurements}`. `target_kind` (report-level, R1) names what was evaluated; `evidence_basis`
    is DERIVED from it, never an input. Each measurement's `availability` (EV-FWD) is likewise
    derived from (target_kind × the indicator's evidence_requirement). Measurements are sorted
    by `(indicator_id, subject)` for a stable array order (REPORT_JSON_SCHEMA §3)."""
    ordered = sorted(measurements, key=lambda m: (m.indicator_id, m.subject))
    evidence_basis = derive_evidence_basis(target_kind)
    assert_evidence_basis_derived(target_kind, evidence_basis)  # single source of truth
    return {
        "schema_version": SCHEMA_VERSION,
        "target_kind": target_kind,
        "evidence_basis": evidence_basis,
        "report": serialize_report(report),
        "measurements": [
            serialize_measurement(
                m,
                target_kind=target_kind,
                evidence_requirements=evidence_requirements,
                has_upstream=has_upstream,
            )
            for m in ordered
        ],
    }


def bundle_to_json(
    report: MaturityReport,
    measurements: Iterable[Measurement],
    *,
    target_kind: str = DEFAULT_TARGET_KIND,
    evidence_requirements: Mapping[str, str] | None = None,
    has_upstream: bool = True,
) -> str:
    """Byte-identical (up to encoding) JSON for the bundle: sorted keys + compact, stable
    separators. `ensure_ascii=False` keeps the Chinese statements readable; UTF-8 encode
    for on-disk bytes."""
    return json.dumps(
        serialize_bundle(
            report,
            measurements,
            target_kind=target_kind,
            evidence_requirements=evidence_requirements,
            has_upstream=has_upstream,
        ),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )


# --------------------------------------------------------------------------- #
# EV-R1 — the self-contained DELIVERY bundle: report + inline registry +
# measurements + a registry fingerprint, so the UI renders the 5×5 grid AND the
# value column (the objective→value join runs through the registry) from ONE file.
# Assembly at serialize time only — the engine dataclasses are unchanged.
# --------------------------------------------------------------------------- #


def _fingerprint_of(registry_dict: dict[str, Any]) -> str:
    """sha256 over a registry's canonical (sorted-key, compact) serialization — the
    mismatch-detection handle the decoupled path uses (EV-R1 §1)."""
    canonical = json.dumps(
        registry_dict, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def registry_fingerprint(registry: DimensionRegistry) -> str:
    """The `registry_fingerprint` for a loaded registry (EV-R1 §1). EV-W1 compares this to
    the registry it loaded and warns on mismatch; within a self-contained bundle it is
    redundant (the registry is inlined) but kept for the future decoupled path."""
    return _fingerprint_of(serialize_registry(registry))


def serialize_self_contained_bundle(
    report: MaturityReport,
    measurements: Iterable[Measurement],
    registry: DimensionRegistry,
    provenance: dict[str, Any] | None = None,
    *,
    target_kind: str = DEFAULT_TARGET_KIND,
    evidence_requirements: Mapping[str, str] | None = None,
    has_upstream: bool = True,
) -> dict[str, Any]:
    """The EV-R1 delivery envelope `{schema_version, target_kind, evidence_basis,
    registry_fingerprint, provenance, report, registry, measurements}`
    (docs/REPORT_JSON_SCHEMA.md §1a). `target_kind`/`evidence_basis` (R1) ride the SAME
    derivation as `serialize_bundle` (one source of truth); each measurement's `availability`
    (EV-FWD) is derived from (target_kind × evidence_requirement). The registry is inlined via the
    EV-W0 serializer so the UI loads one file and never mis-pairs parts. `report`/`measurements`
    are the EV-7 shapes, unchanged."""
    registry_dict = serialize_registry(registry)
    materialized = tuple(measurements)
    base = serialize_bundle(
        report,
        materialized,
        target_kind=target_kind,
        evidence_requirements=evidence_requirements,
        # 🔴 无上游(echo)时 output_only 指标判 n/a_no_upstream 而不是 measured ——
        # 否则泄漏类指标会永久报 0.0 并盖 integrity: verified(一个永久空绿)。
        has_upstream=has_upstream,
    )
    # EV-CITE 件一: the citability gate lives ON the delivery artifact — the only envelope that
    # carries `provenance` (pinned / segment hash), so it is the only one that can judge whether a
    # number may leave the room. Disclosure, not refusal: the bundle is emitted either way.
    citable, citable_blockers = report_citability(
        {
            "evidence_basis": base["evidence_basis"],
            "provenance": provenance,
            "report": base["report"],
        }
    )
    # 件一 §1.4: each measurement gets a paste-whole `citation_form` (n + interval, or "普查", per
    # mechanism) computed here where provenance + the citable verdict are known. Same sort order as
    # serialize_bundle so it zips 1:1 onto the serialized rows.
    pred_by_indicator = {
        obj.evidence.indicator_id: obj.evidence.satisfied_when
        for dim in registry.dimensions.values()
        for level in dim.levels.values()
        for obj in level
        if obj.evidence.kind == "measured" and obj.evidence.indicator_id
    }
    pinned = bool(provenance and provenance.get("pinned"))
    window = provenance.get("window") if provenance else None
    # E3-n ② — the ACTIVE rates (catch / FPR / four-cell / success — any indicator whose
    # evidence_requirement is NOT needs_wal) cite THIS run's probe span, so a 430-probe number is not
    # read as standing on the whole WAL's history. Passive / census (needs_wal) keep observed_window.
    probe_window = provenance.get("probe_window") if provenance else None
    first_blocker = citable_blockers[0] if citable_blockers else None
    config_note = run_config_note(
        provenance
    )  # E3-h: the freeze-pack config, once per run
    # 🔴 法务 2026-09-05 — 报数必须印 ruleset_sha256。算一次（run 级事实，同 config_note），
    # **挂在哪个 id 上由 citation_form 决定** —— 键控集中在 citability.py，不在这里分叉。
    ruleset_note = ruleset_pin(provenance)
    # 🔴 本跑读的是哪一条良性臂 —— 分母构成声明只对 p1 臂成立，必须按臂键控（citability 侧决定挂不挂）。
    benign_arm = (provenance or {}).get("benign_arm") or ""
    # 🔴 EV-JUDGE-UNION 件2 — the co-report gate is PER-MEASUREMENT (not the whole-report verdict): a judge-
    # movable number published without the mention-arm twin is not_citable ON ITS OWN, even in an otherwise
    # citable report. Derived from the ids actually present, asserted (derive-not-store).
    # 🔴 EV-JUDGE-UNION 件5 — under Tier-2 enforce the DECISION-stage FPR is blind to an entire class of
    # blocks, so it must stop emitting a number: the under-count it would report is indistinguishable, in
    # the number, from the system genuinely performing well.
    _fpr_refusal = decision_fpr_refusal(provenance)
    _fpr_verdict = decision_fpr_measurability(provenance)
    _present_ids = {m.indicator_id for m in materialized}
    judge_blocked = derive_judge_coreport(_present_ids)
    assert_judge_coreport_derived(_present_ids, judge_blocked)
    # 🔴 EV-EN-BENIGN-HOLDOUT — 族 C is in the FPR denominator, so its own stratified row must be present.
    # Derived from the subjects actually in the product; blocks ONLY the whole-arm English FPR (the row's
    # absence is what makes that number unreadable), never the CN stratum or the row itself.
    # 🔴 the trigger is "族 C is IN this product's denominator", read from the family-C row's own presence
    # being REQUIRED once any case of it was measured — signalled by the run declaring the stratum at all.
    # A product with no family-C cases at all is unaffected (nothing to co-report).
    _subjects = {m.subject for m in materialized}
    _family_c_in_denominator = any(
        m.notes and FAMILY_C_MARKER in m.notes for m in materialized
    )
    _family_c_missing = _family_c_in_denominator and derive_family_c_coreport(_subjects)
    for m, row in zip(
        sorted(materialized, key=lambda x: (x.indicator_id, x.subject)),
        base["measurements"],
    ):
        _req = (
            evidence_requirements.get(m.indicator_id) if evidence_requirements else None
        )
        # E3-n ② — ACTIVE rates (probe-driven: needs_decision / output_only) cite probe_window; the
        # passive & census indicators (needs_wal, OR unclassified ⇒ None ⇒ they read the whole WAL, not
        # just this run's probes) keep observed_window. 🔴 Key on the ACTIVE set, not `== needs_wal`:
        # the census indicators (chain_integrity / unclosed_loop / duration_p99 / terminal_error) map to
        # None, so a `needs_wal`-only check would wrongly hand them probe_window.
        _active = _req in ("needs_decision", "output_only")
        _window = probe_window if (_active and probe_window) else window
        # 🔴 件2 — a judge-movable measurement missing its mention-arm twin is not_citable on its own; its
        # blocker is the co-report reason (indicator-specific), overriding the report-level verdict here.
        _jb = m.indicator_id in judge_blocked
        # 🔴 族 C co-report: the WHOLE-ARM English FPR is not citable while family C sits in its
        # denominator without its own row. The family-C row itself, and the CN stratum, are untouched.
        _fc = (
            _family_c_missing
            and m.indicator_id in _FPR_IDS
            and m.subject not in (FAMILY_C_SUBJECT, "language:zh")
        )
        # 件5 — refuse the decision-stage FPR entirely (blind everywhere), or refuse only the GLOBAL row
        # (blind on some tenants ⇒ the number must be split, not voided). 🔴 A per-tenant row is fine.
        # 🔴 盲区管的是【所有只读决策阶段的良性侧率】，不只 FPR —— benign_session_disruption_rate
        # 同样读 denied_at_decision。用 _FPR_IDS 会把它漏掉，而它漏掉的后果比 FPR 更重：对一个
        # 误伤率来说，enforce 藏起来的正是被测的东西。
        _enforce_blind = (
            bool(_fpr_refusal) and m.indicator_id in DECISION_STAGE_BLIND_IDS
        )
        if _enforce_blind and _fpr_verdict == FPR_PER_TENANT_ONLY:
            _enforce_blind = not m.subject.startswith("tenant:")
        row["citation_form"] = citation_form(
            m,
            pinned=pinned,
            window=_window,
            evidence_basis=base["evidence_basis"],
            citable=citable and not _jb and not _fc and not _enforce_blind,
            first_blocker=(
                _fpr_refusal
                if _enforce_blind
                else JUDGE_COREPORT_FIX
                if _jb
                else FAMILY_C_COREPORT_FIX
                if _fc
                else first_blocker
            ),
            satisfied_when=pred_by_indicator.get(m.indicator_id),
            config_note=config_note,
            ruleset_note=ruleset_note,
            benign_arm=benign_arm,
        )
    return {
        "schema_version": base["schema_version"],
        "target_kind": base["target_kind"],
        "evidence_basis": base["evidence_basis"],
        "citable": citable,
        "citable_blockers": citable_blockers,
        # 🔴 C16 — the criteria version the verdict above was judged under, written in the SAME dict
        # so a verdict can never be serialized without it. A reader (and the web view) recompute
        # under the CURRENT version and, on disagreement, know it is criteria drift, not data change.
        "citability_criteria": CRITERIA_VERSION,
        "registry_fingerprint": _fingerprint_of(registry_dict),
        # EV-PIN §1.5-1: the pin stamp must reach the DELIVERY artifact, not stop at the
        # collect bundle. Without it a `window=0-0` snapshot is indistinguishable from a
        # pinned run on the wire, and §1.4's "don't cite unpinned" has nothing to check.
        # `None` is honest — a pre-EV-PIN bundle genuinely has no provenance; never invent
        # a window or sha to fill the hole.
        "provenance": provenance,
        "report": base["report"],
        "registry": registry_dict,
        "measurements": base["measurements"],
    }


def self_contained_bundle_to_json(
    report: MaturityReport,
    measurements: Iterable[Measurement],
    registry: DimensionRegistry,
    provenance: dict[str, Any] | None = None,
    *,
    target_kind: str = DEFAULT_TARGET_KIND,
    evidence_requirements: Mapping[str, str] | None = None,
    has_upstream: bool = True,
) -> str:
    """Byte-deterministic JSON for the self-contained bundle (sorted keys + compact
    separators + ensure_ascii=False). This is the golden-fixture / delivery form."""
    return json.dumps(
        serialize_self_contained_bundle(
            report,
            measurements,
            registry,
            provenance,
            target_kind=target_kind,
            evidence_requirements=evidence_requirements,
        ),
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
