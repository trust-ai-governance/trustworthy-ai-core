"""Core data model for the open evaluation engine (treval).

Pure data only — frozen dataclasses + one enum, no logic and no I/O. The field
shapes are the contract surface defined in EVAL_ARCHITECTURE §2.1 (evidence),
§2.2 (measurement) and §2.4 (report). Downstream layers (readers, indicators,
the rubric engine, the web layer) build on these types; this module imports
nothing from them, nor from the closed platform.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # The decoded ir-spec audit proto. Type-only import: treval never decodes a
    # record itself (that is the WAL/Postgres readers' job), so no runtime
    # protobuf dependency is pulled in here.
    from trustworthy_ai.v1.request_context_pb2 import RequestContext


class IntegrityStatus(enum.Enum):
    """Trust basis of one piece of evidence (EVAL_ARCHITECTURE §2.1)."""

    VERIFIED = "verified"  # hash chain + CRC + seq continuity all pass
    UNVERIFIED = "unverified"  # source can't be chain-checked (e.g. index reader)
    BROKEN = "broken"  # tamper/corruption detected


# EV-CIGATE §1.5 — the mechanism class that decides whether a value gets an interval, and (when it
# does not) WHY. 🔴 A machine-parseable home for the three-way (EV-CITE 件一 review): `ci is None`
# alone conflates the last two — a census has no sampling uncertainty; a default-deny total function
# has uncertainty, but it lives in COVERAGE (allow-list holes), not in a rate. The INDICATOR declares
# this (it alone knows its mechanism) and it rides on the Measurement so `citation_form` picks its
# wording by declaration, never by the `ci is None` proxy.
INTERVAL_SAMPLED = "sampled"  # open-space partial detector — carries a Wilson interval
INTERVAL_TOTAL_FUNCTION = (
    "total_function"  # default-deny total function — no interval; residual = coverage
)
INTERVAL_CENSUS = "census"  # full enumeration of the window — no sampling uncertainty
# The no-interval mechanisms an indicator MUST declare (a partial detector declares by attaching ci).
INTERVAL_NO_CI_BASES = frozenset({INTERVAL_TOTAL_FUNCTION, INTERVAL_CENSUS})


@dataclass(frozen=True)
class EvidenceRef:
    """Back-pointer so every Measurement traces to its source records."""

    source: str  # "wal:/mnt/wal/..." | "export:audit.db" | "attest:posture.yaml"
    seq: int | None = None  # WAL seq, when applicable
    request_id: str | None = None


@dataclass(frozen=True)
class AuditEvidence:
    """One decoded audit record (RequestContext), source-agnostic."""

    ref: EvidenceRef
    integrity: IntegrityStatus
    tenant_id: str
    received_at_ns: int
    record: RequestContext  # the decoded ir-spec proto


@dataclass(frozen=True)
class PostureEvidence:
    """One attested posture fact (always attested, never measured)."""

    ref: EvidenceRef
    tenant_id: str
    key: str  # e.g. "security.sso_mfa_enabled"
    value: str  # attested value
    attested_by: str  # signer identity (operator accountability)
    attested_at_ns: int


# 🔴 `sample_unit` 的取值域 —— 分母数的是什么。它是【判据】不是自由文本：
# 拒绝并表的门按它比对，一个拼错的词会让两个不可比的数当成同一单位放过去。
# 新增一个单位是一次有意的决定（要同时回答"它和已有的哪些能并表"），所以这里是白名单不是校验正则。
SAMPLE_UNITS = ("request", "session")


class MixedSampleUnitError(Exception):
    """把不同 `sample_unit` 的 measurement 放进了同一张表 / 同一次比较。

    🔴 为什么是异常而不是警告：单轮件被软标记一次，一个 4 轮会话可能被标 4 次 ——
    两个率的差值没有意义，而它们在一张表里长得**一模一样**。禁令写在别处、
    靠人记得，等于不存在（本轮反复实证）。所以由结构拦，不由注意力拦。
    """


def assert_single_sample_unit(measurements: Iterable[Measurement], where: str) -> str:
    """同一张表 / 同一次比较里的 measurement 必须同单位。返回那个单位（空集 ⇒ 默认 request）。

    调用点就是"哪里算一张表"的定义 —— 所以它是个显式函数，不是渲染器里的一个 if：
    加一个新的并排展示面，就必须在那里回答一次这个问题。"""
    units = {m.sample_unit for m in measurements}
    if len(units) > 1:
        by_unit = {
            u: sorted({m.indicator_id for m in measurements if m.sample_unit == u})
            for u in sorted(units)
        }
        raise MixedSampleUnitError(
            f"{where}: 同一张表里出现了多个样本单位 {sorted(units)} —— "
            + "；".join(f"{u}: {', '.join(ids)}" for u, ids in by_unit.items())
            + "。分母数的东西不同，两个数的差值没有意义 ⇒ 分表，不要并表"
        )
    return units.pop() if units else "request"


@dataclass(frozen=True)
class Measurement:
    """The smallest unit of interpretation: a normalized, evidence-backed signal."""

    indicator_id: str
    dimension: str  # one of the 5 dimension ids
    value: float  # normalized signal
    unit: str  # "ratio" | "count" | "tokens" | "ms" ...
    sample_size: int  # records backing it (0 = insufficient data)
    evidence_refs: tuple[EvidenceRef, ...]  # MUST be populated — auditability
    subject: str = ""  # per-entity key (e.g. agent_id); "" = aggregate
    notes: str = ""
    # Trust basis of THIS signal: the weakest integrity (min) over its backing
    # evidence, set by the indicator (EV-7 D1). The rubric engine reads it to fill
    # verification_basis and to gate `requires_integrity` objectives — a Measurement
    # loses the per-record IntegrityStatus once aggregated, so it must be carried
    # here. Defaults VERIFIED: every current indicator reads chain-verified WAL; the
    # UNVERIFIED (Postgres index) path lands with EV-2.
    integrity: IntegrityStatus = IntegrityStatus.VERIFIED
    # EV-CIGATE §7-A — the 95% Wilson interval of THIS value WHEN it is a binomial proportion (k/n),
    # so an objective can gate on "we are statistically sure" (ci_low >= τ) instead of a point
    # estimate that only crossed the line by luck. 🔴 None = "no interval", NOT 0/1: a non-rate
    # indicator (duration_p99, a count) or a deterministic census (chain_integrity) leaves these None,
    # and a `ci_low >= τ` gate over a None interval RAISES rather than silently passing/failing
    # (EV-CIGATE §7-B). The INDICATOR fills them (only it knows the value is a proportion — §7-A
    # invariant 2); the engine NEVER infers them from unit.
    ci_low: float | None = None
    ci_high: float | None = None
    # EV-CIGATE §1.5 mechanism class (INTERVAL_SAMPLED / _TOTAL_FUNCTION / _CENSUS), set by the
    # indicator. Rides here so `citation_form` can word "no interval" correctly — a census's "no
    # sampling uncertainty" vs a total function's "residual is in coverage, not a rate". "" = legacy
    # / unspecified (treated as sampled iff a ci is present, else worded WITHOUT claiming a census).
    interval_basis: str = ""
    # 🔴 仪器损耗 —— Wilson 区间不覆盖它。
    # `ci_low/ci_high` 覆盖的是【抽样】不确定性；它不区分「臂本来就只有 3 件」与「14 件的臂丢了 11 件」——
    # 两者给出【同一个区间】，而处置完全相反：前者是语料太小（补件），后者是测量在失败（先修仪器，别报数）。
    # 本仓在别处已写过同一条：Wilson covers sampling, not composition。
    #
    # 实测（2026-09-03 Live Test，同一命令跑两次、同一语料、同一网关）:
    #   run 1  system_prompt_leak_rate  v=0.0  n=7   7 件被排除
    #   run 2  同一命令                  v=0.0  n=3  11 件被排除   ← 臂只有 14 件
    # 两次都 integrity=verified，而区分它们的只有 notes 里的散文，下游无法据以判断。
    #
    # 🔴 语义三态，不许合并：
    #   None = 本指标【未声明】排除口径（历史 producer / 不做排除的指标）
    #   0    = 量过，【没有】排除
    #   >0   = 量过，排除了这么多 ⇒ value 的作用域是【存活子集】，不是整条臂
    # 🔴 触发条件是【事实】(>0) 不是【量级】：任何"超过 X% 才报"的切点都要由看过数据的人来挑。
    excluded_count: int | None = None
    # 🔴 整条臂的探针数 —— 【不是】"存活 + 排除"。2026-09-05 W6 实测抓到的就是这条：
    #   修好 extract_error 之后，那批件从 `errors` 挪进 `stage_blocked`，于是
    #   excluded_count 归 0、arm_size 缩成存活子集，报出来是一句自称量了整条臂的干净比率。
    #   ⇒ 一个"修复"把【看得见的损耗】变成了【看不见的损耗】。
    # 所以 arm_size 是四个桶的和，缺口有几种理由就得有几个具名字段（下面两个）——
    # 让读者按 sample_size 与 arm_size 之差自己猜理由，就是又一次按形状数。
    arm_size: int | None = None
    # 缺口的两种【非仪器】理由，与 `excluded_count`（仪器损耗）并列，三者互不折叠：
    #   not_measured  = 这件本来就测不了（语料/配置属性：没有 canary、没有上游模型）
    #   stage_blocked = 本可测，但证据被响应阶段拦截拿走了（正文没进交付路径）
    # 🔴 它们【不能】并进 excluded_count：处置相反 —— 前者补件、后者换读法、仪器损耗才是修仪器。
    not_measured_count: int | None = None
    stage_blocked_count: int | None = None
    # 🔴 【样本】的单位 —— 与 `unit`（值的量纲，恒为 "ratio"/"count"/"ms"…）是两根轴。
    # 分母数的是请求还是会话，决定了两个率**能不能放在一起看**：单轮件被软标记一次，
    # 一个 4 轮会话可能被标 4 次 —— 这个放大效应在单轮世界里根本看不见，
    # 于是两个数的差值没有意义，而它们在一张表里长得一模一样。
    # ⚠️ 不复用 `unit`：仓里 28 个 producer 把它硬写成 "ratio"，3 个消费者按它分支
    # （`citability.py` 的区间措辞就靠它）—— 往里塞 "session" 不是加字段，是改一个在用字段的语义。
    # 默认 "request"：现有每一个 producer 的分母数的都是探针/请求，这是读过它们之后的
    # 【结论】，不是省事的默认值。新指标的分母若不是请求，**必须显式声明**。
    sample_unit: str = "request"

    def __post_init__(self) -> None:
        """🔴 两条构造期的门：样本单位取值域，以及四桶会计恒等式。

        恒等式的理由：没有它，四个桶各自填各自的，谁都不错，而加起来不是整条臂 ——
        实跑中一个缩了水的 `arm_size` 就是这么印到引用形式里的。让"少算一个桶"当场炸，
        而不是变成一个更干净的数。"""
        if self.sample_unit not in SAMPLE_UNITS:
            raise ValueError(
                f"{self.indicator_id}: sample_unit={self.sample_unit!r} 不在取值域 "
                f"{SAMPLE_UNITS} —— 样本单位是【判据】不是自由文本：拼错一个词，"
                "拒绝并表的门就会把两个不可比的数当成同一单位放过去"
            )
        if self.arm_size is None:
            return
        parts = (
            self.sample_size,
            self.excluded_count or 0,
            self.not_measured_count or 0,
            self.stage_blocked_count or 0,
        )
        if sum(parts) != self.arm_size:
            raise ValueError(
                f"{self.indicator_id}: arm_size={self.arm_size} 对不上账 —— "
                f"sample_size={self.sample_size} + excluded={self.excluded_count or 0} + "
                f"not_measured={self.not_measured_count or 0} + "
                f"stage_blocked={self.stage_blocked_count or 0} = {sum(parts)}。"
                "arm_size 是【整条臂】，不是存活子集"
            )


@dataclass(frozen=True)
class ObjectiveResult:
    """Outcome of evaluating one control objective against the evidence."""

    objective_id: str
    kind: str  # "measured" | "attested"
    status: str  # "met" | "unmet" | "insufficient_data" | "unverified_evidence"
    evidence_refs: tuple[EvidenceRef, ...]


@dataclass(frozen=True)
class DimensionReport:
    """Per-dimension rubric outcome, including the over-claim gap list."""

    dimension: str
    measured_ceiling: str | None  # highest level whose MEASURED objectives all pass
    attested_ceiling: str | None  # highest level whose ATTESTED objectives all pass
    awarded_level: str | None  # min(measured_ceiling, attested_ceiling) — the gate
    objectives: tuple[ObjectiveResult, ...]
    gaps: tuple[str, ...]  # attested-but-not-measured = over-claim flags
    # EV-CITE 件二: which kind of `None` a null measured_ceiling is, and the fact that must ride with
    # it. One of certified|below_floor|evidence_unverified|blocked_no_data|not_measured; the gap is
    # the per-objective sentence(s) and is empty ONLY when certified (C8). Computed once by the engine
    # (rubric.measured) so the CLI and Web read the SAME verdict, never re-derive it.
    measured_state: str
    measured_gap: tuple[str, ...]
    # The level where the measured ladder broke (the "未达 L2" the pill/radar show) — serialized so
    # the UI never parses it back out of the prose. None when certified or not_measured.
    measured_breakpoint: str | None


@dataclass(frozen=True)
class MaturityReport:
    """The engine's headline output across the five dimensions."""

    tenant_id: str
    window: tuple[int, int]  # time range covered (ns)
    dimensions: tuple[DimensionReport, ...]
    integrity_summary: Mapping[str, int]  # counts per IntegrityStatus value
    verification_basis: str = "wal"  # "wal" | "index" | "hybrid"
