"""A1–A5 —— 容量搜索函数 + 产物上那四个此前取不到的格子。

🔴 本文件存在的理由是一次 review 结论（2026-09-14，售后研发）：施工单的十条验收
**全是散文，没有一条进 CI**。而验收 3 的原话正是「防用近似冒充搜索」——
**没有测试，日后有人把搜索改回采样近似，CI 不会红**，那正是本单 Problem 段 A3
写的"靠人记得"。

每个测试的 docstring 第一行写【什么输入让它红】。
"""

from __future__ import annotations

import pytest

from treval.provenance import build_provenance
from treval.stats import Z_95, min_n, wilson_interval

# 门 A 那条臂的实测率，本文件多处用到：2026-09-06 认证跑与 2026-09-14 撤线跑均为此值。
_P_GATE_A = 113 / 134
_TARGET = 0.80


def _prov(**kw: object) -> dict:
    return build_provenance(
        wal_dir=None, window=None, pinned=False, tenant_id="t", record_count=0, **kw
    )


# =========================================================================== #
# A1 · min_n —— 搜索，不取样
# =========================================================================== #
def test_a1_gate_a_capacity_is_three_numbers_not_one():
    """🔴 什么让它红：只返回 first_n，或把 gaps 折成一个布尔。

    实证（2026-09-14）：容量数从一份**取样清单**里挑最小值报出，多报 41 件，
    直接打在一条 L 级工作量的排期上。
    """
    r = min_n(_P_GATE_A, _TARGET)
    # 🔴 默认那一格（排期用）必须是【稳健值】，不是首达值：
    # 首达 309 达标而 **310 不达标** —— 一个"多造一件反而不过"的操作点不能拿去排期。
    assert r.n == r.stable_n == 349
    assert r.first_n == 309
    assert len(r.gaps) == 20 and max(r.gaps) == 348
    # 🔴 首达卡在边界上 —— 这正是"只给 first_n"会害人的地方
    assert wilson_interval(round(_P_GATE_A * 309), 309)[0] == pytest.approx(
        0.8001, abs=5e-5
    )
    assert 310 in r.gaps  # 紧挨着首达的那一个就不过


def test_a1_an_unsolvable_gate_returns_none_not_the_search_ceiling():
    """🔴 什么让它红：p < target 时返回 hi —— 那会让读的人以为"再大一点就行"。

    p=0.7761 是 A4 判别器生效时门 A 的实测点估计。点估计低于门槛 ⇒ 扩样只收窄区间、
    不抬点估计 ⇒ **任何样本量都过不了**（本仓 E3_A3_MISS_ANALYSIS.md:693 已写死此判别）。
    """
    r = min_n(104 / 134, _TARGET)
    assert r.n is None and r.first_n is None
    assert r.stable_n is None and r.gaps == ()


def test_a1_the_search_is_exhaustive_not_an_approximation():
    """🔴 什么让它红：把搜索换成"首个连续 K 个达标"之类的近似。

    近似会让 first_n 偏大（跳过卡边界的那一个）、或让 gaps 漏项。这里两侧都验：
    first_n 之前**无一**达标 · gaps 里**每一个**都真不达标 · stable_n 之后**无一**回落。
    """
    r = min_n(_P_GATE_A, _TARGET, hi=600)
    assert r.first_n is not None and r.stable_n is not None

    def ok(n: int) -> bool:
        return wilson_interval(round(_P_GATE_A * n), n, z=Z_95)[0] >= _TARGET

    assert not any(ok(n) for n in range(1, r.first_n))
    assert all(not ok(n) for n in r.gaps)
    assert all(ok(n) for n in range(r.stable_n, 601))


def test_a1_reproduces_the_existing_gate_b_capacity_stairs():
    """🔴 什么让它红：函数与仓内既有容量表不自洽。

    门 B 是 FPR 的 ci_high ≤ 0.05；台阶 73/110/142/173/202/230/257 是既有结论。
    用同一个 Wilson 复现它，证明 min_n 的搜索方式与那张表出自同一套算术
    （而那串台阶不是曲线、是台阶，成因与 A1 的 gaps 同源：取整）。
    """
    stairs = []
    for k in range(7):
        n = max(k, 1)
        while wilson_interval(k, n)[2] > 0.05:
            n += 1
        stairs.append(n)
    assert stairs == [73, 110, 142, 173, 202, 230, 257]


def test_a1_refuses_a_non_proportion():
    """🔴 什么让它红：把一个非比率（例如件数）当 p 传进来还能算出一个"容量"。"""
    with pytest.raises(ValueError):
        min_n(1.5, 0.8)
    with pytest.raises(ValueError):
        min_n(0.8, 1.5)


# =========================================================================== #
# A2 · material_ruleset_sha256 —— 三态，且两侧必须不同源
# =========================================================================== #
def test_a2_declared_value_lands_verbatim():
    """🔴 什么让它红：A2 没接上，或落盘时被改写。"""
    landed = "a" * 64
    assert _prov(material_ruleset_sha256=landed)["material_ruleset_sha256"] == landed


def test_a2_undeclared_is_none_not_an_empty_string():
    """🔴 什么让它红：把"未声明"落成空串。

    citability.py:928 用 `if prov.get(...)` 读它 ⇒ 空串是 falsy ⇒
    「没声明」与「声明了是空」在下游**同形**，而两者的处置相反。
    """
    v = _prov()["material_ruleset_sha256"]
    assert v is None and v != ""


def test_a2_a_mismatch_can_actually_happen():
    """🔴 什么让它红：两侧同源 ⇒ 这道门恒为 matched。

    这一条是 review（2026-09-14）抓出来的：施工单初稿的验收要求"该格等于**运行时**那一格"，
    而 citability.py:995 逐字说它比的是【材料落地时】那一份。
    **只测 matched 测不出"恒 matched"** —— 所以这里测的是 mismatch 真能出现。
    """
    from treval.citability import material_window_verified

    run_sha, landed_sha = "b" * 64, "c" * 64
    prov = _prov(
        material_ruleset_sha256=landed_sha,
        build_fingerprint_before={"runtime": {"ruleset_sha256": run_sha}},
    )
    assert material_window_verified(prov) == "mismatch"
    same = _prov(
        material_ruleset_sha256=run_sha,
        build_fingerprint_before={"runtime": {"ruleset_sha256": run_sha}},
    )
    assert material_window_verified(same) == "matched"


# =========================================================================== #
# A3 / A4 · 判据版本与语料指纹上产物行
# =========================================================================== #
def test_a3_criteria_version_is_imported_never_re_typed():
    """🔴 什么让它红：在 provenance 里写第二个字面量 —— 两处各写一个，就是它们迟早不等的原因。"""
    from treval.citability import CRITERIA_VERSION

    assert _prov()["criteria_version"] == CRITERIA_VERSION


def test_a4_corpus_sha_rides_on_the_artifact_row():
    """🔴 什么让它红：搬漏了，或把空 dict 折成 None。

    `{}`（跑了但没有 producer）与 `None`（这一格不存在）**不是一回事**：
    前者说"有这一格而它是空的"。折叠它，就又造了一次"两种状态同形"。
    """
    fp = {"injection_catch_rate": "sha256:dead"}
    assert _prov(corpus_sha=fp)["corpus_sha"] == fp
    assert _prov(corpus_sha={})["corpus_sha"] == {}
    assert _prov()["corpus_sha"] is None


def test_the_three_new_cells_are_always_emitted():
    """🔴 什么让它红：未声明时这三格**缺席**而不是为空。

    缺席的格子让 PM 的复核判据（「这一格的值，和它服务的那个结论，是同一件事吗」）
    **没有对象可核** —— 兜底是空的。照 tests/test_ev_coverage_e3n.py:400 的形状。
    """
    prov = _prov()
    for key in ("material_ruleset_sha256", "criteria_version", "corpus_sha"):
        assert key in prov, key


# =========================================================================== #
# A5 · 四桶会计 —— 三个桶各有来源，不许用减法凑
# =========================================================================== #
def _cc(**kw: int):
    """构造一个 _CatchCounts：每个出口的件数直接给，不经过探针循环。

    🔴 这样构造是【刻意】的：本组测的是「五个出口 → 三个桶」这张映射表，
    而不是 `_catch_counts` 的分类逻辑（那一条由它自己的 continue 链保证，另有测试）。
    """
    from treval.active_eval.indicators import _CatchCounts

    base = dict(
        refs=[],
        caught=0,
        errors=0,
        undecided=0,
        attribution_excluded=0,
        unattributable=0,
        prefix_fallback=0,
        no_verdict=0,
        evaluated_miss=0,
        stage_cells={"entry_only": 0, "response_only": 0, "both": 0, "neither": 0},
    )
    base.update(kw)
    return _CatchCounts(**base)  # type: ignore[arg-type]


def test_a5_instrument_loss_goes_to_excluded_not_not_measured():
    """🔴 验收 11 —— 什么让它红：把两个桶都实现成 `not_measured`。

    这一条与验收 10 **对称**：只有验收 10 时，"两桶都归 not_measured" 同样能过。
    仪器损耗（harness 传输失败 / 网关没给判定）的处置是【修仪器】，与另两桶相反。
    """
    from treval.active_eval.indicators import _exit_buckets

    eb = _exit_buckets(_cc(errors=4, undecided=1))
    assert eb.excluded == 5
    assert eb.not_measured == 0 and eb.stage_blocked == 0


def test_a5_corpus_property_goes_to_not_measured_not_excluded():
    """🔴 验收 10 —— 什么让它红：把"本来就测不了"并进 `excluded_count`（那会指向修仪器）。

    控制件（期望结局相反）与"没有任何注入规则参与"都是**语料/配置属性**：
    处置是补件或换读法，不是修仪器（models.py:172 逐字：三者处置相反）。
    """
    from treval.active_eval.indicators import _exit_buckets

    eb = _exit_buckets(_cc(attribution_excluded=5, unattributable=2))
    assert eb.not_measured == 7
    assert eb.excluded == 0 and eb.stage_blocked == 0


def test_a5_response_stage_loss_goes_to_stage_blocked():
    """🔴 什么让它红：把 `no_verdict` 并进 excluded —— 那正是 2026-09-05 W6 那次的反向。

    `stage_blocked` 的定义（models.py:171 逐字）：本可测，但证据被响应阶段拦截拿走了。
    """
    from treval.active_eval.indicators import _exit_buckets

    eb = _exit_buckets(_cc(no_verdict=3))
    assert eb.stage_blocked == 3
    assert eb.excluded == 0 and eb.not_measured == 0


def test_a5_every_exit_lands_in_exactly_one_bucket():
    """🔴 验收 12 —— 什么让它红：任何一个出口被算进两个桶，或被漏掉。

    `_catch_counts` 的 continue 链保证每件**恰好走一条出口**；这一条保证
    **每条出口恰好落一个桶**。两者合起来才是"每件恰好落一个桶"。
    """
    from treval.active_eval.indicators import _exit_buckets

    exits = (
        "errors",
        "undecided",
        "attribution_excluded",
        "unattributable",
        "no_verdict",
    )
    seen: dict[str, str] = {}
    for name in exits:
        eb = _exit_buckets(_cc(**{name: 1}))
        hit = [
            b for b in ("excluded", "not_measured", "stage_blocked") if getattr(eb, b)
        ]
        assert len(hit) == 1, f"{name} 落进了 {hit} —— 必须恰好一个桶"
        assert eb.total == 1, f"{name} 的总数不是 1（被重复计或被漏掉）"
        seen[name] = hit[0]
    # 🔴 五条出口必须覆盖三个桶 —— 任一桶没有来源，说明映射表少了一格
    assert set(seen.values()) == {"excluded", "not_measured", "stage_blocked"}


def test_a5_the_four_bucket_identity_holds_on_a_real_measurement():
    """🔴 验收 9 —— 什么让它红：用减法凑某一个桶（凑出来的恒等式恒成立，零信息）。

    `Measurement.__post_init__` 已经在构造期验这条恒等式；这里验的是三个注入指标
    **真的填了**这四格，而不是留 None 让那道门空跑。

    ⚠️ 用**真探针**跑，不用空列表。

    🔴 **覆盖缺口，写下来而不是冒充覆盖**：`InjectionCombinedRecall` 不在本条里 ——
    它要发布就必须同时拿到 Tier-2 的 lift，而本文件的探针助手造不出 type-3 治理记录，
    于是它走的是两条**拒绝发布**支之一（分母不匹配 / Tier-2 不可测）。
    它的出数支与另两个指标共用同一个 `_eb = _exit_buckets(cc)`，但**那条共用没有被
    端到端测到**。这是可维护性覆盖，不是行为覆盖 —— 记在这里，不算进覆盖率。
    """
    from tests.test_c0a_entry_block_column import _probe
    from treval.active_eval.indicators import (
        InjectionCatchRate,
        InjectionDecisionBlockRate,
    )

    probes = [
        _probe("a"),
        _probe("b"),
        _probe("c", error="harness-transport: boom"),  # 仪器损耗 ⇒ excluded
    ]
    for cls in (InjectionCatchRate, InjectionDecisionBlockRate):
        (m,) = cls().measure(probes)
        assert m.arm_size is not None, cls.__name__
        assert m.excluded_count is not None, cls.__name__
        assert m.not_measured_count is not None, cls.__name__
        assert m.stage_blocked_count is not None, cls.__name__
        assert m.arm_size == (
            m.sample_size
            + m.excluded_count
            + m.not_measured_count
            + m.stage_blocked_count
        ), cls.__name__
        # 🔴 独立 oracle —— 上面那条恒等式【在构造期已经不可能为假】
        # （producer 写 arm_size = total + _eb.total，models.__post_init__ 又验一次和）：
        # 它是本单 §Value 命名的那一族，一道比它声称的东西更容易为真的检查。
        # 真正会失败的是这一行：整条臂 = 投喂的件数，**不是"存活子集"**。
        # ⚠️ 它挡的是 `_ExitBuckets` docstring 里记的那次 2026-09-05 W6 实测 ——
        # continue 链若出现缺口（某件既不命中任何出口、也不进 sample），arm_size 会
        # 静默缩水，而恒等式、excluded>=1、arm_size>sample_size 三条【仍然全过】。
        assert m.arm_size == len(probes), cls.__name__
        # 🔴 那件传输失败的探针必须【看得见】—— 它是 arm_size 与 sample_size 之差的来源
        assert m.excluded_count >= 1, cls.__name__
        assert m.arm_size > m.sample_size, cls.__name__


def test_a5_a_refusal_row_is_not_a_measurement_of_the_arm():
    """🔴 什么让它红：给「拒绝发布」那一行也填上 arm_size。

    `InjectionCombinedRecall` 在两半分母不一致时**拒绝发布**（序8 件6）。那一行
    `evidence_refs=()`、notes 以 `n/a` 开头 —— 它声明的是"我不发这个数"。
    给它填 arm_size 等于替它认领一个它明确拒绝的作用域。
    """
    from treval.active_eval.indicators import InjectionCombinedRecall

    (m,) = InjectionCombinedRecall().measure([])
    assert m.notes.startswith("n/a")
    assert m.evidence_refs == ()
    assert m.arm_size is None


def test_min_n_distinguishes_unreachable_from_beyond_the_search_cap() -> None:
    """🔴 红条件：两种 None 又变回同形。

    2026-09-16 实测：combined 0.8116（> 0.80）在 hi=2000 下返回 None，
    差点被报成"任何 n 都过不了"——它其实可达，需 4498 件。
    而 0.7971（< 0.80）是真的任何 n 都过不了，那是定理不是搜索结果。
    ⇒ 两者必须由 `reason` 分开，不能靠调用者记得去调大 hi 再试一次。
    """
    from treval.stats import min_n

    over = min_n(0.8116, 0.80, hi=2000)
    assert over.first_n is None and over.reason == "beyond_hi"
    assert min_n(0.8116, 0.80, hi=20000).first_n is not None, (
        "调大 hi 应当找得到 —— 否则 beyond_hi 这个判别本身是错的"
    )
    under = min_n(0.7971, 0.80, hi=200000)
    assert under.first_n is None and under.reason == "unreachable"


def test_a_successful_search_carries_no_reason() -> None:
    """红条件：找到了却还带着一个理由字符串 ⇒ 读的人不知道该信哪一个。"""
    from treval.stats import min_n

    assert min_n(0.90, 0.80).reason is None
