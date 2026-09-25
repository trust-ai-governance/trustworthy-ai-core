"""C-1b 后半件① —— 网关侧判官指纹随 delta 出示。每条先说【什么输入让它红】。

🔴 本件的落点被改判过一次，而那次改判值得留在这里，因为它是同名不同量的第 N 例：

    施工单的「两侧」  = 基线跑 × 新跑        —— **时间轴**
    pair.py 的「两侧」= raw_model × gateway  —— **归因轴**（`_pick_sides`：target_kind 决定边）

照原单在归因轴上做「两侧对称比较」会踩原单**自己写的红条件**：裸模型侧没有网关 ⇒ 没有判官 ⇒
永远不可能有指纹 ⇒ **每一次配对都必报"不对称"**，恒真 ⇒ 假红一样贵，它训练人去忽略这条门。
⇒ 改判后拆两件：① 本文件（gateway 侧出示，**不做两侧比较**）；② 前后不对称具名归 C2A0 ——
仓里第一条做「两次跑比对」的路，时间轴今天只有那一个落点。

🔴 裸模型那一侧用仓里**已有的专名** `n/a_needs_gateway`（`rubric/serialize.py`）：
那张表存在的理由正是**区分缺席的种类**（它的注释逐字：「"缺网关" would misname a
vendor-self-report absence」）。架构性缺席有名字，就不该再去造一个比较。
"""

from __future__ import annotations

from treval.citability import judge_imprint_state
from treval.cli.pair import pair_bundles
from treval.rubric.serialize import AVAILABILITY_VALUES, NEEDS_GATEWAY

from tests.test_pair import _gw, _measurement, _raw

_TAKEN = {"path": "/tmp/ji.json", "sha256": "9cb352db" + "0" * 56}


def _delta(raw, gw):
    out = pair_bundles(raw, gw)
    assert out["deltas"], out["rejected"]
    return out["deltas"][0]


def _with_prov(bundle, prov):
    b = dict(bundle)
    b["provenance"] = prov
    return b


# =========================================================================== #
# ① 两格都在，且各自是各自的量
# =========================================================================== #
def test_both_imprint_cells_ride_with_every_delta():
    """🔴 什么让它红：只报一侧，或把两侧折成一个布尔（`imprint_ok: false`）。

    一个布尔答不出"是哪一侧缺"，而**处置完全不同**：网关侧缺 ⇒ 去取一次就有；
    裸模型侧缺 ⇒ 按结构永远取不到，只能换证据。折成布尔就是把两种处置合成一个。
    """
    d = _delta(_raw(), _gw())
    assert "raw_judge_imprint" in d and "gateway_judge_imprint" in d
    assert not [k for k in d if "imprint" in k and k.endswith(("_ok", "_match"))]


def test_the_gateway_cell_is_the_state_of_that_bundle():
    """🔴 什么让它红：把网关侧也写成一个常量（那时它就不再回答"这一跑取了没有"）。

    三态照 `judge_imprint_state` 原样出，不转述。
    """
    for prov, expect in (
        ({}, "not_declared"),
        ({"judge_imprint": "not_taken"}, "not_taken"),
        ({"judge_imprint": _TAKEN}, "taken:9cb352db"),
    ):
        d = _delta(_raw(), _with_prov(_gw(), prov))
        assert d["gateway_judge_imprint"] == expect, prov
        assert d["gateway_judge_imprint"] == judge_imprint_state(prov)


def test_the_raw_cell_is_a_construction_not_a_computation():
    """🔴 本件最要紧的一条：裸模型侧恒等于架构性缺席的**专名**，
    **不是**从它的 provenance 算出来的。

    什么让它红：把它写成 `judge_imprint_state(raw.get("provenance"))`。
    那时给裸模型侧塞一份指纹（下面这个输入）就会让它读成 `taken:…` ——
    而"裸模型跑出了判官指纹"是一句不可能为真的话，产物却会照印。
    """
    d = _delta(_with_prov(_raw(), {"judge_imprint": _TAKEN}), _gw())
    assert d["raw_judge_imprint"] == NEEDS_GATEWAY
    assert d["raw_judge_imprint"] != "taken:9cb352db"


def test_the_raw_cell_uses_the_repo_word_not_a_new_one():
    """🔴 什么让它红：在 pair.py 里硬编码那个字符串，或另造一个词（"no_judge" 之类）。

    两处各 own 一份同一个词，就是迟早不等的那个形状；而"另造一个词"会让下游多一个
    需要认识的缺席种类，而仓里那张表**已经**在区分缺席的种类了。
    """
    assert NEEDS_GATEWAY in AVAILABILITY_VALUES


def test_the_constant_cell_is_never_omitted_for_being_constant():
    """🔴 线②：它恒定，**正是它必须被印出来的理由** —— 一个永远是同一个值的格子，
    读的人一眼就知道这一侧从来没有过判官指纹。省掉它，那个事实就只活在施工单里。

    什么让它红：因为"反正恒定"而只在不等于默认值时才写这一格。
    """
    for prov in ({}, {"judge_imprint": "not_taken"}, {"judge_imprint": _TAKEN}):
        d = _delta(_raw(), _with_prov(_gw(), prov))
        assert d["raw_judge_imprint"] == NEEDS_GATEWAY, prov


# =========================================================================== #
# 🔴 ② 不做对称比较，也不阻断
# =========================================================================== #
def test_no_asymmetry_verdict_is_emitted_on_this_axis():
    """🔴 什么让它红：在这条轴上加一个"不对称"判定。

    它会**恒真**（裸模型侧按结构永远缺席）⇒ 一条恒报的门等于没有门，而且更坏：
    **假红一样贵 —— 它训练人去忽略这条门。** 前后（时间轴）的不对称具名归 C2A0。
    """
    d = _delta(_raw(), _with_prov(_gw(), {"judge_imprint": _TAKEN}))
    assert d["raw_judge_imprint"] != d["gateway_judge_imprint"]  # 确实不对称
    joined = " ".join(str(v) for v in d.values())
    assert "不对称" not in joined and "asymmetr" not in joined.lower()


def test_an_absent_gateway_imprint_is_disclosed_not_blocking():
    """🔴 什么让它红：把它误判成 blocker / 让它拒发 delta。

    阶段 2 是**诊断**跑：拦住了就什么也拿不到，而那个代价比"看得见的缺席"大。
    ⇒ 披露格，不是门。两个方向各错一次的代价不同，所以这一条单独立。
    """
    absent = _delta(_raw(), _gw())
    taken = _delta(_raw(), _with_prov(_gw(), {"judge_imprint": _TAKEN}))
    assert absent["gateway_judge_imprint"] == "not_declared"
    assert not any("imprint" in b for b in absent["citable_blockers"])
    # 取了/没取，两者的可引判据与 blocker 集合逐字相同 —— 本格不参与裁决
    assert absent["citable_blockers"] == taken["citable_blockers"]
    assert absent["citable"] == taken["citable"]


# =========================================================================== #
# 验收 5 —— 既有行为一行未改
# =========================================================================== #
def test_the_existing_delta_shape_is_unchanged_apart_from_the_two_cells():
    """🔴 什么让它红：顺手动了既有的"两侧都要出示"清单，或改了 `judge_imprint_state`。

    ⚠️ 期望键集合**手写**，不是从产物反推 —— 反推等于把当前形状当成规格。
    """
    d = _delta(_raw(), _gw())
    assert set(d) == {
        "indicator_id",
        "raw_value",
        "gateway_value",
        "delta",
        "corpus_sha",
        "raw_n",
        "gateway_n",
        "raw_ci",
        "gateway_ci",
        "raw_evidence_basis",
        "gateway_evidence_basis",
        "raw_offline_recomputable",
        "gateway_offline_recomputable",
        "raw_judge_imprint",  # 本件新增
        "gateway_judge_imprint",  # 本件新增
        "traffic_tier",
        "statistical",
        "citable",
        "citable_blockers",
        # 手写这张表时我漏了这一格，而它是既有的（本件没加）：
        # injection_success_rate 在 OBSERVABLE_BIASED_IDS 里 ⇒ caveats 随 delta 走
        "caveats",
        "raw_benign_compliance",
        "gateway_benign_compliance",
    }


def test_a_rejected_pairing_is_still_rejected_for_its_own_reason():
    """🔴 什么让它红：本件把 imprint 读到了 gate 之前，于是一次 gate1 拒发变成了别的形状。

    两份同为 gateway 的产物（实测：仓外那四份 09-06 全是 gateway）⇒ 仍在 gate1 被拒，
    `deltas` 为空 —— 本件一个字都不该改变这条路。
    """
    out = pair_bundles(_gw(), _gw())
    assert out["pairing"] is None and out["deltas"] == []
    assert out["rejected"][0]["indicator_id"] == "*"
    assert "gate1" in out["rejected"][0]["reasons"][0]


def test_the_benign_arm_delta_still_has_no_floor_keys():
    """良性侧 delta 不带对照臂两格（它自己就是那条臂）—— 上面那张手写键集合是攻击侧的。

    🔴 什么让它红：本件把两格加成了无条件的，却顺手把别的可选键也变成无条件。
    """
    ms = [_measurement("benign_compliance_rate", 0.9)]
    d = _delta(_raw(measurements=ms), _gw(measurements=list(ms)))
    assert "raw_benign_compliance" not in d
    assert d["raw_judge_imprint"] == NEEDS_GATEWAY  # 两格仍在
    assert d["gateway_judge_imprint"] == "not_declared"
