"""🔴 分母的单位 —— 与值的量纲是两根轴，而拒绝并表是个【消费者】，不是一个字段。

单轮件被软标记一次，一个 4 轮会话可能被标 4 次 —— 这个放大效应在单轮世界里根本看不见。
于是两个率的差值没有意义，而它们在一张表里长得**一模一样**。

⚠️ 本文件守的是"只加字段不建拒绝"这个失败模式：字段加了、禁令写进了 citation_form，
而渲染面照样把两个单位排在一列里 —— 那就是「指定了目的地，没修路」的又一个实例。
"""

from __future__ import annotations

import pytest

from treval.citability import citation_form
from treval.models import (
    SAMPLE_UNITS,
    IntegrityStatus,
    Measurement,
    MixedSampleUnitError,
    assert_single_sample_unit,
)


def _m(indicator_id: str, unit: str = "request", **over) -> Measurement:
    base = dict(
        indicator_id=indicator_id,
        dimension="robustness",
        value=0.0,
        unit="ratio",
        sample_size=4,
        evidence_refs=(),
        integrity=IntegrityStatus.VERIFIED,
        sample_unit=unit,
    )
    base.update(over)
    return Measurement(**base)  # type: ignore[arg-type]


def test_the_value_dimension_and_the_sample_unit_are_two_axes() -> None:
    """🔴 不复用 `unit`：它是【值】的量纲，仓里 28 个 producer 硬写成 "ratio"，
    3 个消费者按它分支。往里塞 "session" 不是加字段，是改一个在用字段的语义。

    什么让它红：把 sample_unit 折进 unit。那时下面两行会撞在一起。
    """
    s = _m("x", "session")
    assert s.unit == "ratio", "值仍然是一个比率"
    assert s.sample_unit == "session", "而分母数的是会话"


def test_a_typo_in_the_unit_blows_up_at_construction() -> None:
    """🔴 取值域是白名单：拼错一个词，拒绝并表的门就会把两个不可比的数当成同一单位放过去。

    什么让它红：把 `__post_init__` 里的取值域校验删掉。
    """
    with pytest.raises(ValueError, match="不在取值域"):
        _m("x", "sessions")
    assert set(SAMPLE_UNITS) == {"request", "session"}


def test_mixing_units_in_one_table_raises_not_warns() -> None:
    """🔴 由结构拦，不由注意力拦 —— 警告会被读过去，异常不会。

    什么让它红：把 `assert_single_sample_unit` 改成 return / warn。
    """
    with pytest.raises(MixedSampleUnitError) as e:
        assert_single_sample_unit([_m("a"), _m("b", "session")], "表X")
    msg = str(e.value)
    assert "a" in msg and "b" in msg, "必须点名是哪些指标撞了，否则修不了"
    # 同单位不拦；空集回落默认
    assert assert_single_sample_unit([_m("a"), _m("b")], "表X") == "request"
    assert assert_single_sample_unit([], "表X") == "request"


def test_the_two_prohibitions_ride_with_the_number_not_a_footnote() -> None:
    """🔴 一条写在别处的限定，和不存在的限定，对第三个人是同一回事。

    所以两条禁令印在数的旁边。它们由"分母数的东西不同"直接推出 ⇒ 对任何非 request
    单位都成立，不是给某一个 indicator_id 写的字面量（写死在一个 id 上，下一个单位就又漏了）。

    什么让它红：把这段挪进脚注，或用 `if m.indicator_id == "..."` 触发。
    """
    form = citation_form(
        _m(
            "some_future_rate", "session", ci_low=0.0, ci_high=0.5
        ),  # disclosure-ok: 构造性测试输入，非任何实测
        pinned=False,
        window=None,
        evidence_basis="wal_anchored",
        citable=True,
        first_blocker=None,
    )
    assert "unit=session" in form
    assert "不可换算" in form and "并表" in form
    # request 单位不得加这段噪声
    plain = citation_form(
        _m(
            "some_future_rate", "request", ci_low=0.0, ci_high=0.5
        ),  # disclosure-ok: 构造性测试输入，非任何实测
        pinned=False,
        window=None,
        evidence_basis="wal_anchored",
        citable=True,
        first_blocker=None,
    )
    assert "unit=" not in plain and "并表" not in plain


def test_csv_puts_different_units_in_different_tables() -> None:
    """🔴 拒绝并表的那个【消费者】。只加字段、只在 citation_form 写禁令，
    而 CSV 照样把两个单位排在同一列里 —— 那就是"指定了目的地，没修路"。

    什么让它红：让 render_csv 回到单张表（那时两个 header 只会出现一次）。
    """
    from treval.cli.render import render_csv
    from treval.registry import load_registry
    from treval.rubric.engine import evaluate as grade

    reg = load_registry()
    ms = (
        _m(
            "injection_catch_rate",
            "request",
            dimension="robustness",
            value=1.0,
            ci_low=1.0,  # disclosure-ok: 构造性测试输入，非任何实测
            ci_high=1.0,  # disclosure-ok: 构造性测试输入，非任何实测
        ),
        _m(
            "benign_session_disruption_rate",
            "session",
            dimension="robustness",
            ci_low=0.0,  # disclosure-ok: 构造性测试输入，非任何实测
            ci_high=0.5,  # disclosure-ok: 构造性测试输入，非任何实测
        ),
    )

    def _g(mm):
        return grade(reg, mm, (), window=(0, 1), tenant_id="t")

    report = _g(ms)
    out = render_csv(reg, report, ms)
    assert out.count("dimension,level,objective_id") == 2, "两个单位必须是两张表"
    assert "sample_unit" in out, "多于一张表时，读者必须看得见自己在读哪一张"

    # 单一单位时逐字节不变（本改动不得改动既有输出）
    one = (ms[0],)
    assert render_csv(reg, _g(one), one).count("dimension,level,objective_id") == 1
    assert "sample_unit" not in render_csv(reg, _g(one), one)


def test_the_unit_survives_the_collect_to_report_round_trip(tmp_path) -> None:
    """🔴 写了不回读 = 没写 —— 而拒绝并表的门在【消费侧】，读不到单位就没法拒绝。

    这条门是补上去的：`sample_unit` 落地时我做了写这一侧、`citation_form` 和 CSV 都改了，
    变异测试里"不回读"那一发**存活**。同一个形状我在 `excluded_count` 上已经栽过一次，
    教训写在 `bundle.py` 的注释里 —— 写在我自己要改的那个文件里，我仍然漏了第二遍。

    什么让它红：从 `parse_measurement` 里去掉 sample_unit 的恢复。
    """
    import json

    from treval.cli.bundle import SCHEMA_VERSION, load_bundle

    doc = {
        "schema_version": SCHEMA_VERSION,
        "tenant_id": "t",
        "window": [1, 2],
        "measurements": [
            {
                "indicator_id": "x_rate",
                "dimension": "robustness",
                "value": 0.0,
                "unit": "ratio",
                "sample_size": 4,
                "subject": "",
                "notes": "",
                "integrity": "verified",
                "ci_low": None,
                "ci_high": None,
                "interval_basis": "",
                "sample_unit": "session",
                "evidence_refs": [],
            }
        ],
    }
    f = tmp_path / "b.json"
    f.write_text(json.dumps(doc), encoding="utf-8")
    (m,) = load_bundle(f).measurements
    assert m.sample_unit == "session", (
        "回读丢了样本单位 ⇒ 拒绝并表的门永远看不到 session"
    )

    # 缺席 ⇒ request（v8 之前每个 producer 的分母数的都是请求），不是空串、不是报错
    doc["measurements"][0].pop("sample_unit")
    f2 = tmp_path / "b2.json"
    f2.write_text(json.dumps(doc), encoding="utf-8")
    assert load_bundle(f2).measurements[0].sample_unit == "request"
