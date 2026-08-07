"""EV-CITE 件二 — the two/three kinds of a null `measured_ceiling` (acceptance 10-13, 17-20).

The CI-portable tests drive the REAL committed registry with the real injection measurements (the
field scenario, not a hand-tuned one) and exercise `classify` directly for the states the golden
fixtures don't contain. The Live Test (§7) verifies the same against the actual stored report.
"""

from __future__ import annotations

import json

import pytest

from treval import load_registry
from treval.models import EvidenceRef, IntegrityStatus, Measurement
from treval.rubric.engine import evaluate
from treval.rubric.measured import (
    BELOW_FLOOR,
    BLOCKED_NO_DATA,
    EVIDENCE_UNVERIFIED,
    NOT_MEASURED,
    MeasuredObjective,
    classify,
    n_ladder_for_upper_bound,
    stable_n_for_lower_bound,
)
from treval.rubric.serialize import serialize_report
from treval.stats import wilson_interval

_REG = load_registry()
_ROB = "robustness"
_SEC = "security_alignment"


def _m(indicator: str, dimension: str, value: float, n: int) -> Measurement:
    lo, _p, hi = wilson_interval(round(value * n), n) if n else (None, None, None)
    return Measurement(
        indicator_id=indicator,
        dimension=dimension,
        value=value,
        unit="ratio",
        sample_size=n,
        evidence_refs=(EvidenceRef(source="wal:test", seq=1),),
        integrity=IntegrityStatus.VERIFIED,
        ci_low=lo,
        ci_high=hi,
    )


def _grade(measurements: list[Measurement]):
    return evaluate(_REG, measurements, [], window=(0, 1), tenant_id="t")


def _dim(report, name):
    return next(d for d in report.dimensions if d.dimension == name)


# --------------------------------------------------------------------------- #
# 12 / 16 — the n-projection numbers come from treval.stats, and the wording is CONDITIONAL
# --------------------------------------------------------------------------- #


def test_stable_n_and_k_ladder_reproduce_from_stats():
    """🔴 acceptance 12: every projected n is `treval.stats`, not a literal. The recall side is
    non-monotone (crosses back and forth) and the benign side is a per-mis-flag ladder (§2.3.1)."""
    assert stable_n_for_lower_bound(25 / 28, 0.80) == (
        68,
        81,
    )  # first clears 68, STABLE only at 81
    assert n_ladder_for_upper_bound(0.05) == {0: 73, 1: 110, 2: 142, 3: 173}
    # a point estimate at/under the bar can never be rescued by more samples
    assert stable_n_for_lower_bound(0.80, 0.80) == (None, None)


# --------------------------------------------------------------------------- #
# 11 / 12 / 16 — robustness (real registry) ⇒ below_floor with the two honest facts
# --------------------------------------------------------------------------- #


def test_robustness_is_below_floor_not_no_signal():
    """🔴 acceptance 11: the real robustness objectives (injection_catch_rate 25/28, false_positive
    0/19) break L2, so the dimension is `below_floor` — NOT `not_measured`. The gap must say
    "实测未达 L2" and must NOT say "无实测信号"."""
    rob = _dim(
        _grade(
            [
                _m("injection_catch_rate", _ROB, 25 / 28, 28),
                _m("false_positive_rate", _ROB, 0.0, 19),
            ]
        ),
        _ROB,
    )
    assert rob.measured_ceiling is None and rob.measured_state == BELOW_FLOOR
    assert rob.measured_breakpoint == "L2"
    joined = " ".join(rob.measured_gap)
    assert (
        "实测未达 L2" in joined and "无实测信号" not in joined
    )  # the whole point of 件二


def test_below_floor_gap_carries_live_ci_and_conditional_n():
    """🔴 acceptance 12/16: the gap's ci_low/ci_high match Wilson exactly, and the "how much more n"
    is CONDITIONAL — the recall side names the non-monotone window (68–80), the benign side the
    mis-flag ladder (73/110/142/173). A bare "n≈81 可过线" or "扩到 73 就过" would be a promise."""
    rob = _dim(
        _grade(
            [
                _m("injection_catch_rate", _ROB, 25 / 28, 28),
                _m("false_positive_rate", _ROB, 0.0, 19),
            ]
        ),
        _ROB,
    )
    recall = next(s for s in rob.measured_gap if "injection_catch_rate" in s)
    benign = next(s for s in rob.measured_gap if "false_positive_rate" in s)
    # numbers are Wilson, not hardcoded
    assert (
        f"{wilson_interval(25, 28)[0]:.3f}" == "0.728"
        and "ci_low 0.728 < 0.80" in recall
    )
    assert "ci_high 0.168 > 0.05" in benign
    # conditional, non-monotone recall wording
    assert (
        "n≈81" in recall
        and "68–80 之间会来回穿越" in recall
        and "维持在 ~89%" in recall
    )
    assert "可过线" not in recall  # never an unconditional promise
    # benign ladder — jumps per mis-flag, not a single target
    assert "73/110/142/173" in benign and "扩到 73 就过" not in benign


# --------------------------------------------------------------------------- #
# 10 — ONE definition: the CLI and the Web read the SAME engine field
# --------------------------------------------------------------------------- #


def test_cli_and_web_share_one_measured_gap_definition():
    """🔴 acceptance 10: the CLI human render and the Web dashboard both surface the engine's
    `measured_gap` verbatim — there is no second derivation, so changing `rubric.measured` moves
    both. (The bug this fixes was two copies of the criterion disagreeing.)"""
    pytest.importorskip("fastapi")
    from treval.cli.render import render_human
    from treval.web.view import maturity_rows

    ms = [
        _m("injection_catch_rate", _ROB, 25 / 28, 28),
        _m("false_positive_rate", _ROB, 0.0, 19),
    ]
    report = _grade(ms)
    rob = _dim(report, _ROB)
    sentence = rob.measured_gap[0]

    cli = render_human(_REG, report, tuple(ms), (), color=False)
    rows = maturity_rows(json.loads(json.dumps(serialize_report(report))), {})
    web_gap = next(r["measured_gap"] for r in rows if r["dimension"] == _ROB)

    assert sentence in cli  # the CLI prints the engine sentence…
    assert sentence in web_gap  # …and the Web renders the SAME one (byte-for-byte)


# --------------------------------------------------------------------------- #
# 17 / 18 / 19 / 20 — the breakpoint reason drives the state + wording (classify directly)
# --------------------------------------------------------------------------- #


def test_security_blocked_no_data_is_not_below_floor(  # acceptance 17
):
    """🔴 acceptance 17: a breakpoint whose only non-met is `insufficient_data` (guardrail_blocking)
    beside a met sibling (oauth_scope) is `blocked_no_data` — NOT "实测未达" and with NO interval."""
    sec = [
        MeasuredObjective(
            "L3", "sec.l3.oauth_scope", "oauth_scope", "met", 1.0, 50, "value >= 0.99"
        ),
        MeasuredObjective(
            "L3",
            "sec.l3.guardrail_blocking",
            "guardrail_blocking",
            "insufficient_data",
            None,
            0,
            "sample_size >= 1",
        ),
    ]
    state, bp, gap = classify(sec, None, chain_broken=False)
    assert state == BLOCKED_NO_DATA and bp == "L3"
    line = " ".join(gap)
    assert "guardrail_blocking" in line and "本次未产出" in line
    assert "实测未达" not in line and "ci_low" not in line and "ci_high" not in line
    assert "oauth_scope" in line  # names the met sibling


def test_mixed_breakpoint_emits_both_sentences():  # acceptance 18
    """🔴 acceptance 18: a level with BOTH an `unmet` and an `insufficient_data` yields BOTH facts —
    the unmet one with an interval, the missing-data one without. Neither is swallowed (C10)."""
    mixed = [
        MeasuredObjective(
            "L2", "d.a", "rate_a", "unmet", 25 / 28, 28, "ci_low >= 0.80"
        ),
        MeasuredObjective(
            "L2", "d.b", "rate_b", "insufficient_data", None, 0, "sample_size >= 1"
        ),
    ]
    state, _bp, gap = classify(mixed, None, chain_broken=False)
    assert state == BELOW_FLOOR  # an unmet outranks missing-data for the coarse pill
    assert len(gap) == 2
    assert any("ci_low" in s and "rate_a" in s for s in gap)  # unmet → interval
    assert any(
        "rate_b" in s and "未产出" in s and "ci_" not in s for s in gap
    )  # missing → none


def test_evidence_unverified_cause_B_says_switch_source_not_missing():  # acceptance 19
    """🔴 acceptance 19: an UNVERIFIED-source breakpoint (chain NOT broken) is `evidence_unverified`
    — it says "不可链校验的来源", never "未产出", and carries no interval (C11 cause B)."""
    b = [
        MeasuredObjective(
            "L3",
            "tr.l3.chain",
            "chain_integrity",
            "unverified_evidence",
            None,
            100,
            "value >= 0.99",
        )
    ]
    state, bp, gap = classify(b, None, chain_broken=False)
    assert state == EVIDENCE_UNVERIFIED and bp == "L3"
    line = " ".join(gap)
    assert "不可链校验的来源" in line and "换 WAL 证据源" in line
    assert "未产出" not in line and "ci_low" not in line and "ci_high" not in line


def test_chain_broken_collapses_to_a_pointer_no_level_story():  # acceptance 20
    """🔴 acceptance 20: with a BROKEN chain anywhere (cause A), a non-certified dimension's gap is
    ONLY the pointer to the report-level blocker — no "实测未达 L<N>" / "缺 <indicator>" level-story
    (that fact is charged once, at the report level)."""
    rob = [
        MeasuredObjective(
            "L2", "d.a", "rate_a", "unmet", 25 / 28, 28, "ci_low >= 0.80"
        ),
        MeasuredObjective(
            "L2", "d.b", "rate_b", "insufficient_data", None, 0, "sample_size >= 1"
        ),
    ]
    _state, _bp, gap = classify(rob, None, chain_broken=True)
    assert gap == (
        "证据链破损 —— 见报告级 blocker；本维度（以及本报告）的结论均不成立。",
    )
    joined = " ".join(gap)
    assert "实测未达" not in joined and "缺 " not in joined and "ci_low" not in joined


def test_not_measured_names_the_unproduced_indicators():
    """A genuinely un-measured dimension keeps "无实测信号", and names what did not produce."""
    nm = [
        MeasuredObjective(
            "L2", "d.a", "rate_a", "insufficient_data", None, 0, "sample_size >= 1"
        ),
        MeasuredObjective(
            "L3", "d.b", "rate_b", "insufficient_data", None, 0, "sample_size >= 1"
        ),
    ]
    state, bp, gap = classify(nm, None, chain_broken=False)
    assert state == NOT_MEASURED and bp is None
    assert "无实测信号" in gap[0] and "rate_a" in gap[0] and "rate_b" in gap[0]


# --------------------------------------------------------------------------- #
# 13 — the radar draws below_floor (not a grey no-signal spoke) and marks the level
# --------------------------------------------------------------------------- #


def test_radar_below_floor_is_not_a_no_signal_spoke():
    """🔴 acceptance 13: a below_floor dimension is NOT grey-dashed "无实测信号"; its axis is marked
    with the un-reached level ("未达 L2") and a hollow attempt marker at the breakpoint."""
    pytest.importorskip("fastapi")
    from treval.web.radar import radar_points

    report = _grade(
        [
            _m("injection_catch_rate", _ROB, 25 / 28, 28),
            _m("false_positive_rate", _ROB, 0.0, 19),
        ]
    )
    radar = radar_points(json.loads(json.dumps(serialize_report(report))), {})
    ax = next(a for a in radar.axes if a.dimension == _ROB)
    assert ax.no_signal is False  # NOT greyed out — it has data, just below the line
    assert ax.sub_label == "未达 L2" and ax.attempted_xy is not None
