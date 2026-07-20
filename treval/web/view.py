"""View context — turns a stored EV-R1 bundle into what the templates render (EV-W2).

Pure functions over the bundle dict (no engine, no I/O), so every rule below is unit-
testable. Two rules carry most of this module's value:

- **The verdict is DERIVED, never authored** (D5): strict precedence, the worse fact wins.
- **Never invent an aggregate score** (D5): `MaturityReport` has no overall level, so
  computing one here would be the UI asserting a grade the engine refused to give.

The merged objective table (D3) joins registry rules (report-independent) with this run's
outcomes (report-dependent) into ONE row per objective — the same 71 objectives were
previously listed twice on one page.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

_LEVELS = ("L1", "L2", "L3", "L4", "L5")

# Result-state vocabulary. insufficient_data ≠ 不合格 — an outsider WILL read it as a fail unless
# told otherwise, so the label and the hover both say "not enough data", never "failed".
STATUS_LABEL = {
    "met": "达标",
    "unmet": "未达标",
    "insufficient_data": "样本不足",
    "unverified_evidence": "证据未验证",
}
STATUS_HELP = {
    "met": "本次实测证据满足该目标的判定规则。",
    "unmet": "有实测证据，但未达到判定规则的门槛。",
    "insufficient_data": "样本量不足以判定 —— 这不是「不合格」，是「还没测够」。补足样本后可能达标，也可能不达标。",
    "unverified_evidence": "证据来自不可链校验的来源（索引），完整性目标不予采信。",
}


def _lv(level: str | None) -> int:
    """Level → sortable int for min(); 0 means "no level", never a score."""
    return _LEVELS.index(level) + 1 if level in _LEVELS else 0


def dimension_titles(registry: dict) -> dict[str, str]:
    return {
        d["id"]: d.get("title_zh") or d["id"] for d in registry.get("dimensions", [])
    }


def verdict(report: dict) -> dict[str, str]:
    """The one banner, by strict precedence (D5) — the worse fact always wins. Nothing
    below a broken chain is worth reporting."""
    summary = report.get("integrity_summary", {})
    broken = int(summary.get("broken", 0))
    unverified = int(summary.get("unverified", 0))
    dims = report.get("dimensions", [])
    gaps = sum(len(d.get("gaps", [])) for d in dims)
    measured_dims = sum(1 for d in dims if d.get("measured_ceiling"))
    awarded = sum(1 for d in dims if d.get("awarded_level"))

    if broken > 0:
        return {
            "kind": "risk",
            "text": "完整性破损 —— 本报告不可信",
            "sub": f"{broken} 条记录的哈希链校验失败；链断则其下所有结论都不成立。",
        }
    if gaps > 0:
        return {
            "kind": "risk",
            "text": f"声明高于实测 —— {gaps} 项目标",
            "sub": "这些目标已声明达标，但实测证据不支持。",
        }
    if measured_dims == 0:
        return {
            "kind": "warn",
            "text": "无实测信号 —— 不能支撑任何实测授级",
            "sub": "本次没有任何维度采到实测数据；无信号 ≠ 0 分。",
        }
    if unverified > 0:
        return {
            "kind": "warn",
            "text": f"含未验证证据 —— {unverified} 条",
            "sub": "部分证据来自不可链校验的来源（索引），完整性目标不予授级。",
        }
    return {
        "kind": "ok",
        "text": f"实测与声明一致 —— 已授级 {awarded}/{len(dims)} 维",
        "sub": "本次没有过度声明，也没有破损或未验证证据。",
    }


def risk_cards(report: dict, measurements: list[dict]) -> list[dict[str, Any]]:
    """The five cards (D5). Every number traces to a real field — no invented concepts."""
    summary = report.get("integrity_summary", {})
    dims = report.get("dimensions", [])
    gaps = sum(len(d.get("gaps", [])) for d in dims)
    broken = int(summary.get("broken", 0))
    unverified = int(summary.get("unverified", 0))
    with_signal = sum(1 for d in dims if d.get("measured_ceiling"))
    aggregate = sum(1 for m in measurements if m.get("subject") == "")
    return [
        {
            "n": gaps,
            "label": "过度声明目标",
            "sub": "声明达标但实测不支持",
            "kind": "risk" if gaps else "ok",
        },
        {
            "n": broken,
            "label": "完整性破损记录",
            "sub": "哈希链校验失败",
            "kind": "risk" if broken else "ok",
        },
        {
            "n": unverified,
            "label": "未验证证据",
            "sub": "来源不可链校验",
            "kind": "warn" if unverified else "ok",
        },
        {
            "n": f"{with_signal}/{len(dims)}",
            "label": "维度有实测信号",
            "sub": "其余维度无信号（≠ 0 分）",
            "kind": "warn" if with_signal < len(dims) else "ok",
        },
        {
            "n": aggregate,
            "label": "实测指标条数",
            "sub": "本次聚合测量",
            "kind": "",
        },
    ]


def maturity_rows(report: dict, titles: dict[str, str]) -> list[dict[str, Any]]:
    """Per dimension: 实测 · 声明 · 授级 = min(实测, 声明) · 结论 pill. The awarded level
    comes from the engine — this only renders it (and shows the min relationship)."""
    rows = []
    for d in report.get("dimensions", []):
        measured, attested = d.get("measured_ceiling"), d.get("attested_ceiling")
        gaps = len(d.get("gaps", []))
        if gaps:
            pill = {"kind": "risk", "text": f"过度声明 {gaps}"}
        elif not measured:
            pill = {"kind": "warn", "text": "无实测信号"}
        elif _lv(attested) > _lv(measured):
            pill = {"kind": "risk", "text": "声明高于实测"}
        else:
            pill = {"kind": "ok", "text": "一致"}
        rows.append(
            {
                "dimension": d["dimension"],
                "title": titles.get(d["dimension"], d["dimension"]),
                "measured": measured or "—",
                "attested": attested or "—",
                "awarded": d.get("awarded_level") or "—",
                "pill": pill,
            }
        )
    return rows


_UNIT_SUFFIX = {"ms": "ms", "tokens": "tokens", "count": ""}


def _format_value(m: dict) -> str:
    """A measured value WITH its unit. A bare number (60164.0) is a real defect: the reader
    can't tell ms from µs, so a 60-second p99 reads as either a disaster or a non-event. Every
    non-ratio value therefore carries its unit; counts show a thousands separator."""
    unit = m.get("unit", "")
    value = m["value"]
    if unit == "ratio":
        return f"{value * 100:.0f}%"
    # integers render without a trailing .0; keep up to 3 decimals otherwise
    num = f"{value:,.0f}" if float(value).is_integer() else f"{round(value, 3):,}"
    suffix = _UNIT_SUFFIX.get(unit, unit)
    return f"{num} {suffix}".strip() if suffix else num


def _required_sample(rule: str | None) -> int | None:
    """The n a `sample_size >= N` rule needs, so the UI can show the gap (14 / 100) instead of
    a bare `insufficient_data`. None when the rule is not a sample-size threshold."""
    if not rule:
        return None
    m = re.search(r"sample_size\s*>=\s*(\d+)", rule)
    return int(m.group(1)) if m else None


def objective_rows(bundle: dict) -> list[dict[str, Any]]:
    """The MERGED table (D3): one row per objective carrying BOTH the rule (registry,
    report-independent) and this run's outcome (report). Switching report state changes
    the outcome column while the rules stay put — that difference is the explanation."""
    registry = bundle["registry"]
    report = bundle["report"]
    titles = dimension_titles(registry)

    results = {
        o["objective_id"]: o
        for d in report.get("dimensions", [])
        for o in d.get("objectives", [])
    }
    gap_ids = {g for d in report.get("dimensions", []) for g in d.get("gaps", [])}
    agg = {
        m["indicator_id"]: m
        for m in bundle.get("measurements", [])
        if m.get("subject") == ""
    }
    per_subject: dict[str, int] = {}
    for m in bundle.get("measurements", []):
        if m.get("subject"):
            per_subject[m["indicator_id"]] = per_subject.get(m["indicator_id"], 0) + 1

    rows: list[dict[str, Any]] = []
    for dim in registry.get("dimensions", []):
        for level in _LEVELS:
            for obj in dim["levels"].get(level, []):
                res = results.get(obj["id"], {})
                status = res.get("status", "")
                measured = obj["kind"] == "measured"
                indicator = obj.get("indicator_id")
                rule = obj.get("satisfied_when") if measured else obj.get("posture_key")
                m = agg.get(indicator) if indicator else None
                n = m.get("sample_size") if m else None
                need_n = (
                    _required_sample(obj.get("satisfied_when")) if measured else None
                )
                # A measured objective's rule gates on EITHER the value (`value >= X` — the
                # number is judged) OR the sample size (`sample_size >= N` — only "enough data
                # for a baseline" is judged, the value is just a reading). Conflating them is
                # the 60s-p99 trap: duration_p99 met via `sample_size >= 100` reads as "they
                # think 60s latency is fine" — but "met" here means "baseline established", and
                # the latency number is NOT being judged good. The UI must separate the two.
                gate = None
                if measured:
                    gate = "sample" if need_n is not None else "value"
                # insufficient_data must NOT also show a value — "0% · verified · insufficient_data"
                # is self-contradictory. Show "—" and the sample-size gap (14 / 100) instead.
                # "verified" on an n=0 row is meaningless (nothing was measured) — suppress it.
                insufficient = status == "insufficient_data"
                rows.append(
                    {
                        "id": obj["id"],
                        "statement": obj.get("statement_zh", ""),
                        "dimension": dim["id"],
                        "dimension_title": titles.get(dim["id"], dim["id"]),
                        "level": level,
                        "kind": obj["kind"],
                        # 判定规则 — the rule itself, always shown in full (D4)
                        "rule": rule,
                        # 数据源 — where the answer comes from
                        "source": indicator if measured else "posture",
                        "status": status,
                        "value": ""
                        if (insufficient or not (measured and m))
                        else _format_value(m),
                        "sample_size": n,
                        "need_sample": need_n,
                        "short_sample": bool(need_n and n is not None and n < need_n),
                        "gate": gate,  # "value" (number judged) | "sample" (baseline only)
                        # only claim integrity when there is actually evidence behind it
                        "integrity": (m.get("integrity") if (m and n) else None),
                        "subjects": per_subject.get(indicator or "", 0),
                        "gap": obj["id"] in gap_ids,
                    }
                )
    return rows


def build_context(bundle: dict) -> dict[str, Any]:
    """Everything both views need from one stored bundle."""
    from treval.web.radar import radar_points

    report = bundle["report"]
    registry = bundle["registry"]
    titles = dimension_titles(registry)
    measurements = bundle.get("measurements", [])
    rows = objective_rows(bundle)
    return {
        "report": report,
        "registry_fingerprint": bundle.get("registry_fingerprint", ""),
        "verdict": verdict(report),
        "risk_cards": risk_cards(report, measurements),
        "maturity_rows": maturity_rows(report, titles),
        "radar": radar_points(report, titles),
        "objective_rows": rows,
        "objective_count": len(rows),
        "gap_count": sum(1 for r in rows if r["gap"]),
        "dimension_titles": titles,
        "measurement_count": len(measurements),
        # EV-PIN §1.5-2/3: is this report reproducible (⇒ citable), and the window rendered
        # for humans. The raw ns stays the selector's value elsewhere — this is label only.
        "pin": pin_status(bundle),
        "window_label": window_label(report.get("window", [0, 0])),
        "STATUS_LABEL": STATUS_LABEL,
        "STATUS_HELP": STATUS_HELP,
    }


def ts_label(ns: int | None) -> str:
    """ns-since-epoch → a readable UTC stamp. Bare 19-digit nanoseconds are unreadable to a
    human (two windows differ only in the middle digits), so labels render this — while the
    raw ns stays the selector's VALUE, because that value is the selection key (EV-PIN §1.5-3:
    change the label, never the key, or switching/deep-links break)."""
    if not ns:
        return "—"
    return datetime.fromtimestamp(ns / 1_000_000_000, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )


def window_label(window: tuple[int, int] | list[int]) -> str:
    """A window rendered for humans: `2026-07-19 19:45 → 19:57 UTC`."""
    start, end = ts_label(window[0]), ts_label(window[1])
    if start == "—" or end == "—":
        return "未记录窗口"
    same_day = start[:10] == end[:10]
    return f"{start} → {end[11:] if same_day else end}"


def pin_status(bundle: dict) -> dict[str, Any]:
    """What kind of report is this, and may it be quoted? (EV-PIN §1.5-2, +PROV §5)

    Three states, in descending order of trust:

    - `pinned`    — measured, window frozen: a third party with the same WAL segments
                    recomputes the same numbers. Citable.
    - `unpinned`  — measured, moving-window snapshot (including every pre-EV-PIN bundle,
                    whose `provenance` is legitimately null). True, but not reproducible.
    - `synthetic` — not measured at all. The demo report: every number is fabricated.

    `synthetic` outranks the pin question because it is a strictly worse defect — an unpinned
    report is real data that may drift, a synthetic one was never measured. It is also the one
    that has already escaped: the demo's fabricated `chain_integrity n=520` reached an external
    document (PROV §5) precisely because a synthetic report rendered exactly like a real one.
    The source-level "SYNTHETIC" banner in the generator cannot stop a screenshot; this can.

    Customer-facing wording, no internal jargon."""
    prov = bundle.get("provenance") or {}
    synthetic = prov.get("data_source") == "synthetic_demo"
    pinned = bool(prov.get("pinned")) and not synthetic
    segs = prov.get("wal_segments") or {}
    if synthetic:
        state, label = "synthetic", "示例数据"
        note = "本报告用于功能演示，全部数值为合成，非任何真实系统的实测结果。"
    elif pinned:
        state, label = "pinned", "已固定窗口"
        note = "本报告的评测窗口已冻结，第三方可用同一批审计日志复算出相同结果。"
    else:
        state, label = "unpinned", "未固定窗口"
        note = "本报告取自移动窗口的快照，数字可能无法复现 —— 不可对外引用。"
    return {
        "state": state,
        "pinned": pinned,
        "synthetic": synthetic,
        "label": label,
        "note": note,
        "wal_sha": segs.get("sha256", ""),
        "segment_range": (
            f"{segs.get('first')} … {segs.get('last')}（{segs.get('count')} 段）"
            if segs
            else ""
        ),
        "record_count": prov.get("record_count"),
    }
