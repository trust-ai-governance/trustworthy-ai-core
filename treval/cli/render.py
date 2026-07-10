"""Human + CSV renderers for a graded MaturityReport (EV-8 §4). JSON is EV-7's
`bundle_to_json` (byte-deterministic); these two are the operator/spreadsheet views.

Pure functions of (registry, report, measurements): the registry supplies the level +
indicator per objective (an `ObjectiveResult` carries neither), the report supplies each
objective's status + the ceilings, the measurements supply the measured value/integrity.
The human view leads with the 5×5 grid (whole-picture-first, §4); `color=False` drops
ANSI to plain letters (non-TTY / piped) so the text stays diff-stable.
"""

from __future__ import annotations

import csv
import io

from treval.models import DimensionReport, MaturityReport, Measurement
from treval.registry import ControlObjective, DimensionRegistry

_LEVELS = ("L1", "L2", "L3", "L4", "L5")
_LEVEL_INDEX = {level: i for i, level in enumerate(_LEVELS, start=1)}

# Cell classification → (letter, ANSI colour). A maturity grid is cumulative, so a cell
# is coloured by the strongest support that reaches its level.
_AWARDED, _MEASURED, _ATTESTED, _NONE = "AWARDED", "MEASURED", "ATTESTED", "NONE"
_CELL_CHAR = {_AWARDED: "A", _MEASURED: "M", _ATTESTED: "D", _NONE: "·"}
_CELL_ANSI = {
    _AWARDED: "\033[32m",  # green  — verified AND declared
    _MEASURED: "\033[34m",  # blue   — measurement supports, attestation is short
    _ATTESTED: "\033[33m",  # yellow — declared only (the over-claim zone)
    _NONE: "\033[90m",  # grey   — not reached
}
_RESET = "\033[0m"


def _idx(level: str | None) -> int:
    return _LEVEL_INDEX.get(level, 0) if level is not None else 0


def _cell(level: str, awarded: int, measured: int, attested: int) -> str:
    li = _LEVEL_INDEX[level]
    if li <= awarded:
        return _AWARDED
    if li <= measured:
        return _MEASURED
    if li <= attested:
        return _ATTESTED
    return _NONE


def _paint(text: str, cell: str, color: bool) -> str:
    if not color:
        return text
    return f"{_CELL_ANSI[cell]}{text}{_RESET}"


def _all_objectives(reg: DimensionRegistry, dim_id: str) -> dict[str, ControlObjective]:
    dim = reg.dimensions[dim_id]
    return {o.id: o for level in _LEVELS for o in dim.levels[level]}


def _is_not_measured(dim: DimensionReport) -> bool:
    """A dimension is NotMeasured when it produced NO measured signal — every measured
    objective is `insufficient_data` (or it has none). Distinct from measured-but-failing
    (some data, below threshold), which is NOT tagged NotMeasured (EV-7 §0)."""
    measured = [o for o in dim.objectives if o.kind == "measured"]
    return all(o.status == "insufficient_data" for o in measured)


def _level_of(reg: DimensionRegistry, dim_id: str, obj_id: str) -> str:
    dim = reg.dimensions[dim_id]
    for level in _LEVELS:
        if any(o.id == obj_id for o in dim.levels[level]):
            return level
    return "?"


def render_human(
    reg: DimensionRegistry,
    report: MaturityReport,
    measurements: tuple[Measurement, ...],
    warnings: tuple[str, ...],
    *,
    color: bool,
) -> str:
    agg = {m.indicator_id: m for m in measurements if m.subject == ""}
    out: list[str] = []

    out.append(f"treval maturity report  (schema v{_bundle_schema_version()})")
    out.append(
        f"tenant: {report.tenant_id}    window: {list(report.window)}    "
        f"verification_basis: {report.verification_basis}"
    )
    out.append("")

    if warnings:
        out.append(f"⚠ warnings ({len(warnings)}):")
        out.extend(f"  - {w}" for w in warnings)
        out.append("")

    # 1. the 5×5 grid — the whole-picture-first headline.
    out.append("maturity grid  (rows = dimension, cols = L1..L5)")
    label_w = max(len(d.dimension) for d in report.dimensions) + 2
    out.append(" " * label_w + "  ".join(f"{lvl:>2}" for lvl in _LEVELS))
    for dim in report.dimensions:
        not_measured = _is_not_measured(dim)
        a, mc, ac = (
            _idx(dim.awarded_level),
            _idx(dim.measured_ceiling),
            _idx(dim.attested_ceiling),
        )
        cells = []
        for level in _LEVELS:
            cell = _cell(level, a, mc, ac)
            cells.append(f"{_paint(_CELL_CHAR[cell], cell, color):>2}")
        tag = "  (NotMeasured)" if not_measured else ""
        out.append(f"{dim.dimension:<{label_w}}" + "  ".join(cells) + tag)
    out.append(
        "  legend: A awarded  M measured-only  D declared-only  · none"
        "   NotMeasured = no measured signal collected (all insufficient_data)"
    )
    out.append("")

    # 2. the over-claim gap table (the audit finding).
    gap_lines: list[str] = []
    for dim in report.dimensions:
        for gap_id in dim.gaps:
            gap_lines.append(
                f"  {dim.dimension}: {gap_id} "
                f"(declared {_level_of(reg, dim.dimension, gap_id)}, "
                f"measured ceiling {dim.measured_ceiling or 'None'})"
            )
    out.append("over-claim gaps (declared above what measurement supports):")
    out.extend(gap_lines or ["  (none)"])
    out.append("")

    # 3. per-dimension detail.
    out.append("dimension detail:")
    for dim in report.dimensions:
        obj_by_id = _all_objectives(reg, dim.dimension)
        out.append(
            f"  {dim.dimension} — awarded {dim.awarded_level or 'None'} "
            f"(measured {dim.measured_ceiling or 'None'} / "
            f"attested {dim.attested_ceiling or 'None'})"
        )
        for res in dim.objectives:
            spec = obj_by_id.get(res.objective_id)
            level = _level_of(reg, dim.dimension, res.objective_id)
            detail = ""
            if spec is not None and spec.evidence.kind == "measured":
                ind = spec.evidence.indicator_id
                m = agg.get(ind) if ind else None
                if m is not None:
                    detail = f"  {ind}={m.value:.2f} [{m.integrity.value}]"
                else:
                    detail = f"  {ind}=—"
            out.append(
                f"    {level} {res.objective_id:<40} {res.kind:<9} "
                f"{res.status:<18}{detail}"
            )
    out.append("")

    # 4. appendix.
    summ = report.integrity_summary
    out.append("appendix:")
    out.append(f"  verification_basis: {report.verification_basis}")
    out.append(
        "  integrity_summary: "
        + " ".join(
            f"{k}={summ.get(k, 0)}" for k in ("verified", "unverified", "broken")
        )
    )
    out.append(
        "  methodology: measured>attested — awarded_level = "
        "min(measured_ceiling, attested_ceiling); attestation can only lower, never "
        "raise, a verified level. NotMeasured dimensions are declared-only."
    )
    return "\n".join(out) + "\n"


def render_csv(
    reg: DimensionRegistry,
    report: MaturityReport,
    measurements: tuple[Measurement, ...],
) -> str:
    """One flat row per objective — dimension/level/kind/status/indicator/value/integrity
    — for a spreadsheet. Deterministic (dimensions in registry order, objectives L1→L5)."""
    agg = {m.indicator_id: m for m in measurements if m.subject == ""}
    buf = io.StringIO()
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(
        [
            "dimension",
            "level",
            "objective_id",
            "kind",
            "status",
            "indicator_id",
            "value",
            "integrity",
        ]
    )
    for dim in report.dimensions:
        obj_by_id = _all_objectives(reg, dim.dimension)
        for res in dim.objectives:
            spec = obj_by_id.get(res.objective_id)
            indicator = ""
            value = ""
            integrity = ""
            if spec is not None and spec.evidence.kind == "measured":
                indicator = spec.evidence.indicator_id or ""
                m = agg.get(indicator)
                if m is not None:
                    value = f"{m.value}"
                    integrity = m.integrity.value
            writer.writerow(
                [
                    dim.dimension,
                    _level_of(reg, dim.dimension, res.objective_id),
                    res.objective_id,
                    res.kind,
                    res.status,
                    indicator,
                    value,
                    integrity,
                ]
            )
    return buf.getvalue()


def _bundle_schema_version() -> int:
    from treval.cli.bundle import SCHEMA_VERSION

    return SCHEMA_VERSION
