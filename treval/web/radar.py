"""Radar geometry — server-side, no chart library (EV-W1 D6).

A five-axis radar is ~30 lines of trigonometry emitting SVG, so the template just
interpolates numbers and the geometry is unit-testable without a browser.

**`null` is not zero — this is the whole point of the function.** A dimension with
`measured_ceiling = None` has NO SIGNAL; plotting it at radius 0 renders "we never
measured this" as "we scored zero" — a fabricated failing grade for something never
tested. So `RadarAxis.measured` stays `None` (never coerced to 0) and `no_signal` marks
the axis for the dashed/grey treatment (EV-W2 D2). The polygons are built only from the
axes that HAVE a value.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

# Canvas geometry. VIEWBOX is exported so the template cannot drift from these numbers —
# it previously hard-coded "0 0 320 300" while the labels were laid out past its right edge,
# and four of the five axis labels rendered clipped.
#
# Sizing rule: axes are laid out in REPORT order (alphabetical by dimension id), NOT registry
# order — so 隐私与数据保护 lands on the right and 透明、可控、可问责 on the left, and the box
# must clear the longest label on each side. R is the largest radius that still fits every
# label; tests/test_web_report.py::test_radar_labels_stay_inside_the_viewbox pins it.
VIEWBOX_W = 560.0
VIEWBOX_H = 360.0
CX = 280.0
CY = 174.0
R = 146.0
LEVELS = 5  # L1..L5 → radius fractions 1/5 .. 5/5
_LABEL_RING = 5.4  # axis labels sit just outside the outer ring


@dataclass(frozen=True)
class RadarAxis:
    """One dimension's axis. `measured`/`attested` are level numbers 1..5, or None for
    "no signal" — never 0. `over_claim` marks the axes where the claim exceeds the
    measurement (the money shot: the gap made visible)."""

    dimension: str
    title: str
    measured: int | None
    attested: int | None
    awarded: int | None  # = min(measured, attested); the maturity actually granted
    x: float  # outer-ring point (the spoke's end)
    y: float
    label_x: float
    label_y: float
    label_anchor: str  # svg text-anchor: start | middle | end
    measured_xy: tuple[float, float] | None
    attested_xy: tuple[float, float] | None
    awarded_xy: tuple[float, float] | None
    no_signal: bool  # measured is None → dashed grey spoke + 无实测信号 sub-label
    over_claim: bool  # attested > measured (or measured absent while attested present)


@dataclass(frozen=True)
class Radar:
    """Everything the template needs: rings, axes, and the two polygons."""

    axes: tuple[RadarAxis, ...]
    rings: tuple[tuple[str, float], ...]  # (points, label_y) per level L1..L5
    # Three polygons, matching the maturity table's three value columns 1:1 (same colours).
    # awarded is the HERO (green solid) — it is the maturity actually granted. Because
    # awarded == min(measured, attested), its vertices always coincide with the LOWER of the
    # other two, so exactly one of measured/attested shows outside it per axis (the higher
    # one) and the other hides beneath it. No information is lost — the table carries all
    # three numbers — and the green outline traces the real maturity floor.
    measured_polygon: str  # "" when no axis has a measured value
    attested_polygon: str
    awarded_polygon: str
    cx: float = CX
    cy: float = CY
    viewbox: str = f"0 0 {VIEWBOX_W:g} {VIEWBOX_H:g}"


def level_number(level: str | None) -> int | None:
    """ "L3" → 3; None/"" → None. NEVER 0 — absence is not a score."""
    if not level:
        return None
    try:
        return int(str(level)[1:])
    except ValueError:
        return None


def _angle(i: int, n: int) -> float:
    return -math.pi / 2 + i * 2 * math.pi / n


def _point(i: int, n: int, level: float) -> tuple[float, float]:
    a = _angle(i, n)
    r = (level / LEVELS) * R
    return (round(CX + r * math.cos(a), 2), round(CY + r * math.sin(a), 2))


def radar_points(report: dict, dimension_titles: dict[str, str]) -> Radar:
    """Build the radar from a serialized report (the bundle's `report` object) and the
    registry's dimension titles. Pure + deterministic; dimensions in report order."""
    dims = report.get("dimensions", [])
    n = len(dims) or 1
    axes: list[RadarAxis] = []
    for i, d in enumerate(dims):
        measured = level_number(d.get("measured_ceiling"))
        attested = level_number(d.get("attested_ceiling"))
        # awarded comes from the engine (= min of the two), never recomputed here — the UI
        # renders the grade, it does not derive one.
        awarded = level_number(d.get("awarded_level"))
        ox, oy = _point(i, n, LEVELS)
        lx, ly = _point(i, n, _LABEL_RING)
        anchor = "middle" if abs(lx - CX) < 8 else ("start" if lx > CX else "end")
        axes.append(
            RadarAxis(
                dimension=d["dimension"],
                title=dimension_titles.get(d["dimension"], d["dimension"]),
                measured=measured,
                attested=attested,
                awarded=awarded,
                x=ox,
                y=oy,
                label_x=lx,
                label_y=ly,
                label_anchor=anchor,
                measured_xy=_point(i, n, measured) if measured else None,
                attested_xy=_point(i, n, attested) if attested else None,
                awarded_xy=_point(i, n, awarded) if awarded else None,
                no_signal=measured is None,
                over_claim=(attested or 0) > (measured or 0),
            )
        )

    rings = tuple(
        (
            " ".join(f"{x},{y}" for x, y in (_point(i, n, lv) for i in range(n))),
            round(CY - (lv / LEVELS) * R + 3, 2),
        )
        for lv in range(1, LEVELS + 1)
    )

    def _poly(getter) -> str:
        # Only plot when at least one axis has a value; a None axis contributes its
        # CENTRE point purely to close the polygon — it is NOT a rendered score, and the
        # dashed spoke + 无实测信号 label is what the reader actually sees on that axis.
        pts = [getter(a) for a in axes]
        if not any(p is not None for p in pts):
            return ""
        return " ".join(f"{p[0]},{p[1]}" if p else f"{CX},{CY}" for p in pts)

    return Radar(
        axes=tuple(axes),
        rings=rings,
        measured_polygon=_poly(lambda a: a.measured_xy),
        attested_polygon=_poly(lambda a: a.attested_xy),
        awarded_polygon=_poly(lambda a: a.awarded_xy),
    )
