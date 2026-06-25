"""Dimension Registry data model (EV-6) — frozen, data-driven taxonomy.

The registry is the open "fact-standard" carrier: 5 trustworthiness dimensions ×
5 maturity levels, each level a set of control objectives mapped to either a
runtime indicator (measured) or a posture key (attested). Data, not code, so the
standard can version independently (EVAL_ARCHITECTURE §2.3). These types only
hold the parsed shape; scoring is EV-7.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Evidence:
    """How one control objective is satisfied: a measured indicator (+ a
    satisfied_when predicate) or an attested posture key."""

    kind: str  # "measured" | "attested"
    indicator_id: str | None  # set iff kind == "measured"
    posture_key: str | None  # set iff kind == "attested"
    satisfied_when: str | None  # set iff kind == "measured" (the §4 mini-grammar)


@dataclass(frozen=True)
class ControlObjective:
    """One CSA-aligned control objective at a given level."""

    id: str
    statement_zh: str  # the ratified statement text (the contract key)
    evidence: Evidence


@dataclass(frozen=True)
class Dimension:
    """One trustworthiness dimension and its L1..L5 control objectives."""

    dimension: str  # stable id, e.g. "robustness"
    title_en: str
    title_zh: str
    levels: Mapping[str, tuple[ControlObjective, ...]]  # "L1".."L5"


@dataclass(frozen=True)
class DimensionRegistry:
    """The authoritative 5-dimension taxonomy."""

    dimensions: Mapping[str, Dimension]
