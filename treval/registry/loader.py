"""Dimension Registry loader + validation (EV-6).

Loads the 5 dimension YAMLs into a frozen DimensionRegistry, running structural +
completeness validation at load time. Cross-reference validation against the live
indicator set is a separable method (validate_against) — indicators land across
EV-4/5/9, so the registry can't resolve them all at load time.

The loader takes a path (default = repo-root registry/dimensions/) so the
registry can later move to ir-spec with no code change (EVAL_ARCHITECTURE §2.3).
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import yaml

from treval.registry.models import (
    ControlObjective,
    Dimension,
    DimensionRegistry,
    Evidence,
)
from treval.registry.satisfied_when import SatisfiedWhenError, compile_satisfied_when

_DEFAULT_DIR = Path(__file__).resolve().parents[2] / "registry" / "dimensions"

_EXPECTED_DIMENSIONS = frozenset(
    {
        "robustness",
        "efficient_reliability",
        "security_alignment",
        "transparency_accountability",
        "privacy_data_protection",
    }
)
_LEVELS = ("L1", "L2", "L3", "L4", "L5")
_KINDS = ("measured", "attested")


class RegistryError(Exception):
    """The registry data is malformed (structure or completeness violation)."""


def load_registry(path: str | Path | None = None) -> DimensionRegistry:
    base = Path(path) if path is not None else _DEFAULT_DIR
    if not base.is_dir():
        raise RegistryError(f"registry directory not found: {base}")

    dimensions: dict[str, Dimension] = {}
    for yaml_path in sorted(base.glob("*.yaml")):  # deterministic load order
        dim = _load_dimension(yaml_path)
        if dim.dimension in dimensions:
            raise RegistryError(f"duplicate dimension id {dim.dimension!r}")
        dimensions[dim.dimension] = dim

    _validate_completeness(dimensions)
    return DimensionRegistry(dimensions=dimensions)


def _load_dimension(yaml_path: Path) -> Dimension:
    try:
        doc = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise RegistryError(f"cannot read {yaml_path}: {e}") from e

    if not isinstance(doc, dict):
        raise RegistryError(f"{yaml_path}: top level must be a mapping")
    for field in ("dimension", "title_en", "title_zh", "levels"):
        if doc.get(field) is None:
            raise RegistryError(f"{yaml_path}: missing required '{field}'")

    raw_levels = doc["levels"]
    if not isinstance(raw_levels, dict):
        raise RegistryError(f"{yaml_path}: 'levels' must be a mapping")
    if set(raw_levels) != set(_LEVELS):
        raise RegistryError(
            f"{yaml_path}: levels must be exactly {list(_LEVELS)}, got "
            f"{sorted(raw_levels)} — an empty level must be explicit (N/A)"
        )

    levels: dict[str, tuple[ControlObjective, ...]] = {}
    for level in _LEVELS:
        cell = raw_levels[level]
        # An empty cell must be an explicit `control_objectives: []` (N/A), never
        # a missing key or a bare null — a silent gap is an error (§6).
        if not isinstance(cell, dict) or "control_objectives" not in cell:
            raise RegistryError(
                f"{yaml_path} {level}: must declare 'control_objectives' "
                f"(use [] for N/A)"
            )
        objs = cell["control_objectives"]
        if not isinstance(objs, list):
            raise RegistryError(
                f"{yaml_path} {level}: control_objectives must be a list "
                f"(use [] for N/A)"
            )
        levels[level] = tuple(_build_objective(yaml_path, level, o) for o in objs)

    return Dimension(
        dimension=doc["dimension"],
        title_en=doc["title_en"],
        title_zh=doc["title_zh"],
        levels=levels,
    )


def _build_objective(yaml_path: Path, level: str, o: object) -> ControlObjective:
    if not isinstance(o, dict):
        raise RegistryError(f"{yaml_path} {level}: each objective must be a mapping")
    for field in ("id", "statement_zh", "evidence"):
        if o.get(field) is None:
            raise RegistryError(
                f"{yaml_path} {level}: objective missing '{field}' (id={o.get('id')!r})"
            )
    ev = _build_evidence(yaml_path, level, o["id"], o["evidence"])
    return ControlObjective(id=o["id"], statement_zh=o["statement_zh"], evidence=ev)


def _build_evidence(yaml_path: Path, level: str, oid: str, raw: object) -> Evidence:
    where = f"{yaml_path} {level} {oid}"
    if not isinstance(raw, dict):
        raise RegistryError(f"{where}: evidence must be a mapping")

    kind = raw.get("kind")
    if kind not in _KINDS:
        raise RegistryError(f"{where}: evidence.kind must be one of {list(_KINDS)}")

    indicator_id = raw.get("indicator_id")
    posture_key = raw.get("posture_key")
    satisfied_when = raw.get("satisfied_when")

    if kind == "measured":
        if not indicator_id or posture_key:
            raise RegistryError(
                f"{where}: a measured objective needs indicator_id and no posture_key"
            )
        if not satisfied_when:
            raise RegistryError(f"{where}: a measured objective needs satisfied_when")
        try:
            compile_satisfied_when(satisfied_when)  # validate it parses
        except SatisfiedWhenError as e:
            raise RegistryError(f"{where}: {e}") from e
    else:  # attested
        if not posture_key or indicator_id:
            raise RegistryError(
                f"{where}: an attested objective needs posture_key and no indicator_id"
            )
        if satisfied_when is not None:
            raise RegistryError(
                f"{where}: an attested objective must not carry satisfied_when"
            )

    # Optional integrity gate (EV-7 D2 / EV-6 §11) — default False, must be a bool.
    requires_integrity = raw.get("requires_integrity", False)
    if not isinstance(requires_integrity, bool):
        raise RegistryError(
            f"{where}: requires_integrity, if set, must be a bool "
            f"(got {requires_integrity!r})"
        )

    return Evidence(
        kind=kind,
        indicator_id=indicator_id,
        posture_key=posture_key,
        satisfied_when=satisfied_when,
        requires_integrity=requires_integrity,
    )


def _validate_completeness(dimensions: Mapping[str, Dimension]) -> None:
    have = set(dimensions)
    if have != set(_EXPECTED_DIMENSIONS):
        missing = sorted(_EXPECTED_DIMENSIONS - have)
        extra = sorted(have - _EXPECTED_DIMENSIONS)
        raise RegistryError(
            f"registry must define exactly the 5 dimensions; "
            f"missing={missing} extra={extra}"
        )


def validate_against(
    reg: DimensionRegistry,
    *,
    indicator_ids: set[str],
    posture_keys: set[str] | None = None,
) -> list[str]:
    """Cross-reference check (NOT run at load): every measured objective's
    indicator_id resolves to a known indicator, and (optionally) every attested
    objective's posture_key resolves. Returns a list of problems ([] = clean)."""
    problems: list[str] = []
    for dim in reg.dimensions.values():
        for level in _LEVELS:
            for obj in dim.levels[level]:
                ev = obj.evidence
                if ev.kind == "measured" and ev.indicator_id not in indicator_ids:
                    problems.append(
                        f"{obj.id}: unknown indicator_id {ev.indicator_id!r}"
                    )
                if (
                    posture_keys is not None
                    and ev.kind == "attested"
                    and ev.posture_key not in posture_keys
                ):
                    problems.append(f"{obj.id}: unknown posture_key {ev.posture_key!r}")
    return problems
