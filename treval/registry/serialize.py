"""Serialize a loaded DimensionRegistry to the canonical `registry.json` shape.

Pure registry → dict: no web, no engine deps. It lives WITH the registry (not the web
layer) because more than one consumer needs it and the engine must never import web:
  - `treval.web` renders it as the EV-W0 `GET /api/registry` payload;
  - `treval.rubric.serialize` inlines it into the EV-R1 self-contained report bundle
    (+ hashes it for `registry_fingerprint`).
Both edges are then `→ treval.registry`, keeping the "engine never imports web" invariant
(guarded by tests/test_layering.py).

The output mirrors EV-6's model field-for-field (no parallel schema): each
`ControlObjective`'s `Evidence` is flattened onto the objective, and the universal
`levels_meta` constant is added (levels are not in the per-dimension YAML). The shape is
the contract in `docs/issues/EV-W0.md` §1 / `docs/web/registry.sample.json`, and the
`registry` half of `docs/report.schema.json` (EV-R1).

Imports `treval.registry.models` directly (not the `treval.registry` package) so the
package `__init__` can re-export this module without an import cycle.
"""

from __future__ import annotations

from typing import Any

from treval.registry.models import ControlObjective, Dimension, DimensionRegistry

SCHEMA_VERSION = 1

# The five maturity levels, in order. Mirrors EV-6's loader (`_LEVELS`).
LEVELS: tuple[str, ...] = ("L1", "L2", "L3", "L4", "L5")

# Level display names are universal (not per-dimension), so the serializer adds
# them as a fixed constant — see EV-W0 §3. The UI reads these instead of
# hardcoding 偶发/可重复/… .
LEVELS_META: tuple[dict[str, str], ...] = (
    {"id": "L1", "name_en": "Initial", "name_zh": "偶发"},
    {"id": "L2", "name_en": "Repeatable", "name_zh": "可重复"},
    {"id": "L3", "name_en": "Standardized", "name_zh": "标准化"},
    {"id": "L4", "name_en": "Quantitatively Managed", "name_zh": "量化管理"},
    {"id": "L5", "name_en": "Optimizing", "name_zh": "优化"},
)

# Canonical presentation order, matching docs/MATURITY_MODEL.md and the committed
# registry.sample.json (robustness first). The registry's own dict order is sorted
# by filename, so the serializer imposes this stable order for deterministic output.
DIMENSION_ORDER: tuple[str, ...] = (
    "robustness",
    "efficient_reliability",
    "security_alignment",
    "transparency_accountability",
    "privacy_data_protection",
)


def serialize_registry(reg: DimensionRegistry) -> dict[str, Any]:
    """Serialize the registry to the EV-W0 §1 JSON shape (deterministic order)."""
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "dimension_registry",
        "levels_meta": [dict(meta) for meta in LEVELS_META],
        "dimensions": [
            _serialize_dimension(reg.dimensions[dim_id])
            for dim_id in _ordered_dimension_ids(reg)
        ],
    }


def _ordered_dimension_ids(reg: DimensionRegistry) -> list[str]:
    """Canonical order first; any dimension not listed appended (sorted) so the
    output never silently drops a dimension if the registry grows."""
    ordered = [d for d in DIMENSION_ORDER if d in reg.dimensions]
    extra = sorted(d for d in reg.dimensions if d not in DIMENSION_ORDER)
    return ordered + extra


def _serialize_dimension(dim: Dimension) -> dict[str, Any]:
    return {
        "id": dim.dimension,
        "title_en": dim.title_en,
        "title_zh": dim.title_zh,
        "levels": {
            level: [_serialize_objective(obj) for obj in dim.levels[level]]
            for level in LEVELS
        },
    }


def _serialize_objective(obj: ControlObjective) -> dict[str, Any]:
    """Flatten the objective + its Evidence into one record (the §1 shape)."""
    ev = obj.evidence
    return {
        "id": obj.id,
        "statement_zh": obj.statement_zh,
        "kind": ev.kind,
        "indicator_id": ev.indicator_id,
        "posture_key": ev.posture_key,
        "satisfied_when": ev.satisfied_when,
    }
