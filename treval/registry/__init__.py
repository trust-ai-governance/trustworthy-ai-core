"""Dimension Registry — the data-driven 5×5 maturity taxonomy (EV-6)."""

from __future__ import annotations

from treval.registry.loader import (
    RegistryError,
    load_registry,
    validate_against,
)
from treval.registry.models import (
    ControlObjective,
    Dimension,
    DimensionRegistry,
    Evidence,
)
from treval.registry.satisfied_when import (
    SatisfiedWhenError,
    compile_satisfied_when,
)
from treval.registry.serialize import (
    DIMENSION_ORDER,
    LEVELS,
    LEVELS_META,
    serialize_registry,
)

__all__ = [
    "Evidence",
    "ControlObjective",
    "Dimension",
    "DimensionRegistry",
    "load_registry",
    "validate_against",
    "RegistryError",
    "compile_satisfied_when",
    "SatisfiedWhenError",
    # canonical registry → dict (consumed by treval.web AND treval.rubric)
    "serialize_registry",
    "LEVELS",
    "LEVELS_META",
    "DIMENSION_ORDER",
]
