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
]
