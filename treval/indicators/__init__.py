"""Indicator SDK — registry + runner + the reference indicators (EV-4).

EV-4 ships the machinery (IndicatorRegistry, run_indicators) and the first
concrete indicator (BlockRate). Later issues (EV-5a/5b, EV-9) append more
indicators to build_default_registry().
"""

from __future__ import annotations

from treval.indicators.block_rate import BlockRate
from treval.indicators.registry import IndicatorRegistry
from treval.indicators.runner import run_indicators


def build_default_registry() -> IndicatorRegistry:
    """The indicators core ships, registered. EV-5+ append to this."""
    reg = IndicatorRegistry()
    reg.register(BlockRate())
    return reg


__all__ = [
    "IndicatorRegistry",
    "run_indicators",
    "BlockRate",
    "build_default_registry",
]
