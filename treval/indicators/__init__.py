"""Indicator SDK — registry + runner + the reference indicators (EV-4, EV-5).

EV-4 ships the machinery (IndicatorRegistry, run_indicators) and the first concrete
indicator (BlockRate). EV-5 adds the passive WAL indicators — chain_integrity /
duration_p99 / terminal_error_ratio (single-record) + unclosed_loop_rate (A↔B) — and the
shared `join_ab` correlation helper (EV-9 reuses it). Later issues (EV-9) append more.
"""

from __future__ import annotations

from treval.indicators.block_rate import BlockRate
from treval.indicators.chain_integrity import ChainIntegrity
from treval.indicators.correlate import JoinResult, join_ab
from treval.indicators.duration_p99 import DurationP99
from treval.indicators.registry import IndicatorRegistry
from treval.indicators.runner import run_indicators
from treval.indicators.terminal_error_ratio import TerminalErrorRatio
from treval.indicators.unclosed_loop_rate import UnclosedLoopRate


def build_default_registry() -> IndicatorRegistry:
    """The indicators core ships, registered. EV-9+ append to this."""
    reg = IndicatorRegistry()
    reg.register(BlockRate())
    reg.register(ChainIntegrity())
    reg.register(DurationP99())
    reg.register(TerminalErrorRatio())
    reg.register(UnclosedLoopRate())
    return reg


__all__ = [
    "IndicatorRegistry",
    "run_indicators",
    "BlockRate",
    # EV-5a — passive single-record WAL indicators
    "ChainIntegrity",
    "DurationP99",
    "TerminalErrorRatio",
    # EV-5b — A↔B join + closed-loop check
    "UnclosedLoopRate",
    "join_ab",
    "JoinResult",
    "build_default_registry",
]
