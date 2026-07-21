"""Indicator SDK — registry + runner + the reference indicators (EV-4, EV-5, EV-9).

EV-4 ships the machinery (IndicatorRegistry, run_indicators) and the first concrete
indicator (BlockRate). EV-5 adds the passive WAL indicators — chain_integrity /
duration_p99 / terminal_error_ratio (single-record) + unclosed_loop_rate (A↔B) — and the
shared `join_ab` correlation helper. EV-9 adds boundary_breach_rate (composes rule surfaces
+ authz via join_ab) and the PII pair redaction_hit_ratio / pii_exposure_surface (B1 marker).
Only drift_alert_count stays DEFERRED (no code) until Platform P3-drift lands — see EV-9 §3
(its row stays insufficient_data).
"""

from __future__ import annotations

from treval.indicators.block_rate import BlockRate
from treval.indicators.boundary_breach_rate import BoundaryBreachRate
from treval.indicators.chain_integrity import ChainIntegrity
from treval.indicators.correlate import JoinResult, join_ab
from treval.indicators.duration_p99 import DurationP50, DurationP95, DurationP99
from treval.indicators.pii import PiiExposureSurface, RedactionHitRatio
from treval.indicators.registry import IndicatorRegistry
from treval.indicators.runner import run_indicators
from treval.indicators.terminal_error_ratio import TerminalErrorRatio
from treval.indicators.unclosed_loop_rate import UnclosedLoopRate


def build_default_registry() -> IndicatorRegistry:
    """The indicators core ships, registered. The one deferred EV-9 indicator
    (drift_alert_count) appends here when P3-drift lands."""
    reg = IndicatorRegistry()
    reg.register(BlockRate())
    reg.register(ChainIntegrity())
    reg.register(DurationP99())
    reg.register(TerminalErrorRatio())
    reg.register(UnclosedLoopRate())
    reg.register(BoundaryBreachRate())
    reg.register(RedactionHitRatio())
    reg.register(PiiExposureSurface())
    return reg


__all__ = [
    "IndicatorRegistry",
    "run_indicators",
    "BlockRate",
    # EV-5a — passive single-record WAL indicators
    "ChainIntegrity",
    "DurationP99",
    # P3C-harness C1 — latency distribution (p50/p95 alongside the p99 baseline). Exported
    # for the selection spike; NOT in build_default_registry (the maturity report keeps p99
    # as its single latency objective — adding p50/p95 there would churn every golden bundle).
    "DurationP50",
    "DurationP95",
    "TerminalErrorRatio",
    # EV-5b — A↔B join + closed-loop check
    "UnclosedLoopRate",
    "join_ab",
    "JoinResult",
    # EV-9 — dimension attribution
    "BoundaryBreachRate",
    "RedactionHitRatio",
    "PiiExposureSurface",
    "build_default_registry",
]
