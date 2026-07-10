"""treval CLI (EV-8) — Measurement bundle → MaturityReport → {json, human, csv}.

The pure grade/render path (`run_report`, bundle I/O, renderers) is importable and
CI-tested; the operator `collect` path lives in `treval.cli.collect` and is only pulled
in when that subcommand runs. Entry point: `python -m treval.cli`.
"""

from __future__ import annotations

from treval.cli.bundle import (
    BundleError,
    LoadedBundle,
    build_bundle,
    load_bundle,
    parse_measurement,
)
from treval.cli.main import main, run_report
from treval.cli.render import render_csv, render_human

__all__ = [
    "main",
    "run_report",
    "load_bundle",
    "build_bundle",
    "parse_measurement",
    "LoadedBundle",
    "BundleError",
    "render_human",
    "render_csv",
]
