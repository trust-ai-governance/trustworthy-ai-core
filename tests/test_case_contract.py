"""UI-3 §5.1 / C1 — the case contract's READ half is pure (stdlib only) and importing it (or the
`cases verify` CLI) must NOT drag in the active-eval harness. That isolation is what lets the case
SERVICE and the verify CLI read contracts with ZERO ability to fire a probe (EV-W1 §7-5)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _no_harness(module: str) -> None:
    code = (
        f"import sys; import {module}; "
        "leaked = [m for m in sys.modules if m.startswith('treval.active_eval')]; "
        f"assert not leaked, '{module} pulled the harness: ' + repr(leaked)"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, cwd=_ROOT
    )
    assert proc.returncode == 0, proc.stderr


def test_case_contract_is_engine_free():
    """🔴 import the pure reader ⇒ the harness stays out of sys.modules. Add an active_eval import
    to treval/case_contract.py and this goes red."""
    _no_harness("treval.case_contract")


def test_cases_verify_cli_is_engine_free():
    """🔴 C1: `cases verify` reads the pure module now (module-level import), so the CLI no longer
    pulls the harness either."""
    _no_harness("treval.cli.cases_verify")


def test_read_half_is_reexported_unchanged():
    """The split is invisible to existing import paths: the names re-exported from active_eval.cases
    ARE the pure module's objects (not copies)."""
    from treval import case_contract
    from treval.active_eval import cases

    for name in (
        "CaseContractError",
        "recompute_from_cases",
        "compare_cases_to_aggregates",
        "validate_case_contract",
        "SCHEMA_VERSION",
        "VERDICTS",
    ):
        assert getattr(cases, name) is getattr(case_contract, name)
