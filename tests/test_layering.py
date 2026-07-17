"""Layering invariants — the dependency edges the architecture forbids.

The engine (`treval` + its subpackages: models/readers/indicators/registry/rubric/posture/
active_eval/cli) must NEVER import the optional web layer (`treval.web`). Web deps live in
the `treval[web]` extra; an engine→web edge means a plain `import treval` starts pulling the
extra the day anyone adds a FastAPI/Jinja import to `treval.web` — a silent, latent break.

EV-R1 briefly introduced exactly that edge (`treval.rubric.serialize` imported
`treval.web.serialize` for the registry serializer). The fix moved the pure registry→dict
serializer to `treval.registry.serialize`, so both consumers point AT the registry:
`treval.web → treval.registry` and `treval.rubric → treval.registry`. This test keeps it
from creeping back.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _run(code: str) -> subprocess.CompletedProcess[str]:
    """Run in a CLEAN interpreter — an in-process check would see modules another test
    already imported, masking the leak."""
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        cwd=_ROOT,
    )


def test_import_treval_does_not_pull_the_web_layer():
    code = (
        "import sys; import treval; "
        "leaked = sorted(m for m in sys.modules "
        "if m == 'treval.web' or m.startswith('treval.web.')); "
        "print(','.join(leaked)); "
        "sys.exit(1 if leaked else 0)"
    )
    proc = _run(code)
    assert proc.returncode == 0, (
        f"`import treval` pulled the web layer: {proc.stdout.strip()} — the engine must "
        "never import treval.web (put shared pure helpers in the layer both sides own, "
        f"e.g. treval.registry). stderr: {proc.stderr.strip()}"
    )


def test_engine_subpackages_do_not_pull_the_web_layer():
    """The rubric/serialize path is the one that regressed — assert the whole engine
    surface (incl. the CLI's pure report path) stays web-free."""
    code = (
        "import sys; "
        "import treval, treval.rubric, treval.registry, treval.indicators, "
        "treval.readers, treval.posture, treval.cli; "
        "leaked = sorted(m for m in sys.modules "
        "if m == 'treval.web' or m.startswith('treval.web.')); "
        "print(','.join(leaked)); "
        "sys.exit(1 if leaked else 0)"
    )
    proc = _run(code)
    assert proc.returncode == 0, (
        f"an engine subpackage pulled the web layer: {proc.stdout.strip()} — "
        f"stderr: {proc.stderr.strip()}"
    )


def test_registry_serializer_is_importable_without_web():
    """The moved serializer must be reachable from the registry alone (its new home)."""
    code = (
        "import sys; from treval.registry import serialize_registry; "
        "from treval.registry.serialize import LEVELS_META, DIMENSION_ORDER; "
        "assert callable(serialize_registry); "
        "leaked = [m for m in sys.modules if m.startswith('treval.web')]; "
        "sys.exit(1 if leaked else 0)"
    )
    proc = _run(code)
    assert proc.returncode == 0, proc.stderr
