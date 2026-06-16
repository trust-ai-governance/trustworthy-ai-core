import sys
from pathlib import Path

# Make tools/ modules (wal_verify, wal_dump, _wal_format) and the walgen helper
# importable both in CI and when running pytest from the repo root.
_ROOT = Path(__file__).resolve().parent.parent
for _p in (_ROOT, _ROOT / "tools", _ROOT / "tests"):
    sys.path.insert(0, str(_p))
