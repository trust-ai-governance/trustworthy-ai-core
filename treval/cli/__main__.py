"""`python -m treval.cli` entry point (mirrors treval.web)."""

from __future__ import annotations

import sys

from treval.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
