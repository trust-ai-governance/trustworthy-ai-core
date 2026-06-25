"""Tests for tools._rc_decode (the shared lazy RequestContext decoder)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from tools._rc_decode import decode_request_context
from trustworthy_ai.v1 import request_context_pb2 as rc_pb


def test_decodes_real_payload():
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = "req-x"
    out = decode_request_context(ctx.SerializeToString())
    assert out.envelope.request_id == "req-x"


def test_proto_missing_raises_rc_decode_unavailable():
    """With the ir-spec proto blocked at import, decode raises the typed error
    (not a bare ImportError) — in a fresh process so the block takes effect."""
    env = {
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
        "PATH": "/usr/bin:/bin",
    }
    code = (
        "import sys, importlib.abc\n"
        "class _Block(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.startswith('trustworthy_ai'):\n"
        "            raise ImportError('blocked for test')\n"
        "        return None\n"
        "sys.meta_path.insert(0, _Block())\n"
        "from tools._rc_decode import RcDecodeUnavailable, decode_request_context\n"
        "try:\n"
        "    decode_request_context(b'')\n"
        "except RcDecodeUnavailable:\n"
        "    sys.exit(0)\n"
        "sys.exit(1)\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr
