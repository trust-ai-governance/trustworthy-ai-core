"""Tests for `wal_dump --decode` (Issue: readable audit).

Builds a real v2 WAL segment (per _wal_format byte layout) whose payload is a
serialized RequestContext, then exercises:
  - default dump (byte preview) unchanged
  - --decode renders the RequestContext as JSON with params_raw decoded to the
    actual chat request (not base64)
  - --decode degrades gracefully when the proto is unavailable
  - _render_bytes_field unit behaviour
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
import zlib
from pathlib import Path

import pytest

from tools import wal_dump
from tools._wal_format import GENESIS, MAGIC, SEG_FMT_V2, REC_FMT_V2
from trustworthy_ai.v1 import request_context_pb2 as rc_pb


def _build_ctx(params: dict) -> bytes:
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = "019ed524-c1a8-76ab-9162-f31e1ad72f1b"
    ctx.envelope.received_at_ns = 1781692795000000000
    ctx.envelope.tenant_id = "dogfood"
    ctx.envelope.protocol = 2   # type: ignore[assignment]
    ctx.envelope.source_addr = "127.0.0.1:54321"
    ctx.identity.agent.agent_id = "dogfood-agent"
    ctx.identity.agent.agent_type = "unknown"
    ctx.invocation.tool_id = "chat"
    ctx.invocation.params_raw = json.dumps(params).encode("utf-8")
    ctx.decision.decision_reason = "allowed"
    return ctx.SerializeToString()


def _write_v2_segment(path: Path, start_seq: int, payloads: list[bytes]) -> None:
    """Write a minimal valid v2 segment: header + records (length, crc, hash)."""
    created_at_ns = 1781692322566720246
    prev = GENESIS
    header = struct.pack(SEG_FMT_V2, MAGIC, 2, start_seq, created_at_ns, prev)
    body = b""
    for payload in payloads:
        h = hashlib.sha256(prev + payload).digest()
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        body += struct.pack(REC_FMT_V2, len(payload), crc, h)
        body += payload
        prev = h
    path.write_bytes(header + body)


@pytest.fixture()
def wal_dir(tmp_path: Path) -> Path:
    d = tmp_path / "wal"
    d.mkdir()
    params = {
        "model": "deepseek-v4-flash",
        "messages": [{"role": "user", "content": "用5个字打个招呼"}],
    }
    _write_v2_segment(d / "00000000000000034.wal", 34, [_build_ctx(params)])
    return d


def test_default_dump_shows_byte_preview(wal_dir, capsys):
    rc = wal_dump.main([str(wal_dir)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "seq=34" in out
    assert "payload_preview=" in out
    assert "RequestContext=" not in out  # no decode without the flag


def test_decode_renders_requestcontext_json(wal_dir, capsys):
    # Reset the module-level decoder cache so the proto is (re)discovered.
    wal_dump._DECODER = None
    rc = wal_dump.main([str(wal_dir), "--decode"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "seq=34" in out
    assert "RequestContext=" in out
    # The decoded JSON block is everything after the first "RequestContext=".
    blob = out.split("RequestContext=", 1)[1]
    decoded = json.loads(blob[blob.index("{") :])
    assert decoded["envelope"]["tenant_id"] == "dogfood"
    assert decoded["envelope"]["request_id"].startswith("019ed524")
    assert decoded["identity"]["agent"]["agent_id"] == "dogfood-agent"
    assert decoded["invocation"]["tool_id"] == "chat"
    # params_raw rendered as the actual chat request, NOT base64.
    pr = decoded["invocation"]["params_raw"]
    assert pr["model"] == "deepseek-v4-flash"
    assert pr["messages"][0]["content"] == "用5个字打个招呼"


def test_decode_unavailable_falls_back(wal_dir, tmp_path):
    """In a fresh process with no proto importable, --decode warns + falls back
    to the preview, still exits 0."""
    env = {
        "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
        "PATH": "/usr/bin:/bin",
    }
    # A throwaway sitecustomize that hides the proto package.
    code = (
        "import sys, importlib.abc, importlib.machinery\n"
        "class _Block(importlib.abc.MetaPathFinder):\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.startswith('trustworthy_ai'):\n"
        "            raise ImportError('blocked for test')\n"
        "        return None\n"
        "sys.meta_path.insert(0, _Block())\n"
        "from tools import wal_dump\n"
        f"rc = wal_dump.main(['{wal_dir}', '--decode'])\n"
        "sys.exit(rc)\n"
    )
    r = subprocess.run(
        [sys.executable, "-c", code], env=env, capture_output=True, text=True
    )
    assert r.returncode == 0
    assert "warning: --decode unavailable" in r.stderr
    assert "payload_preview=" in r.stdout  # fell back to preview
    assert "RequestContext=" not in r.stdout


def test_render_bytes_field_json():
    import base64

    b64 = base64.b64encode(b'{"a": 1}').decode()
    assert wal_dump._render_bytes_field(b64) == {"a": 1}


def test_render_bytes_field_plain_text():
    import base64

    b64 = base64.b64encode("héllo".encode("utf-8")).decode()
    assert wal_dump._render_bytes_field(b64) == "héllo"


def test_render_bytes_field_non_utf8():
    import base64

    b64 = base64.b64encode(b"\xff\xfe\x00").decode()
    out = wal_dump._render_bytes_field(b64)
    assert isinstance(out, dict) and out["_bytes_len"] == 3


def test_render_bytes_field_not_base64_passthrough():
    assert wal_dump._render_bytes_field("not base64 @@@") == "not base64 @@@"
    assert wal_dump._render_bytes_field(123) == 123
