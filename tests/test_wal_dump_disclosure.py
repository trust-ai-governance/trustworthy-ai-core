"""GATE-EGRESS 件二 — `wal_dump --decode/--join` self-declares its disclosure level. The teeth (§2.5):

• --decode / --join ⇒ the three sentences appear on STDERR;
• `wal_dump --decode > out` ⇒ out (stdout) has NO header (still pipeable/diffable);
• the default (undecoded) dump ⇒ NO header (the level follows the content, not the tool);
• --help and the module docstring carry the same three sentences;
• 🔴 there is NO --tenant flag (a filter on a local-file tool is not a boundary — §2.4).
"""

from __future__ import annotations

import hashlib
import json
import struct
import zlib
from pathlib import Path

import pytest

from tools import wal_dump
from tools._wal_format import GENESIS, MAGIC, REC_FMT_V2, SEG_FMT_V2
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

# A distinctive phrase from each of the three sentences — used to assert presence without pinning
# exact wording letter-for-letter (but tied to the constant, so a real change is still caught).
_PHRASES = (
    "UN-REDACTED request content",
    "internal_handoff",
    "interleaves MULTIPLE tenants",
)


def _build_ctx() -> bytes:
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = "req-disc-1"
    ctx.envelope.tenant_id = "dogfood"
    ctx.invocation.tool_id = "chat"
    ctx.invocation.params_raw = json.dumps(
        {"messages": [{"role": "user", "content": "hello"}]}
    ).encode("utf-8")
    return ctx.SerializeToString()


@pytest.fixture()
def wal_dir(tmp_path: Path) -> Path:
    d = tmp_path / "wal"
    d.mkdir()
    payload = _build_ctx()
    header = struct.pack(SEG_FMT_V2, MAGIC, 2, 1, 1781692322566720246, GENESIS)
    h = hashlib.sha256(GENESIS + payload).digest()
    crc = zlib.crc32(payload) & 0xFFFFFFFF
    (d / "00000000000000001.wal").write_bytes(
        header + struct.pack(REC_FMT_V2, len(payload), crc, h) + payload
    )
    return d


def _has_proto() -> bool:
    return bool(wal_dump._get_decoder())


def test_decode_prints_the_header_on_stderr(wal_dir, capsys):
    if not _has_proto():
        pytest.skip(
            "proto unavailable — --decode falls back to preview, no content, no header"
        )
    wal_dump._DECODER = None  # reset the module cache so _get_decoder re-runs cleanly
    rc = wal_dump.main([str(wal_dir), "--decode"])
    err = capsys.readouterr().err
    assert rc in (0, 2)
    for phrase in _PHRASES:
        assert phrase in err, f"missing disclosure phrase on stderr: {phrase!r}"


def test_header_is_on_stderr_not_stdout(wal_dir, capsys):
    """🔴 §2.5: stdout stays clean (pipeable/diffable) — the header is stderr-only."""
    if not _has_proto():
        pytest.skip("proto unavailable")
    wal_dump._DECODER = None
    wal_dump.main([str(wal_dir), "--decode"])
    cap = capsys.readouterr()
    assert "internal_handoff" not in cap.out  # 🔴 not in the piped stdout
    assert "internal_handoff" in cap.err


def test_join_prints_the_header(wal_dir, capsys):
    if not _has_proto():
        pytest.skip("proto unavailable")
    wal_dump._DECODER = None
    wal_dump.main([str(wal_dir), "--join"])
    assert "internal_handoff" in capsys.readouterr().err


def test_default_dump_has_no_header(wal_dir, capsys):
    """The undecoded dump prints only preview + hash — a different kind of thing (§2.3), no header."""
    wal_dump._DECODER = None
    wal_dump.main([str(wal_dir)])
    cap = capsys.readouterr()
    assert "internal_handoff" not in cap.out
    assert "internal_handoff" not in cap.err


def test_help_and_docstring_carry_the_three_sentences(capsys):
    with pytest.raises(SystemExit):
        wal_dump.main(["--help"])
    help_text = capsys.readouterr().out
    for phrase in _PHRASES:
        assert phrase in help_text, f"--help missing: {phrase!r}"
        assert phrase in (wal_dump.__doc__ or ""), f"docstring missing: {phrase!r}"


def test_there_is_no_tenant_filter(wal_dir, capsys):
    """🔴 §2.4 / acceptance: NO --tenant flag. A filter on a local-file reader is not a boundary
    (omit it and it's gone) — it would look like containment while adding none. Adding the option
    makes this go green-when-it-should-be-red, so the test pins its ABSENCE."""
    with pytest.raises(SystemExit) as exc:
        wal_dump.main([str(wal_dir), "--tenant", "dogfood"])
    assert exc.value.code == 2  # argparse: unrecognized arguments
    assert "--tenant" in capsys.readouterr().err
