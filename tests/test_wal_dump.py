"""Unit tests for wal_dump (core repo)."""

from __future__ import annotations

import struct
import zlib

import tools.wal_dump as wal_dump
from tools._wal_format import REC_FMT_V2, REC_SIZE_V2, SEG_SIZE_V2
from walgen import build_v2_wal


def test_dump_clean_exit_zero(tmp_path, capsys):
    build_v2_wal(tmp_path, total=12, per_segment=5)
    rc = wal_dump.main([str(tmp_path)])
    assert rc == 0
    out = capsys.readouterr()
    assert out.out.count("seq=") == 12  # one record line each
    assert "hash=" in out.out


def test_dump_seq_range_filter(tmp_path, capsys):
    build_v2_wal(tmp_path, total=20, per_segment=20)
    rc = wal_dump.main([str(tmp_path), "--from", "5", "--to", "9"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.count("seq=") == 5  # seqs 5..9


def test_dump_summary_no_record_lines(tmp_path, capsys):
    build_v2_wal(tmp_path, total=10, per_segment=10)
    rc = wal_dump.main([str(tmp_path), "--summary"])
    assert rc == 0
    out = capsys.readouterr()
    assert "payload_preview" not in out.out
    assert "segment" in out.err  # summary goes to stderr


def test_dump_detects_corruption_exit_two(tmp_path, capsys):
    build_v2_wal(tmp_path, total=5, per_segment=5)
    seg = sorted(tmp_path.glob("*.wal"))[0]
    raw = bytearray(seg.read_bytes())
    # Corrupt the first record's payload without fixing CRC.
    off = SEG_SIZE_V2
    length = struct.unpack(REC_FMT_V2, raw[off : off + REC_SIZE_V2])[0]
    raw[off + REC_SIZE_V2] ^= 0xFF
    seg.write_bytes(bytes(raw))
    _ = (length, zlib)  # keep imports honest
    rc = wal_dump.main([str(tmp_path)])
    assert rc == 2
    assert "CRC MISMATCH" in capsys.readouterr().err
