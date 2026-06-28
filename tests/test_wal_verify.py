"""Unit tests for the independent verifier (core repo)."""

from __future__ import annotations

import hashlib
import struct
import zlib

import tools.wal_verify as wal_verify
from tools._wal_format import (
    GENESIS,
    REC_FMT_V2,
    REC_SIZE_V2,
    SEG_SIZE_V2,
    list_segments,
)
from walgen import NAME, build_v2_wal, write_v1_segment, write_v2_segment


def test_clean_wal_passes(tmp_path):
    build_v2_wal(tmp_path, total=30, per_segment=7)
    rep = wal_verify.verify(tmp_path, full=True)
    assert rep.ok
    assert rep.records == 30


def test_single_archived_segment_self_verifies(tmp_path):
    # An archived segment in the MIDDLE of a chain still verifies on its own,
    # because its header carries first_prev_hash (self-contained).
    build_v2_wal(tmp_path, total=30, per_segment=10)
    middle = sorted(tmp_path.glob("*.wal"))[1]
    rep = wal_verify.verify(middle, full=True)
    assert rep.ok and rep.records == 10


def _archive_name(start: int, end: int, created_ns: int) -> str:
    # A3 self-describing archive key: <start_seq>-<end_seq>-<created_ns>.wal
    return f"{start:017d}-{end:017d}-{created_ns}.wal"


def test_archived_segment_naming_is_discovered_and_sorted(tmp_path):
    # Archived segments use START-END-CREATEDNS.wal, not <seq>.wal. They must be
    # discovered AND sorted by start_seq (regression: int(p.stem) choked on hyphens).
    s1 = [f"a-{i}".encode() for i in range(10)]  # seq 0..9
    s2 = [f"b-{i}".encode() for i in range(10)]  # seq 10..19
    head = write_v2_segment(tmp_path / _archive_name(0, 9, 111), 0, s1, GENESIS)
    # write the LATER segment with an earlier-sorting filesystem name to prove the
    # sort uses start_seq, not name/creation order.
    write_v2_segment(tmp_path / _archive_name(10, 19, 222), 10, s2, head)

    segs = list_segments(tmp_path)
    assert [p.name.split("-", 1)[0] for p in segs] == [
        "00000000000000000",
        "00000000000000010",
    ]

    rep = wal_verify.verify(tmp_path, full=True)
    assert rep.ok and rep.records == 20  # chain continuous across archived segments


def test_mixed_live_and_archived_names_sort_by_start_seq(tmp_path):
    # A live segment (seq 0) + an archived continuation (seq 10..19) interleave fine.
    head = build_v2_wal(tmp_path, total=10, per_segment=10)  # live NAME 0..9
    s2 = [f"b-{i}".encode() for i in range(10)]
    write_v2_segment(tmp_path / _archive_name(10, 19, 333), 10, s2, head)
    rep = wal_verify.verify(tmp_path, full=True)
    assert rep.ok and rep.records == 20


def _tamper(seg, record_index, *, fix_crc):
    raw = bytearray(seg.read_bytes())
    off = SEG_SIZE_V2
    for i in range(record_index + 1):
        length, crc, h = struct.unpack(REC_FMT_V2, raw[off : off + REC_SIZE_V2])
        body = off + REC_SIZE_V2
        if i == record_index:
            raw[body] ^= 0xFF
            if fix_crc:
                new_crc = zlib.crc32(bytes(raw[body : body + length])) & 0xFFFFFFFF
                raw[off : off + REC_SIZE_V2] = struct.pack(
                    REC_FMT_V2, length, new_crc, h
                )
            break
        off = body + length
    seg.write_bytes(bytes(raw))


def test_tamper_breaks_chain_localised(tmp_path):
    build_v2_wal(tmp_path, total=10, per_segment=10)
    seg = sorted(tmp_path.glob("*.wal"))[0]
    _tamper(seg, 4, fix_crc=False)
    rep = wal_verify.verify(tmp_path, full=True)
    assert not rep.ok
    breaks = [f for f in rep.findings if "CHAIN BREAK" in f["message"]]
    assert any(f["seq"] == 4 for f in breaks)


def test_crc_fixed_tamper_still_caught_by_chain(tmp_path):
    """The key property: an attacker who recomputes CRC still cannot beat the
    hash chain (proves hash > CRC)."""
    build_v2_wal(tmp_path, total=10, per_segment=10)
    seg = sorted(tmp_path.glob("*.wal"))[0]
    _tamper(seg, 3, fix_crc=True)
    rep = wal_verify.verify(tmp_path, full=True)
    assert not rep.ok
    assert not any(f["seq"] == 3 and "CRC" in f["message"] for f in rep.findings)
    assert any(f["seq"] == 3 and "CHAIN BREAK" in f["message"] for f in rep.findings)


def test_missing_segment_seq_gap(tmp_path):
    build_v2_wal(tmp_path, total=30, per_segment=10)
    segs = sorted(tmp_path.glob("*.wal"))
    segs[1].unlink()  # drop the middle segment
    rep = wal_verify.verify(tmp_path, full=True)
    assert not rep.ok
    assert any(
        "discontinuity" in f["message"] or "chain break at segment" in f["message"]
        for f in rep.findings
    )


def test_v1_epoch_then_v2(tmp_path):
    # Legacy v1 segment, then a fresh v2 epoch starting at GENESIS.
    write_v1_segment(
        tmp_path / NAME.format(0), 0, [b"legacy-0", b"legacy-1", b"legacy-2"]
    )
    write_v2_segment(tmp_path / NAME.format(3), 3, [b"modern-3", b"modern-4"], GENESIS)
    rep = wal_verify.verify(tmp_path, full=True)
    assert rep.ok
    assert rep.records == 5


def test_v2_epoch_with_wrong_first_prev_is_caught(tmp_path):
    # If the first v2 segment after v1 does NOT start at GENESIS, it's flagged.
    write_v1_segment(tmp_path / NAME.format(0), 0, [b"legacy-0"])
    write_v2_segment(
        tmp_path / NAME.format(1), 1, [b"x"], hashlib.sha256(b"not-genesis").digest()
    )
    rep = wal_verify.verify(tmp_path, full=True)
    assert not rep.ok
    assert any("segment boundary" in f["message"] for f in rep.findings)
