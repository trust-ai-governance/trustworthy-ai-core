"""Test-only WAL writer — the inverse of the verifier, used to build fixtures.

Core is independent of the platform, so its tests construct WAL bytes directly
from the published format. This writer is the minimal reference encoder.
"""

from __future__ import annotations

import hashlib
import struct
import zlib
from pathlib import Path

from tools._wal_format import (
    GENESIS,
    MAGIC,
    REC_FMT_V1,
    REC_FMT_V2,
    SEG_FMT_V1,
    SEG_FMT_V2,
)

NAME = "{:017d}.wal"


def write_v2_segment(
    path: Path, start_seq: int, payloads: list[bytes], first_prev: bytes
) -> bytes:
    """Write a v2 segment; return the chain head after the last record."""
    buf = bytearray(struct.pack(SEG_FMT_V2, MAGIC, 2, start_seq, 1, first_prev))
    prev = first_prev
    for p in payloads:
        h = hashlib.sha256(prev + p).digest()
        buf += struct.pack(REC_FMT_V2, len(p), zlib.crc32(p) & 0xFFFFFFFF, h) + p
        prev = h
    path.write_bytes(bytes(buf))
    return prev


def write_v1_segment(path: Path, start_seq: int, payloads: list[bytes]) -> None:
    buf = bytearray(struct.pack(SEG_FMT_V1, MAGIC, 1, start_seq, 1))
    for p in payloads:
        buf += struct.pack(REC_FMT_V1, len(p), zlib.crc32(p) & 0xFFFFFFFF) + p
    path.write_bytes(bytes(buf))


def build_v2_wal(directory: Path, total: int, per_segment: int) -> bytes:
    """Build a multi-segment v2 WAL of `total` records; return final chain head."""
    directory.mkdir(parents=True, exist_ok=True)
    prev = GENESIS
    seq = 0
    while seq < total:
        chunk = [
            f"rec-{i:04d}".encode() for i in range(seq, min(seq + per_segment, total))
        ]
        prev = write_v2_segment(directory / NAME.format(seq), seq, chunk, prev)
        seq += len(chunk)
    return prev
