"""WAL format parser — independent, zero-dependency.

Lives in the OPEN core repo. It deliberately RE-DECLARES the WAL byte format
(rather than importing the platform's wal.py) so customers can inspect and
verify audit integrity WITHOUT trusting — or even possessing — the closed-source
Gateway. The canonical spec is published in trustworthy-ai-ir-spec; this module
is its executable reference parser, shared by wal_verify and wal_dump.

Format (big-endian):
  segment file name : NNNNNNNNNNNNNNNNN.wal   (live: 17-digit zero-padded start_seq)
                      START-END-CREATEDNS.wal (archived/A3: self-describing seq range)
  segment header v1 : 8s magic | I version=1 | q start_seq | q created_at_ns          (28B)
  segment header v2 : ...as v1... | 32s first_prev_hash                               (60B)
  record v1         : I length | I crc32 | <payload>                                  (8B hdr)
  record v2         : I length | I crc32 | 32s sha256_hash | <payload>                (44B hdr)
  hash_i = SHA256(prev_hash || payload_i)   (over the stored bytes; v2 only)
  seq is NOT stored: seq = segment.start_seq + position-within-segment
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

MAGIC = b"TAIWAL01"
SEG_FMT_V1 = ">8sIqq"
SEG_SIZE_V1 = struct.calcsize(SEG_FMT_V1)  # 28
SEG_FMT_V2 = ">8sIqq32s"
SEG_SIZE_V2 = struct.calcsize(SEG_FMT_V2)  # 60
REC_FMT_V1 = ">II"
REC_SIZE_V1 = struct.calcsize(REC_FMT_V1)  # 8
REC_FMT_V2 = ">II32s"
REC_SIZE_V2 = struct.calcsize(REC_FMT_V2)  # 44
HASH_SIZE = 32
V1, V2 = 1, 2
GENESIS = hashlib.sha256(b"trustworthy-ai-wal-genesis-v2").digest()


class WalFormatError(Exception):
    """Header is unreadable / unsupported (not a per-record integrity failure)."""


@dataclass(frozen=True)
class SegHeader:
    version: int
    start_seq: int
    created_at_ns: int
    first_prev_hash: bytes  # 32B for v2, b"" for v1
    header_size: int


@dataclass(frozen=True)
class Record:
    seq: int
    payload: bytes
    crc: int
    stored_hash: bytes  # b"" for v1
    version: int


def _segment_start_seq(p: Path) -> int:
    """Start seq encoded in a segment filename, for discovery/sort. Two schemes:
    live `<start_seq>.wal` (17-digit) and archived `<start_seq>-<end_seq>-<created_ns>.wal`
    (A3 self-describing key). Both lead with start_seq, so take the first field. The
    authoritative seq still comes from the segment HEADER, not the name."""
    return int(p.stem.split("-", 1)[0])


def list_segments(directory: Path) -> list[Path]:
    files = [p for p in directory.iterdir() if p.is_file() and p.name.endswith(".wal")]
    files.sort(key=_segment_start_seq)
    return files


def read_segment_header(data: bytes) -> SegHeader:
    if len(data) < SEG_SIZE_V1:
        raise WalFormatError("segment too short for header")
    magic, ver, start_seq, created = struct.unpack(SEG_FMT_V1, data[:SEG_SIZE_V1])
    if magic != MAGIC:
        raise WalFormatError(f"bad magic {magic!r}")
    if ver == V1:
        return SegHeader(V1, start_seq, created, b"", SEG_SIZE_V1)
    if ver == V2:
        if len(data) < SEG_SIZE_V2:
            raise WalFormatError("segment too short for v2 header")
        first_prev = struct.unpack(SEG_FMT_V2, data[:SEG_SIZE_V2])[4]
        return SegHeader(V2, start_seq, created, first_prev, SEG_SIZE_V2)
    raise WalFormatError(f"unsupported format_version {ver}")


def iter_records(data: bytes, header: SegHeader) -> Iterator[Record]:
    """Yield records from one segment's bytes. Stops cleanly at a truncated tail.

    Does NOT raise on CRC/hash mismatch — callers decide. Yields the raw stored
    crc and hash so verifiers can re-check them.
    """
    rec_size = REC_SIZE_V2 if header.version == V2 else REC_SIZE_V1
    off = header.header_size
    seq = header.start_seq
    n = len(data)
    while off + rec_size <= n:
        hbytes = data[off : off + rec_size]
        if header.version == V2:
            length, crc, stored = struct.unpack(REC_FMT_V2, hbytes)
        else:
            length, crc = struct.unpack(REC_FMT_V1, hbytes)
            stored = b""
        body = off + rec_size
        payload = data[body : body + length]
        if len(payload) < length:
            return  # truncated tail
        yield Record(
            seq=seq,
            payload=payload,
            crc=crc,
            stored_hash=stored,
            version=header.version,
        )
        off = body + length
        seq += 1
