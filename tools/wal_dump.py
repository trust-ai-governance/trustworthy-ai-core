"""wal_dump — human-readable dump of WAL segment files (v1 + v2).

Lives in the OPEN core repo alongside wal_verify; both share the zero-dependency
_wal_format parser and do NOT import the platform. Compensates for the binary
WAL format being unreadable to grep.

Default output, one line per record:
    seq=<n> bytes=<len> crc=ok hash=<first8hex>… payload_preview=<repr>

Usage:
    python wal_dump.py <wal_dir> [--from N] [--to M] [--hex] [--strict] [--summary]
Exit: 0 clean | 2 corruption (CRC mismatch on a non-tail record) | 3 io/arg error
"""

from __future__ import annotations

import argparse
import sys
import zlib
from pathlib import Path

from tools._wal_format import (
    V2,
    WalFormatError,
    iter_records,
    list_segments,
    read_segment_header,
)


def _format_record(rec, hex_mode: bool) -> str:
    h = rec.stored_hash.hex()[:16] if rec.stored_hash else "(v1:none)"
    if hex_mode:
        return f"seq={rec.seq} bytes={len(rec.payload)} crc=ok hash={h} payload_hex={rec.payload.hex()}"
    preview = rec.payload[:64]
    ell = "…" if len(rec.payload) > 64 else ""
    return f"seq={rec.seq} bytes={len(rec.payload)} crc=ok hash={h} payload_preview={preview!r}{ell}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="wal_dump", description="Dump WAL segment files in human-readable form."
    )
    ap.add_argument(
        "wal_dir", type=Path, help="Directory containing .wal files (or one .wal file)"
    )
    ap.add_argument(
        "--from", dest="from_seq", type=int, default=None, help="Start seq (inclusive)."
    )
    ap.add_argument(
        "--to", dest="to_seq", type=int, default=None, help="End seq (inclusive)."
    )
    ap.add_argument("--hex", action="store_true", help="Print full payload as hex.")
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Treat any CRC mismatch as error (default: report).",
    )
    ap.add_argument(
        "--summary",
        action="store_true",
        help="Per-segment summary only, no per-record lines.",
    )
    args = ap.parse_args(argv)

    if not args.wal_dir.exists():
        print(f"error: {args.wal_dir} does not exist", file=sys.stderr)
        return 3

    segments = [args.wal_dir] if args.wal_dir.is_file() else list_segments(args.wal_dir)
    if not segments:
        print(f"(no .wal files in {args.wal_dir})")
        return 0

    total = 0
    corruption = False
    for seg_path in segments:
        data = seg_path.read_bytes()
        try:
            hdr = read_segment_header(data)
        except WalFormatError as e:
            print(f"segment {seg_path.name}: HEADER CORRUPT — {e}", file=sys.stderr)
            corruption = True
            continue

        seg_count = 0
        done = False
        for rec in iter_records(data, hdr):
            crc_ok = (zlib.crc32(rec.payload) & 0xFFFFFFFF) == rec.crc
            if not crc_ok:
                print(
                    f"segment {seg_path.name}: CRC MISMATCH at seq {rec.seq}",
                    file=sys.stderr,
                )
                corruption = True
                if args.strict:
                    done = True
                    break
                continue
            if args.from_seq is not None and rec.seq < args.from_seq:
                continue
            if args.to_seq is not None and rec.seq > args.to_seq:
                done = True
                break
            seg_count += 1
            total += 1
            if not args.summary:
                print(_format_record(rec, args.hex))

        fp = hdr.first_prev_hash.hex()[:16] if hdr.version == V2 else "(v1)"
        print(
            f"-- segment {seg_path.name}: v{hdr.version} start_seq={hdr.start_seq} "
            f"first_prev_hash={fp} matched={seg_count} created_at_ns={hdr.created_at_ns}",
            file=sys.stderr,
        )
        if done:
            break

    print(f"-- total: {total} records across {len(segments)} segments", file=sys.stderr)
    return 2 if corruption else 0


if __name__ == "__main__":
    sys.exit(main())
