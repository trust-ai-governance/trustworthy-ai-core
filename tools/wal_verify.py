"""wal_verify — independent WAL integrity verifier (open, zero external deps).

Checks, per segment then across segments:
  - SHA-256 hash chain: stored_hash_i == SHA256(running_head || payload_i)  [v2]
  - CRC32 per record (with --full; v1 always CRC-checked since it has no chain)
  - sequence continuity (no gaps / overlaps across segments)
  - cross-segment linkage: segment.first_prev_hash == running head at boundary

Epoch rule: v1 segments carry no chain (CRC + seq only); the chain restarts
from GENESIS at the first v2 segment. A v1→v2 boundary resets the running head
to GENESIS.

Usage:  python wal_verify.py <wal_dir_or_segment> [--full] [--json]
Exit:   0 ok | 2 integrity failure | 3 io/arg error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from tools._wal_format import (
    GENESIS,
    V1,
    V2,
    WalFormatError,
    iter_records,
    list_segments,
    read_segment_header,
)


@dataclass
class Report:
    ok: bool = True
    records: int = 0
    segments: int = 0
    chain_head: str = ""
    findings: list[dict] = field(default_factory=list)

    def error(self, segment: str, seq, msg: str) -> None:
        self.ok = False
        self.findings.append(
            {"level": "error", "segment": segment, "seq": seq, "message": msg}
        )


def _verify_segment(path: Path, *, running: bytes, expect_seq, full: bool, rep: Report):
    name = path.name
    data = path.read_bytes()
    try:
        hdr = read_segment_header(data)
    except WalFormatError as e:
        rep.error(name, None, str(e))
        return running, expect_seq
    rep.segments += 1

    if expect_seq is not None and hdr.start_seq != expect_seq:
        rep.error(
            name,
            hdr.start_seq,
            f"seq discontinuity: expected start {expect_seq}, got {hdr.start_seq}",
        )

    if hdr.version == V1:
        running = GENESIS  # epoch boundary: next v2 segment must start at GENESIS
    elif hdr.version == V2:
        if expect_seq is None:
            # First segment of this run: we cannot verify linkage to an absent
            # predecessor (e.g. a single archived mid-chain segment). Accept its
            # declared baseline and verify the internal chain from there.
            running = hdr.first_prev_hash
        else:
            if hdr.first_prev_hash != running:
                rep.error(
                    name,
                    hdr.start_seq,
                    "chain break at segment boundary (first_prev_hash != running head)",
                )
            running = hdr.first_prev_hash  # trust the segment's declared start link

    last_seq = hdr.start_seq - 1
    for rec in iter_records(data, hdr):
        if full or hdr.version == V1:
            if (zlib.crc32(rec.payload) & 0xFFFFFFFF) != rec.crc:
                rep.error(name, rec.seq, "CRC mismatch")
        if hdr.version == V2:
            computed = hashlib.sha256(running + rec.payload).digest()
            if computed != rec.stored_hash:
                rep.error(
                    name,
                    rec.seq,
                    "HASH CHAIN BREAK (stored hash != SHA256(prev||payload))",
                )
            running = (
                rec.stored_hash
            )  # advance using stored value to localise the break
        rep.records += 1
        last_seq = rec.seq

    return running, last_seq + 1


def verify(target: Path, *, full: bool = False) -> Report:
    rep = Report()
    segments = [target] if target.is_file() else list_segments(target)
    if not segments:
        rep.error(str(target), None, "no .wal segments found")
        return rep
    running = GENESIS
    expect = None
    for seg in segments:
        running, expect = _verify_segment(
            seg, running=running, expect_seq=expect, full=full, rep=rep
        )
    rep.chain_head = running.hex()
    return rep


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="wal_verify", description="Independent WAL integrity verifier."
    )
    ap.add_argument("target", type=Path, help="WAL directory or a single .wal segment")
    ap.add_argument(
        "--full", action="store_true", help="also re-check CRC on every v2 record"
    )
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    if not args.target.exists():
        print(f"error: {args.target} does not exist", file=sys.stderr)
        return 3

    rep = verify(args.target, full=args.full)
    if args.json:
        print(json.dumps(vars(rep), indent=2))
    else:
        for f in rep.findings:
            loc = f"seq={f['seq']} " if f["seq"] is not None else ""
            print(
                f"[{f['level'].upper()}] {f['segment']}: {loc}{f['message']}",
                file=sys.stderr,
            )
        print(
            f"-- {'OK' if rep.ok else 'FAILED'}: {rep.records} records / "
            f"{rep.segments} segments / head={rep.chain_head[:16]}…"
        )
    return 0 if rep.ok else 2


if __name__ == "__main__":
    sys.exit(main())
