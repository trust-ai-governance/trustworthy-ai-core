"""wal_dump — human-readable dump of WAL segment files (v1 + v2).

Lives in the OPEN core repo alongside wal_verify; both share the zero-dependency
_wal_format parser and do NOT import the platform. Compensates for the binary
WAL format being unreadable to grep.

Default output, one line per record:
    seq=<n> bytes=<len> crc=ok hash=<first8hex>… payload_preview=<repr>

With --decode, each payload is deserialized as a trustworthy_ai.v1
RequestContext and printed as readable JSON. This is the ONLY path that imports
the (open, ir-spec) proto, and the import is LAZY and OPTIONAL: the default dump
and ALL verification stay zero-dependency and work without the proto, preserving
the core repo's "inspect/verify without possessing the Gateway" property. If the
proto is unavailable, --decode warns once and falls back to the byte preview.
The WAL payload is the audited RequestContext as written at the decision point;
note the MVP writes only the pre-forward record, so the upstream response /
token_usage are NOT present until the response.observed record lands.

Usage:
    python wal_dump.py <wal_dir> [--from N] [--to M] [--hex | --decode] [--strict] [--summary]
Exit: 0 clean | 2 corruption (CRC mismatch on a non-tail record) | 3 io/arg error
"""

from __future__ import annotations

import argparse
import base64
import json
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


# ---------------------------------------------------------------------------
# Optional RequestContext decoder (--decode). Lazy + graceful: importing the
# proto is deferred to first use so the default/verify paths stay zero-dep.
# _DECODER is None (untried) | False (unavailable) | callable(payload)->dict.
# ---------------------------------------------------------------------------

_DECODER = None


def _get_decoder():
    global _DECODER
    if _DECODER is not None:
        return _DECODER
    try:
        from google.protobuf.json_format import MessageToDict
        from trustworthy_ai.v1 import request_context_pb2 as rc_pb
    except Exception as e:  # ImportError, or proto runtime mismatch
        print(
            f"warning: --decode unavailable ({type(e).__name__}: {e}). Install the "
            f"trustworthy-ai-ir-spec proto package (provides "
            f"trustworthy_ai.v1.request_context_pb2) to decode payloads. Falling "
            f"back to byte preview.",
            file=sys.stderr,
        )
        _DECODER = False
        return False

    def decode(payload: bytes) -> dict:
        ctx = rc_pb.RequestContext.FromString(payload)
        d = MessageToDict(ctx, preserving_proto_field_name=True)
        # Convenience: render invocation.params_raw (a base64-encoded bytes
        # field) back to text/JSON so the actual request is readable.
        inv = d.get("invocation")
        if isinstance(inv, dict) and "params_raw" in inv:
            inv["params_raw"] = _render_bytes_field(inv["params_raw"])
        return d

    _DECODER = decode
    return _DECODER


def _render_bytes_field(b64val):
    """MessageToDict encodes bytes fields as base64 strings; make them readable.

    Returns parsed JSON if the bytes are JSON, else the decoded text, else a
    small descriptor for non-UTF-8 bytes. Never raises.
    """
    if not isinstance(b64val, str):
        return b64val
    try:
        raw = base64.b64decode(b64val, validate=True)
    except Exception:
        return b64val
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return {"_bytes_len": len(raw), "_b64": b64val}
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text


def _format_record(rec, hex_mode: bool) -> str:
    h = rec.stored_hash.hex()[:16] if rec.stored_hash else "(v1:none)"
    if hex_mode:
        return f"seq={rec.seq} bytes={len(rec.payload)} crc=ok hash={h} payload_hex={rec.payload.hex()}"
    preview = rec.payload[:64]
    ell = "…" if len(rec.payload) > 64 else ""
    return f"seq={rec.seq} bytes={len(rec.payload)} crc=ok hash={h} payload_preview={preview!r}{ell}"


def _format_decoded(rec) -> str | None:
    """Decoded multi-line form for --decode. Returns None if the decoder is
    unavailable (caller falls back to the preview line)."""
    decode = _get_decoder()
    if not decode:
        return None
    h = rec.stored_hash.hex()[:16] if rec.stored_hash else "(v1:none)"
    try:
        d = decode(rec.payload)
    except Exception as e:
        # A record that isn't a RequestContext, or a proto-version mismatch.
        preview = rec.payload[:48]
        return (
            f"seq={rec.seq} bytes={len(rec.payload)} hash={h} "
            f"DECODE FAILED ({type(e).__name__}: {e}) payload_preview={preview!r}…"
        )
    body = json.dumps(d, indent=2, ensure_ascii=False)
    return f"seq={rec.seq} bytes={len(rec.payload)} crc=ok hash={h} RequestContext=\n{body}"


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
        "--decode",
        action="store_true",
        help=(
            "Deserialize each payload as a RequestContext and print readable JSON "
            "(lazily imports the open ir-spec proto; falls back to preview if "
            "unavailable). Takes precedence over --hex."
        ),
    )
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
                line = _format_decoded(rec) if args.decode else None
                if line is None:
                    line = _format_record(rec, args.hex)
                print(line)

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
