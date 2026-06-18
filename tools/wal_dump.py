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

Two-record audit (Issue B2): a forwarded request produces two records under one
request_id — a DECISION_MADE record (pre-forward decision) and a
RESPONSE_OBSERVED record (response status/usage/preview, written before
delivery). --decode prints record_type prominently and renders
response.response_body_preview readably. --join groups the pair (and flags a
DECISION_MADE that allowed a forward but has no matching RESPONSE_OBSERVED — a
detectable incomplete-request signal).

Usage:
    python wal_dump.py <wal_dir> [--from N] [--to M]
                       [--hex | --decode | --join] [--strict] [--summary]
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
# Optional RequestContext decoder (--decode / --join). Lazy + graceful.
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
            f"warning: decode unavailable ({type(e).__name__}: {e}). Install the "
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
        # Convenience: render bytes fields (base64 in MessageToDict) readably.
        inv = d.get("invocation")
        if isinstance(inv, dict) and "params_raw" in inv:
            inv["params_raw"] = _render_bytes_field(inv["params_raw"])
        # B2: response.response_body_preview is a bytes field too.
        resp = d.get("response")
        if isinstance(resp, dict) and "response_body_preview" in resp:
            resp["response_body_preview"] = _render_bytes_field(
                resp["response_body_preview"]
            )
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


# ---------------------------------------------------------------------------
# record_type helpers (B2)
# ---------------------------------------------------------------------------

# MessageToDict omits default-valued fields, so a legacy record (record_type=0)
# has NO "record_type" key; post-B2 records carry the enum name.
_RT_DECISION = "AUDIT_RECORD_TYPE_DECISION_MADE"
_RT_RESPONSE = "AUDIT_RECORD_TYPE_RESPONSE_OBSERVED"
_RT_UNSPEC = "AUDIT_RECORD_TYPE_UNSPECIFIED"


def _record_type_label(d: dict) -> str:
    """Short, human label. Legacy (absent/UNSPECIFIED) ⇒ decision.made (legacy)."""
    rt = d.get("record_type")
    if rt in (None, _RT_UNSPEC):
        return "decision.made (legacy)"
    if rt == _RT_DECISION:
        return "decision.made"
    if rt == _RT_RESPONSE:
        return "response.observed"
    return str(rt)


def _is_decision(d: dict) -> bool:
    return _record_type_label(d).startswith("decision.made")


def _is_explicit_decision(d: dict) -> bool:
    """True only for post-B2 DECISION_MADE (not legacy) — used for the
    incomplete-request flag so legacy single-record data isn't false-flagged."""
    return d.get("record_type") == _RT_DECISION


def _is_response(d: dict) -> bool:
    return d.get("record_type") == _RT_RESPONSE


def _short_decision(final: str | None) -> str:
    if not final:
        return "?"
    return final.replace("FINAL_DECISION_", "")


# ---------------------------------------------------------------------------
# Per-record formatting
# ---------------------------------------------------------------------------


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
        preview = rec.payload[:48]
        return (
            f"seq={rec.seq} bytes={len(rec.payload)} hash={h} "
            f"DECODE FAILED ({type(e).__name__}: {e}) payload_preview={preview!r}…"
        )
    # B2: surface record_type prominently in the header line.
    label = _record_type_label(d)
    body = json.dumps(d, indent=2, ensure_ascii=False)
    return (
        f"seq={rec.seq} bytes={len(rec.payload)} crc=ok hash={h} "
        f"record_type={label} RequestContext=\n{body}"
    )


# ---------------------------------------------------------------------------
# --join: group A + B by request_id (B2)
# ---------------------------------------------------------------------------


def _join_line_decision(d: dict, seq: int, legacy: bool) -> str:
    inv = d.get("invocation") or {}
    ident = d.get("identity") or {}
    dec = d.get("decision") or {}
    agent = (ident.get("agent") or {}).get("agent_id", "?")
    tag = "decision.made(legacy)" if legacy else "decision.made"
    return (
        f"  {tag:<22} seq={seq}  tool={inv.get('tool_id', '?')}  "
        f"agent={agent}  final={_short_decision(dec.get('final_decision'))}"
    )


def _join_line_response(d: dict, seq: int) -> str:
    r = d.get("response") or {}
    tu = r.get("token_usage") or {}
    extra = tu.get("extra") or {}
    reasoning = extra.get("completion_tokens_details.reasoning_tokens")
    rtxt = f" reasoning={reasoning}" if reasoning else ""
    rules = [rr.get("rule_id") for rr in (r.get("on_tool_response_rules") or [])]
    rules_txt = f"  rules={rules}" if rules else ""
    return (
        f"  {'response.observed':<22} seq={seq}  →A.seq={r.get('decision_seq', '?')}  "
        f"final={r.get('final_terminal', '?')}  status={r.get('response_status_code', 0)}  "
        f"tokens={tu.get('prompt_tokens', 0)}/{tu.get('completion_tokens', 0)}/"
        f"{tu.get('total_tokens', 0)}{rtxt}  dur={r.get('duration_ms', 0)}ms{rules_txt}"
    )


def _run_join(records: list, decode) -> None:
    """Group decoded records by request_id and print A+B together. `records` is a
    list of (seq, decoded_dict). Flags an explicit DECISION_MADE that allowed a
    forward but has no matching RESPONSE_OBSERVED as an incomplete request."""
    groups: dict[str, list[tuple[int, dict]]] = {}
    order: list[str] = []
    for seq, d in records:
        rid = (
            (d.get("envelope") or {}).get("request_id")
        ) or f"(no-request_id seq={seq})"
        if rid not in groups:
            groups[rid] = []
            order.append(rid)
        groups[rid].append((seq, d))

    incomplete = 0
    for rid in order:
        items = sorted(groups[rid], key=lambda x: x[0])
        decisions = [(s, d) for s, d in items if _is_decision(d)]
        responses = [(s, d) for s, d in items if _is_response(d)]
        n = len(items)
        print(f"=== request_id={rid}  ({n} record{'s' if n != 1 else ''}) ===")
        for s, d in items:
            if _is_response(d):
                print(_join_line_response(d, s))
            else:
                print(_join_line_decision(d, s, legacy=not _is_explicit_decision(d)))
        # Incomplete-request flag: an explicit (post-B2) decision.made that
        # allowed a forward but produced no response.observed.
        if not responses:
            for _s, d in decisions:
                if _is_explicit_decision(d):
                    final = _short_decision(
                        (d.get("decision") or {}).get("final_decision")
                    )
                    if final == "ALLOW":
                        print(
                            "  ⚠ INCOMPLETE: decision.made allowed forward but no "
                            "response.observed"
                        )
                        incomplete += 1
                        break
        print()

    print(
        f"-- join: {len(order)} request_id group(s), {len(records)} record(s); "
        f"{incomplete} incomplete",
        file=sys.stderr,
    )
    if incomplete:
        print(
            "-- note: --join over a --from/--to window can split a pair; run over "
            "the full WAL to confirm incompleteness.",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


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
            "unavailable). Shows record_type. Takes precedence over --hex."
        ),
    )
    ap.add_argument(
        "--join",
        action="store_true",
        help=(
            "Group records by request_id and print decision.made + "
            "response.observed together (implies --decode). Flags a decision.made "
            "that allowed a forward but has no response.observed."
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

    # --join needs the decoder; if unavailable, fall back to a plain dump.
    join_decode = None
    if args.join:
        join_decode = _get_decoder()
        if not join_decode:
            print(
                "warning: --join requires the proto to decode request_id; "
                "falling back to default dump.",
                file=sys.stderr,
            )
            args.join = False

    total = 0
    corruption = False
    join_records: list[tuple[int, dict]] = []

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
            if args.join:
                try:
                    if join_decode is None:
                        # 这里根据上下文决定处理方式：要么跳过，要么抛出异常
                        # 由于这是工具脚本，跳过可能不合理，建议抛出 RuntimeError
                        raise RuntimeError(
                            "join_decode unexpectedly None, cannot decode payload"
                        )
                    join_records.append((rec.seq, join_decode(rec.payload)))
                except Exception as e:
                    print(
                        f"seq={rec.seq}: DECODE FAILED ({type(e).__name__}: {e}); "
                        f"excluded from --join",
                        file=sys.stderr,
                    )
                continue
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

    if args.join:
        _run_join(join_records, join_decode)

    print(f"-- total: {total} records across {len(segments)} segments", file=sys.stderr)
    return 2 if corruption else 0


if __name__ == "__main__":
    sys.exit(main())
