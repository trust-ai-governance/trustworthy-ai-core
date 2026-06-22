"""WAL v2 golden conformance — CORE side.

Self-contained: asserts core's _wal_format reader reproduces the SAME frozen
golden (manifest.yaml + .wal bytes) as platform. This is the other half of the
binding — if _wal_format drifts from the committed format, it fails here in CI
instead of at the customer (deployment shape C).

Only the ADAPTER differs from the platform copy. Fill the three TODOs with
core's _wal_format entry points; the assertion body is identical by design
(intentional duplication — the shared thing is the DATA, not runner code).
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from tools import wal_verify
from tools._wal_format import (
    REC_SIZE_V1,
    REC_SIZE_V2,
    V2,
    iter_records,
    read_segment_header,
)


# ---- ADAPTER: core _wal_format reader ---------------------------------------
# core's _wal_format surface differs from platform's wal.py: read_segment_header()
# takes bytes, records come from iter_records() (which stops cleanly at a truncated
# tail and NEVER raises on integrity), and each frame carries its stored 32-byte
# record_hash as Record.stored_hash. Two oracle-preserving choices here:
#   * record_hash binds on the STORED bytes (Record.stored_hash), not a recompute —
#     a recompute of SHA256(prev||payload) would tautologically equal the manifest
#     (the manifest IS that recompute) and would never catch a stored-hash drift.
#   * strict-mode corruption is delegated to core's PRODUCTION verifier (wal_verify),
#     so the golden exercises what CORE detects, not a test-local re-check. The one
#     thing wal_verify can't model — a frame-incomplete (truncated) trailing record —
#     is rejected by the reader itself via the consumed-vs-size check below.
class WalCorruptionError(Exception):
    """Strict-mode integrity failure flagged by core (CRC/hash chain or truncated tail)."""


CORRUPTION_ERROR: type[Exception] = WalCorruptionError


def read_header(path: Path) -> dict:
    h = read_segment_header(path.read_bytes())
    return {
        "start_seq": h.start_seq,
        "first_prev_hash_hex": h.first_prev_hash.hex(),
        "format_version": h.version,
    }


def decode(path: Path, *, lenient: bool) -> list[dict]:
    data = path.read_bytes()
    hdr = read_segment_header(data)
    if not lenient and not wal_verify.verify(path, full=True).ok:
        raise CORRUPTION_ERROR(f"wal_verify flagged {path.name}")
    rec_size = REC_SIZE_V2 if hdr.version == V2 else REC_SIZE_V1
    out: list[dict] = []
    consumed = hdr.header_size
    for rec in iter_records(data, hdr):
        out.append(
            {
                "seq": rec.seq,
                "payload_hex": rec.payload.hex(),
                "record_hash_hex": rec.stored_hash.hex(),  # READ the stored field
            }
        )
        consumed += rec_size + len(rec.payload)
    if not lenient and consumed != len(data):
        raise CORRUPTION_ERROR("truncated tail")  # frame-incomplete trailing record
    return out


# -----------------------------------------------------------------------------


def _golden_root() -> Path:
    env = os.environ.get("TRUSTAI_WAL_GOLDEN")
    if env:
        return Path(env)
    from importlib.resources import files

    return Path(str(files("trustworthy_ai_conformance"))) / "wal_v2_golden"


def _run(root: Path) -> None:
    m = yaml.safe_load((root / "manifest.yaml").read_text())
    assert m["format_version"] == 2 and m["magic"] == "TAIWAL01"
    assert (
        m["genesis_hex"]
        == "7dc8a92266863c5abcecfba93a49935663a44f69959529377d926baec0d32d04"
    )
    for case in m["cases"]:
        cid = case["id"]
        for seg in case["segments"]:
            path = root / seg["file"]
            h = read_header(path)
            assert h["start_seq"] == seg["start_seq"], (cid, "start_seq")
            assert h["first_prev_hash_hex"] == seg["first_prev_hash_hex"], (
                cid,
                "first_prev_hash",
            )
            for g, e in zip(decode(path, lenient=True), seg["records"]):
                assert (g["seq"], g["payload_hex"], g["record_hash_hex"]) == (
                    e["seq"],
                    e["payload_hex"],
                    e["record_hash_hex"],
                ), (cid, e["seq"])
        read = case.get("read", {})
        if "lenient_expect_records" in read:
            n = sum(
                len(decode(root / s["file"], lenient=True)) for s in case["segments"]
            )
            assert n == read["lenient_expect_records"], (cid, "lenient count")
        if "strict_expect_records" in read:
            n = sum(
                len(decode(root / s["file"], lenient=False)) for s in case["segments"]
            )
            assert n == read["strict_expect_records"], (cid, "strict count")
        strict = read.get("strict")
        if isinstance(strict, str) and (
            "corruption" in strict or "truncation" in strict
        ):
            raised = False
            for s in case["segments"]:
                try:
                    decode(root / s["file"], lenient=False)
                except CORRUPTION_ERROR:
                    raised = True
            assert raised, (cid, "expected strict read to raise", strict)


def test_wal_v2_golden():
    _run(_golden_root())
