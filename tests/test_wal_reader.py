"""Tests for treval.readers.WalEvidenceReader (EV-1).

Fixtures use REAL serialized RequestContext payloads (the reader decodes them),
written into v2 WAL segments via the walgen reference encoder. Integrity is
asserted by driving real corruption through tools.wal_verify, never hand-rolled.
"""

from __future__ import annotations

import pytest

import walgen
from tools._wal_format import REC_SIZE_V2, SEG_SIZE_V2
from treval import WalEvidenceReader, WalReadError
from treval.models import AuditEvidence, IntegrityStatus
from treval.readers import wal_reader
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

# (request_id, tenant_id, received_at_ns) for the happy-path fixture, seq 0..3.
_RECORDS = [
    ("req-0000", "tenant-a", 1_000),
    ("req-0001", "tenant-a", 2_000),
    ("req-0002", "tenant-b", 3_000),
    ("req-0003", "tenant-b", 4_000),
]


def _payload(request_id: str, tenant_id: str, received_at_ns: int) -> bytes:
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = request_id
    ctx.envelope.tenant_id = tenant_id
    ctx.envelope.received_at_ns = received_at_ns
    return ctx.SerializeToString()


def _write_wal(directory, records=_RECORDS) -> list[bytes]:
    """Write a single clean v2 segment; return the payload list (for offsets)."""
    directory.mkdir(parents=True, exist_ok=True)
    payloads = [_payload(*r) for r in records]
    walgen.write_v2_segment(
        directory / walgen.NAME.format(0), 0, payloads, walgen.GENESIS
    )
    return payloads


def _corrupt_crc(seg_path, payloads, k: int) -> None:
    """Flip a byte in record k's stored CRC field (header bytes; payload intact,
    still proto-decodable). Drives a real wal_verify CRC finding at seq k."""
    off = SEG_SIZE_V2
    for i in range(k):
        off += REC_SIZE_V2 + len(payloads[i])
    crc_pos = off + 4  # record header is [length(4) | crc(4) | hash(32)]
    data = bytearray(seg_path.read_bytes())
    data[crc_pos] ^= 0xFF
    seg_path.write_bytes(bytes(data))


# --------------------------------------------------------------------------- #
# 1. Happy path
# --------------------------------------------------------------------------- #


def test_happy_path_all_verified_in_seq_order(tmp_path):
    _write_wal(tmp_path)
    ev = list(WalEvidenceReader(tmp_path).read_audit())

    assert len(ev) == len(_RECORDS)
    assert [e.ref.seq for e in ev] == [0, 1, 2, 3]  # seq order
    for e, (rid, tid, ts) in zip(ev, _RECORDS):
        assert isinstance(e, AuditEvidence)
        assert e.integrity is IntegrityStatus.VERIFIED
        assert e.ref.request_id == rid
        assert e.tenant_id == tid
        assert e.received_at_ns == ts
        assert e.record.envelope.request_id == rid
        assert e.ref.source.startswith("wal:")


# --------------------------------------------------------------------------- #
# 2. Tamper: poison the tail
# --------------------------------------------------------------------------- #


def test_tamper_poisons_tail(tmp_path):
    payloads = _write_wal(tmp_path)
    _corrupt_crc(tmp_path / walgen.NAME.format(0), payloads, k=2)

    ev = list(WalEvidenceReader(tmp_path).read_audit())
    by_seq = {e.ref.seq: e.integrity for e in ev}

    assert by_seq[0] is IntegrityStatus.VERIFIED
    assert by_seq[1] is IntegrityStatus.VERIFIED
    assert by_seq[2] is IntegrityStatus.BROKEN
    assert by_seq[3] is IntegrityStatus.BROKEN


# --------------------------------------------------------------------------- #
# 3. Filters
# --------------------------------------------------------------------------- #


def test_tenant_filter(tmp_path):
    _write_wal(tmp_path)
    ev = list(WalEvidenceReader(tmp_path).read_audit(tenant_id="tenant-b"))
    assert [e.ref.seq for e in ev] == [2, 3]
    assert {e.tenant_id for e in ev} == {"tenant-b"}


def test_time_window_is_half_open(tmp_path):
    _write_wal(tmp_path)
    # [2_000, 4_000): seq 1 (2_000) and 2 (3_000); 'from' inclusive, 'to' exclusive.
    ev = list(
        WalEvidenceReader(tmp_path).read_audit(time_from_ns=2_000, time_to_ns=4_000)
    )
    assert [e.received_at_ns for e in ev] == [2_000, 3_000]


# --------------------------------------------------------------------------- #
# 4. Decode unavailable -> propagate (no preview fallback)
# --------------------------------------------------------------------------- #


def test_decode_unavailable_propagates(tmp_path, monkeypatch):
    """When the proto decode fails, the reader propagates RcDecodeUnavailable —
    it does NOT fall back to a preview (unlike wal_dump). Evaluation strictly
    needs the decoded record."""
    _write_wal(tmp_path)

    from tools._rc_decode import RcDecodeUnavailable

    def _raise(_payload):
        raise RcDecodeUnavailable("blocked for test")

    monkeypatch.setattr(wal_reader, "decode_request_context", _raise)
    with pytest.raises(RcDecodeUnavailable):
        list(WalEvidenceReader(tmp_path).read_audit())


# --------------------------------------------------------------------------- #
# 6. Edge cases
# --------------------------------------------------------------------------- #


def test_nonexistent_dir_raises(tmp_path):
    reader = WalEvidenceReader(tmp_path / "does-not-exist")
    with pytest.raises(FileNotFoundError):
        list(reader.read_audit())


def test_empty_dir_yields_nothing(tmp_path):
    assert list(WalEvidenceReader(tmp_path).read_audit()) == []


# --------------------------------------------------------------------------- #
# F1. Corrupt (undecodable) payload -> clear WalReadError naming the seq
# --------------------------------------------------------------------------- #


def test_corrupt_payload_raises_clear_error(tmp_path):
    # A VERIFIED chain (walgen recomputes CRC+hash over the garbage) but record 2
    # is not a decodable RequestContext. One bad payload must fail closed with a
    # clear locator, not a raw protobuf traceback.
    tmp_path.mkdir(parents=True, exist_ok=True)
    payloads = [_payload(*_RECORDS[0]), _payload(*_RECORDS[1]), b"\xff\xff\xff\xff"]
    walgen.write_v2_segment(
        tmp_path / walgen.NAME.format(0), 0, payloads, walgen.GENESIS
    )
    with pytest.raises(WalReadError, match="seq=2"):
        list(WalEvidenceReader(tmp_path).read_audit())


# --------------------------------------------------------------------------- #
# F2. Unreadable segment header -> skipped; structural finding => all BROKEN
# --------------------------------------------------------------------------- #


def test_unreadable_header_segment_skipped_all_broken(tmp_path):
    _write_wal(tmp_path, _RECORDS[:2])  # good segment, seq 0..1
    # A second .wal with a numeric stem but a garbage (too-short) header.
    (tmp_path / walgen.NAME.format(2)).write_bytes(b"\x00" * 16)

    ev = list(WalEvidenceReader(tmp_path).read_audit())
    # Bad segment yields nothing; good records survive but, with an unverifiable
    # structural finding, none can be trusted (fail closed).
    assert [e.ref.seq for e in ev] == [0, 1]
    assert all(e.integrity is IntegrityStatus.BROKEN for e in ev)


# --------------------------------------------------------------------------- #
# F3. Multi-segment: cross-segment order + poison-tail across the boundary
# --------------------------------------------------------------------------- #


def _write_two_segments(directory) -> list[bytes]:
    """Two v2 segments (seq 0..1, seq 2..3) on one continued chain."""
    directory.mkdir(parents=True, exist_ok=True)
    payloads = [_payload(*r) for r in _RECORDS]
    head = walgen.write_v2_segment(
        directory / walgen.NAME.format(0), 0, payloads[:2], walgen.GENESIS
    )
    walgen.write_v2_segment(directory / walgen.NAME.format(2), 2, payloads[2:], head)
    return payloads


def test_multi_segment_clean_order(tmp_path):
    _write_two_segments(tmp_path)
    ev = list(WalEvidenceReader(tmp_path).read_audit())

    assert [e.ref.seq for e in ev] == [0, 1, 2, 3]  # order across segments
    assert all(e.integrity is IntegrityStatus.VERIFIED for e in ev)
    assert ev[0].ref.source.endswith(walgen.NAME.format(0))
    assert ev[2].ref.source.endswith(walgen.NAME.format(2))


def test_multi_segment_poison_crosses_boundary(tmp_path):
    payloads = _write_two_segments(tmp_path)
    # Corrupt the first record of the SECOND segment (seq 2, index 0 within it).
    _corrupt_crc(tmp_path / walgen.NAME.format(2), payloads[2:], k=0)

    by_seq = {e.ref.seq: e.integrity for e in WalEvidenceReader(tmp_path).read_audit()}
    assert by_seq[0] is IntegrityStatus.VERIFIED
    assert by_seq[1] is IntegrityStatus.VERIFIED
    assert by_seq[2] is IntegrityStatus.BROKEN
    assert by_seq[3] is IntegrityStatus.BROKEN
