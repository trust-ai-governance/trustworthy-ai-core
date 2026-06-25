"""WalEvidenceReader — the canonical, integrity-bearing audit source (EV-1).

Reads a read-only WAL directory the gateway wrote, derives each record's
IntegrityStatus from the SAME production verifier a customer would run
(``tools.wal_verify``), decodes each payload to a RequestContext via the shared
``tools._rc_decode`` helper, and yields uniform AuditEvidence. It reuses the
framing parser (``tools._wal_format``) — no second copy of the chain/CRC logic
lives here. It never imports the closed platform and never connects to the
gateway: ``treval -> tools`` is the only dependency direction (EVAL_ARCHITECTURE
§0.1, §2.1, §4a).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from tools import wal_verify
from tools._rc_decode import RcDecodeUnavailable, decode_request_context
from tools._wal_format import (
    WalFormatError,
    iter_records,
    list_segments,
    read_segment_header,
)
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus


class WalReadError(Exception):
    """A WAL record's payload is not decodable (corrupt WAL). Distinct from
    RcDecodeUnavailable (the proto package itself isn't importable)."""


class WalEvidenceReader:
    """Reads a WAL directory as AuditEvidence (satisfies AuditEvidenceReader)."""

    def __init__(self, wal_dir: str | Path) -> None:
        self._dir = Path(wal_dir)

    def read_audit(
        self,
        *,
        tenant_id: str | None = None,
        time_from_ns: int | None = None,
        time_to_ns: int | None = None,
    ) -> Iterator[AuditEvidence]:
        if not self._dir.exists():
            raise FileNotFoundError(f"WAL directory does not exist: {self._dir}")

        # Integrity, reusing the production verifier (one eager pass). The first
        # break poisons the tail: a record is VERIFIED only if the WAL verified
        # clean, or its seq is strictly below the first finding's seq. Structural
        # findings carry seq=None -> broken_from is None and rep.ok is False, so
        # every record reads as BROKEN (we cannot trust any of it).
        rep = wal_verify.verify(self._dir, full=True)
        err_seqs = [f["seq"] for f in rep.findings if f["seq"] is not None]
        broken_from: int | None = min(err_seqs) if err_seqs else None

        for seg_path in list_segments(self._dir):
            data = seg_path.read_bytes()
            try:
                hdr = read_segment_header(data)
            except WalFormatError:
                # Unreadable header: verify already recorded it as a structural
                # finding (all records read BROKEN); we cannot parse its records.
                continue
            for rec in iter_records(data, hdr):
                verified = rep.ok or (broken_from is not None and rec.seq < broken_from)
                integrity = (
                    IntegrityStatus.VERIFIED if verified else IntegrityStatus.BROKEN
                )
                try:
                    record = decode_request_context(rec.payload)
                except RcDecodeUnavailable:
                    raise  # proto package missing — eval cannot proceed at all
                except Exception as e:
                    # A single garbage payload must not crash the whole scan with
                    # a raw protobuf traceback — fail closed with a clear locator.
                    raise WalReadError(
                        f"record seq={rec.seq} in {seg_path} payload not "
                        f"decodable — WAL corrupt"
                    ) from e
                env = record.envelope

                if tenant_id is not None and env.tenant_id != tenant_id:
                    continue
                if time_from_ns is not None and env.received_at_ns < time_from_ns:
                    continue
                if time_to_ns is not None and env.received_at_ns >= time_to_ns:
                    continue

                ref = EvidenceRef(
                    source=f"wal:{seg_path}",
                    seq=rec.seq,
                    request_id=env.request_id or None,
                )
                yield AuditEvidence(
                    ref=ref,
                    integrity=integrity,
                    tenant_id=env.tenant_id,
                    received_at_ns=env.received_at_ns,
                    record=record,
                )
