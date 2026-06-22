"""wal_challenge_verify — zero-dependency reference verifier for the WAL Challenge.

OPEN / auditable (core repo). An auditor runs THIS, not platform code, so the
verification is independent: the platform serves only neighbour hashes
(audit:challenge) + raw record bytes (audit:raw), and trust comes from
re-deriving the chain here.

WAL v2 chain:  H(n) = SHA256( H(n-1) || payload_n ),  with H(-1) := GENESIS.
"""

from __future__ import annotations

import hashlib

# WAL v2 chain seed H(-1) — the domain-separated genesis link, fixed by the WAL
# v2 format spec. Public by design: an independent verifier MUST know it. This is
# NOT the first record's hash, which is H(0)=SHA256(GENESIS||payload_0).
# Pinned value: 7dc8a92266863c5abcecfba93a49935663a44f69959529377d926baec0d32d04
WAL_GENESIS = hashlib.sha256(b"trustworthy-ai-wal-genesis-v2").digest()


def record_hash(prev_hash: bytes, payload: bytes) -> bytes:
    return hashlib.sha256(prev_hash + payload).digest()


def verify_link(payload_n: bytes, prev_hash: bytes, record_hash_n: bytes) -> bool:
    """Backward link: payload_n under prev_hash must reproduce the claimed H(n)."""
    return record_hash(prev_hash, payload_n) == record_hash_n


def verify_seal(record_hash_n: bytes, next_payload: bytes, next_hash: bytes) -> bool:
    """Forward seal: record N is committed-to by record N+1 (tamper-evidence)."""
    return record_hash(record_hash_n, next_payload) == next_hash


def verify_challenge(
    payload_n: bytes,
    prev_hash: bytes,
    record_hash_n: bytes,
    *,
    next_payload: bytes | None = None,
    next_hash: bytes | None = None,
) -> bool:
    """Verify a single DB record against its WAL chain neighbours.

    payload_n + prev_hash must reproduce record_hash_n (backward link). If the
    record is not the chain tail, also verify the forward seal — which needs the
    next record's raw bytes (fetch via audit:raw?seq=N+1).
    """
    if not verify_link(payload_n, prev_hash, record_hash_n):
        return False
    if next_hash is not None:
        if next_payload is None:
            return False  # cannot verify the seal without the next payload
        if not verify_seal(record_hash_n, next_payload, next_hash):
            return False
    return True
