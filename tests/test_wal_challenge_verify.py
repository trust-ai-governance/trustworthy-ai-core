"""Reference verifier tests (CORE repo) — self-contained, zero platform import.

Builds a chain by hand with hashlib exactly as the WAL does
(H(n)=SHA256(H(n-1)||payload)) and checks verify_challenge accept/reject. Imports
NO platform code — that independence is the whole point of an open verifier.

Place under the core (open) repo alongside tools/wal_challenge_verify.py; adjust
the import to your core layout if tools/ is not importable as a package.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.wal_challenge_verify import WAL_GENESIS, verify_challenge  # noqa: E402

# Shared contract value, pinned independently in BOTH repos (no cross-import).
_GENESIS_HEX = "7dc8a92266863c5abcecfba93a49935663a44f69959529377d926baec0d32d04"


def _chain(payloads):
    hashes, prev = [], WAL_GENESIS
    for p in payloads:
        prev = hashlib.sha256(prev + p).digest()
        hashes.append(prev)
    return hashes


def test_genesis_pinned():
    assert WAL_GENESIS.hex() == _GENESIS_HEX


def test_accepts_authentic():
    pays = [b"r0", b"r1", b"r2"]
    h = _chain(pays)
    assert verify_challenge(pays[1], h[0], h[1], next_payload=pays[2], next_hash=h[2])


def test_accepts_record_zero_under_genesis():
    pays = [b"r0", b"r1"]
    h = _chain(pays)
    assert verify_challenge(
        pays[0], WAL_GENESIS, h[0], next_payload=pays[1], next_hash=h[1]
    )


def test_rejects_tampered_payload():
    pays = [b"r0", b"r1", b"r2"]
    h = _chain(pays)
    assert not verify_challenge(b"TAMPERED", h[0], h[1])


def test_rejects_broken_seal():
    pays = [b"r0", b"r1", b"r2"]
    h = _chain(pays)
    assert not verify_challenge(pays[1], h[0], h[1], next_payload=b"x", next_hash=h[2])


def test_seal_requires_next_payload():
    pays = [b"r0", b"r1", b"r2"]
    h = _chain(pays)
    assert not verify_challenge(pays[1], h[0], h[1], next_payload=None, next_hash=h[2])


def test_tail_record_no_seal():
    pays = [b"r0", b"r1"]
    h = _chain(pays)
    assert verify_challenge(pays[1], h[0], h[1])
