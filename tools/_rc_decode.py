"""Shared lazy RequestContext decoder.

Extracted from wal_dump so both the human dump and the open eval engine
(treval) decode WAL payloads through one code path. The ir-spec proto import is
LAZY (inside the function) so importing this module stays zero-dependency — the
core repo keeps its "inspect/verify without possessing the Gateway" property.
"""

from __future__ import annotations


class RcDecodeUnavailable(RuntimeError):
    """The ir-spec proto package isn't importable — decode cannot proceed."""


def decode_request_context(payload: bytes):  # -> trustworthy_ai.v1...RequestContext
    try:
        from trustworthy_ai.v1 import request_context_pb2 as rc_pb
    except Exception as e:  # ImportError, or proto runtime mismatch
        raise RcDecodeUnavailable(
            "trustworthy-ai-ir-spec proto not importable; cannot decode WAL payload"
        ) from e
    return rc_pb.RequestContext.FromString(payload)
