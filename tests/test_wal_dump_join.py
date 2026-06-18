"""Tests for wal_dump B2 features: record_type rendering, response_body_preview
rendering, and --join grouping (incl. the incomplete-request flag).

Self-contained: builds RequestContext payloads via the proto and writes a real
v2 WAL segment using the documented framing — no platform dependency.
"""

from __future__ import annotations

import hashlib
import struct

import pytest

from tools import wal_dump
from tools._wal_format import GENESIS, MAGIC, REC_FMT_V2, SEG_FMT_V2, V2

rc_pb = pytest.importorskip("trustworthy_ai.v1.request_context_pb2")


# --------------------------------------------------------------------------- #
# Minimal v2 WAL segment writer (matches _wal_format framing)
# --------------------------------------------------------------------------- #


def _write_segment(directory, payloads, start_seq=0):
    import zlib

    path = directory / f"{start_seq:017d}.wal"
    prev = GENESIS
    body = bytearray()
    for payload in payloads:
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        h = hashlib.sha256(prev + payload).digest()
        body += struct.pack(REC_FMT_V2, len(payload), crc, h)
        body += payload
        prev = h
    header = struct.pack(SEG_FMT_V2, MAGIC, V2, start_seq, 1, GENESIS)
    path.write_bytes(header + bytes(body))
    return path


# --------------------------------------------------------------------------- #
# Payload builders
# --------------------------------------------------------------------------- #


def _decision(request_id, *, final, legacy=False, tool="chat", agent="dogfood-agent"):
    c = rc_pb.RequestContext()
    if not legacy:
        c.record_type = rc_pb.AUDIT_RECORD_TYPE_DECISION_MADE
    c.envelope.request_id = request_id
    c.invocation.tool_id = tool
    c.identity.agent.agent_id = agent
    c.decision.final_decision = final
    return c.SerializeToString()


def _response(
    request_id,
    *,
    decision_seq,
    terminal,
    status=200,
    body=b'{"choices":[{"message":{"content":"hi"}}]}',
    usage=None,
    rules=(),
):
    c = rc_pb.RequestContext()
    c.record_type = rc_pb.AUDIT_RECORD_TYPE_RESPONSE_OBSERVED
    c.envelope.request_id = request_id
    r = c.response
    r.decision_seq = decision_seq
    r.final_terminal = terminal
    r.response_status_code = status
    r.response_body_sha256 = hashlib.sha256(body).hexdigest()
    r.response_body_preview = body
    r.duration_ms = 3
    if usage:
        r.token_usage.prompt_tokens = usage[0]
        r.token_usage.completion_tokens = usage[1]
        r.token_usage.total_tokens = usage[2]
        if len(usage) > 3:
            r.token_usage.extra["completion_tokens_details.reasoning_tokens"] = usage[3]
    for rid in rules:
        e = r.on_tool_response_rules.add()
        e.rule_id = rid
        e.matched = True
    return c.SerializeToString()


ALLOW = rc_pb.DecisionTrace.FinalDecision.FINAL_DECISION_ALLOW
BLOCK = rc_pb.DecisionTrace.FinalDecision.FINAL_DECISION_BLOCK


@pytest.fixture
def mixed_wal(tmp_path):
    """A WAL with: a complete pair, a request-block A-only, a dangling A
    (allowed-but-no-B), and a legacy A (no record_type)."""
    payloads = [
        _decision("rid-pair", final=ALLOW),  # 0  A
        _response(
            "rid-pair",
            decision_seq=0,
            terminal="ALLOWED",
            usage=(9, 922, 931, 917),
            rules=["pii-block-response"],
        ),  # 1  B
        _decision("rid-block", final=BLOCK),  # 2  A only (block)
        _decision("rid-dangling", final=ALLOW),  # 3  A, no B → incomplete
        _decision("rid-legacy", final=ALLOW, legacy=True),  # 4  legacy A, no B
    ]
    _write_segment(tmp_path, payloads)
    return tmp_path


# --------------------------------------------------------------------------- #
# --decode
# --------------------------------------------------------------------------- #


def test_decode_shows_record_type_and_renders_preview(mixed_wal, capsys):
    rc = wal_dump.main([str(mixed_wal), "--decode"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "record_type=decision.made" in out
    assert "record_type=response.observed" in out
    assert "record_type=decision.made (legacy)" in out
    # response_body_preview must be rendered as readable JSON, not base64.
    assert '"response_body_preview"' in out
    assert '"content": "hi"' in out
    # reasoning tokens preserved in token_usage.extra
    assert "completion_tokens_details.reasoning_tokens" in out


# --------------------------------------------------------------------------- #
# --join
# --------------------------------------------------------------------------- #


def test_join_groups_pair_and_extracts_reasoning(mixed_wal, capsys):
    rc = wal_dump.main([str(mixed_wal), "--join"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "=== request_id=rid-pair" in out
    # decision.made + response.observed printed under the same group
    assert "decision.made" in out and "response.observed" in out
    # back-pointer + reasoning surfaced on the response line
    assert "→A.seq=0" in out
    assert "tokens=9/922/931 reasoning=917" in out
    assert "final=ALLOWED" in out


def test_join_flags_dangling_allow_as_incomplete(mixed_wal, capsys):
    wal_dump.main([str(mixed_wal), "--join"])
    out = capsys.readouterr().out
    # The dangling allow-to-forward A is flagged...
    assert "rid-dangling" in out
    assert "⚠ INCOMPLETE" in out


def test_join_does_not_flag_request_block(mixed_wal, capsys):
    wal_dump.main([str(mixed_wal), "--join"])
    out = capsys.readouterr().out
    # Find the rid-block group block and ensure it is NOT marked incomplete.
    section = out.split("=== request_id=rid-block")[1].split("=== request_id=")[0]
    assert "final=BLOCK" in section
    assert "INCOMPLETE" not in section


def test_join_does_not_flag_legacy_record(mixed_wal, capsys):
    wal_dump.main([str(mixed_wal), "--join"])
    out = capsys.readouterr().out
    section = out.split("=== request_id=rid-legacy")[1]
    assert "decision.made(legacy)" in section
    assert "INCOMPLETE" not in section


def test_join_incomplete_count_is_one(mixed_wal, capsys):
    wal_dump.main([str(mixed_wal), "--join"])
    err = capsys.readouterr().err
    # Exactly one incomplete (rid-dangling); block + legacy are not counted.
    assert "1 incomplete" in err
