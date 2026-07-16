"""C0-d — deterministic drain-cursor stop for GatewayTarget.drain_governance.

The live drain (network + real sleep) is operator-run; here we drive the STOP condition
deterministically by monkeypatching `_read_cursor` (the admin drain cursor), stubbing the
WAL read, and installing a fake clock so no real seconds elapse. Covers the three paths:
a clean cursor-driven stop, a degraded evaluator (timeout backstop), and no cursor endpoint
(timeout-path fallback == the old drain).
"""

from __future__ import annotations

from collections.abc import Callable

import treval.active_eval.target as tgt
from treval.active_eval.target import GatewayTarget, ProbeResult
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus
from trustworthy_ai.v1 import request_context_pb2 as rc_pb


def _gov_ev(rid: str) -> AuditEvidence:
    """A fabricated record_type=3 (async governance) evidence for one request_id."""
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = rid
    ctx.record_type = rc_pb.AUDIT_RECORD_TYPE_GOVERNANCE_OBSERVED
    ctx.audit.hint_emitted = True
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=0, request_id=rid),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="__eval__",
        received_at_ns=0,
        record=ctx,
    )


def _probe(rid: str) -> ProbeResult:
    return ProbeResult(
        case_id=rid,
        request_id=rid,
        decision="ALLOW",
        response_text="",
        evidence=None,
    )


class _Clock:
    """A fake monotonic clock — only sleep() advances it, so the drain's timeout is
    reached in a fixed number of poll iterations with zero wall-clock time."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, secs: float) -> None:
        self.now += secs


def _install_reader(monkeypatch, rids_present: set[str]) -> None:
    """Stub the WAL read so a scan yields a type-3 record only for `rids_present`."""
    evs = [_gov_ev(r) for r in rids_present]

    class _Reader:
        def __init__(self, wal_dir) -> None:
            pass

        def read_audit(self, **_kw):
            yield from evs

    monkeypatch.setattr(tgt, "WalEvidenceReader", _Reader)


def _seq_cursor(*values: dict | None) -> Callable[[], dict | None]:
    """A no-arg `_read_cursor` replacement returning each value in turn, then repeating
    the last (guards against an unexpected extra poll)."""
    seq = list(values)

    def _read() -> dict | None:
        return seq.pop(0) if len(seq) > 1 else seq[0]

    return _read


def _target(monkeypatch, tmp_path, cursor: Callable[[], dict | None]) -> GatewayTarget:
    t = GatewayTarget(
        "http://gw:8080",
        wal_dir=tmp_path,
        admin_url="http://gw:8081",
        tenant_id="__eval__",
    )
    monkeypatch.setattr(t, "_read_cursor", cursor)
    clock = _Clock()
    monkeypatch.setattr(tgt.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(tgt.time, "sleep", clock.sleep)
    return t


def test_deterministic_stop_no_timeout(monkeypatch, tmp_path, capsys):
    """Cursor below probe_head for a couple polls, then >= probe_head → drain stops on the
    cursor (not the timeout), attaching every present record, with no warning."""
    _install_reader(monkeypatch, {"req-a", "req-b", "req-c"})
    cursor = _seq_cursor(
        {"wal_head_seq": 100, "guardrail_cursor_seq": 50},  # probe_head snapshot = 100
        {"wal_head_seq": 105, "guardrail_cursor_seq": 80},  # still catching up
        {"wal_head_seq": 110, "guardrail_cursor_seq": 100},  # caught up → done
    )
    t = _target(monkeypatch, tmp_path, cursor)
    probes = [_probe("req-a"), _probe("req-b"), _probe("req-c")]

    out = t.drain_governance(probes, timeout=100.0, poll_interval=2.0)

    assert all(r.governance_evidence is not None for r in out)
    assert capsys.readouterr().err == ""  # clean deterministic stop → no warning


def test_degraded_falls_to_timeout_backstop(monkeypatch, tmp_path, capsys):
    """guardrail_degraded → stop blocking on the cursor, warn, and finish on the timeout
    backstop without hanging; present records still attach, a genuinely-absent one stays
    no-async."""
    _install_reader(monkeypatch, {"req-a", "req-b"})  # req-c never lands
    cursor = _seq_cursor(
        {"wal_head_seq": 100, "guardrail_cursor_seq": 50},
        {"guardrail_cursor_seq": 60, "guardrail_degraded": True},
    )
    t = _target(monkeypatch, tmp_path, cursor)
    probes = [_probe("req-a"), _probe("req-b"), _probe("req-c")]

    out = t.drain_governance(probes, timeout=6.0, poll_interval=2.0)

    by_id = {r.request_id: r for r in out}
    assert by_id["req-a"].governance_evidence is not None
    assert by_id["req-b"].governance_evidence is not None
    assert by_id["req-c"].governance_evidence is None  # genuine no-async
    assert "guardrail degraded" in capsys.readouterr().err


def test_no_endpoint_falls_back_to_timeout(monkeypatch, tmp_path, capsys):
    """_read_cursor returns None (no admin endpoint) → the timeout-path fallback (== the old
    drain): warn loudly, attach what lands, leave the absent one no-async."""
    _install_reader(monkeypatch, {"req-a", "req-b"})  # req-c never lands
    t = _target(monkeypatch, tmp_path, _seq_cursor(None))
    probes = [_probe("req-a"), _probe("req-b"), _probe("req-c")]

    out = t.drain_governance(probes, timeout=6.0, poll_interval=2.0)

    by_id = {r.request_id: r for r in out}
    assert by_id["req-a"].governance_evidence is not None
    assert by_id["req-b"].governance_evidence is not None
    assert by_id["req-c"].governance_evidence is None
    assert "no cursor endpoint" in capsys.readouterr().err


def test_read_cursor_none_without_admin_url(tmp_path):
    """The config contract: no admin_url ⇒ _read_cursor is None (the safe fallback), with
    no network touched."""
    t = GatewayTarget("http://gw:8080", wal_dir=tmp_path)
    assert t._read_cursor() is None
