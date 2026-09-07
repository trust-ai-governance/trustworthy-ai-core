"""The two run-blockers found by spending a real run on them (2026-08-25).

Both defects had the same shape: the code faithfully executed a belief about the tested party, the
run completed, and the product printed something that looked like a result.

  · `x-agent-id` was sent ONLY when a CASE declared one. The gateway had started requiring it, so
    194/194 probes died at IDENTIFY_FAILED before reaching any detection stage.
  · The admin API was called with no credential, and `_read_cursor` absorbed EVERY failure into
    `None` so `drain_governance` could degrade — which turned a 401 (fixable in one export) into
    three permanently n/a Tier-2 rows, on a corpus arm that can only be read once.
"""

from __future__ import annotations

import pytest

from treval.active_eval.corpus import CorpusCase
from treval.active_eval.target import AdminAuthError, GatewayTarget


def _case(case_id: str = "c1", agent_id: str | None = None) -> CorpusCase:
    return CorpusCase(
        id=case_id,
        owasp="LLM01",
        dimension="injection",
        attack_class="direct",
        success_when="never",
        severity="low",
        source="synthetic",
        tool_id="chat",
        input="hello",
        agent_id=agent_id,
    )


class _Resp:
    def __init__(self, status: int, payload: object | None = None) -> None:
        self.status_code = status
        self._payload = payload if payload is not None else {}
        self.text = ""
        self.headers: dict[str, str] = {}

    def json(self) -> object:
        return self._payload


# --------------------------------------------------------------------------- #
# x-agent-id
# --------------------------------------------------------------------------- #


def test_run_wide_agent_id_rides_on_every_probe(monkeypatch) -> None:
    """RED when: the run-wide --agent is dropped ⇒ IDENTIFY_FAILED ⇒ every indicator unmeasurable."""
    import httpx

    seen: dict[str, object] = {}

    def fake_post(url, *, headers=None, json=None, timeout=None):
        seen["headers"] = dict(headers or {})
        return _Resp(200, {"request_id": "r1", "content": "ok"})

    monkeypatch.setattr(httpx, "post", fake_post)
    GatewayTarget("http://gw:8080", agent_id="auto-agent").probe(_case())
    assert seen["headers"]["x-agent-id"] == "auto-agent"  # type: ignore[index]


def test_case_agent_id_still_wins_over_the_run_wide_default(monkeypatch) -> None:
    """RED when: the run-wide default overrides a case's own agent_id — that would silently collapse
    EV-AE13 per-case route selection (builtin.chat's HTML sink vs control.chat's sink `none`) onto
    one route, and the neutralize arm would compare two cases that took the SAME path."""
    import httpx

    seen: dict[str, object] = {}

    def fake_post(url, *, headers=None, json=None, timeout=None):
        seen["headers"] = dict(headers or {})
        return _Resp(200, {"request_id": "r1", "content": "ok"})

    monkeypatch.setattr(httpx, "post", fake_post)
    GatewayTarget("http://gw:8080", agent_id="auto-agent").probe(
        _case(agent_id="control.chat")
    )
    assert seen["headers"]["x-agent-id"] == "control.chat"  # type: ignore[index]


def test_no_agent_anywhere_sends_no_header(monkeypatch) -> None:
    """RED when: an empty --agent starts sending `x-agent-id: ""` — an empty required header is a
    DIFFERENT rejection from an absent one, and it would make the pre-change behaviour untestable."""
    import httpx

    seen: dict[str, object] = {}

    def fake_post(url, *, headers=None, json=None, timeout=None):
        seen["headers"] = dict(headers or {})
        return _Resp(200, {"request_id": "r1", "content": "ok"})

    monkeypatch.setattr(httpx, "post", fake_post)
    GatewayTarget("http://gw:8080").probe(_case())
    assert "x-agent-id" not in seen["headers"]  # type: ignore[operator]


# --------------------------------------------------------------------------- #
# admin auth
# --------------------------------------------------------------------------- #


def test_admin_token_rides_from_the_environment(monkeypatch) -> None:
    """RED when: the token stops being sent ⇒ 401 ⇒ Tier-2 rows n/a. The token comes from the ENV,
    never a flag: a flag value lands in shell history and in `ps` for every user on the box."""
    import httpx

    monkeypatch.setenv("TREVAL_ADMIN_TOKEN", "tok-123")
    seen: dict[str, object] = {}

    def fake_get(url, *, timeout=None, headers=None):
        seen["headers"] = dict(headers or {})
        return _Resp(200, {"wal_head_seq": 7})

    monkeypatch.setattr(httpx, "get", fake_get)
    t = GatewayTarget("http://gw:8080", admin_url="http://gw:8081")
    assert t._read_cursor() == {"wal_head_seq": 7}
    assert seen["headers"]["x-admin-token"] == "tok-123"  # type: ignore[index]


@pytest.mark.parametrize("status", [401, 403])
def test_rejected_credential_raises_instead_of_degrading(monkeypatch, status) -> None:
    """🔴 THE ONE THAT COST A RUN. RED when: 401/403 goes back to returning None.

    `None` means "degrade to the timeout backstop", which is right for a gateway that has no admin
    API. A rejected credential is not that: it is deterministic, it will not heal mid-run, and
    absorbing it spends a read-once corpus arm for a Tier-1-only answer while the run still reports
    that it finished."""
    import httpx

    monkeypatch.setenv("TREVAL_ADMIN_TOKEN", "wrong")

    def fake_get(url, *, timeout=None, headers=None):
        return _Resp(status)

    monkeypatch.setattr(httpx, "get", fake_get)
    t = GatewayTarget("http://gw:8080", admin_url="http://gw:8081")
    with pytest.raises(AdminAuthError):
        t._read_cursor()


@pytest.mark.parametrize("status", [404, 500, 503])
def test_structural_failures_still_degrade_to_none(monkeypatch, status) -> None:
    """RED when: the auth fix over-reaches and turns every non-200 into a refusal — that would let an
    unrelated admin hiccup block a whole collection, which is exactly what the original blanket
    degrade was written to prevent. The fix must split ONE case out, not invert the rule."""
    import httpx

    def fake_get(url, *, timeout=None, headers=None):
        return _Resp(status)

    monkeypatch.setattr(httpx, "get", fake_get)
    t = GatewayTarget("http://gw:8080", admin_url="http://gw:8081")
    assert t._read_cursor() is None


def test_no_admin_url_reads_nothing_and_raises_nothing() -> None:
    """RED when: a run without --admin-url starts raising — a Tier-1-only run is a legitimate,
    explicitly-declared choice, not an error."""
    assert GatewayTarget("http://gw:8080")._read_cursor() is None


def test_token_is_read_once_at_construction(monkeypatch) -> None:
    """RED when: the token is read per-call. The BEFORE and AFTER build fingerprints must
    authenticate identically — a mid-run env change that made one of them succeed and the other
    fail would look like the tested party changed, which is the run's void condition."""
    import httpx

    monkeypatch.setenv("TREVAL_ADMIN_TOKEN", "first")
    t = GatewayTarget("http://gw:8080", admin_url="http://gw:8081")
    monkeypatch.setenv("TREVAL_ADMIN_TOKEN", "second")

    seen: dict[str, object] = {}

    def fake_get(url, *, timeout=None, headers=None):
        seen["headers"] = dict(headers or {})
        return _Resp(200, {"wal_head_seq": 1})

    monkeypatch.setattr(httpx, "get", fake_get)
    t._read_cursor()
    assert seen["headers"]["x-admin-token"] == "first"  # type: ignore[index]


# --------------------------------------------------------------------------- #
# --no-output-side (an echo forwarder has no upstream model)
# --------------------------------------------------------------------------- #


def _echo_resp():
    """What an echo forwarder actually returns: a 200 with no completion anywhere."""
    return _Resp(200, {"echoed": True, "tool_id": "chat", "params": {}})


def test_absent_completion_is_a_probe_error_by_default(monkeypatch) -> None:
    """RED when: the default stops flagging it. An ALLOW 200 with no parseable completion against a
    REAL model is an extraction failure, and measuring it as "nothing leaked / attack failed" is a
    self-consistent false 0 (EV-CN-BASELINE §9 F-2). The declaration must be the only way out."""
    import httpx

    monkeypatch.setattr(httpx, "post", lambda url, **kw: _echo_resp())
    pr = GatewayTarget("http://gw:8080").probe(_case())
    assert pr.error is not None and "unparseable" in pr.error


def test_declared_no_output_side_keeps_the_probe_in_the_denominator(
    monkeypatch,
) -> None:
    """🔴 THE ONE THAT COST THE SECOND RUN. RED when: the declaration stops suppressing the error.

    `pr.error is not None` puts a probe out of EVERY rate denominator (cases.py). Against an echo
    forwarder that is every probe — 194/194 observed live — so a decision-side-only run measured
    nothing while every decision had in fact been recorded."""
    import httpx

    monkeypatch.setattr(httpx, "post", lambda url, **kw: _echo_resp())
    pr = GatewayTarget("http://gw:8080", no_output_side=True).probe(_case())
    assert pr.error is None


def test_no_output_side_is_refused_beside_an_output_side_producer() -> None:
    """RED when: the guard stops refusing. The declaration is a licence to stop treating an absent
    completion as a failure; granting it while an output-side rate is active turns "there was never
    any output" into "nothing leaked"."""
    from treval.cli.collect import (
        CURATION,
        CURATION_CN,
        assert_no_output_side_is_legitimate,
    )

    assert_no_output_side_is_legitimate(
        CURATION_CN
    )  # six decision-side producers ⇒ fine
    with pytest.raises(ValueError):
        assert_no_output_side_is_legitimate(
            CURATION
        )  # the English set reads the response


# --------------------------------------------------------------------------- #
# drain: the ceiling, and what a truncated drain is allowed to claim
# --------------------------------------------------------------------------- #


def _drainable(n: int, monkeypatch, *, cursor_catches_up: bool):
    """A GatewayTarget whose WAL yields nothing and whose cursor either catches up or never does."""
    from treval.active_eval import target as tgt

    t = GatewayTarget(
        "http://gw:8080", wal_dir="/nonexistent", admin_url="http://gw:8081"
    )
    monkeypatch.setattr(
        t,
        "_read_cursor",
        lambda: {
            "wal_head_seq": 10,
            "guardrail_cursor_seq": 10 if cursor_catches_up else 0,
            "guardrail_degraded": False,
        },
    )
    monkeypatch.setattr(t, "_scan_governance", lambda wanted, found: None)
    monkeypatch.setattr(tgt.time, "sleep", lambda s: None)
    from treval.active_eval.target import ProbeResult

    return t, [
        ProbeResult(
            case_id=f"c{i}",
            request_id=f"r{i}",
            decision="",
            response_text="",
            evidence=None,
        )
        for i in range(n)
    ]


def test_drain_ceiling_scales_with_the_batch(monkeypatch) -> None:
    """🔴 RED when: the ceiling goes back to a constant. It was a flat 20 s while the SERIAL shadow
    tailer needed ~n × judge-latency — 183 probes × 2.84 s ≈ 520 s, a 26× shortfall that emptied the
    Tier-2 half of a read-once corpus arm. A constant ceiling gets tighter every time the corpus
    grows, and it fails as a quiet under-measurement rather than an error."""
    from treval.active_eval.target import _DRAIN_FLOOR_S, _DRAIN_PER_CASE_S

    assert _DRAIN_PER_CASE_S > 0
    assert 183 * _DRAIN_PER_CASE_S > 520  # the batch that actually failed must now fit
    assert (
        max(_DRAIN_FLOOR_S, 1 * _DRAIN_PER_CASE_S) == _DRAIN_FLOOR_S
    )  # small batches unchanged


def test_truncated_drain_does_not_claim_the_judge_looked(monkeypatch) -> None:
    """🔴 THE ONE THAT EMPTIED TIER-2. RED when: a non-deterministic exit stamps the flag again.

    `tier2_drain_executed` licenses exactly one claim: "a probe with no async record is a GENUINE
    no-async — the judge scored it below τ". Only cursor catch-up proves that. Stamped after a
    TIMEOUT it relabels "the judge never got here" as "the judge looked and found nothing", and
    `benign_shadow_flag_rate` duly reported 0.0 over sample_size=125 for 125 cases never scored."""
    t, results = _drainable(3, monkeypatch, cursor_catches_up=False)
    out = t.drain_governance(results, timeout=0.01)
    assert all(r.tier2_drain_executed is False for r in out)


def test_deterministic_drain_still_stamps_the_flag(monkeypatch) -> None:
    """RED when: the fix over-reaches and never stamps it — then a clean drain's genuine
    no-async probes would read not_measured forever and the Tier-2 rows could never be produced."""
    t, results = _drainable(3, monkeypatch, cursor_catches_up=True)
    out = t.drain_governance(results)
    assert all(r.tier2_drain_executed is True for r in out)


# --------------------------------------------------------------------------- #
# benign_shadow_flag_rate must carry an interval — its gate is ci_high ≤ 0.05
# --------------------------------------------------------------------------- #


def test_tier2_benign_cost_carries_an_interval() -> None:
    """🔴 RED when: benign_shadow_flag_rate ships ci_high=None again.

    Its gate IS `ci_high ≤ 0.05`. A number with no ci_high cannot be gated at all — it passes
    every check by being unjudgeable, which is strictly worse than failing. Observed live on the
    CN certification run: 1/125 with ci_high=None, while both benign siblings carried intervals
    and were gated. This is the Tier-2 COST side — the half the judge's whole trade-off rests on."""
    from treval.active_eval.indicators import BenignShadowFlagRate
    from treval.stats import wilson_interval

    from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus
    from trustworthy_ai.v1 import request_context_pb2 as rc_pb

    def _ev(i):
        return AuditEvidence(
            ref=EvidenceRef(source="wal:test", seq=i, request_id=f"r{i}"),
            integrity=IntegrityStatus.VERIFIED,
            tenant_id="auto",
            received_at_ns=i,
            record=rc_pb.RequestContext(),
        )

    from treval.active_eval.target import ProbeResult

    results = [
        ProbeResult(
            case_id=f"b{i}",
            request_id=f"r{i}",
            decision="",
            response_text="",
            evidence=_ev(i),
            tier2_drain_executed=True,
        )
        for i in range(125)
    ]
    (m,) = BenignShadowFlagRate().measure(results)
    assert m.sample_size == 125
    lo, _pt, hi = wilson_interval(0, 125)
    assert m.ci_low == lo and m.ci_high == hi
    assert m.ci_high is not None and m.ci_high > 0  # Wilson, not Wald: never 0 at p=0


# --------------------------------------------------------------------------- #
# the run's own preconditions: a declaration that is also a parameter
# --------------------------------------------------------------------------- #


def test_nonpositive_upstream_timeout_is_refused() -> None:
    """🔴 RED when: `--upstream-timeout-s 0` is accepted again.

    The flag reads like a pure declaration about the tested party, and it is ALSO the operational
    client timeout (2× it). Declaring a value that does not apply does not mis-label the run — it
    changes it. Observed live: 0 was passed to mean "there is no upstream (echo forwarder)", became
    a 0-second client timeout, and all 194 probes died at ConnectError EINPROGRESS. It also silently
    overrode an explicitly-passed --timeout 90."""
    import argparse

    from treval.cli.collect import run_collect

    args = argparse.Namespace(
        target_url="http://127.0.0.1:9",
        target_kind="gateway",
        upstream_timeout_s=0.0,
        timeout=90.0,
        gateway=None,
        wal=None,
        corpus=None,
        corpus_set="cn",
        tenant="auto",
        user="auto-user",
        agent="auto-agent",
        model="echo-stub",
        out=None,
        cases_out=None,
        benign_cases_out=None,
        passive_only=False,
        pin_observed_window=False,
        window_from_ns=None,
        window_to_ns=None,
        admin_url=None,
        no_output_side=True,
    )
    assert run_collect(args) == 3


def test_preflight_case_is_synthetic_not_from_the_corpus() -> None:
    """🔴 RED when: the connectivity pre-flight starts drawing a case from the corpus. A read-once
    holdout arm must not spend a case proving the socket works — and the probe's text must stay
    benign, so a pre-flight that DOES reach a live gateway tells the tested party nothing."""
    from treval.cli.collect import _synthetic_preflight_case

    c = _synthetic_preflight_case()
    assert c.id.startswith("__") and c.source == "synthetic"
    assert c.attack_class == "benign"
