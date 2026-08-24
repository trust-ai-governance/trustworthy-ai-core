"""EV-CN-BASELINE §9 F-2 — the value-EXTRACTION-layer census. A silent fallback disguises a batch of
extraction failures as a self-consistent, clean 0 (被污染的数据给自洽的错结论). The GatewayTarget gap: a
NON-BLOCKED 200 with no parseable completion was read as "nothing leaked / attack failed" across the four
output-side indicators, with no count of how many fell through. The fix records it as an error ⇒ those
indicators EXCLUDE + COUNT it (mirrors OpenAITarget's _has_completion guard, respecting block semantics)."""

from __future__ import annotations

import json

import pytest

httpx = pytest.importorskip(
    "httpx", reason="active-eval extra (requirements-eval.txt) not installed"
)

from treval.active_eval import GatewayTarget, InjectionSuccessRate  # noqa: E402
from treval.active_eval.corpus import CorpusCase  # noqa: E402
from treval.active_eval.indicators import ProbeResult  # noqa: E402


class _Resp:
    def __init__(self, body):
        self.headers = {}
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body


def _case():
    return CorpusCase(
        id="c1",
        owasp="LLM01",
        dimension="robustness",
        attack_class="direct_prompt_injection",
        input="x",
        success_when="not_leaked",
        severity="high",
        source="core-authored",
    )


def _probe_with(monkeypatch, body):
    monkeypatch.setattr(httpx, "post", lambda *a, **k: _Resp(body))
    return GatewayTarget("http://gw", tenant_id="__eval__").probe(_case())


def test_f2_non_blocked_no_completion_is_recorded_as_extraction_error(monkeypatch):
    # 🔴 F-2 验收 — a 200, decision ALLOW, NO `choices` (an error payload some compat layers return) is an
    # EXTRACTION FAILURE. What reds it: remove the no_output detection ⇒ error None ⇒ the output indicators
    # measure it as a clean "nothing leaked" 0.
    pr = _probe_with(
        monkeypatch, {"decision": "ALLOW", "error": {"message": "upstream 500"}}
    )
    assert pr.error is not None and "gateway-output-unparseable" in pr.error


def test_f2_unparseable_body_on_a_non_blocked_response_is_an_error(monkeypatch):
    # a body that isn't even JSON (→ {}) on a non-blocked response ⇒ extraction failure, not a clean 0.
    monkeypatch.setattr(
        httpx, "post", lambda *a, **k: _RawResp("<html>502 Bad Gateway</html>")
    )
    pr = GatewayTarget("http://gw", tenant_id="__eval__").probe(_case())
    assert pr.error is not None and "gateway-output-unparseable" in pr.error


def test_f2_governance_block_with_empty_body_is_not_an_error(monkeypatch):
    # 🔴 a BLOCK legitimately has no output — it is a CAUGHT injection, a REAL 0, never an extraction failure.
    pr = _probe_with(monkeypatch, {"decision": "BLOCK"})
    assert pr.error is None and pr.decision == "BLOCK"


def test_f2_real_empty_answer_stays_measurable(monkeypatch):
    # an ALLOW with a VALID but empty completion (choices present, content "") is a real empty answer —
    # measurable, NOT an extraction failure (the distinction _has_completion draws).
    pr = _probe_with(
        monkeypatch, {"decision": "ALLOW", "choices": [{"message": {"content": ""}}]}
    )
    assert pr.error is None


def test_f2_valid_completion_is_not_an_error(monkeypatch):
    pr = _probe_with(
        monkeypatch, {"decision": "ALLOW", "choices": [{"message": {"content": "hi"}}]}
    )
    assert pr.error is None and pr.response_text == "hi"


def test_f2_extraction_failure_is_excluded_and_counted_not_a_measured_zero():
    # 🔴 "计数进报告" — a marker-bearing extraction-failure probe (error set) is EXCLUDED from the output
    # denominator AND its count is readable in the product notes; it is NOT folded in as a measured 0.
    ok = ProbeResult(
        case_id="a",
        request_id="ra",
        decision="ALLOW",
        response_text="ZZMARK stuff",
        evidence=None,
        output_marker="ZZMARK",
    )
    fail = ProbeResult(
        case_id="b",
        request_id="rb",
        decision="ALLOW",
        response_text="",
        evidence=None,
        output_marker="ZZMARK",
        error="gateway-output-unparseable（网关输出解不动，非工装失败）: {}",
    )
    (m,) = InjectionSuccessRate().measure([ok, fail])
    assert m.sample_size == 1  # the extraction failure is OUT of the denominator
    assert (
        "error(s) excluded" in m.notes
    )  # and its count is readable (读得出有几条没取到)


class _RawResp:
    """A response whose body is not JSON (resp.json() raises) — _parse_body → ({}, text)."""

    def __init__(self, text):
        self.headers = {}
        self.text = text

    def json(self):
        raise ValueError("not json")


def test_f2_cause_string_names_which_side_failed(monkeypatch):
    # 🔴 件⑥ — "工装失败" and "网关输出解不动" have DIFFERENT owners and DIFFERENT fixes. A cause string that
    # conflates them sends the wrong person looking. What reds it: collapse both to one generic message.
    import httpx

    pr_out = _probe_with(monkeypatch, {"decision": "ALLOW", "error": {"m": 1}})
    assert "gateway-output-unparseable" in pr_out.error and "非工装失败" in pr_out.error

    def boom(*a, **k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "post", boom)
    pr_harness = GatewayTarget("http://gw", tenant_id="__eval__").probe(_case())
    assert "harness-transport-failure" in pr_harness.error
    assert "非网关输出问题" in pr_harness.error
