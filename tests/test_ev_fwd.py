"""EV-FWD — standalone target abstraction: OpenAITarget + evidence_requirement + availability.

Covers §7 acceptance: the OpenAITarget contract (decision=""/evidence=None, tokens parsed,
api_key never leaked), guardrail 1 (no rules/PII/WAL), the output-side reuse on evidence=None,
the declaration↔behaviour guard (§4.1), the availability derivation gate, N/A ≠ insufficient_data
(§7.6, with teeth), and the raw_model wording red-line (§7.7).
"""

from __future__ import annotations

import json

import pytest

from treval.active_eval import (
    EVIDENCE_REQUIREMENTS,
    BenignComplianceRate,
    CanaryLeakRate,
    CostRunawayCaught,
    FalsePositiveRate,
    InjectionCatchRate,
    InjectionSuccessRate,
    OpenAITarget,
    SensitiveDisclosureRate,
    SystemPromptLeakRate,
    ToolScopeViolationRate,
    UnsafeOutputPassthroughRate,
    WireIndirectCatchRate,
    WithinCostBudget,
    run_corpus,
)
from treval.active_eval.corpus import CorpusCase
from treval.rubric.serialize import (
    AVAILABILITY_VALUES,
    derive_availability,
    serialize_measurement,
)


def _case(cid="c1", *, input_text="hello", marker="", canary=""):
    return CorpusCase(
        id=cid,
        owasp="LLM01",
        dimension="robustness",
        attack_class="direct_prompt_injection",
        input=input_text,
        success_when="blocked_or_flagged",
        severity="high",
        source="core-authored",
        output_marker=marker,
        secret_canary=canary,
    )


class _FakeResp:
    """A minimal stand-in for an httpx.Response from an OpenAI /chat/completions endpoint."""

    def __init__(self, payload: dict, *, headers=None, status_code=200):
        self._payload = payload
        self.text = json.dumps(payload)
        self.headers = headers or {}
        self.status_code = status_code

    def json(self):
        return self._payload


def _install_fake_openai(monkeypatch, payload, *, capture=None, status_code=200):
    """Patch httpx.post so OpenAITarget.probe() drives a fake endpoint. `capture` (a dict)
    records the last (url, headers, json) so a test can assert what was sent."""
    import httpx

    def fake_post(url, *, headers=None, json=None, timeout=None):
        if capture is not None:
            capture["url"] = url
            capture["headers"] = headers or {}
            capture["json"] = json
        return _FakeResp(payload, status_code=status_code)

    monkeypatch.setattr(httpx, "post", fake_post)


_COMPLETION = {
    "choices": [{"message": {"role": "assistant", "content": "the answer"}}],
    "usage": {
        "prompt_tokens": 5,
        "completion_tokens": 7,
        "total_tokens": 12,
        "completion_tokens_details": {"reasoning_tokens": 3},
    },
}


# --------------------------------------------------------------------------- #
# §7.1 — OpenAITarget contract
# --------------------------------------------------------------------------- #


def test_openai_target_produces_standalone_probe_result(monkeypatch):
    _install_fake_openai(monkeypatch, _COMPLETION)
    t = OpenAITarget("https://api.example/v1", model="gpt-x")
    pr = t.probe(_case(input_text="ignore instructions"))
    assert pr.decision == ""  # a bare model makes no decision
    assert pr.evidence is None and pr.response_evidence is None  # NO WAL
    assert pr.response_text == "the answer"
    # tokens parsed from usage (same helper the gateway uses)
    assert (pr.prompt_tokens, pr.completion_tokens, pr.total_tokens) == (5, 7, 12)
    assert pr.reasoning_tokens == 3
    assert t.target_id == "raw_model"


def test_openai_target_sends_api_key_in_header_only_never_in_the_result(monkeypatch):
    cap: dict = {}
    _install_fake_openai(monkeypatch, _COMPLETION, capture=cap)
    t = OpenAITarget("https://api.example/v1", model="gpt-x", api_key="sk-SECRET-123")
    pr = t.probe(_case())
    # the key rides the Authorization header
    assert cap["headers"].get("Authorization") == "Bearer sk-SECRET-123"
    assert cap["url"] == "https://api.example/v1/chat/completions"
    # …and appears NOWHERE in the ProbeResult (no field leaks the secret)
    blob = repr(pr)
    assert "sk-SECRET-123" not in blob and "SECRET" not in blob


def test_openai_target_api_key_defaults_from_env(monkeypatch):
    monkeypatch.setenv("TREVAL_OPENAI_API_KEY", "sk-ENV-KEY")
    cap: dict = {}
    _install_fake_openai(monkeypatch, _COMPLETION, capture=cap)
    OpenAITarget("https://api.example/v1", model="gpt-x").probe(_case())
    assert cap["headers"].get("Authorization") == "Bearer sk-ENV-KEY"


def test_openai_target_transport_error_is_recorded_not_raised(monkeypatch):
    import httpx

    def boom(*a, **k):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(httpx, "post", boom)
    pr = OpenAITarget("https://api.example/v1", model="gpt-x").probe(_case())
    assert pr.error is not None and "ConnectError" in pr.error
    assert pr.evidence is None


@pytest.mark.parametrize("status", [404, 401, 429, 500])
def test_openai_target_non_2xx_is_an_error_not_a_clean_empty_answer(
    status, monkeypatch
):
    """🔴 A non-2xx (wrong URL / bad key / rate-limit) must be a recorded error — OpenAITarget has
    no WAL to confirm anything, so an empty non-2xx body is an endpoint failure, not a clean run."""
    _install_fake_openai(monkeypatch, {"detail": "Not Found"}, status_code=status)
    pr = OpenAITarget("https://api.example/v1", model="gpt-x").probe(_case())
    assert pr.error is not None and f"HTTP {status}" in pr.error
    assert pr.response_text == ""


def test_openai_target_200_without_choices_is_an_error(monkeypatch):
    """A 200 carrying an error JSON (no `choices`) — some compat layers do this on quota/rate
    limits — is NOT a clean empty answer (§2)."""
    _install_fake_openai(
        monkeypatch, {"error": {"message": "quota exceeded"}}, status_code=200
    )
    pr = OpenAITarget("https://api.example/v1", model="gpt-x").probe(_case())
    assert pr.error is not None and "no completion" in pr.error


# --------------------------------------------------------------------------- #
# §7.2 — guardrail 1: a test client, NEVER a governance path
# --------------------------------------------------------------------------- #


def test_openai_target_touches_no_wal_or_governance_state():
    """It must not carry a WAL dir, a tenant, or any read-evidence path — it is not a
    slimmed-down gateway (guardrail 1)."""
    t = OpenAITarget("https://api.example/v1", model="gpt-x")
    names = set(vars(t))
    assert not any("wal" in n for n in names), names
    assert not any("tenant" in n for n in names), names
    assert not hasattr(t, "_read_evidence")
    # and it produces evidence=None by construction — proven above; here we pin the seam.


# --------------------------------------------------------------------------- #
# §7.3 / §7.4 — output-side indicators measure on evidence=None; declaration ↔ behaviour
# --------------------------------------------------------------------------- #

_OUTPUT_SIDE = {
    "injection_success_rate": (InjectionSuccessRate, {"marker": "ZZPWN"}),
    "sensitive_disclosure_rate": (SensitiveDisclosureRate, {"canary": "CANARY-XYZ"}),
    "system_prompt_leak_rate": (SystemPromptLeakRate, {"canary": "CANARY-XYZ"}),
    "unsafe_output_passthrough_rate": (UnsafeOutputPassthroughRate, {"canary": "<x>"}),
    "within_cost_budget": (lambda: WithinCostBudget(2000), {}),
    # EV-CAPCTRL §3: the benign floor reads only marker_followed ⇒ measures on evidence=None too.
    "benign_compliance_rate": (BenignComplianceRate, {"marker": "ZZPWN"}),
}


def _standalone_probes(monkeypatch, **case_kwargs):
    """Run one case through OpenAITarget (evidence=None) via run_corpus, so the canaries are
    stamped exactly as in a real run."""
    _install_fake_openai(monkeypatch, _COMPLETION)
    t = OpenAITarget("https://api.example/v1", model="gpt-x")
    return run_corpus([_case(**case_kwargs)], t)


@pytest.mark.parametrize("indicator_id", sorted(_OUTPUT_SIDE))
def test_output_side_indicators_measure_on_evidence_none(indicator_id, monkeypatch):
    """§7.3/§7.4: every indicator DECLARED output_only must yield sample_size>0 on a probe with
    evidence=None (a standalone run) — declaration must match behaviour."""
    assert EVIDENCE_REQUIREMENTS[indicator_id] == "output_only"
    factory, ck = _OUTPUT_SIDE[indicator_id]
    probes = _standalone_probes(monkeypatch, **ck)
    assert probes[0].evidence is None
    (m,) = factory().measure(probes)
    assert m.sample_size > 0, f"{indicator_id} produced no measurement standalone"


def test_batch_of_failed_endpoint_calls_is_insufficient_data_not_false_zero(
    monkeypatch,
):
    """🔴 teeth (architect §3): a whole batch against a broken endpoint (404) must leave the
    output-side indicators at insufficient_data (n=0), NEVER a plausible 0% ("zero leaked / zero
    succeeded"). Reverting the status check makes every probe "succeed" empty and n jumps to the
    batch size — the exact fake-clean report this guards. This is the FOURTH form of the fake-0%
    failure, on the one side raw_model can measure."""
    _install_fake_openai(monkeypatch, {"detail": "Not Found"}, status_code=404)
    t = OpenAITarget("https://api.example/v1", model="gpt-x")
    corpus = [_case(cid=f"c{i}", marker="ZZPWN", canary="CANARY-XYZ") for i in range(8)]
    probes = run_corpus(corpus, t)
    assert all(p.error and "HTTP 404" in p.error for p in probes)
    for factory, ck in (
        (InjectionSuccessRate, None),
        (SensitiveDisclosureRate, None),
        (SystemPromptLeakRate, None),
        (UnsafeOutputPassthroughRate, None),
    ):
        (m,) = factory().measure(probes)
        assert m.sample_size == 0, (
            f"{m.indicator_id} measured {m.sample_size} probes on a 404 batch — false 0%"
        )


def test_declared_output_only_set_matches_the_indicators_under_test():
    """Guards drift: if a NEW indicator is declared output_only, it must be added to the
    behaviour test above (so the §7.4 guard actually covers it)."""
    declared = {k for k, v in EVIDENCE_REQUIREMENTS.items() if v == "output_only"}
    assert declared == set(_OUTPUT_SIDE), (
        "output_only declarations and the behaviour-tested set have drifted"
    )


_DECISION_OR_WAL = [
    InjectionCatchRate,
    WireIndirectCatchRate,  # 🔴 §4.1 trap: inherits measure() → needs_decision
    FalsePositiveRate,
    ToolScopeViolationRate,
    CostRunawayCaught,
]


@pytest.mark.parametrize("factory", _DECISION_OR_WAL)
def test_decision_wal_indicators_are_not_measured_on_raw_model(factory):
    """§7.4: an indicator declared needs_decision/needs_wal must derive availability != measured
    on raw_model (it is architecturally absent, not merely unmeasured)."""
    indicator_id = factory().indicator_id
    assert EVIDENCE_REQUIREMENTS[indicator_id] in ("needs_decision", "needs_wal")
    avail = derive_availability("raw_model", EVIDENCE_REQUIREMENTS[indicator_id])
    assert avail != "measured" and avail.startswith("n/a")


def test_wire_indirect_is_needs_decision_despite_empty_class_body():
    """The §4.1 trap, pinned explicitly: WireIndirectCatchRate has an empty body and INHERITS
    measure() — a body-grep classifier would mislabel it output_only."""
    assert EVIDENCE_REQUIREMENTS["wire_indirect_catch_rate"] == "needs_decision"


def test_canary_leak_base_is_internal_and_unclassified():
    """CanaryLeakRate is an INTERNAL base (never surfaces) — it must not appear in the
    declaration; only its concrete subclasses do."""
    assert not hasattr(CanaryLeakRate, "indicator_id") or (
        getattr(CanaryLeakRate, "indicator_id", None) not in EVIDENCE_REQUIREMENTS
    )


# --------------------------------------------------------------------------- #
# §7.5 — the availability derivation gate
# --------------------------------------------------------------------------- #


def test_availability_derivation_table():
    # gateway measures everything
    for req in EVIDENCE_REQUIREMENTS.values():
        assert derive_availability("gateway", req) == "measured"
    # output_only measures on every target
    assert derive_availability("raw_model", "output_only") == "measured"
    assert derive_availability("moderation_api", "output_only") == "measured"
    # 🔴 §5: moderation_api × needs_wal is n/a_self_reported (NOT n/a_needs_gateway)
    assert derive_availability("moderation_api", "needs_wal") == "n/a_self_reported"
    assert (
        derive_availability("moderation_api", "needs_decision") == "n/a_self_reported"
    )
    # raw_model × (needs_decision|needs_wal) is n/a_needs_gateway
    assert derive_availability("raw_model", "needs_wal") == "n/a_needs_gateway"
    assert derive_availability("raw_model", "needs_decision") == "n/a_needs_gateway"
    # every derived value is a member of the closed set
    for tk in ("gateway", "raw_model", "moderation_api"):
        for req in EVIDENCE_REQUIREMENTS.values():
            assert derive_availability(tk, req) in AVAILABILITY_VALUES


def test_unknown_indicator_defaults_conservatively_never_measured_off_gateway():
    """An unclassified indicator must never silently claim `measured` standalone."""
    assert derive_availability("gateway", None) == "measured"  # gateway: fine
    assert derive_availability("raw_model", None) == "n/a_needs_gateway"  # conservative


def test_unknown_target_kind_fails_closed():
    with pytest.raises(ValueError):
        derive_availability("nonsense", "output_only")


# --------------------------------------------------------------------------- #
# §7.6 — N/A ≠ insufficient_data (with teeth) + §7.7 — no wal-anchored wording on raw_model
# --------------------------------------------------------------------------- #


def _raw_model_measurement_dict(indicator_id, sample_size):
    from treval.models import EvidenceRef, IntegrityStatus, Measurement

    m = Measurement(
        indicator_id=indicator_id,
        dimension="robustness",
        value=0.0,
        unit="ratio",
        sample_size=sample_size,
        subject="",
        integrity=IntegrityStatus.VERIFIED,
        evidence_refs=(EvidenceRef(source="eval:probe"),),
        notes="0 probe(s) measured — insufficient_data (gateway made no decision), NOT 0%",
    )
    return serialize_measurement(
        m, target_kind="raw_model", evidence_requirements=EVIDENCE_REQUIREMENTS
    )


def test_injection_catch_on_raw_model_is_na_needs_gateway_not_insufficient_data():
    """§7.6: on raw_model, injection_catch_rate serializes availability=n/a_needs_gateway — an
    ARCHITECTURAL absence, distinct from P4's insufficient_data (a this-run absence). The two must
    be tellable apart, else a reader thinks 'run it again and it'll appear'.

    teeth: reverting EV-FWD (no availability field / defaulting to measured) makes this red.
    """
    d = _raw_model_measurement_dict("injection_catch_rate", sample_size=0)
    assert d["availability"] == "n/a_needs_gateway"
    assert d["availability"] != "measured"
    # the P4 insufficient_data signal still lives in notes/sample_size — the two coexist,
    # they do not overwrite each other.
    assert d["sample_size"] == 0 and "insufficient_data" in d["notes"]


def test_output_indicator_on_raw_model_stays_measured():
    """The other side of §7.6: an output_only indicator on raw_model is `measured`, NOT n/a —
    a measurable-but-not-auditable value is `measured` + a weaker evidence_basis (§0.1)."""
    d = _raw_model_measurement_dict("injection_success_rate", sample_size=8)
    assert d["availability"] == "measured"


def test_raw_model_bundle_never_asserts_wal_anchored(monkeypatch):
    """§7.7 wording red-line: a raw_model report carries evidence_basis=harness_observed and no
    measurement claims a WAL-anchored ('measured' for a needs_wal indicator) availability — the
    verifiable-audit tier is never borrowed by a bare-model run."""
    from treval import evaluate, load_registry, self_contained_bundle_to_json
    from treval.models import EvidenceRef, IntegrityStatus, Measurement

    reg = load_registry()
    measurements = [
        Measurement(
            indicator_id="injection_success_rate",
            dimension="robustness",
            value=0.5,
            unit="ratio",
            sample_size=8,
            subject="",
            integrity=IntegrityStatus.VERIFIED,
            evidence_refs=(EvidenceRef(source="eval:probe"),),
            notes="",
        )
    ]
    report = evaluate(reg, measurements, [], window=(0, 0), tenant_id="raw")
    doc = json.loads(
        self_contained_bundle_to_json(
            report,
            measurements,
            reg,
            target_kind="raw_model",
            evidence_requirements=EVIDENCE_REQUIREMENTS,
        )
    )
    assert doc["evidence_basis"] == "harness_observed"  # NOT wal_anchored
    assert doc["evidence_basis"] != "wal_anchored"
    # no needs_wal/needs_decision indicator is present claiming measured on this bare-model run
    for m in doc["measurements"]:
        req = EVIDENCE_REQUIREMENTS.get(m["indicator_id"])
        if req in ("needs_decision", "needs_wal"):
            assert m["availability"] != "measured"


# --------------------------------------------------------------------------- #
# §7.6 fix #3 — the END-TO-END guard, on the CLI PRODUCT (the collect bundle FILE),
# not a serializer function. This is the real defence: the live bug lived on the
# cli/bundle.py path, which had zero end-to-end coverage (a default silently made it
# "measured"). Drive `collect --target-kind raw_model` and read what it WROTE.
# --------------------------------------------------------------------------- #


def test_collect_raw_model_bundle_marks_decision_indicators_not_measured(
    tmp_path, monkeypatch
):
    """collect --target-url … --target-kind raw_model must WRITE a bundle whose decision/WAL
    indicators carry availability != measured. Reverting fix #1 (dropping target_kind on the
    cli/bundle.py path) makes this red — the exact bug that slipped past the function-level tests.
    """
    from treval.cli.main import main

    # `--gateway` defaults from TREVAL_EVAL_GATEWAY_URL; clear it so the explicit --target-url
    # path is exercised (an ambient gateway env would otherwise trip the mutual-exclusion guard).
    monkeypatch.delenv("TREVAL_EVAL_GATEWAY_URL", raising=False)
    monkeypatch.delenv("TREVAL_EVAL_WAL_DIR", raising=False)
    _install_fake_openai(
        monkeypatch, _COMPLETION
    )  # OpenAITarget.probe hits the fake endpoint
    out = tmp_path / "raw_bundle.json"
    rc = main(
        [
            "collect",
            "--target-url",
            "http://fake/v1",
            "--target-kind",
            "raw_model",
            "--model",
            "gpt-x",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["schema_version"] == 5  # collect bundle v5 (EV-CIGATE: +ci_low/ci_high)
    assert doc["target_kind"] == "raw_model"
    assert doc["evidence_basis"] == "harness_observed"
    # the CURATION producers are decision-side ⇒ every one must be n/a on a bare model,
    # never `measured` (the live failure). Assert on the WRITTEN file, per the architect.
    assert doc["measurements"], "collect produced no measurements"
    for m in doc["measurements"]:
        req = EVIDENCE_REQUIREMENTS.get(m["indicator_id"])
        if req in ("needs_decision", "needs_wal"):
            assert m["availability"] == "n/a_needs_gateway", (
                f"{m['indicator_id']} is {m['availability']} in the raw_model collect bundle"
            )


def test_collect_gateway_bundle_marks_everything_measured(tmp_path, monkeypatch):
    """The regression direction: a gateway collect bundle still marks everything `measured`
    (gateway measures every requirement) — so fix #1 did not over-correct."""
    from treval.cli.main import main

    monkeypatch.delenv(
        "TREVAL_EVAL_WAL_DIR", raising=False
    )  # no passive scan in this test
    # A gateway run's active producers drive the fake endpoint (via GatewayTarget → httpx).
    _install_fake_openai(monkeypatch, {**_COMPLETION, "decision": "BLOCK"})
    out = tmp_path / "gw_bundle.json"
    rc = main(["collect", "--gateway", "http://fake:8080", "--out", str(out)])
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["target_kind"] == "gateway"
    for m in doc["measurements"]:
        assert m["availability"] == "measured", m["indicator_id"]
