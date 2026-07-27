"""GATE-LASTMILE P3–P6 — eval_report's evidence header, undecided guardrail, admin-URL
derivation, and chain-integrity-aware coverage.

Pure/render-layer only (no gateway): the helpers take counts / probes and emit lines; they
never touch a live probe or the indicators.
"""

from __future__ import annotations

from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from tools.eval_report import (
    _derive_admin_url,
    _evidence_coverage,
    _evidence_header,
    _indicator_line,
    _resolve_admin_url,
    _undecided_banner,
    _undecided_count,
    _wal_anchored_count,
)
from treval.active_eval.target import ProbeResult
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus
from treval.rubric.serialize import derive_evidence_basis

_UNDECIDED = rc_pb.DecisionTrace.FINAL_DECISION_UNDECIDED
_ALLOW = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW


def _probe(
    rid: str,
    *,
    anchored: bool = True,
    integrity: IntegrityStatus = IntegrityStatus.VERIFIED,
    final=_ALLOW,
    rules: bool = True,
) -> ProbeResult:
    """A ProbeResult carrying (or not) a WAL decision record of a given integrity/decision."""
    ev = None
    if anchored:
        ctx = rc_pb.RequestContext()
        ctx.envelope.request_id = rid
        ctx.decision.final_decision = final  # type: ignore[assignment]
        if rules:
            r = ctx.decision.rules_evaluated.add()
            r.rule_id = "inj-lexical-1"
        ev = AuditEvidence(
            ref=EvidenceRef(source="wal:x", seq=1, request_id=rid),
            integrity=integrity,
            tenant_id="acme",
            received_at_ns=1,
            record=ctx,
        )
    return ProbeResult(
        case_id="c", request_id=rid, decision="", response_text="", evidence=ev
    )


# --------------------------------------------------------------------------- #
# P3 / C4 — evidence basis is derived, coverage is honest
# --------------------------------------------------------------------------- #


def test_evidence_basis_is_derived_from_target_kind_not_a_local_constant():
    header = "\n".join(_evidence_header("gateway", anchored=5, total=10))
    assert "target_kind=gateway" in header
    assert f"evidence_basis={derive_evidence_basis('gateway')}" in header
    assert "5/10" in header


def test_zero_wal_coverage_is_flagged_as_not_reproducible():
    header = "\n".join(_evidence_header("gateway", anchored=0, total=8))
    assert "0/8" in header
    assert "无可复算 WAL 证据" in header and "不具备可复算性" in header
    assert "⚠" in header
    assert "不得作" in header  # "可验证审计" appears only inside the negation


def test_positive_coverage_header_has_no_unreproducible_warning():
    header = "\n".join(_evidence_header("gateway", anchored=8, total=8))
    assert "8/8" in header
    assert "无可复算 WAL 证据" not in header and "⚠" not in header


# --------------------------------------------------------------------------- #
# P6 — only VERIFIED chains are anchored; UNVERIFIED / BROKEN surface separately
# --------------------------------------------------------------------------- #


def test_evidence_coverage_splits_by_integrity():
    probes = [
        _probe("v1", integrity=IntegrityStatus.VERIFIED),
        _probe("v2", integrity=IntegrityStatus.VERIFIED),
        _probe("u1", integrity=IntegrityStatus.UNVERIFIED),
        _probe("b1", integrity=IntegrityStatus.BROKEN),
        _probe("none", anchored=False),
    ]
    assert _evidence_coverage(probes) == (2, 1, 1)


def test_broken_chain_is_not_counted_as_anchored():
    """A BROKEN record is present but NOT reproducible — it must not inflate the anchored
    count, and it must be visible on its own line (P6)."""
    probes = [
        _probe("v1", integrity=IntegrityStatus.VERIFIED),
        _probe("b1", integrity=IntegrityStatus.BROKEN),
    ]
    assert _wal_anchored_count(probes) == 1  # BROKEN excluded, not 2
    header = "\n".join(_evidence_header("gateway", anchored=1, total=2, broken=1))
    assert "1/2" in header
    assert "BROKEN" in header and "不可复算" in header


def test_all_verified_coverage_matches_the_pre_p6_number():
    """Regression: with no UNVERIFIED/BROKEN records the coverage number is unchanged and the
    chain-integrity line is absent."""
    probes = [_probe(f"v{i}", integrity=IntegrityStatus.VERIFIED) for i in range(3)]
    assert _wal_anchored_count(probes) == 3
    header = "\n".join(_evidence_header("gateway", anchored=3, total=3))
    assert "chain integrity" not in header


# --------------------------------------------------------------------------- #
# P4 — undecided guardrail: no-decision runs render insufficient_data, not 0%
# --------------------------------------------------------------------------- #


def test_indicator_line_renders_insufficient_data_at_zero_samples():
    line = _indicator_line("injection_catch_rate", 0.0, 0, "")
    assert "insufficient_data" in line
    assert (
        "= 0%" not in line
    )  # the METRIC is not rendered as 0% (the disclaimer's "非 0%" is fine)
    # a real measurement still renders a percentage
    assert "89%" in _indicator_line("injection_catch_rate", 0.8928, 28, "")


def test_undecided_count_ignores_errored_and_governed_probes():
    results = [
        _probe("a", final=_ALLOW, rules=True),  # governed allow — decided
        _probe("u1", final=_UNDECIDED, rules=False),  # undecided
        _probe("u2", rules=False),  # zero rules — undecided
        ProbeResult(
            case_id="e",
            request_id="",
            decision="",
            response_text="",
            evidence=None,
            error="boom",
        ),
    ]
    assert _undecided_count(results) == 2


def test_whole_run_banner_fires_only_when_every_measurable_probe_is_undecided():
    # the incident: all 142 undecided ⇒ banner declares the run unmeasurable
    banner = "\n".join(_undecided_banner(142, 142))
    assert "未产生任何裁决" in banner and "非 0%" in banner
    assert "端口在听 ≠ 治理就绪" in banner
    # a mixed run (some decided) does NOT get the whole-run banner (per-indicator handles it)
    assert _undecided_banner(142, 100) == []
    # an empty run does not fire it either
    assert _undecided_banner(0, 0) == []


# --------------------------------------------------------------------------- #
# P5 — admin URL is derived from the gateway URL when unset
# --------------------------------------------------------------------------- #


def test_admin_url_derives_data_plane_port_plus_one():
    url, why = _derive_admin_url("http://127.0.0.1:8080")
    assert url == "http://127.0.0.1:8081" and why == ""


def test_admin_url_derivation_reports_why_it_cannot():
    url, why = _derive_admin_url("http://127.0.0.1")  # no explicit port
    assert url is None and "no explicit port" in why


def test_resolve_admin_url_prefers_explicit_then_derives(monkeypatch):
    monkeypatch.setenv("TREVAL_EVAL_GATEWAY_URL", "http://127.0.0.1:8080")
    # explicit wins
    monkeypatch.setenv("TREVAL_EVAL_ADMIN_URL", "http://admin.internal:9000")
    url, note = _resolve_admin_url()
    assert url == "http://admin.internal:9000" and "explicit" in note
    # unset ⇒ derived (so the deterministic drain works by default — no more silent under-measure)
    monkeypatch.delenv("TREVAL_EVAL_ADMIN_URL", raising=False)
    url, note = _resolve_admin_url()
    assert url == "http://127.0.0.1:8081" and "derived" in note


def test_banner_explains_the_errored_gap_between_its_two_denominators():
    """P9: the banner counts MEASURABLE probes, the evidence line counts ALL probes, so the two
    adjacent header lines legitimately differ (live: 136 vs 142). Unexplained, that reads as if
    the numbers disagree — so the banner names the errored probes it left out."""
    (line, _blank) = _undecided_banner(136, 136, 142)
    assert "136/136 可测探针" in line
    assert "6 条 errored" in line
    # no gap ⇒ no distracting note
    (line2, _b2) = _undecided_banner(28, 28, 28)
    assert "errored" not in line2
    # not-all-undecided ⇒ no banner at all
    assert _undecided_banner(28, 27, 28) == []
