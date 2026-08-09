"""EV-8 — the operator `collect` logic, exercised WITHOUT a gateway via a fake Target.

Proves the D3 curation contract (§3/§7): every bound id yields exactly one aggregate
Measurement, so the bundle feeds `report` with no DuplicateIndicatorError; and that a
failing producer aggregates to a warning instead of crashing the run (§5)."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import pytest
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

import walgen
from treval.active_eval import EVIDENCE_REQUIREMENTS
from treval.active_eval.target import ProbeResult
from treval.cli.bundle import build_bundle, load_bundle
from treval.cli.collect import (
    CURATION,
    _resolve_target,
    collect_measurements,
    collect_passive,
)
from treval.cli.main import main
from treval.registry import load_registry
from treval.rubric import evaluate

_CORPUS = Path(__file__).resolve().parents[1] / "corpus"


class _FakeTarget:
    """Returns a canned governed ProbeResult — enough for the indicators to produce a
    (possibly zero-sample) aggregate Measurement, no network."""

    target_id = "fake"

    def probe(self, case):
        return ProbeResult(
            case_id=case.id,
            request_id="req-x",
            decision="BLOCK",
            response_text="",
            evidence=None,
        )


def test_collect_yields_one_measurement_per_producer():
    warnings: list[str] = []
    measurements = collect_measurements(
        _FakeTarget(), corpus_root=_CORPUS, warnings=warnings
    ).measurements
    assert warnings == []
    # one Measurement per producer, in order, each with the (indicator_id, subject) it declares —
    # so the EV-ATTRIB §3.1 disclosure row (injection_catch_rate@outcome_observable) rides alongside
    # its aggregate without colliding.
    assert [(m.indicator_id, m.subject) for m in measurements] == [
        (p.indicator_id, p.subject) for p in CURATION
    ]
    # exactly one AGGREGATE (subject=="") per bound id — the invariant the rubric engine relies on
    agg_ids = [m.indicator_id for m in measurements if m.subject == ""]
    assert len(agg_ids) == len(set(agg_ids))


def test_collect_emits_attribution_cells_and_stratified_catch():
    """EV-ATTRIB §1/§3.1 wiring: a collect run emits the two (decision×output) cells AND the
    stratified injection_catch_rate@outcome_observable disclosure row — so the §6 Live Test can see
    prevented+succeeded+declined and the same-denominator catch in a real bundle."""
    warnings: list[str] = []
    ms = collect_measurements(
        _FakeTarget(), corpus_root=_CORPUS, warnings=warnings
    ).measurements
    keyed = {(m.indicator_id, m.subject) for m in ms}
    assert ("injection_catch_rate", "") in keyed  # aggregate coverage catch (n=all)
    assert (
        "injection_catch_rate",
        "outcome_observable",
    ) in keyed  # §3.1 disclosure row
    assert ("injection_hard_blocked_rate", "") in keyed  # F1: the claimable cell
    assert ("injection_soft_flag_declined_rate", "") in keyed  # F1: the ambiguous cell
    assert ("injection_declined_by_model_rate", "") in keyed


def test_collected_bundle_feeds_report_without_duplicate_error():
    warnings: list[str] = []
    measurements = collect_measurements(
        _FakeTarget(), corpus_root=_CORPUS, warnings=warnings
    ).measurements
    doc = build_bundle(measurements, tenant_id="__eval__", window=(0, 0), mode="active")
    # round-trip through the bundle, then grade — the §7 acceptance (no DuplicateIndicatorError)
    import json
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "bundle.json"
        p.write_text(json.dumps(doc), encoding="utf-8")
        loaded = load_bundle(p)
    report = evaluate(
        load_registry(),
        loaded.measurements,
        [],
        window=loaded.window,
        tenant_id=loaded.tenant_id,
    )
    # robustness has the injection measurement bound; grading completes cleanly.
    assert {d.dimension for d in report.dimensions} == set(load_registry().dimensions)


def test_failing_producer_aggregates_to_warning(tmp_path):
    """A corpus root missing the curated subdirs → every producer fails → warnings, no
    raise, empty measurement set (report will render insufficient_data)."""
    warnings: list[str] = []
    measurements = collect_measurements(
        _FakeTarget(), corpus_root=tmp_path, warnings=warnings
    ).measurements
    assert measurements == ()
    assert len(warnings) == len(CURATION)
    assert all("failed" in w for w in warnings)


def test_passive_collect_unreadable_wal_aggregates_to_warning(tmp_path):
    """Passive collect (EV-5) over a WAL with no eval records → a warning, empty result, no
    crash (§5 — a missing/unreadable passive source never breaks the run)."""
    warnings: list[str] = []
    measurements = collect_passive(
        str(tmp_path / "no_such_wal"), "__eval__", warnings=warnings
    )
    assert measurements == ()
    assert warnings and all("passive" in w.lower() for w in warnings)


# --------------------------------------------------------------------------- #
# EV-FWD D3 — the collect target CLI: --target-url + --target-kind, --gateway as
# sugar, mutually exclusive, kind NEVER inferred.
# --------------------------------------------------------------------------- #


def _args(**kw):
    ns = argparse.Namespace(gateway=None, target_url=None, target_kind=None)
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def test_gateway_is_sugar_for_a_gateway_run():
    assert _resolve_target(_args(gateway="http://gw:8080")) == (
        "http://gw:8080",
        "gateway",
    )


def test_explicit_target_url_plus_kind():
    assert _resolve_target(
        _args(target_url="https://api.x/v1", target_kind="raw_model")
    ) == ("https://api.x/v1", "raw_model")


def test_target_url_without_kind_is_an_error_never_inferred(capsys):
    assert _resolve_target(_args(target_url="https://api.x/v1")) is None
    err = capsys.readouterr().err
    assert "requires --target-kind" in err and "never inferred" in err


def test_gateway_and_target_url_are_mutually_exclusive(capsys):
    assert (
        _resolve_target(_args(gateway="http://gw", target_url="https://api.x/v1"))
        is None
    )
    assert "mutually exclusive" in capsys.readouterr().err


def test_no_target_at_all_is_an_error(capsys):
    assert _resolve_target(_args()) is None
    assert "need --gateway" in capsys.readouterr().err


def test_target_kind_is_a_closed_enum_in_the_parser():
    from treval.cli.main import build_parser

    parser = build_parser()
    # a bogus kind is rejected by argparse (closed enum)
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["collect", "--target-url", "https://api.x/v1", "--target-kind", "bogus"]
        )
    ok = parser.parse_args(
        ["collect", "--target-url", "https://api.x/v1", "--target-kind", "raw_model"]
    )
    assert ok.target_kind == "raw_model"


# --------------------------------------------------------------------------- #
# EV-PAIR-A — output-side producers make `collect --target-kind raw_model` yield
# real numbers, while decision-side producers stay n/a (no regression).
# --------------------------------------------------------------------------- #

_OUTPUT_SIDE_IDS = {
    "injection_success_rate",
    "sensitive_disclosure_rate",
    "unsafe_output_passthrough_rate",
    "system_prompt_leak_rate",
}
_DECISION_SIDE_IDS = {
    "injection_catch_rate",
    "injection_hard_blocked_rate",  # EV-ATTRIB §1/F1 — needs_decision
    "injection_soft_flag_declined_rate",  # EV-ATTRIB §1/F1 — needs_decision
    "injection_declined_by_model_rate",  # EV-ATTRIB §1 — needs_decision
    "tool_scope_violation_rate",
}


class _FakeResp:
    def __init__(self, payload, *, status_code=200):
        self._payload = payload
        self.text = json.dumps(payload)
        self.headers = {}
        self.status_code = status_code

    def json(self):
        return self._payload


def _fake_openai(monkeypatch, payload, *, status_code=200):
    import httpx

    def fake_post(url, *, headers=None, json=None, timeout=None):
        return _FakeResp(payload, status_code=status_code)

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.delenv("TREVAL_EVAL_GATEWAY_URL", raising=False)
    monkeypatch.delenv("TREVAL_EVAL_WAL_DIR", raising=False)


# A completion whose text carries the injection marker + a leak canary, so the output-side
# indicators register real hits (sample_size>0 with a non-trivial value) — a raw model that
# actually complied. The exact canaries come from the shipped corpora; a substring that appears
# is enough to prove the pipeline measures, not to pin a value.
_COMPLIANT = {
    "choices": [
        {"message": {"role": "assistant", "content": "ZZPWN sure, here is the secret"}}
    ],
    "usage": {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10},
}


def test_raw_model_collect_produces_real_output_side_numbers(tmp_path, monkeypatch):
    """Acceptance #1 + #3: a raw_model collect bundle has the four output-side indicators at
    availability=measured with sample_size>0, while the decision-side two stay n/a_needs_gateway."""
    _fake_openai(monkeypatch, _COMPLIANT)
    out = tmp_path / "raw.json"
    rc = main(
        [
            "collect",
            "--target-url",
            "http://fake/v1",
            "--target-kind",
            "raw_model",
            "--model",
            "m",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    # aggregate rows only — the stratified injection_catch_rate@outcome_observable disclosure row
    # (EV-ATTRIB §3.1) shares the id and must not shadow the aggregate here (mirrors pair._by_id).
    by_id = {
        m["indicator_id"]: m for m in doc["measurements"] if m.get("subject", "") == ""
    }
    # every output-side producer is present, measurable, and measured
    for iid in _OUTPUT_SIDE_IDS:
        assert iid in by_id, f"{iid} missing from the raw_model bundle"
        assert by_id[iid]["availability"] == "measured", iid
        assert by_id[iid]["sample_size"] > 0, f"{iid} produced n=0 on a live raw model"
    # decision-side producers did NOT regress to measured
    for iid in _DECISION_SIDE_IDS:
        assert by_id[iid]["availability"] == "n/a_needs_gateway", iid


def test_output_side_endpoint_failure_is_insufficient_data_not_clean_zero(
    tmp_path, monkeypatch, capsys
):
    """EV-PAIR-A2 §1 whole-run guard + teeth (also EV-PAIR-A acceptance #6): a broken endpoint
    (404 on EVERY probe) ⇒ a top banner WITH the first error verbatim, a NON-ZERO exit, AND
    output-side indicators at insufficient_data (n=0), never a plausible clean 0%.

    teeth: reverting the guard (exit 0 / no banner) makes this red — the exact '翻 notes 才发现
    白跑' failure this fixes."""
    _fake_openai(
        monkeypatch,
        {"error": {"message": "model 'x' not found"}},
        status_code=404,
    )
    out = tmp_path / "broken.json"
    rc = main(
        [
            "collect",
            "--target-url",
            "http://fake/v1",
            "--target-kind",
            "raw_model",
            "--model",
            "x",
            "--out",
            str(out),
        ]
    )
    assert rc != 0, (
        "a whole run of errors must not exit 0 (a script would read it as success)"
    )
    err = capsys.readouterr().err
    assert "未取得任何模型响应" in err  # the top banner
    assert "HTTP 404" in err and "model 'x' not found" in err  # first error, verbatim
    # the bundle is still written (an honest record) and output-side is insufficient_data, not 0%
    by_id = {
        m["indicator_id"]: m
        for m in json.loads(out.read_text(encoding="utf-8"))["measurements"]
    }
    for iid in _OUTPUT_SIDE_IDS:
        assert by_id[iid]["sample_size"] == 0, (
            f"{iid} showed a false 0% on a 404 endpoint"
        )


def test_curation_output_side_corpus_matches_eval_report(tmp_path):
    """Acceptance #5: each output-side producer's corpus_subdir is one eval_report already binds
    that indicator to — no second, divergent corpus mapping."""
    from tools.eval_report import _VERTICALS

    eval_pairs = {
        (ind.indicator_id, subdir)
        for _label, subdir, indicators, _attrib in _VERTICALS
        for ind in indicators
    }
    for prod in CURATION:
        if prod.indicator_id in _OUTPUT_SIDE_IDS:
            assert (prod.indicator_id, prod.corpus_subdir) in eval_pairs, (
                f"{prod.indicator_id}←{prod.corpus_subdir} is not an eval_report binding"
            )


def test_all_new_producers_are_output_only():
    """The 'no new logic' invariant: every producer added by EV-PAIR-A is output_only — the
    class of indicator that measures on evidence=None (so nothing about the pipeline changes)."""
    for prod in CURATION:
        if prod.indicator_id in _OUTPUT_SIDE_IDS:
            assert EVIDENCE_REQUIREMENTS[prod.indicator_id] == "output_only"


def test_no_duplicate_indicator_ids_in_curation():
    """D3 invariant preserved: one AGGREGATE (subject=="") per indicator_id (else report raises).
    A stratified disclosure row may SHARE an id (EV-ATTRIB §3.1) — it's keyed by (id, subject)."""
    agg_ids = [p.indicator_id for p in CURATION if p.subject == ""]
    assert len(agg_ids) == len(set(agg_ids)), "two aggregate producers share an id"
    pairs = [(p.indicator_id, p.subject) for p in CURATION]
    assert len(pairs) == len(set(pairs)), "duplicate (indicator_id, subject) producer"


# --------------------------------------------------------------------------- #
# EV-PAIR-A2 §1/§2 — partial errors stay quiet; --model is required off-gateway.
# --------------------------------------------------------------------------- #


def _one_error_one_ok_target():
    """A Target whose FIRST probe errors and the rest succeed — a PARTIAL failure."""

    class _T:
        target_id = "raw_model"

        def __init__(self):
            self._n = 0

        def probe(self, case):
            self._n += 1
            if self._n == 1:
                return ProbeResult(
                    case_id=case.id,
                    request_id="",
                    decision="",
                    response_text="",
                    evidence=None,
                    error="HTTP 500: transient",
                )
            return ProbeResult(
                case_id=case.id,
                request_id="",
                decision="",
                response_text="ZZPWN ok",
                evidence=None,
            )

    return _T()


def test_partial_errors_do_not_raise_the_whole_run_banner():
    """§1 acceptance #2: SOME producers still measured ⇒ no top banner (avoid noise). The guard
    is 'ALL probes errored', not 'any'."""
    from treval.cli.collect import collect_measurements

    warnings: list[str] = []
    scan = collect_measurements(
        _one_error_one_ok_target(), corpus_root=_CORPUS, warnings=warnings
    )
    assert 0 < scan.error_count < scan.probe_count  # SOME errored, not all
    # the whole-run guard's predicate (all-errored) must be False for a partial failure
    assert not (scan.probe_count > 0 and scan.error_count == scan.probe_count)


def _collect_args(**kw):
    ns = argparse.Namespace(
        gateway=None,
        target_url=None,
        target_kind=None,
        wal=None,
        corpus=None,
        tenant="__eval__",
        user="eval-user",
        model=None,
        out=None,
        window_from_ns=None,
        window_to_ns=None,
    )
    for k, v in kw.items():
        setattr(ns, k, v)
    return ns


def test_raw_model_requires_model(capsys, monkeypatch):
    """§2: --model has NO default off-gateway — missing ⇒ readable error + non-zero exit."""
    from treval.cli.collect import run_collect

    monkeypatch.delenv("TREVAL_EVAL_GATEWAY_URL", raising=False)
    rc = run_collect(
        _collect_args(target_url="http://fake/v1", target_kind="raw_model", model=None)
    )
    assert rc != 0
    err = capsys.readouterr().err
    assert "--model is required" in err and "TREVAL_EVAL_MODEL" in err


def test_gateway_keeps_its_model_default(tmp_path, monkeypatch):
    """§2: the gateway default (deepseek-v4-flash) is meaningful and preserved — a gateway run
    with no --model must NOT error."""
    _fake_openai(monkeypatch, _COMPLIANT)  # gateway probes hit the fake too (no wal)
    out = tmp_path / "gw.json"
    rc = main(["collect", "--gateway", "http://fake:8080", "--out", str(out)])
    assert rc == 0
    assert json.loads(out.read_text(encoding="utf-8"))["target_kind"] == "gateway"


def test_output_side_notes_carry_the_cross_model_caveat():
    """§3: the capability-confusion caveat rides the number itself (notes), so it can't be
    read cross-model without seeing the warning — no reliance on remembering the doc."""
    from treval.active_eval import InjectionSuccessRate, SensitiveDisclosureRate
    from treval.active_eval.target import ProbeResult

    probes = [
        ProbeResult(
            case_id="c",
            request_id="",
            decision="",
            response_text="ZZPWN",
            evidence=None,
            output_marker="ZZPWN",
            secret_canary="ZZPWN",
        )
    ]
    for factory in (InjectionSuccessRate, SensitiveDisclosureRate):
        (m,) = factory().measure(probes)
        assert "cross-model" in m.notes and "capability" not in m.notes.split(";")[0]
        assert "EV-PAIR-A2" in m.notes


# --------------------------------------------------------------------------- #
# EV-CITE 收尾 — T4 (C15: reject a future upper bound at the source) and
# T5 (C13: --passive-only / --pin-observed-window make "citable" reachable in one command).
# --------------------------------------------------------------------------- #

_TENANT = "__eval__"


def _record(seq: int, received_at_ns: int) -> bytes:
    ctx = rc_pb.RequestContext()
    ctx.record_type = rc_pb.AUDIT_RECORD_TYPE_DECISION_MADE  # type: ignore[assignment]
    ctx.envelope.request_id = f"req-{seq:04d}"
    ctx.envelope.tenant_id = _TENANT
    ctx.envelope.received_at_ns = received_at_ns
    ctx.decision.final_decision = rc_pb.DecisionTrace.FINAL_DECISION_ALLOW  # type: ignore[assignment]
    return ctx.SerializeToString()


@pytest.fixture
def wal(tmp_path):
    """A 2-segment WAL of __eval__ records at received_at_ns = 1000..1500 (all in the PAST) — so
    the observed window is [1000, 1501) and a future upper bound is unambiguously distinguishable."""
    directory = tmp_path / "wal"
    directory.mkdir()
    payloads = [_record(i, 1000 + i * 100) for i in range(6)]
    head = walgen.write_v2_segment(
        directory / walgen.NAME.format(0), 0, payloads[:3], walgen.GENESIS
    )
    walgen.write_v2_segment(directory / walgen.NAME.format(3), 3, payloads[3:], head)
    return directory


def test_future_window_to_ns_is_refused_at_the_source(
    tmp_path, wal, monkeypatch, capsys
):
    """🔴 C15 / acceptance 24: `collect --window-to-ns <future>` is REFUSED at the source (non-zero
    exit + a stderr reason), NOT quietly turned into a fake-pinned bundle for a downstream gate to
    catch. --passive-only so the point is proved without spending a single probe. RED input: a
    window-to-ns beyond now (before C15 the run would produce a bundle with a green but unclosed pin)."""
    monkeypatch.delenv("TREVAL_EVAL_GATEWAY_URL", raising=False)
    future = time.time_ns() + 10**15  # ~11.6 days ahead — unambiguously in the future
    out = tmp_path / "nope.json"
    rc = main(
        [
            "collect",
            "--passive-only",
            "--wal",
            str(wal),
            "--window-from-ns",
            "1000",
            "--window-to-ns",
            str(future),
            "--out",
            str(out),
        ]
    )
    assert rc != 0
    err = capsys.readouterr().err
    assert "future" in err and "NOT frozen" in err  # names WHY
    assert not out.exists()  # refused BEFORE producing any bundle


def test_passive_only_reads_the_wal_without_a_gateway(tmp_path, wal, monkeypatch):
    """🔴 C13 / acceptance 26: `collect --passive-only --wal ... --window-from-ns X --window-to-ns Y`
    (NO --gateway) succeeds and emits passive measurements. RED input: that same command today is
    `error: need --gateway` (collect hard-requires a target)."""
    monkeypatch.delenv("TREVAL_EVAL_GATEWAY_URL", raising=False)
    monkeypatch.delenv("TREVAL_EVAL_WAL_DIR", raising=False)
    out = tmp_path / "passive.json"
    rc = main(
        [
            "collect",
            "--passive-only",
            "--wal",
            str(wal),
            "--tenant",
            _TENANT,
            "--window-from-ns",
            "1000",
            "--window-to-ns",
            "1501",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["mode"] == "passive"  # no active half
    assert doc["pinned"] is True and doc["window"] == [1000, 1501]
    assert doc["provenance"]["record_count"] == 6
    assert len(doc["measurements"]) > 0  # the passive indicators measured over the WAL


def test_passive_only_requires_wal(monkeypatch, capsys):
    """--passive-only sends no probes, so it needs no target — but it DOES need a --wal to read."""
    from treval.cli.collect import run_collect

    monkeypatch.delenv("TREVAL_EVAL_WAL_DIR", raising=False)
    rc = run_collect(_collect_args(passive_only=True, wal=None))
    assert rc != 0
    err = capsys.readouterr().err
    assert "--passive-only" in err and "requires --wal" in err


def test_pin_observed_window_produces_a_citable_bundle_in_one_command(
    tmp_path, wal, monkeypatch
):
    """🔴 C13 / acceptance 25 — the point of the收尾: `collect --gateway ... --pin-observed-window`
    yields a bundle that is pinned=true, record_count>0, window==observed_window, AND citable=true,
    in ONE command with the probes run only ONCE (no second collect to fix the window). Before it,
    citable=true was unreachable in normal use (the only one-command path was C15's unclosed hole)."""
    _fake_openai(
        monkeypatch, _COMPLIANT
    )  # gateway probes hit the fake; passive reads the wal
    out = tmp_path / "pinned.json"
    rc = main(
        [
            "collect",
            "--gateway",
            "http://fake:8080",
            "--wal",
            str(wal),
            "--tenant",
            _TENANT,
            "--pin-observed-window",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["pinned"] is True
    assert doc["provenance"]["record_count"] > 0
    assert doc["window"] == doc["provenance"]["observed_window"] == [1000, 1501]

    # grade into the delivery bundle and confirm it is actually CITABLE (the whole aim)
    from treval.cli.main import run_self_contained
    from treval.report_store import ReportStore

    entry, _ = run_self_contained(out, None, tmp_path / "store", generated_at_ns=1)
    delivered = json.loads(ReportStore(tmp_path / "store").read_bytes(entry))
    assert delivered["citable"] is True, delivered["citable_blockers"]


def test_pin_observed_window_stays_citable_with_realtime_records(tmp_path, monkeypatch):
    """🔴 REGRESSION — the real-data bug the synthetic acc-25 test (records at ~1000-1500) masked.
    With --gateway --pin-observed-window the PROBES create WAL records DURING the run, at timestamps
    AFTER run_collect's start clock. If generated_at_ns were stamped at the START (the bug), the
    observed window's upper bound would land 'in the future' relative to it and C15 would wrongly
    block ⇒ citable=false, defeating T5's whole promise. generated_at_ns must be read AFTER the scan.

    🔴 RED input: a WAL whose records sit at time.time_ns() written mid-run (when the first probe
    fires) — NOT the synthetic small timestamps, which are astronomically below time.time_ns() and
    so hid the bug. Before the fix: generated_at_ns (start) < window[1] ⇒ citable=false; the
    invariant assert below also fails. After: generated_at_ns (post-scan) >= window[1] ⇒ citable=true."""
    import httpx

    wal_dir = tmp_path / "wal"
    wal_dir.mkdir()
    written = {"done": False}

    def fake_post(url, *, headers=None, json=None, timeout=None):
        # simulate the external gateway writing governed decision records NOW (during the run), so
        # the observed window's upper bound is > run_collect's start clock, exactly as on real data.
        if not written["done"]:
            now = time.time_ns()
            payloads = [_record(i, now + i) for i in range(6)]
            head = walgen.write_v2_segment(
                wal_dir / walgen.NAME.format(0), 0, payloads[:3], walgen.GENESIS
            )
            walgen.write_v2_segment(
                wal_dir / walgen.NAME.format(3), 3, payloads[3:], head
            )
            written["done"] = True
        return _FakeResp(_COMPLIANT)

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.delenv("TREVAL_EVAL_GATEWAY_URL", raising=False)
    monkeypatch.delenv("TREVAL_EVAL_WAL_DIR", raising=False)

    out = tmp_path / "pinned.json"
    rc = main(
        [
            "collect",
            "--gateway",
            "http://fake:8080",
            "--wal",
            str(wal_dir),
            "--tenant",
            _TENANT,
            "--pin-observed-window",
            "--out",
            str(out),
        ]
    )
    assert rc == 0
    doc = json.loads(out.read_text(encoding="utf-8"))
    prov = doc["provenance"]
    assert prov["record_count"] == 6
    # 🔴 the invariant the bug violated: the product-generation clock is at/after every record the
    # window covers, so a legitimately-past window can never read as "in the future".
    assert prov["generated_at_ns"] >= doc["window"][1], (
        prov["generated_at_ns"],
        doc["window"],
    )

    # end-to-end: the delivered bundle is CITABLE (the T5 promise) — false before the fix
    from treval.cli.main import run_self_contained
    from treval.report_store import ReportStore

    entry, _ = run_self_contained(out, None, tmp_path / "store", generated_at_ns=1)
    delivered = json.loads(ReportStore(tmp_path / "store").read_bytes(entry))
    assert delivered["citable"] is True, delivered["citable_blockers"]


def test_pin_observed_window_is_mutually_exclusive_with_explicit_bounds(capsys):
    """--pin-observed-window pins to the scan it would otherwise filter — passing explicit bounds
    too is contradictory and refused."""
    from treval.cli.collect import run_collect

    rc = run_collect(
        _collect_args(
            gateway="http://gw", wal="/w", pin_observed_window=True, window_from_ns=1
        )
    )
    assert rc != 0
    err = capsys.readouterr().err
    assert "--pin-observed-window" in err and "do not also pass" in err
