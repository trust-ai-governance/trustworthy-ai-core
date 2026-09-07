"""EV-PIN — pinned runs: explicit windows, WAL segment provenance, reproducibility.

The defect this guards against is concrete: a whitepaper cited `chain_integrity 100% n=463`
taken from the live (moving) `__eval__` window; once the WAL tail advanced, 463 could never
be reproduced. These tests assert the properties that make a citation survive that:
same WAL + same bounds ⇒ same n, same value, same segment sha.
"""

from __future__ import annotations

import hashlib

import pytest
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

import walgen
from treval.cli.bundle import build_bundle
from treval.cli.collect import scan_passive
from treval.indicators import ChainIntegrity
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus
from treval.provenance import (
    build_provenance,
    observed_window,
    segment_provenance,
)
from treval.readers import WalEvidenceReader

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
    """A 2-segment WAL whose records sit at received_at_ns = 1000, 1100, … 1500."""
    directory = tmp_path / "wal"
    directory.mkdir()
    payloads = [_record(i, 1000 + i * 100) for i in range(6)]
    head = walgen.write_v2_segment(
        directory / walgen.NAME.format(0), 0, payloads[:3], walgen.GENESIS
    )
    walgen.write_v2_segment(directory / walgen.NAME.format(3), 3, payloads[3:], head)
    return directory


# --------------------------------------------------------------------------- #
# Segment provenance — "you ran THIS batch of WAL"
# --------------------------------------------------------------------------- #


def test_segment_provenance_covers_all_segments(wal):
    prov = segment_provenance(wal)
    assert prov is not None
    assert prov.count == 2
    assert prov.first.endswith(".wal") and prov.last.endswith(".wal")
    assert prov.sha256.startswith("sha256:") and len(prov.sha256) == 7 + 64


def test_segment_provenance_is_deterministic(wal):
    assert segment_provenance(wal) == segment_provenance(wal)


def test_segment_sha_changes_when_wal_bytes_change(wal, tmp_path):
    before = segment_provenance(wal).sha256
    seg = sorted(wal.glob("*.wal"))[0]
    seg.write_bytes(seg.read_bytes() + b"\x00")  # tamper
    assert segment_provenance(wal).sha256 != before


def test_segment_sha_binds_the_segment_NAME_not_just_bytes(wal):
    """A rename must not pass unnoticed — the digest folds in each name."""
    before = segment_provenance(wal).sha256
    seg = sorted(wal.glob("*.wal"))[-1]
    seg.rename(seg.parent / walgen.NAME.format(999))
    assert segment_provenance(wal).sha256 != before


def test_segment_provenance_none_for_empty_dir(tmp_path):
    assert segment_provenance(tmp_path) is None  # no segments ⇒ nothing to claim


# --------------------------------------------------------------------------- #
# The half-open window — the off-by-one that would silently break reproducibility
# --------------------------------------------------------------------------- #


def _ev(ns: int) -> AuditEvidence:
    ctx = rc_pb.RequestContext()
    ctx.envelope.received_at_ns = ns
    return AuditEvidence(
        ref=EvidenceRef(source="wal:x", seq=0, request_id="r"),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id=_TENANT,
        received_at_ns=ns,
        record=ctx,
    )


def test_observed_window_is_half_open():
    # max is 1500 → the window must end at 1501 so re-selecting includes that record.
    assert observed_window([_ev(1000), _ev(1500), _ev(1200)]) == (1000, 1501)


def test_observed_window_none_when_empty():
    assert observed_window([]) is None


def test_observed_window_round_trips_exactly(wal):
    """THE reproducibility property: feed a scan's own observed window back as bounds and
    get the identical record set. With a closed [min,max] window this drops the last
    record — the silent off-by-one this guards."""
    warnings: list[str] = []
    full = scan_passive(str(wal), _TENANT, warnings=warnings)
    assert full.record_count == 6
    lo, hi = full.observed_window

    replay = scan_passive(
        str(wal), _TENANT, warnings=warnings, window_from_ns=lo, window_to_ns=hi
    )
    assert replay.record_count == full.record_count  # 6, not 5

    # the closed-interval mistake would have lost the final record
    truncated = scan_passive(
        str(wal), _TENANT, warnings=warnings, window_from_ns=lo, window_to_ns=hi - 1
    )
    assert truncated.record_count == full.record_count - 1


# --------------------------------------------------------------------------- #
# C12 — a pin over an empty window recovers the REAL window (unfiltered) for the blocker
# --------------------------------------------------------------------------- #


def test_build_provenance_carries_observed_window():
    """C12: build_provenance records the actual observed window; absent ⇒ null (never fabricated)."""
    prov = build_provenance(
        wal_dir="/w",
        window=(1, 2),
        pinned=True,
        tenant_id=_TENANT,
        record_count=0,
        observed_window=(100, 251),
    )
    assert prov["observed_window"] == [100, 251]
    assert (
        build_provenance(
            wal_dir=None, window=None, pinned=False, tenant_id=_TENANT, record_count=5
        )["observed_window"]
        is None
    )


def test_build_provenance_carries_generated_at_ns():
    """🔴 C15: build_provenance stamps the collect-time clock (generated_at_ns) INTO the product, so
    citability can judge a future window from data inside the bundle. Absent ⇒ null (a pre-C15
    bundle has no stamp; the future-upper-bound blocker then skips — never a clock fallback)."""
    stamped = build_provenance(
        wal_dir="/w",
        window=(1, 2),
        pinned=True,
        tenant_id=_TENANT,
        record_count=1,
        generated_at_ns=1786019882041459593,
    )
    assert stamped["generated_at_ns"] == 1786019882041459593
    # RED input: no generated_at_ns kwarg ⇒ null, never invented
    assert (
        build_provenance(
            wal_dir=None, window=None, pinned=False, tenant_id=_TENANT, record_count=0
        )["generated_at_ns"]
        is None
    )


def test_build_provenance_always_emits_the_config_keys_E3h():
    """🔴 E3-h (§3.1): the freeze-pack config keys are ALWAYS present — empty when the operator did
    NOT declare (present-but-empty), populated when they did. This is what lets citability tell a v2
    run that didn't declare (keys present, empty) apart from a pre-E3 bundle (keys absent). config_source
    defaults to 'declared' (no query endpoint exists yet). RED input: build_provenance omitting the keys."""
    undeclared = build_provenance(
        wal_dir=None, window=None, pinned=False, tenant_id=_TENANT, record_count=0
    )
    # E3-m folds language_scope into the SAME always-present set (the #1 axis)
    for k in ("language_scope", "tested_version", "detect_config", "exec_mode"):
        assert k in undeclared and undeclared[k] == ""  # PRESENT but empty, not absent
    assert undeclared["config_source"] == "declared"

    declared = build_provenance(
        wal_dir=None,
        window=None,
        pinned=False,
        tenant_id=_TENANT,
        record_count=0,
        language_scope="英文为主 · 含跨语言手法件 · 中文金融流量未测",
        tested_version="v4@2026-01-30",
        detect_config="encode_decode=off",
        exec_mode="block",
    )
    assert declared["language_scope"] == "英文为主 · 含跨语言手法件 · 中文金融流量未测"
    assert declared["tested_version"] == "v4@2026-01-30"
    assert declared["detect_config"] == "encode_decode=off"
    assert declared["exec_mode"] == "block"


def test_pinned_empty_window_recovers_the_real_window_for_the_blocker(wal):
    """🔴 C12: a PINNED window with no records (record_count==0) — the windowed scan sees nothing,
    but an UNFILTERED read recovers where the records really are ([1000,1501)); that window rides in
    provenance so report_citability blocks AND hands the operator the numbers to re-pin."""
    from treval.cli.collect import _observed_window_unfiltered
    from treval.citability import report_citability

    empty = scan_passive(
        str(wal), _TENANT, warnings=[], window_from_ns=5000, window_to_ns=6000
    )
    assert (
        empty.record_count == 0 and empty.observed_window is None
    )  # the pin caught nothing…
    recovered = _observed_window_unfiltered(
        str(wal), _TENANT
    )  # …but the records are here
    assert recovered == (1000, 1501)

    prov = build_provenance(
        wal_dir=str(wal),
        window=(5000, 6000),
        pinned=True,
        tenant_id=_TENANT,
        record_count=empty.record_count,
        observed_window=recovered,
    )
    citable, blockers = report_citability(
        {
            "evidence_basis": "wal_anchored",
            "provenance": prov,
            "report": {"integrity_summary": {"broken": 0}},
        }
    )
    assert citable is False
    assert any(
        "1000" in b and "1501" in b for b in blockers
    )  # copyable, not "compute it yourself"


# --------------------------------------------------------------------------- #
# Pinned runs — same WAL + same bounds ⇒ same n, same value
# --------------------------------------------------------------------------- #


def test_explicit_window_selects_a_stable_subset(wal):
    warnings: list[str] = []
    scan = scan_passive(
        str(wal), _TENANT, warnings=warnings, window_from_ns=1100, window_to_ns=1400
    )
    assert scan.record_count == 3  # 1100, 1200, 1300 — 1400 excluded (half-open)
    assert scan.observed_window == (1100, 1301)


def test_pinned_run_is_reproducible_across_runs(wal):
    """EV-PIN §3.2 — same WAL + same [A,B] twice ⇒ same n, same value, same segment sha."""
    warnings: list[str] = []
    a = scan_passive(
        str(wal), _TENANT, warnings=warnings, window_from_ns=1000, window_to_ns=1400
    )
    b = scan_passive(
        str(wal), _TENANT, warnings=warnings, window_from_ns=1000, window_to_ns=1400
    )
    assert a.record_count == b.record_count
    assert a.measurements == b.measurements  # frozen dataclasses compare by value
    assert segment_provenance(wal) == segment_provenance(wal)


def test_chain_integrity_n_is_constant_under_a_pinned_window(wal):
    """EV-PIN §3.4 — the number that got burned. Appending to the WAL tail (the thing that
    made n=463 unreproducible) must NOT move n inside a pinned window."""
    ev = tuple(
        WalEvidenceReader(wal).read_audit(
            tenant_id=_TENANT, time_from_ns=1000, time_to_ns=1400
        )
    )
    (before,) = ChainIntegrity().measure(ev)

    # the WAL tail advances (a new later segment lands)
    head = None
    for seg in sorted(wal.glob("*.wal")):
        head = seg
    assert head is not None
    walgen.write_v2_segment(
        wal / walgen.NAME.format(6), 6, [_record(9, 9_000)], walgen.GENESIS
    )

    ev_after = tuple(
        WalEvidenceReader(wal).read_audit(
            tenant_id=_TENANT, time_from_ns=1000, time_to_ns=1400
        )
    )
    (after,) = ChainIntegrity().measure(ev_after)
    assert after.sample_size == before.sample_size  # n did not move
    assert after.value == before.value


# --------------------------------------------------------------------------- #
# The bundle stamp — pinned:true/false is explicit and citable-ness is legible
# --------------------------------------------------------------------------- #


def test_bundle_records_pinned_true_with_provenance(wal):
    prov = build_provenance(
        wal_dir=wal,
        window=(1000, 1400),
        pinned=True,
        tenant_id=_TENANT,
        record_count=4,
    )
    doc = build_bundle(
        (),
        tenant_id=_TENANT,
        window=(1000, 1400),
        mode="active+passive",
        pinned=True,
        provenance=prov,
    )
    assert doc["pinned"] is True
    assert doc["window"] == [1000, 1400]
    assert doc["provenance"]["wal_segments"]["count"] == 2
    assert doc["provenance"]["wal_segments"]["sha256"].startswith("sha256:")
    assert doc["provenance"]["window_semantics"] == "half-open [from_ns, to_ns)"
    assert doc["provenance"]["record_count"] == 4


def test_bundle_defaults_to_unpinned():
    """A bundle built without pin metadata is explicitly NOT citable — never silently
    'maybe pinned'."""
    doc = build_bundle((), tenant_id=_TENANT, window=(0, 0), mode="active")
    assert doc["pinned"] is False
    assert "provenance" not in doc


def test_provenance_of_missing_wal_is_null_not_invented():
    prov = build_provenance(
        wal_dir=None, window=None, pinned=False, tenant_id=_TENANT, record_count=0
    )
    assert prov["pinned"] is False
    assert prov["wal_segments"] is None and prov["window"] is None


def test_segment_sha_matches_an_independent_recomputation(wal):
    """A third party recomputes the digest from the files alone — no treval internals."""
    digest = hashlib.sha256()
    for path in sorted(wal.glob("*.wal"), key=lambda p: p.name):
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    assert segment_provenance(wal).sha256 == "sha256:" + digest.hexdigest()


# --------------------------------------------------------------------------- #
# EV-PIN §3.6 — the pin stamp must survive into the DELIVERY bundle, and the UI
# must be able to tell a citable report from a moving-window snapshot.
# --------------------------------------------------------------------------- #


def _delivery(tmp_path, doc: dict) -> dict:
    """Grade a measurement bundle into the EV-R1 delivery bundle and read it back."""
    import json as _json

    from treval.cli.main import run_self_contained
    from treval.report_store import ReportStore

    mb = tmp_path / "m.json"
    mb.write_text(_json.dumps(doc), encoding="utf-8")
    store = tmp_path / "store"
    entry, _ = run_self_contained(mb, None, store, generated_at_ns=1)
    return _json.loads(ReportStore(store).read_bytes(entry))


def test_provenance_survives_into_the_delivery_bundle(tmp_path, wal):
    """§3.6.1 — the pin stamp reaches the artifact a third party actually receives."""
    prov = build_provenance(
        wal_dir=wal,
        window=(1000, 1400),
        pinned=True,
        tenant_id=_TENANT,
        record_count=4,
    )
    doc = build_bundle(
        (),
        tenant_id=_TENANT,
        window=(1000, 1400),
        mode="active+passive",
        pinned=True,
        provenance=prov,
    )
    delivered = _delivery(tmp_path, doc)
    assert "provenance" in delivered  # top level, per §3.6.1
    assert delivered["provenance"]["pinned"] is True
    assert delivered["provenance"]["wal_segments"]["sha256"].startswith("sha256:")
    assert delivered["report"]["window"] == [1000, 1400]


def test_pre_ev_pin_bundle_delivers_null_provenance_not_a_fake(tmp_path):
    """§3.6.2 — an old bundle has no provenance. Say null; never invent a window or sha."""
    doc = {
        "schema_version": 1,
        "tenant_id": _TENANT,
        "window": [0, 0],
        "mode": "active",
        "measurements": [],
    }
    delivered = _delivery(tmp_path, doc)
    assert delivered["provenance"] is None


def test_ui_distinguishes_pinned_from_unpinned(tmp_path, wal):
    """§3.6.3 — the two states are legibly different, and a null-provenance (pre-EV-PIN)
    report is presented as unpinned rather than silently passing as citable."""
    from treval.web.view import pin_status

    unpinned = pin_status({"provenance": None})
    assert unpinned["pinned"] is False
    assert "不可对外引用" in unpinned["note"]

    pinned = pin_status(
        {
            "provenance": {
                "pinned": True,
                "wal_segments": {
                    "first": "a.wal",
                    "last": "b.wal",
                    "count": 2,
                    "sha256": "sha256:" + "0" * 64,
                },
            }
        }
    )
    assert pinned["pinned"] is True and pinned["label"] != unpinned["label"]


def test_window_label_is_human_readable_not_bare_nanoseconds():
    """§3.6.4 — the regression guard: a label must never be a bare 19-digit ns pair (two
    windows then differ only in the middle digits and no human can tell them apart)."""
    import re

    from treval.web.view import window_label

    label = window_label([1784461551481085225, 1784462268427192905])
    assert not re.fullmatch(r"\d{15,}[–-]\d{15,}", label), label
    assert "UTC" in label and "2026-" in label


# --------------------------------------------------------------------------- #
# PROV §4.1 — a pinned ACTIVE number must stay replayable from the frozen WAL.
# --------------------------------------------------------------------------- #


def _decision_ev(rid: str, *, block: bool) -> AuditEvidence:
    ctx = rc_pb.RequestContext()
    ctx.envelope.request_id = rid
    ctx.decision.final_decision = (  # type: ignore[assignment]
        rc_pb.DecisionTrace.FINAL_DECISION_BLOCK
        if block
        else rc_pb.DecisionTrace.FINAL_DECISION_ALLOW
    )
    # F1 (§1.3): a real injection block fires an injection rule — carry one (matched iff BLOCK, inj-
    # id) so catch is ATTRIBUTABLE; a bare BLOCK with no rule would (correctly) read as unattributable.
    r = ctx.decision.rules_evaluated.add()
    r.rule_id = "inj-1"
    r.matched = block
    return AuditEvidence(
        ref=EvidenceRef(source="wal:frozen", seq=1, request_id=rid),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id=_TENANT,
        received_at_ns=1,
        record=ctx,
    )


def test_injection_catch_is_decided_by_wal_records_not_the_http_response():
    """The published claim (PROV §5.2): a third party can recompute `injection_catch_rate`
    from the FROZEN WAL segments alone, given the run's request_ids.

    That only holds while the catch predicate reads the chain-verifiable records and
    nothing else. Here the HTTP-visible fields say the exact OPPOSITE of the WAL records
    in both directions — if either probe follows the HTTP body, the frozen bytes stop
    being sufficient evidence and the external reproducibility claim silently breaks.
    """
    from treval.active_eval.indicators import InjectionCatchRate
    from treval.active_eval.target import ProbeResult

    # Both probes point the two sources in OPPOSITE directions, and both the same way, so
    # the two implementations cannot agree on the answer: WAL-only ⇒ 1.0, HTTP-body ⇒ 0.0.
    # (A symmetric mix would score 0.5 either way and silently guard nothing.)
    caught_but_http_says_allow = [
        ProbeResult(
            case_id=f"c{i}",
            request_id=f"req-{i}",
            decision="ALLOW",  # HTTP body claims it went through …
            response_text="here you go",
            raw_response='{"decision":"ALLOW"}',
            evidence=_decision_ev(f"req-{i}", block=True),  # … the WAL says BLOCK
        )
        for i in (1, 2)
    ]

    (m,) = InjectionCatchRate().measure(caught_but_http_says_allow)
    assert m.sample_size == 2
    assert m.value == 1.0, "catch must follow the WAL records, not the HTTP response"


def test_injection_catch_without_a_decision_record_is_unmeasurable_not_zero():
    """No decision record ⇒ UNMEASURABLE, not a 0% miss (GATE-LASTMILE P4, corrects the
    earlier reading here). The live failure mode: an unprovisioned eval identity yields 400s
    with no decision record — counting those as "not caught" is exactly the silent false 0%
    that C2-2 hit and that P4 forbids. So the probe is excluded (n=0) and flagged, never a
    plausible-looking 0%."""
    from treval.active_eval.indicators import InjectionCatchRate
    from treval.active_eval.target import ProbeResult

    (m,) = InjectionCatchRate().measure(
        [
            ProbeResult(
                case_id="c1",
                request_id="req-1",
                decision="BLOCK",
                response_text="",
                raw_response='{"decision":"BLOCK"}',
                evidence=None,
                response_evidence=None,
            )
        ]
    )
    assert m.sample_size == 0, (
        "a probe with no decision record must not enter the denominator"
    )
    assert "undecided" in m.notes and "insufficient_data" in m.notes


# --------------------------------------------------------------------------- #
# PROV §5 — a SYNTHETIC report must not be able to pass as a measured one.
# The failure this pins already happened: the demo generator's fabricated
# `chain_integrity n=520` was cited in an external document, because a synthetic
# report rendered exactly like a real one.
# --------------------------------------------------------------------------- #


def test_synthetic_report_is_a_distinct_state_not_merely_unpinned():
    """`synthetic` must outrank the pin question. Treating it as "just another unpinned
    report" understates it: an unpinned report is REAL data that may drift, a synthetic one
    was never measured at all."""
    from treval.web.view import pin_status

    synthetic = pin_status(
        {"provenance": {"data_source": "synthetic_demo", "pinned": False}}
    )
    unpinned = pin_status({"provenance": None})
    measured = pin_status({"provenance": {"data_source": "measured", "pinned": True}})

    assert synthetic["state"] == "synthetic"
    assert unpinned["state"] == "unpinned"
    assert measured["state"] == "pinned"
    # All three must be legibly different — same label ⇒ the badge tells the reader nothing.
    assert len({synthetic["label"], unpinned["label"], measured["label"]}) == 3
    assert "合成" in synthetic["note"] and "合成" not in unpinned["note"]


def test_synthetic_cannot_claim_pinned_even_if_the_bundle_says_so():
    """Fail-safe on the field that matters. A synthetic bundle asserting `pinned: true` —
    hand-edited, or a future generator copying a real provenance block — must still render as
    synthetic and must NOT report itself citable. `pinned` is the field the discipline keys
    on, so it is the one an over-claim would target."""
    from treval.web.view import pin_status

    st = pin_status({"provenance": {"data_source": "synthetic_demo", "pinned": True}})
    assert st["state"] == "synthetic"
    assert st["pinned"] is False, "synthetic data must never present as citable"


def test_demo_report_declares_itself_synthetic_end_to_end(tmp_path):
    """The whole point is the PAGE, not the source file: run the real generator, load what it
    wrote, and assert the delivered bundle carries the synthetic declaration. A guard that only
    checked `tools/make_demo_report.py` would still pass if the flag never reached the store."""
    import json

    from tools.make_demo_report import main
    from treval.web.view import pin_status

    assert main(["--out-dir", str(tmp_path)]) == 0
    (stored,) = (tmp_path / "bundles").glob("*.json")
    bundle = json.loads(stored.read_text(encoding="utf-8"))

    assert bundle["provenance"]["data_source"] == "synthetic_demo"
    assert pin_status(bundle)["state"] == "synthetic"


def test_a_measured_run_declares_itself_measured(wal):
    """The other half of the positive declaration: a real collect run says `measured`, so the
    field's absence means "produced before this existed", not "nobody knows"."""
    from treval.provenance import build_provenance

    prov = build_provenance(
        wal_dir=wal, window=(1, 2), pinned=True, tenant_id="t", record_count=1
    )
    assert prov["data_source"] == "measured"


# --------------------------------------------------------------------------- #
# 🔴 弱门（PM 2026-09-07）—— 判官指纹的声明：让【缺席】从沉默变成一个具名第三态
# --------------------------------------------------------------------------- #


def test_an_empty_imprint_file_is_refused_not_downgraded(tmp_path) -> None:
    """🔴 0 字节的 imprint 一律拒，**不许回落成 not_taken，更不许记成 taken**。

    2026-09-05 的 W6 跑：`judge_imprint_pre_…_1528.json` 是 0 字节，而跑照常继续。
    空文件的 sha256 是一个完全合法的哈希（`e3b0c442…`）—— 照单收下，这道门会对
    **它要拦的那一跑**输出 `taken:e3b0c442`。**一道对着自己要拦的事说"通过"的门，比没有门贵。**

    也不许回落成 `not_taken`：「我以为取到了」与「我明确说没取」是两件事，
    合成一格就把前者洗成了一个像样的声明。

    什么让它红：把空文件判断去掉，或把它 `except → return "not_taken"`。
    """
    import pytest

    from treval.provenance import JudgeImprintError, resolve_judge_imprint

    empty = tmp_path / "judge_imprint_pre.json"
    empty.write_bytes(b"")
    with pytest.raises(JudgeImprintError) as e:
        resolve_judge_imprint(str(empty))
    assert "0 字节" in str(e.value) and "not_taken" in str(e.value), (
        "拒了，但没告诉操作者正确的说法是 --judge-imprint none"
    )

    with pytest.raises(JudgeImprintError):
        resolve_judge_imprint(str(tmp_path / "does-not-exist.json"))


def test_the_three_states_stay_distinguishable(tmp_path) -> None:
    """🔴 未声明 / 明确没取 / 取了 —— 三态不许合并。

    `not_declared` 与 `not_taken` 合并 ⇒ 一次**忘了**和一次**明确的缺席声明**读起来一样，
    而后者是有人做过判断、前者没有。什么让它红：把 `--judge-imprint` 缺省解析成 "not_taken"。
    """
    from treval.citability import judge_imprint_state
    from treval.provenance import resolve_judge_imprint

    assert resolve_judge_imprint(None) is None
    assert resolve_judge_imprint("none") == "not_taken"

    f = tmp_path / "imp.json"
    f.write_text('{"model":"m","quant":"Q8_0"}', encoding="utf-8")
    ref = resolve_judge_imprint(str(f))
    assert isinstance(ref, dict) and ref["bytes"] > 0 and len(ref["sha256"]) == 64

    assert judge_imprint_state({}) == "not_declared"  # 老产物：键根本不在
    assert judge_imprint_state({"judge_imprint": None}) == "not_declared"
    assert judge_imprint_state({"judge_imprint": "not_taken"}) == "not_taken"
    assert judge_imprint_state({"judge_imprint": ref}).startswith("taken:")
    # 声明了但说不出是哪一份 ⇒ 按"没声明"读，不许按"取了"读（宁可欠，不许冒）
    assert judge_imprint_state({"judge_imprint": {"path": "x"}}) == "not_declared"


def test_the_weak_gate_reds_nothing_and_says_what_it_does_not_answer() -> None:
    """🔴 按裁定它**不许**红任何现存可引产物 —— 所以它不进 `_config_keys`，只随数走。

    ⚠️ 而它也**不**回答「这一跑的判官身份立得住吗」：`taken` 只说取到过一份指纹，
    不说它取于本跑窗口之内 —— 09-05 那份取于跑后 15 分钟，一样会是 `taken`。
    同窗门要 imprint 侧先记 `taken_at`（Platform），本轮只治「缺席不留痕」。

    什么让它红：把 `judge_imprint` 加进 `_config_keys`（那会让每一份现存 bundle 立刻不可引）。

    ⚠️ 本条的第一版断言的是 `"judge_imprint" not in _CONFIG_UNDECLARED_FIX` —— 一句**提示文案**。
    它在自己声称能抓的那个变异下**照样通过**（变异由别人的测试抓住）。
    🔴 形状门列表里的第⑤条原样重演：**断言命中的是提示文案，不是被判定的那个东西。**
    现在断言的是【行为】：一份不带这一格的 bundle 必须仍然可引。
    """
    from treval.citability import report_citability, run_config_note

    # 一份今天可引的 bundle —— 它没有 judge_imprint 这一格（所有现存产物都没有）
    _citable = {
        "evidence_basis": "wal_anchored",
        "provenance": {
            "pinned": True,
            "wal_dir": "/wal",
            "generated_at_ns": 10,
            "wal_segments": {"sha256": "sha256:" + "a" * 64},
            "language_scope": "en",
            "tested_version": "v1",
            "detect_config": "c",
            "exec_mode": "block",
            "detection_layer_status": "tier1_only",
            "upstream_timeout_s": 60.0,
            "judge_form": "single",
            "measurement_path": "in_product_gateway",
            "tau_declared": "0.45",
            "tau_source": "shipped",
        },
        "report": {"integrity_summary": {"verified": 5, "unverified": 0, "broken": 0}},
    }
    ok, blockers = report_citability(_citable)
    assert ok and not blockers, f"弱门把一份现存可引产物弄红了 —— 裁定不许：{blockers}"

    prov = {
        "language_scope": "en",
        "tested_version": "v",
        "detect_config": "c",
        "exec_mode": "shadow",
        "judge_form": "single",
        "tau_declared": "0.45",
        "tau_source": "shipped",
    }
    note = run_config_note(prov)
    assert "判官指纹 not_declared" in note, "缺席必须写在数字旁边，不能是沉默"
