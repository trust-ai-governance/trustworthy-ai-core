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


def test_injection_catch_is_fail_closed_when_the_frozen_wal_lacks_the_record():
    """No record in the frozen segments ⇒ NOT caught. The failure mode this pins is the
    live one: an unprovisioned eval identity yields 400s with no decision record, which
    must read as an honest 0%-with-no-evidence rather than a silent pass."""
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
    assert m.value == 0.0 and m.sample_size == 1


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
