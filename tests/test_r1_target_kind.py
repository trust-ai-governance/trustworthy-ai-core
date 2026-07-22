"""R1 — target_kind + derived evidence_basis, the report-contract acceptance (R1 §7).

Scope is R1's schema fields ONLY: `target_kind` (report-level enum, default gateway) and
`evidence_basis` (DERIVED from target_kind, single source of truth). `availability` /
`evidence_requirement` are EV-FWD, not tested here (R1 §1.5-A / §7-7).
"""

from __future__ import annotations

import json

import pytest

from treval.cli.bundle import BundleError, build_bundle, load_bundle
from treval.models import IntegrityStatus, MaturityReport, Measurement
from treval.registry import load_registry
from treval.rubric.serialize import (
    DEFAULT_TARGET_KIND,
    TARGET_KINDS,
    assert_evidence_basis_derived,
    derive_evidence_basis,
    serialize_bundle,
    serialize_self_contained_bundle,
)

# The one ratified mapping (R1 §2 裁定 A). If §5.2 changes it, this table changes with it.
_DERIVATION = {
    "gateway": "wal_anchored",
    "raw_model": "harness_observed",
    "moderation_api": "self_reported",
}

_WORDS = "可验证审计 · WAL 锚定 · 可复算".split()  # the self_reported redline (R1 §7-3)


def _report() -> MaturityReport:
    return MaturityReport(
        tenant_id="t", window=(0, 0), dimensions=(), integrity_summary={}
    )


def _m() -> Measurement:
    return Measurement(
        indicator_id="injection_catch_rate",
        dimension="robustness",
        value=0.9,
        unit="ratio",
        sample_size=10,
        evidence_refs=(),
        integrity=IntegrityStatus.VERIFIED,
    )


# --- §7-1: both bundles carry the two report-level fields; default is gateway ---------- #


def test_serialize_bundle_defaults_gateway_and_carries_both_fields():
    b = serialize_bundle(_report(), [_m()])
    assert b["target_kind"] == DEFAULT_TARGET_KIND == "gateway"
    assert b["evidence_basis"] == "wal_anchored"


def test_self_contained_bundle_carries_both_fields_at_top_level():
    reg = load_registry()
    b = serialize_self_contained_bundle(_report(), [_m()], reg, target_kind="raw_model")
    # top-level envelope, beside schema_version / provenance (R1 §1.5-D)
    assert b["target_kind"] == "raw_model"
    assert b["evidence_basis"] == "harness_observed"


# --- §7-2: the derivation gate — three values map correctly; tampering FAILS ---------- #


@pytest.mark.parametrize("target_kind,expected", sorted(_DERIVATION.items()))
def test_evidence_basis_is_derived_for_each_target_kind(target_kind, expected):
    assert derive_evidence_basis(target_kind) == expected
    b = serialize_bundle(_report(), [_m()], target_kind=target_kind)
    assert b["evidence_basis"] == expected


def test_tampered_evidence_basis_fails_the_gate():
    # Reverting evidence_basis to independent setting (≠ derive(target_kind)) MUST go red.
    with pytest.raises(ValueError, match="derived from target_kind"):
        assert_evidence_basis_derived("moderation_api", "wal_anchored")


def test_unknown_target_kind_fails_closed():
    with pytest.raises(ValueError, match="unknown target_kind"):
        derive_evidence_basis("some_new_thing")


def test_collect_bundle_derivation_gate_rejects_a_hand_tampered_file(tmp_path):
    # A collect bundle whose stored evidence_basis was hand-edited away from derive() is
    # rejected on load (靠门不靠人) — the machine gate, not a convention.
    doc = build_bundle((), tenant_id="t", window=(0, 0), mode="active")
    assert doc["target_kind"] == "gateway" and doc["evidence_basis"] == "wal_anchored"
    doc["evidence_basis"] = (
        "self_reported"  # tamper: claim weakest tier on a gateway run
    )
    p = tmp_path / "b.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(BundleError, match="derived from target_kind"):
        load_bundle(p)


def test_collect_bundle_rejects_unknown_target_kind(tmp_path):
    doc = build_bundle((), tenant_id="t", window=(0, 0), mode="active")
    doc["target_kind"] = "bogus"
    p = tmp_path / "b.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(BundleError, match="target_kind must be one of"):
        load_bundle(p)


# --- §7-3: self_reported never borrows the WAL/verifiable tier ------------------------ #


def test_moderation_api_resolves_to_self_reported_never_a_stronger_tier():
    # R1-scope of the redline: the weakest target NEVER resolves to a reproducible/WAL tier.
    # (The rendered-report "no 可验证审计/WAL wording" guard is the rendering layer, EV-W1/C4;
    # here we lock the field-level derivation that everything downstream reads.)
    b = serialize_self_contained_bundle(
        _report(), [], load_registry(), target_kind="moderation_api"
    )
    assert b["evidence_basis"] == "self_reported"
    assert b["evidence_basis"] not in ("wal_anchored", "harness_observed")


def test_no_stored_evidence_basis_can_upgrade_self_reported_to_wal():
    # There is no code path that lets moderation_api carry wal_anchored — the gate forbids it.
    for word in _WORDS:  # sanity: these are the phrases the tier must never claim
        assert word
    with pytest.raises(ValueError):
        assert_evidence_basis_derived("moderation_api", "wal_anchored")


# --- §7-4: no candidate ⇒ honestly absent, not a fabricated target -------------------- #


def test_moderation_api_with_no_measurements_is_honestly_empty():
    # "无候选走 moderation_api 时报告显 absent，非伪造一个空 target" — zero measurements
    # serialize as an empty array (honest absence), the target_kind is the real declared one,
    # and no placeholder measurement is invented.
    b = serialize_self_contained_bundle(
        _report(), [], load_registry(), target_kind="moderation_api"
    )
    assert b["measurements"] == []
    assert b["target_kind"] == "moderation_api"


# --- §7-1 coverage: the enum tuple is exactly the three ratified values ---------------- #


def test_target_kinds_enum_is_the_three_ratified_values():
    assert set(TARGET_KINDS) == {"raw_model", "gateway", "moderation_api"}
