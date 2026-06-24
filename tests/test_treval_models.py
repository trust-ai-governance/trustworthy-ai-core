"""EV-0 acceptance: the contract surface constructs, is frozen, and the three
Protocols accept a dummy implementation (statically and at runtime).
"""

from __future__ import annotations

import dataclasses
from collections.abc import Iterable, Iterator

import pytest

import treval
from treval import (
    AuditEvidence,
    AuditEvidenceReader,
    DimensionReport,
    EvidenceRef,
    Indicator,
    IntegrityStatus,
    MaturityReport,
    Measurement,
    ObjectiveResult,
    PostureEvidence,
    PostureProvider,
)

# treval never decodes a record itself, so the data model is agnostic to the
# concrete proto. A trivial stand-in is enough to exercise construction/read.
_FAKE_RECORD = object()


def _ref() -> EvidenceRef:
    return EvidenceRef(source="wal:/mnt/wal/000.wal", seq=1, request_id="req-1")


def test_public_api_exported() -> None:
    for name in treval.__all__:
        assert hasattr(treval, name), name


def test_integrity_status_value_contract() -> None:
    # These strings are a stable cross-repo contract: they are the
    # integrity_summary keys and the Postgres reader / EV-7 depend on them.
    assert {s.name: s.value for s in IntegrityStatus} == {
        "VERIFIED": "verified",
        "UNVERIFIED": "unverified",
        "BROKEN": "broken",
    }


def test_evidence_ref_defaults() -> None:
    ref = EvidenceRef(source="attest:posture.yaml")
    assert ref.seq is None and ref.request_id is None


def test_construct_and_read_back() -> None:
    ref = _ref()
    audit = AuditEvidence(
        ref=ref,
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="t1",
        received_at_ns=42,
        record=_FAKE_RECORD,  # type: ignore[arg-type]
    )
    assert audit.integrity is IntegrityStatus.VERIFIED
    assert audit.ref.seq == 1

    posture = PostureEvidence(
        ref=EvidenceRef(source="attest:posture.yaml", seq=None, request_id=None),
        tenant_id="t1",
        key="security.sso_mfa_enabled",
        value="true",
        attested_by="ops@example.com",
        attested_at_ns=99,
    )
    assert posture.attested_by == "ops@example.com"

    m = Measurement(
        indicator_id="block_rate",
        dimension="security_alignment",
        value=0.25,
        unit="ratio",
        sample_size=4,
        evidence_refs=(ref,),
    )
    assert m.subject == "" and m.notes == ""  # defaults

    report = MaturityReport(
        tenant_id="t1",
        window=(0, 100),
        dimensions=(
            DimensionReport(
                dimension="security_alignment",
                measured_ceiling="L2",
                attested_ceiling="L3",
                awarded_level="L2",
                objectives=(
                    ObjectiveResult(
                        objective_id="sec.l2.block",
                        kind="measured",
                        status="met",
                        evidence_refs=(ref,),
                    ),
                ),
                gaps=("sec.l3.attested_only",),
            ),
        ),
        integrity_summary={"verified": 4, "unverified": 0, "broken": 0},
    )
    assert report.verification_basis == "wal"  # default
    assert report.dimensions[0].awarded_level == "L2"


@pytest.mark.parametrize(
    ("obj", "field"),
    [
        (EvidenceRef(source="s", seq=None, request_id=None), "source"),
        (Measurement("i", "d", 0.0, "ratio", 0, ()), "value"),
        (ObjectiveResult("o", "measured", "met", ()), "status"),
    ],
)
def test_frozen(obj: object, field: str) -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        setattr(obj, field, "x")


# --- dummy Protocol implementations (structural conformance check) ----------


class _DummyReader:
    def read_audit(
        self,
        *,
        tenant_id: str | None = None,
        time_from_ns: int | None = None,
        time_to_ns: int | None = None,
    ) -> Iterator[AuditEvidence]:
        return iter(())


class _DummyProvider:
    provider_id = "dummy"

    def collect(self, *, tenant_id: str | None = None) -> Iterator[PostureEvidence]:
        return iter(())


class _DummyIndicator:
    indicator_id = "block_rate"
    dimension = "security_alignment"

    def measure(self, evidence: Iterable[AuditEvidence]) -> tuple[Measurement, ...]:
        refs = tuple(e.ref for e in evidence)
        # Empty input -> a single sample_size=0 aggregate, never an empty tuple.
        return (
            Measurement(
                indicator_id=self.indicator_id,
                dimension=self.dimension,
                value=0.0,
                unit="ratio",
                sample_size=len(refs),
                evidence_refs=refs,
            ),
        )


def test_protocols_accept_dummy_impls() -> None:
    reader: AuditEvidenceReader = _DummyReader()
    provider: PostureProvider = _DummyProvider()
    indicator: Indicator = _DummyIndicator()

    assert list(reader.read_audit()) == []
    assert list(provider.collect(tenant_id="t1")) == []

    empty = indicator.measure([])
    assert len(empty) == 1
    assert empty[0].sample_size == 0
    assert empty[0].subject == ""
