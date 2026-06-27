"""Tests for the Indicator SDK: registry + runner (EV-4 §3.2/§3.3)."""

from __future__ import annotations

import pytest

from treval.indicators import IndicatorRegistry, run_indicators
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus, Measurement


class _Dummy:
    """A minimal Indicator: emits one aggregate Measurement counting records."""

    def __init__(self, indicator_id: str, dimension: str):
        self.indicator_id = indicator_id
        self.dimension = dimension

    def measure(self, evidence):
        refs = tuple(ev.ref for ev in evidence)
        return (
            Measurement(
                indicator_id=self.indicator_id,
                dimension=self.dimension,
                value=float(len(refs)),
                unit="count",
                sample_size=len(refs),
                evidence_refs=refs,
            ),
        )


def _evidence(seq: int) -> AuditEvidence:
    return AuditEvidence(
        ref=EvidenceRef(source="wal:test", seq=seq),
        integrity=IntegrityStatus.VERIFIED,
        tenant_id="t",
        received_at_ns=seq,
        record=object(),  # type: ignore[arg-type]  # dummy never reads the record
    )


# --------------------------------------------------------------------------- #
# Registry (acceptance #6)
# --------------------------------------------------------------------------- #


def test_register_get_and_ids():
    reg = IndicatorRegistry()
    a = _Dummy("a", "robustness")
    b = _Dummy("b", "security_alignment")
    reg.register(a)
    reg.register(b)
    assert reg.get("a") is a
    assert reg.ids() == frozenset({"a", "b"})
    assert reg.all() == (a, b)  # registration order


def test_duplicate_register_raises():
    reg = IndicatorRegistry()
    reg.register(_Dummy("a", "robustness"))
    with pytest.raises(ValueError, match="duplicate indicator_id 'a'"):
        reg.register(_Dummy("a", "security_alignment"))


def test_get_unknown_raises_keyerror():
    with pytest.raises(KeyError):
        IndicatorRegistry().get("nope")


def test_by_dimension_filters_in_registration_order():
    reg = IndicatorRegistry()
    a = _Dummy("a", "robustness")
    b = _Dummy("b", "security_alignment")
    c = _Dummy("c", "robustness")
    for ind in (a, b, c):
        reg.register(ind)
    assert reg.by_dimension("robustness") == (a, c)
    assert reg.by_dimension("security_alignment") == (b,)
    assert reg.by_dimension("unknown") == ()


# --------------------------------------------------------------------------- #
# Runner (acceptance #7)
# --------------------------------------------------------------------------- #


def test_runner_materializes_single_pass_iterator():
    a = _Dummy("a", "robustness")
    b = _Dummy("b", "robustness")
    # A generator is exhausted after one pass — if the runner didn't materialize
    # it, the second indicator would see zero records.
    stream = (_evidence(i) for i in range(3))
    out = run_indicators([a, b], stream)
    assert len(out) == 2
    assert out[0].sample_size == 3
    assert out[1].sample_size == 3  # second indicator still saw all 3


def test_runner_flattens_in_order():
    a = _Dummy("a", "robustness")
    b = _Dummy("b", "security_alignment")
    out = run_indicators([a, b], [_evidence(0)])
    assert [m.indicator_id for m in out] == ["a", "b"]


def test_runner_empty_indicators_yields_empty():
    assert run_indicators([], [_evidence(0)]) == ()
