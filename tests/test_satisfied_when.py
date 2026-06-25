"""Tests for the locked `satisfied_when` mini-grammar (EV-6 §4)."""

from __future__ import annotations

import pytest

from treval.models import EvidenceRef, Measurement
from treval.registry import SatisfiedWhenError, compile_satisfied_when


def _m(value=0.0, sample_size=0):
    return Measurement(
        indicator_id="x",
        dimension="robustness",
        value=value,
        unit="ratio",
        sample_size=sample_size,
        evidence_refs=(EvidenceRef(source="t"),),
    )


@pytest.mark.parametrize(
    "expr, measurement, expected",
    [
        ("value >= 0.5", _m(value=0.6), True),
        ("value >= 0.5", _m(value=0.4), False),
        ("value <= 0", _m(value=0.0), True),
        ("value <= 0", _m(value=0.1), False),
        ("value >= 1", _m(value=1.0), True),
        ("sample_size < 10", _m(sample_size=4), True),
        ("sample_size < 10", _m(sample_size=10), False),
        ("sample_size >= 100", _m(sample_size=100), True),
        ("value == -1.5", _m(value=-1.5), True),
        ("value>1", _m(value=2.0), True),  # whitespace optional
    ],
)
def test_grammar_evaluates(expr, measurement, expected):
    assert compile_satisfied_when(expr)(measurement) is expected


@pytest.mark.parametrize(
    "expr",
    [
        "__import__('os')",
        "value; os.system('rm -rf /')",
        "other_field > 1",  # field not whitelisted
        "value > 1 and sample_size > 2",  # compound not supported
        "len(value) > 1",  # function call
        "value >= ",  # missing number
        "value => 1",  # bad operator
        "value != 1",  # operator not in set
        "1 >= value",  # field must be on the left
        "",  # empty
        "value >= 1; value <= 2",
    ],
)
def test_grammar_rejects_non_grammar(expr):
    with pytest.raises(SatisfiedWhenError):
        compile_satisfied_when(expr)


def test_non_string_rejected():
    with pytest.raises(SatisfiedWhenError):
        compile_satisfied_when(None)  # type: ignore[arg-type]
