"""The `satisfied_when` mini-grammar (EV-6) — LOCKED, security-sensitive.

Ratified grammar (implement EXACTLY this, nothing more):

    satisfied_when := <field> <op> <number>
      field  ∈ { "value", "sample_size" }     # a Measurement attribute
      op     ∈ { ">=", ">", "<=", "<", "==" }
      number := optional '-', digits, optional '.' digits

NO eval/exec, no names beyond the two fields, no function calls, no attribute
walking (Charter §4 — never execute arbitrary expressions). Parsing is a strict
regex; evaluation is a fixed operator applied to one whitelisted attribute.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Callable

from treval.models import Measurement

_GRAMMAR = re.compile(r"^(value|sample_size)\s*(>=|<=|==|>|<)\s*(-?\d+(?:\.\d+)?)$")
_OPS: dict[str, Callable[[float, float], bool]] = {
    ">=": operator.ge,
    ">": operator.gt,
    "<=": operator.le,
    "<": operator.lt,
    "==": operator.eq,
}


class SatisfiedWhenError(ValueError):
    """The expression is not a valid `satisfied_when` (rejected, never executed)."""


def compile_satisfied_when(expr: str) -> Callable[[Measurement], bool]:
    """Parse a `satisfied_when` string into a predicate over a Measurement.

    Raises SatisfiedWhenError on anything outside the locked grammar.
    """
    m = _GRAMMAR.match(expr.strip()) if isinstance(expr, str) else None
    if m is None:
        raise SatisfiedWhenError(f"invalid satisfied_when expression: {expr!r}")
    field, op_symbol, number_text = m.group(1), m.group(2), m.group(3)
    number = float(number_text)
    op = _OPS[op_symbol]

    def predicate(measurement: Measurement) -> bool:
        return bool(op(getattr(measurement, field), number))

    return predicate
