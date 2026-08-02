"""The `satisfied_when` mini-grammar (EV-6 + EV-CIGATE) — LOCKED, security-sensitive.

Ratified grammar (implement EXACTLY this, nothing more):

    satisfied_when := <field> <op> <number>
      field  ∈ { "value", "sample_size", "ci_low", "ci_high" }   # a Measurement attribute
      op     ∈ { ">=", ">", "<=", "<", "==" }
      number := optional '-', digits, optional '.' digits

EV-CIGATE adds `ci_low` / `ci_high` — the Wilson interval bounds — so an objective can gate on
"statistically sure" (`ci_low >= τ`) rather than a point estimate that crossed the line by luck.
🔴 DIRECTION is EXPLICIT, never inferred: a higher-is-better metric writes `ci_low >= τ`, a
lower-is-better one `ci_high <= τ` (same "never let the machine guess a writable thing" discipline as
target_kind). A `ci_low`/`ci_high` reference where the Measurement has None (a non-rate / census
indicator) RAISES — the engine turns it into a named error, never a silent pass/fail (§7-B).

NO eval/exec, no names beyond the four fields, no function calls, no attribute walking (Charter §4 —
never execute arbitrary expressions). Parsing is a strict regex; evaluation is a fixed operator
applied to one whitelisted attribute.
"""

from __future__ import annotations

import operator
import re
from collections.abc import Callable

from treval.models import Measurement

_GRAMMAR = re.compile(
    r"^(value|sample_size|ci_low|ci_high)\s*(>=|<=|==|>|<)\s*(-?\d+(?:\.\d+)?)$"
)
_OPS: dict[str, Callable[[float, float], bool]] = {
    ">=": operator.ge,
    ">": operator.gt,
    "<=": operator.le,
    "<": operator.lt,
    "==": operator.eq,
}
# The interval fields — a reference to one over a Measurement with None RAISES (EV-CIGATE §7-B).
_INTERVAL_FIELDS = frozenset({"ci_low", "ci_high"})


class SatisfiedWhenError(ValueError):
    """The expression is not a valid `satisfied_when` (rejected, never executed), OR it references an
    interval bound the Measurement does not carry (a non-rate indicator — EV-CIGATE §7-B; never
    silently passed or failed)."""


def compile_satisfied_when(expr: str) -> Callable[[Measurement], bool]:
    """Parse a `satisfied_when` string into a predicate over a Measurement.

    Raises SatisfiedWhenError on anything outside the locked grammar, and — at evaluation time — if
    the expression references `ci_low`/`ci_high` but the Measurement's is None (no interval, §7-B).
    """
    m = _GRAMMAR.match(expr.strip()) if isinstance(expr, str) else None
    if m is None:
        raise SatisfiedWhenError(f"invalid satisfied_when expression: {expr!r}")
    field, op_symbol, number_text = m.group(1), m.group(2), m.group(3)
    number = float(number_text)
    op = _OPS[op_symbol]

    def predicate(measurement: Measurement) -> bool:
        attr = getattr(measurement, field)
        if field in _INTERVAL_FIELDS and attr is None:
            # 🔴 EV-CIGATE §7-B: no interval to compare — a non-rate indicator, or the indicator did
            # not fill it. Never coerce None to 0/1 (that would silently pass a `<=` / fail a `>=`).
            raise SatisfiedWhenError(
                f"satisfied_when references {field!r} but the measurement has no interval "
                "(non-rate/census indicator — it did not fill ci_low/ci_high)"
            )
        return bool(op(attr, number))

    return predicate


def parse_satisfied_when(expr: str) -> tuple[str, str, float]:
    """(field, op_symbol, threshold) for a `satisfied_when` — the same strict grammar. Lets the
    RENDER layer explain a CI-gate `unmet` ("point crossed τ but the 95% CI did not" vs "the value
    itself missed τ", EV-CIGATE §C) without re-implementing the parse. Raises on anything else."""
    m = _GRAMMAR.match(expr.strip()) if isinstance(expr, str) else None
    if m is None:
        raise SatisfiedWhenError(f"invalid satisfied_when expression: {expr!r}")
    return m.group(1), m.group(2), float(m.group(3))


def satisfied_when_field(expr: str) -> str:
    """The Measurement field a `satisfied_when` tests — `"value"` or `"sample_size"`. Same
    strict grammar as `compile_satisfied_when` (raises `SatisfiedWhenError` on anything else).

    Lets the rubric distinguish a failed **`sample_size`** gate (a data-sufficiency check →
    `insufficient_data`, "not enough data yet") from a failed **`value`** gate (a quality
    verdict → `unmet`), so a volume-gated baseline at N<threshold reads honestly rather than
    as an SLO failure."""
    m = _GRAMMAR.match(expr.strip()) if isinstance(expr, str) else None
    if m is None:
        raise SatisfiedWhenError(f"invalid satisfied_when expression: {expr!r}")
    return m.group(1)
