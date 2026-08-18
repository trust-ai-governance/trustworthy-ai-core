"""序8 件3 — the response `final_terminal` whitelist + classifier, in a DEPENDENCY-FREE module.

Both the active_eval catch predicates (`treval.active_eval.checks`) AND the passive reliability
indicator (`treval.indicators.terminal_error_ratio`, which the engine-free web app imports) share ONE
source of truth here, without either pulling the other's layer.

🔴 `final_terminal` is a free proto TYPE_STRING; its value DOMAIN is a gateway CONVENTION, NOT a schema
guarantee. So it is read by EXACT membership (never substring — `"BLOCK" in x` also matched
"NOT_BLOCKED"), and an UNREGISTERED value RAISES: register + consciously classify it before reading,
never silently default it into a governance class ("没法判 不许伪装成 判了").
"""

from __future__ import annotations

# Three governance classes:
#   block      — DENIED at the response stage.
#   allow      — ALLOWED (a clean terminal).
#   no_verdict — the request reached NO clean governance terminal: REJECTED (400 protocol/identity) /
#                PENDING (non-terminal) / ERROR (500) / TIMEOUT… / "" (protobuf DEFAULT — a record with
#                NO response observation, e.g. a type-1 record read via `.response`). These must NEVER
#                count as "allowed".
_BLOCK_TERMINALS = frozenset({"BLOCKED"})
_ALLOW_TERMINALS = frozenset({"ALLOWED"})
# CONFIRMED no-verdict — the gateway's declared domain (real WAL so far: only ALLOWED/BLOCKED).
_NO_VERDICT_TERMINALS = frozenset({"REJECTED", "PENDING", "ERROR", ""})
# 🔴 序8 件2 — TIMEOUT/TIMED_OUT/FAIL appear ONLY in our own tests + this whitelist; the real WAL and the
# gateway's DECLARED domain do NOT contain them. Pre-absolving them defeats the gate (an unknown value
# must be VISIBLE, not silently blessed). Keep the HISTORICAL classification (no_verdict / error) so
# terminal_error_ratio's existing tests don't break, but FLAG them UNREGISTERED so the number carries a
# "reconcile with the gateway" note. NOT a raise — a truly-unknown value (e.g. FOO) still raises.
_UNREGISTERED_TERMINALS = frozenset({"TIMEOUT", "TIMED_OUT", "FAIL"})
# the reliability-error subset (ERROR confirmed; the rest are unregistered-but-historically-error)
_ERROR_TERMINALS = frozenset({"ERROR", "TIMEOUT", "TIMED_OUT", "FAIL"})


class UnknownTerminalError(ValueError):
    """序8 件3 — `final_terminal` carried a value outside the registered domain. Its domain is a
    convention, not a schema guarantee, so an unregistered value must be registered (and consciously
    classified) before it is read — never silently defaulted into a governance class."""


def _norm(terminal: object) -> str:
    return str(terminal).strip().upper()


def response_terminal_class(terminal: object) -> str:
    """Classify a response `final_terminal` into 'block' | 'allow' | 'no_verdict' by WHITELIST membership
    (never substring). The UNREGISTERED terminals (序8 件2) classify by HISTORICAL convention (no_verdict)
    — surface them via `is_unregistered_terminal`, don't raise here. 🔴 A truly-unknown value RAISES
    UnknownTerminalError — the gate never rests on the gateway's promise about the string's domain."""
    t = _norm(terminal)
    if t in _BLOCK_TERMINALS:
        return "block"
    if t in _ALLOW_TERMINALS:
        return "allow"
    if t in _NO_VERDICT_TERMINALS or t in _UNREGISTERED_TERMINALS:
        return "no_verdict"
    raise UnknownTerminalError(
        f"final_terminal 出现未登记取值 {terminal!r} —— 该字段是自由字符串，取值域是约定不是 schema "
        "保证；请先与网关侧登记该取值，再决定它属于哪一类。"
    )


def is_unregistered_terminal(terminal: object) -> bool:
    """🔴 序8 件2 — True iff `terminal` is classified by HISTORICAL convention but the gateway's DECLARED
    domain does NOT include it (TIMEOUT/TIMED_OUT/FAIL — seen only in our own tests). The caller must
    surface a reconcile-with-gateway note WITH the number. NOT a raise; a truly-unknown value (FOO)
    returns False here and RAISES in `response_terminal_class`."""
    return _norm(terminal) in _UNREGISTERED_TERMINALS


def is_error_terminal(terminal: object) -> bool:
    """Reliability view of the SAME whitelist: True iff `final_terminal` is an errored/timed-out terminal.
    Membership, never substring; a truly-unknown value RAISES (an unregistered-historical one does not)."""
    response_terminal_class(
        terminal
    )  # validate against the domain (raise on truly-unknown)
    return _norm(terminal) in _ERROR_TERMINALS
