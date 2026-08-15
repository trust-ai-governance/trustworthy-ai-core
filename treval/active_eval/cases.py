"""EV-R2 — active-eval CASE-LEVEL result contract (Tier 0 default; Tier 1 opt-in).

The report tells you "injection catch rate 89%"; it can NOT tell you WHICH cases got through.
The per-case data already exists (reporting.format_attribution_report) but is an internal gap
map with no contract and no disclosure discipline. This module gives it a contract + a discipline.

🔴 Two load-bearing rules:

  1. **A per-case result IS a bypass map** (§1). Even zero response content, the pair
     `(attack_technique, verdict != hard_blocked)` says "this technique beats this gateway". So
     the contract carries `disclosure_class` as a MANDATORY, fail-closed field, and Tier 0 (the
     default) ships POINTERS ONLY — request_id + a WAL evidence_ref — never one byte of output.
     Tier 1 (response content) is explicit opt-in and is `internal_handoff`, which the report
     store REFUSES (report_store.write_bundle, §6.1-1).

  2. **The aggregates must recompute from the cases, bit-for-bit** (§3.1 — the hardest acceptance):
     it is what turns "89%" from a number we report into a number anyone can re-add. A single
     `verdict` can NOT do it (§3.2): success needs the marker-subset denominator and catch needs
     the reacted-vs-denied split, both of which one verdict word drops. So each case also carries
     the two predicates verdict loses — `observable_via` (the denominator selector) and
     `governance_reacted` (blocked_or_flagged ≠ denied). `assert_recomputes` re-adds all three
     aggregates from the case rows alone and fails CLOSED if they diverge from the indicators.

No new verdict word is minted here (§3): a second source of truth would eventually disagree with
the rates and nobody would know which to trust. `verdict` is the EV-ATTRIB four cells + errored +
unmeasurable; `observable_via` reuses EV-COVERAGE axis③'s vocabulary.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

# UI-3 §5.1 — the READ half now lives in the pure, stdlib-only treval.case_contract; re-exported
# here so every existing `from treval.active_eval.cases import <name>` path is unchanged (the case
# SERVICE / `cases verify` import the pure module directly and never pull this engine-bound module).
from treval.active_eval.checks import attribution_cell, evaluate, gateway_undecided
from treval.active_eval.corpus import CorpusCase, corpus_fingerprint
from treval.active_eval.indicators import (
    InjectionCatchRate,
    InjectionDeclinedByModelRate,
    InjectionHardBlockedRate,
    InjectionSoftFlagDeclinedRate,
    InjectionSuccessRate,
)
from treval.active_eval.target import ProbeResult
from treval.case_contract import (
    AGGREGATES_INTRODUCED_IN,
    DISCLOSURE_CLASSES,
    OBSERVABLE_VIA,
    SCHEMA_VERSION,
    TENANT_INTRODUCED_IN,
    VERDICTS,
    CaseContractError,
    _fork_message,
    compare_cases_to_aggregates,
    recompute_from_cases,
    validate_case_contract,
)
from treval.models import Measurement
from treval.rubric.serialize import derive_availability

__all__ = [
    # read half — re-exported from treval.case_contract (pure)
    "CaseContractError",
    "SCHEMA_VERSION",
    "AGGREGATES_INTRODUCED_IN",
    "TENANT_INTRODUCED_IN",
    "VERDICTS",
    "DISCLOSURE_CLASSES",
    "OBSERVABLE_VIA",
    "recompute_from_cases",
    "compare_cases_to_aggregates",
    "validate_case_contract",
    # emit half — engine-bound (this module)
    "case_verdict",
    "observable_via",
    "build_cases",
    "aggregates_from_results",
    "assert_recomputes",
    "serialize_case_contract",
]


def case_verdict(pr: ProbeResult) -> str:
    """§3 — one case's verdict, REUSING existing semantics (no new word):

      errored       — pr.error (infra failure); out of EVERY rate denominator;
      unmeasurable  — gateway_undecided (the gateway never judged) — 🔴 NEVER "not caught", that
                      is the fake-0% family; out of the CATCH denominator;
      else          — the EV-ATTRIB four-cell (checks.attribution_cell).

    Priority errored > unmeasurable > cell keeps an undecided probe out of CATCH (see the
    undecided-marker note on recompute_from_cases)."""
    if pr.error is not None:
        return "errored"
    if gateway_undecided(pr):
        return "unmeasurable"
    return attribution_cell(pr)


def observable_via(pr: ProbeResult) -> str | None:
    """§3.2 — the DENOMINATOR SELECTOR for injection_success_rate / the four cells: the KIND of
    outcome signal the case plants (output_marker → success measurable; secret_canary → a leak
    case; None → detection-only, in NO success/attribution denominator). The value set is
    EV-COVERAGE axis③'s, so the case contract and the coverage report agree BY CONSTRUCTION."""
    if pr.output_marker:
        return "output_marker"
    if pr.secret_canary:
        return "secret_canary"
    return None


def _governance_reacted(pr: ProbeResult) -> bool:
    """§3.2 — the per-case blocked_or_flagged predicate: the gateway REACTED (block OR flag). 🔴
    This is the predicate injection_catch_rate COUNTS; it is NOT "the attack was blocked" (a soft
    flag reacts yet lets the request through). The whole round separates 'reacted' from 'denied'
    (the four cells) — this field keeps that separation on the case row."""
    return evaluate("blocked_or_flagged", pr)


def _evidence_ref(pr: ProbeResult) -> dict | None:
    """A POINTER into the WAL (§2), never content: {source, seq} from the decision record's ref.
    None when the probe carried no WAL record (errored / no-evidence target)."""
    ev = pr.evidence
    if ev is None:
        return None
    return {"source": ev.ref.source, "seq": ev.ref.seq}


def _fired_rule_ids(pr: ProbeResult) -> list[str]:
    """E3-n ① — the rule_ids that FIRED (matched) on the decision record this run, as bare FACTS
    (emit-not-interpret: NO categorization into content/injection/observability — the case row states
    WHICH rules matched, the reader/operator attributes). Paired with the decision-stage FPR/flag口径
    (denied_at_decision / flagged_at_decision): when a benign case is flagged, this names the rules that
    fired without the indicator judging them. Empty when no decision record (errored / no-WAL target)."""
    ev = pr.evidence
    if ev is None:
        return []
    return [r.rule_id for r in ev.record.decision.rules_evaluated if r.matched]


def build_cases(
    cases: Iterable[CorpusCase],
    results: Iterable[ProbeResult],
    *,
    target_kind: str,
    include_response_content: bool = False,
) -> list[dict]:
    """One record per probe, joined to its CorpusCase by id (a probe whose case is absent is
    skipped, like reporting.py). Tier 0 carries POINTERS only (request_id + evidence_ref) — 🔴 not
    one byte of response content, and observable_via is the TYPE, never the marker/canary text.
    include_response_content=True adds the Tier-1 content fields (an internal handoff artifact,
    §2.2). `availability` is the EV-FWD axis DERIVED from target_kind (gateway ⇒ measured), one
    source of truth."""
    by_id = {c.id: c for c in cases}
    availability = derive_availability(target_kind, None)
    out: list[dict] = []
    for pr in results:
        case = by_id.get(pr.case_id)
        if case is None:
            continue
        rec: dict = {
            "case_id": case.id,
            "owasp": case.owasp,
            "attack_class": case.attack_class,
            # E3-l (§2.2.3) — the raw signal recompute_from_cases' catch-exclusion needs: for a
            # control_bare_payload case, the partner it controls; empty on every other case. Without it
            # the read-half re-add cannot drop a caught control's partner and would FORK a correct file.
            "control_for": case.control_for,
            "attack_technique": case.attack_technique,
            "verdict": case_verdict(pr),
            "observable_via": observable_via(pr),
            "governance_reacted": _governance_reacted(pr),
            # E3-n ① — the rule_ids that FIRED this run, emitted as bare facts (no categorization),
            # so a flagged benign case can be inspected for WHICH rules matched.
            "fired_rule_ids": _fired_rule_ids(pr),
            "availability": availability,
            "request_id": pr.request_id or None,
            "evidence_ref": _evidence_ref(pr),
        }
        if include_response_content:
            # 🔴 Tier 1 ONLY (internal_handoff): the full output + raw body + planted markers.
            rec["response_text"] = pr.response_text
            rec["raw_response"] = pr.raw_response
        out.append(rec)
    return out


def _cell_count(m: Measurement) -> int:
    """The integer count behind a cell rate — round(value·n) recovers the hits the indicator
    counted (value is exactly hits/n, so the product is the integer for any realistic n)."""
    return round(m.value * m.sample_size)


def aggregates_from_results(results: Iterable[ProbeResult]) -> dict:
    """§9.2 — the aggregate block the case contract embeds: 🔴 the values the INDICATORS produced
    this run (NOT recompute_from_cases' output). The rows must re-add to THIS at write time
    (assert_recomputes proves it against the indicators, §9.5 "它对的是指标，不是自己"), and the
    reader (`cases verify`) re-adds the rows to this stored block."""
    results = list(results)
    (catch,) = InjectionCatchRate().measure(results)
    (succ,) = InjectionSuccessRate().measure(results)
    (hard,) = InjectionHardBlockedRate().measure(results)
    (soft,) = InjectionSoftFlagDeclinedRate().measure(results)
    (declined,) = InjectionDeclinedByModelRate().measure(results)
    return {
        "injection_catch_rate": {"value": catch.value, "n": catch.sample_size},
        "injection_success_rate": {"value": succ.value, "n": succ.sample_size},
        "four_cell": {
            "hard_blocked": _cell_count(hard),
            "soft_flag_declined": _cell_count(soft),
            "succeeded": _cell_count(succ),
            "declined_by_model": _cell_count(declined),
            "n": succ.sample_size,  # the four cells share the marker denominator
        },
    }


def assert_recomputes(cases: Sequence[Mapping], results: Iterable[ProbeResult]) -> None:
    """§3.1 guard — the case rows must re-add the INDICATOR aggregates BIT-FOR-BIT, or the contract
    has forked and is not trustworthy (raise CaseContractError). The runtime form of "加不回来 =
    不可信": a divergence (a tampered row, or an undecided-marker case) fails CLOSED here instead of
    shipping a lying contract. Compares against the indicators (§9.5 — not against itself)."""
    mismatches = compare_cases_to_aggregates(cases, aggregates_from_results(results))
    if mismatches:
        raise CaseContractError(_fork_message(mismatches))


def serialize_case_contract(
    cases: Iterable[CorpusCase],
    results: Iterable[ProbeResult],
    *,
    target_kind: str,
    tenant_id: str,
    generated_at_ns: int,
    include_response_content: bool = False,
) -> dict:
    """The EV-R2 case contract envelope (§2). disclosure_class is set here and is MANDATORY:
    Tier 0 ⇒ 'operator_only'; --include-response-content flips it to 'internal_handoff' (Tier 1,
    which the report store refuses, §2.2). Runs the §3.1 recompute guard BEFORE returning — a
    contract that cannot re-add its own aggregates is never emitted.

    🔴 UI-3 §5.2 (v3): `tenant_id` is MANDATORY and must be the tenant the probes ACTUALLY ran as
    (the caller passes `target.tenant_id`, the same tenant `evidence_ref` points at) — it is the
    key the case service scopes access by, so it must never be a second, drifting env read."""
    cases = list(cases)
    results = list(results)
    built = build_cases(
        cases,
        results,
        target_kind=target_kind,
        include_response_content=include_response_content,
    )
    # §9.2 — embed the INDICATOR aggregates, then prove the rows re-add to them (fail-closed).
    aggregates = aggregates_from_results(results)
    mismatches = compare_cases_to_aggregates(built, aggregates)
    if mismatches:
        raise CaseContractError(_fork_message(mismatches))
    return {
        "schema_version": SCHEMA_VERSION,
        "disclosure_class": "internal_handoff"
        if include_response_content
        else "operator_only",
        "corpus_sha": corpus_fingerprint(cases),
        "target_kind": target_kind,
        "tenant_id": tenant_id,
        "generated_at_ns": generated_at_ns,
        "aggregates": aggregates,
        "cases": built,
    }
