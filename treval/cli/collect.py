"""`collect` — the operator path (EV-8 §3/§6): drive the live gateway through the
curated active corpora and emit a Measurement bundle.

The D3 curation map is the whole point: each bound `indicator_id` is produced from exactly
ONE canonical corpus, so the bundle holds one aggregate per id and the engine's
`DuplicateIndicatorError` net never trips.

Two producer families, distinct `indicator_id`s (no D3 collision):
  - ACTIVE (detection efficacy) — drive the gateway with a corpus, measure over ProbeResults.
  - PASSIVE (EV-5, §6) — read the eval WAL once, measure over its AuditEvidence stream.
    `chain_integrity` / `unclosed_loop_rate` are live-meaningful over the eval WAL NOW (the
    Transparency moat); `duration_p99` / `terminal_error_ratio` reflect the eval probes
    (mechanically valid, not a production SLA). Production-scoped passive reads land later.

Errors aggregate (§5): a producer that fails (gateway down / WAL unreadable / …) records a
warning and the run continues; its indicator is simply absent from the bundle (→ `report`
renders insufficient_data, honest missing data, not a crash).
"""

from __future__ import annotations

import argparse
import secrets
import sys
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from treval.active_eval import (
    CorpusIndicator,
    BenignFlagRate,
    BenignFlagRateHardOnly,
    FalsePositiveRate,
    InjectionCatchRate,
    InjectionCombinedRecall,
    InjectionCatchRateObservable,
    InjectionDeclinedByModelRate,
    InjectionHardBlockedRate,
    InjectionSoftFlagDeclinedRate,
    InjectionSuccessRate,
    SensitiveDisclosureRate,
    SpeechActSeparationRate,
    SystemPromptLeakRate,
    Tier2ShadowRecallLift,
    ToolScopeViolationRate,
    UnsafeOutputPassthroughRate,
    load_corpus,
    run_corpus,
)
from treval.active_eval.canary import (
    CanaryLeakError,
    CanarySet,
    assert_no_canary_plaintext,
)
from treval.active_eval.cases import (
    serialize_benign_case_table,
    serialize_case_contract,
)
from treval.active_eval.corpus import CorpusCase, corpus_fingerprint
from treval.active_eval.indicators import DEFAULT_ARM_PARITY, check_arm_parity
from treval.active_eval.target import ProbeResult
from treval.case_contract import CaseContractError
from treval.cli.bundle import build_bundle
from treval.indicators import (
    BoundaryBreachRate,
    ChainIntegrity,
    DurationP99,
    PiiExposureSurface,
    RedactionHitRatio,
    TerminalErrorRatio,
    UnclosedLoopRate,
)
from treval.models import Measurement
from treval.protocols import Indicator
from treval.provenance import build_provenance, observed_window
from treval.readers import WalEvidenceReader

_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_CORPUS = _ROOT / "corpus"

EXIT_OK = 0
EXIT_IO = 3


class DuplicateProbeError(RuntimeError):
    """F5 (§5) — a case_id was probed more than once in one collection (the case-level dedup broke)."""


def _assert_probed_once(results: tuple[ProbeResult, ...]) -> None:
    """🔴 F5 (§5.2) — the case-level dedup guarantee as a fail-CLOSED assertion (RAISE, never warn):
    each case_id appears in the probe results EXACTLY once. A duplicate means a case was probed twice,
    so its decision- and output-side numbers would read DIFFERENT executions — the exact bug F5 removes.
    Restoring the old directory-level key (a case in two directories) trips this."""
    counts: dict[str, int] = {}
    for pr in results:
        counts[pr.case_id] = counts.get(pr.case_id, 0) + 1
    dups = sorted(cid for cid, n in counts.items() if n > 1)
    if dups:
        raise DuplicateProbeError(
            f"F5: case_id(s) probed more than once in one collection: {dups[:5]} — the case-level "
            "dedup broke (a case's decision- and output-side numbers would read different executions)"
        )


def _apply_declared_subject(prod: Producer, m: Measurement) -> Measurement:
    """🔴 件2 fix — the producer's DECLARED `subject` must REACH the row, and be CHECKED that it did.

    It used to be pure documentation: `Producer.subject` said "MUST match what factory().measure()
    stamps" and NOTHING enforced it, so the `cn` producers declared subject="language:zh" while the
    indicators stamped "". The CN rows came out as AGGREGATE rows — which BIND to rubric objectives.
    Observed live on the first CN baseline: the report graded rob.l2 off 54 diagnostic Chinese cases
    and printed 「能力缺口 · 任何样本量都过不了线」 for a batch declared NOT citable.
    🔴 A declaration nobody enforces is not a declaration.

    FILLS an empty subject only, so an indicator that stamps its own (the outcome_observable
    disclosure row) still wins — the two never fight. Then RAISES if the declared value did not end
    up on the row, so this can never silently regress to documentation again."""
    if prod.subject and not m.subject:
        m = replace(m, subject=prod.subject)
    if prod.subject and m.subject != prod.subject:
        raise ValueError(
            f"producer {prod.indicator_id} declares subject={prod.subject!r} but the measurement "
            f"carries {m.subject!r} — a declared subject that does not reach the row is how a "
            "diagnostic batch silently becomes a graded aggregate"
        )
    return m


def _run_arm_parity() -> str:
    """E3F §4 (F4) — the single arm-parity口径 this run stamped. The curated producers all build via
    the zero-arg factory, so catch and benign both use DEFAULT_ARM_PARITY; check_arm_parity enforces
    that they agree (it RAISES on a mismatch, §4.4-4) so the invariant is asserted, not merely assumed,
    at the one place the value enters the bundle."""
    catch_arm = benign_arm = DEFAULT_ARM_PARITY
    check_arm_parity(catch_arm, benign_arm)
    return catch_arm


@dataclass(frozen=True)
class Producer:
    """One curated active producer: bound id ← indicator over its canonical corpus.

    `subject` is the EV-0 stratification key the producer emits ("" = the aggregate row that binds
    to a rubric objective; non-empty = a disclosure/stratified row that never binds). It MUST match
    what `factory().measure()` stamps — two producers may share an `indicator_id` iff their
    `subject` differs (EV-ATTRIB §3.1: injection_catch_rate has an aggregate row AND an
    outcome_observable row)."""

    indicator_id: str
    factory: type[CorpusIndicator]
    corpus_subdir: str
    subject: str = ""


# The D3 curation map (§3). Each bound indicator_id ← exactly ONE canonical corpus (so the
# bundle holds one aggregate per id — DuplicateIndicatorError never trips). Corpus subdirs are
# copied VERBATIM from eval_report's bindings (one source of truth for corpus↔indicator).
#
# DECISION-side (read the WAL decision record): `measured` only on a gateway; on a raw_model /
# moderation_api they are `n/a_needs_gateway` by construction (EV-FWD) — kept so a gateway run
# still measures them.
# OUTPUT-side (EV-PAIR-A): read response_text / secret_canary / output_marker only, so they are
# `measured` on BOTH gateway AND raw_model — this is what lets `collect --target-kind raw_model`
# produce real numbers (the same corpus↔indicator pairs eval_report already runs). 🔴 NOTE: several
# producers share a corpus (llm01_prompt_injection has six). They are probed ONCE and share that one
# run — see collect_measurements PHASE 1; the old one-run-per-producer model made catch and success
# read DIFFERENT executions of the same corpus. `within_cost_budget` is deliberately NOT here — it needs a budget arg while
# `factory()` is no-arg; it lands with EV-PAIR's factory-form change (EV-PAIR-A §3).
CURATION: tuple[Producer, ...] = (
    # decision-side
    Producer("injection_catch_rate", InjectionCatchRate, "llm01_prompt_injection"),
    # EV-ATTRIB §3.1 — the SAME catch metric re-denominated to the marker-bearing subset, so catch
    # and success read on ONE denominator. Shares the injection_catch_rate id, differentiated by
    # subject="outcome_observable" (a disclosure row — never binds, never trips DuplicateIndicatorError).
    Producer(
        "injection_catch_rate",
        InjectionCatchRateObservable,
        "llm01_prompt_injection",
        subject="outcome_observable",
    ),
    # EV-ATTRIB §1 (+ F1) — the other THREE (decision×output) cells: WHO earned a "0% succeeded"
    # (governance vs the model). needs_decision ⇒ n/a on a bare model; the four cells sum to 1 (§4).
    # 🔴 hard_blocked is the ONLY one that alone backs a governance claim; soft_flag_declined is the
    # ambiguous 'attribution undetermined' cell, disclosed separately, never folded in.
    Producer(
        "injection_hard_blocked_rate",
        InjectionHardBlockedRate,
        "llm01_prompt_injection",
    ),
    Producer(
        "injection_soft_flag_declined_rate",
        InjectionSoftFlagDeclinedRate,
        "llm01_prompt_injection",
    ),
    Producer(
        "injection_declined_by_model_rate",
        InjectionDeclinedByModelRate,
        "llm01_prompt_injection",
    ),
    Producer("tool_scope_violation_rate", ToolScopeViolationRate, "llm06_tool_scope"),
    # GATE-CONSISTENCY 件一 — the FALSE-POSITIVE side of the two-sided detector gate (README: "catch
    # ≥0.80 AND false-positive ≤0.05, Both or neither"). Without these in CURATION, standard collect
    # never produced FPR, so rob.l2 graded RECALL-ONLY — an all-blocking gateway scored full marks
    # (the exact recall-only benchmark the README criticises). Over corpus/llm01_benign; both
    # needs_decision (WAL rule decisions). BenignFlagRate rides alongside as FPR's advisory companion
    # (EV-AE10: a soft flag did not deny the user — NOT gated, but same-frame so a flag-everything
    # rule that scores 0% hard-FPR yet high recall is still loud).
    Producer("false_positive_rate", FalsePositiveRate, "llm01_benign"),
    Producer("benign_flag_rate", BenignFlagRate, "llm01_benign"),
    # E3F "两种读法" — the SAME benign_flag_rate under the hard_only口径, as a DISCLOSURE row (subject),
    # side-by-side with the graded hard_or_flag aggregate in ONE bundle so the口径's effect is visible
    # without a second run. Shares the id, differentiated by subject ⇒ never trips DuplicateIndicatorError.
    Producer(
        "benign_flag_rate",
        BenignFlagRateHardOnly,
        "llm01_benign",
        subject="arm_parity:hard_only",
    ),
    # output-side (measurable on a bare model)
    Producer("injection_success_rate", InjectionSuccessRate, "llm01_prompt_injection"),
    Producer(
        "sensitive_disclosure_rate",
        SensitiveDisclosureRate,
        "llm02_sensitive_disclosure",
    ),
    Producer(
        "unsafe_output_passthrough_rate",
        UnsafeOutputPassthroughRate,
        "llm05_improper_output",
    ),
    Producer(
        "system_prompt_leak_rate", SystemPromptLeakRate, "llm07_system_prompt_leak"
    ),
    # G1 — the async Tier-2 shadow judge's recall lift over Tier-1. Unbound (not in the registry):
    # a DISCLOSURE row, never graded. 🔴 Wired so a Tier-2-on run actually MEASURES the layer it is
    # labelled with: without this producer a run with the judge enabled emits a bundle that says
    # "Tier-2 on" while every number in it is Tier-1-only — the worst of the three options. Reads
    # governance_evidence, which only PHASE 2's drain populates ⇒ no drain ⇒ `no-async`, never 0.
    Producer(
        "tier2_shadow_recall_lift", Tier2ShadowRecallLift, "llm01_prompt_injection"
    ),
    # 🔴 序8 件6 — the SUM of the two halves, published as ONE measurement over ONE denominator, so a
    # reader never has to (and must never) add injection_catch_rate to the lift by hand. It refuses to
    # publish at all if the two denominators ever diverge again.
    Producer(
        "injection_combined_recall", InjectionCombinedRecall, "llm01_prompt_injection"
    ),
    # EV-BENIGN-N173 §2 — use/mention separation. Unbound (not in the registry): a DISCLOSURE row, never
    # graded (无门槛·首测, §2.4). The 24 cases are control_ prefixed ⇒ E3F's generic exclusion keeps them
    # out of every existing denominator + the carrier arms. 🔴 §5: this indicator is canary-independent,
    # so it is NOT in _ATTACK_ARM_INDICATOR_IDS / _BENIGN_ARM_INDICATOR_IDS — adding it would pollute the
    # carrier-rate arms (acceptance §7-14).
    Producer("speech_act_separation_rate", SpeechActSeparationRate, "llm01_speech_act"),
)


# 🔴 EV-CN-BASELINE 件2 — the CN diagnostic batch is a SEPARATE producer set, NEVER folded into
# CURATION. CURATION is全量: adding a CN row would make EVERY run (the English frozen/paired runs
# included) probe the Chinese corpus ⇒ `--language-scope 英文…` becomes a lie and the run gets longer.
# So CN lives in its own tuple, selected by `--corpus-set cn`; the DEFAULT (`en`) leaves CURATION — and
# therefore every existing run — BIT-IDENTICAL. The three CN producers ride the EXISTING ids as
# subject="language:zh" DISCLOSURE rows (§2): a subject-bearing row never binds a rubric objective and
# never trips DuplicateIndicatorError, so the CN numbers can never be graded (a diagnostic batch must
# not). The out-of-repo corpus root is passed at runtime via `--corpus`; this file names no path.
CURATION_CN: tuple[Producer, ...] = (
    Producer(
        "injection_catch_rate",
        InjectionCatchRate,
        "llm01_cn_injection",
        subject="language:zh",
    ),
    Producer(
        "false_positive_rate",
        FalsePositiveRate,
        "llm01_cn_benign",
        subject="language:zh",
    ),
    Producer(
        "benign_flag_rate", BenignFlagRate, "llm01_cn_benign", subject="language:zh"
    ),
)

CORPUS_SETS: tuple[str, ...] = ("en", "cn")
_CURATION_BY_SET: dict[str, tuple[Producer, ...]] = {"en": CURATION, "cn": CURATION_CN}


def curation_for(corpus_set: str) -> tuple[Producer, ...]:
    """The active producer set for a run — `en` ⇒ CURATION (the default, bit-identical to every existing
    run), `cn` ⇒ CURATION_CN (件2). Fail-closed on an unknown set so a typo can never silently fall back
    to the English corpus and mislabel a CN run."""
    try:
        return _CURATION_BY_SET[corpus_set]
    except KeyError:
        raise ValueError(
            f"unknown --corpus-set {corpus_set!r}; expected one of {CORPUS_SETS}"
        ) from None


def _assert_no_id_subdir_collision(producers: tuple[Producer, ...]) -> None:
    """🔴 EV-CN-BASELINE 件1 — a GUARD, not a restructure. `corpus_sha` is keyed by indicator_id alone,
    so two producers sharing an indicator_id but pointing at DIFFERENT corpus_subdirs would silently
    overwrite each other's fingerprint (today safe only by the COINCIDENCE that same-id producers share a
    subdir — nothing enforced it). 件2 makes the collision impossible in practice (CN is its own set, one
    set active per run), so this does NOT change the data structure; it fails CLOSED if the invariant is
    ever violated, rather than shipping a bundle whose corpus_sha lies about which corpus a producer ran.
    Same-id/same-subdir (the aggregate + its disclosure rows) is fine — only a subdir SPLIT raises."""
    by_id: dict[str, str] = {}
    for p in producers:
        prior = by_id.setdefault(p.indicator_id, p.corpus_subdir)
        if prior != p.corpus_subdir:
            raise ValueError(
                f"indicator_id {p.indicator_id!r} bound to two corpus_subdirs "
                f"({prior!r} and {p.corpus_subdir!r}) in one producer set — corpus_sha is keyed by "
                "indicator_id, so this would silently overwrite one fingerprint (EV-CN-BASELINE 件1)"
            )


# §8.5.2 — the §6.2-3 carrier-rate gate's two arms are DERIVED from CURATION, never hand-listed. The
# ATTACK arm is whatever corpus the injection indicators bind to; the BENIGN arm whatever the benign
# indicators bind to. A hand-list is correct only by COINCIDENCE — the day someone binds a benign
# indicator to a new corpus, a hand-list silently fails to widen and nothing reminds them. Deriving it
# means the gate's benign arm expands WITH the binding (构造一致, not coincidentally-consistent). 🔴 The
# indicator SETS here are the definition of each arm; the DIRS come from the bindings, so a known benign
# indicator on a new corpus pulls that corpus into the arm automatically.
_ATTACK_ARM_INDICATOR_IDS = frozenset(
    {"injection_catch_rate", "tier2_shadow_recall_lift"}
)
_BENIGN_ARM_INDICATOR_IDS = frozenset({"false_positive_rate", "benign_flag_rate"})


def carrier_arm_dirs(
    producers: tuple[Producer, ...] | None = None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """(attack_dirs, benign_dirs) for the carrier-rate gate, derived from `producers` so the arms track
    the indicator↔corpus bindings (the single source of truth, §8.5.2). Each sorted + de-duplicated.
    `producers=None` ⇒ the module CURATION global (resolved at CALL time, so a monkeypatch of CURATION is
    honoured) == (("llm01_prompt_injection",), ("llm01_benign",)).

    🔴 EV-CN-BASELINE 件3 — pass the ACTIVE corpus-set's tuple (CURATION_CN) and both arms become the CN
    dirs, so the "carrier-rate gap ≤ 20pp" is measured WITHIN a language, never across one. Fold the CN
    dirs into the English arms and that gap stops being the quantity it claims to be (a judge could then
    separate the arms by language, not by whether the canary is carried)."""
    if producers is None:
        producers = CURATION

    def _dirs(ids: frozenset[str]) -> tuple[str, ...]:
        return tuple(
            sorted({p.corpus_subdir for p in producers if p.indicator_id in ids})
        )

    return _dirs(_ATTACK_ARM_INDICATOR_IDS), _dirs(_BENIGN_ARM_INDICATOR_IDS)


# PASSIVE producers (EV-5, EV-9): measured over the eval WAL's AuditEvidence stream, feeding the
# MaturityReport's dimension grid (NOT the OWASP eval_report). Distinct ids, so they never collide
# with the active ones. `block_rate` is intentionally NOT here — over eval-attack probes it's
# DEGENERATE (~all-block), a misleading value (§6). The EV-9 dimension-attribution indicators ARE
# here: their registry bindings are `sample_size`-gated (a capability claim — "measured on N real
# VERIFIED requests" — not a value-quality claim), and over the eval WAL they produce non-degenerate,
# correctly-attributed values (production-representative only on the production passive path, §6).
PASSIVE: tuple[Indicator, ...] = (
    ChainIntegrity(),
    UnclosedLoopRate(),
    DurationP99(),
    TerminalErrorRatio(),
    BoundaryBreachRate(),  # EV-9 → robustness
    RedactionHitRatio(),  # EV-9 → privacy
    PiiExposureSurface(),  # EV-9 → privacy
)


@dataclass(frozen=True)
class PassiveScan:
    """One passive WAL read: its measurements plus the window it actually covered.

    `observed_window` is the HALF-OPEN `[min, max+1)` of the records read (None when the scan
    was empty) — the interval that re-selects exactly these records. `record_count` is the
    scan's n, so the pin artifact states the sample size the numbers came from."""

    measurements: tuple[Measurement, ...]
    observed_window: tuple[int, int] | None
    record_count: int


def scan_passive(
    wal_dir: str,
    tenant: str,
    *,
    warnings: list[str],
    window_from_ns: int | None = None,
    window_to_ns: int | None = None,
) -> PassiveScan:
    """Read the eval WAL ONCE (optionally windowed) and measure every passive indicator over
    its AuditEvidence stream (EV-5 §6). Best-effort (§5): an unreadable WAL or a failing
    indicator is a warning, not a crash. The stream is materialized once — each indicator
    iterates it, and the observed window is derived from the same materialized scan.

    Passing BOTH bounds is what makes a run reproducible (EV-PIN): the reader's filter is
    half-open `[from, to)`, so the same WAL + the same bounds always yields the same records."""
    try:
        evidence = tuple(
            WalEvidenceReader(wal_dir).read_audit(
                tenant_id=tenant,
                time_from_ns=window_from_ns,
                time_to_ns=window_to_ns,
            )
        )
    except Exception as e:  # unreadable / undecodable WAL — record, keep going
        warnings.append(f"passive WAL read failed: {type(e).__name__}: {e}")
        return PassiveScan((), None, 0)
    if not evidence:
        warnings.append(f"passive WAL had no records for tenant {tenant!r}")
        return PassiveScan((), None, 0)

    measurements: list[Measurement] = []
    for ind in PASSIVE:
        try:
            measurements.extend(ind.measure(evidence))
        except Exception as e:
            warnings.append(
                f"passive {ind.indicator_id} failed: {type(e).__name__}: {e}"
            )
    return PassiveScan(
        measurements=tuple(measurements),
        observed_window=observed_window(evidence),
        record_count=len(evidence),
    )


def _observed_window_unfiltered(wal_dir: str, tenant: str) -> tuple[int, int] | None:
    """The [min, max+1) span of ALL of a tenant's records, IGNORING any window filter (EV-CITE C12).
    Used only when a pinned window caught nothing — to tell the operator where the records really are
    so they can re-pin. Best-effort: an unreadable WAL yields None (the blocker degrades gracefully)."""
    try:
        evidence = tuple(WalEvidenceReader(wal_dir).read_audit(tenant_id=tenant))
    except Exception:
        return None
    return observed_window(evidence)


def collect_passive(
    wal_dir: str, tenant: str, *, warnings: list[str]
) -> tuple[Measurement, ...]:
    """Measurements only — the pre-EV-PIN shape, kept for callers that don't need the
    window. New code should prefer `scan_passive` (it also reports the covered window)."""
    return scan_passive(wal_dir, tenant, warnings=warnings).measurements


@dataclass(frozen=True)
class ActiveScan:
    """The active-collection result: the aggregate measurements PLUS run-level probe stats.

    `probe_count`/`error_count` are the totals across ALL producers' probes; `first_error` is the
    first probe error seen (verbatim). They power the EV-PAIR-A2 whole-run guard: when every probe
    across the whole run errored, `collect` must SHOUT at the top (not bury `N error(s) excluded`
    in each indicator's notes) and exit non-zero — a wasted run is not a success.

    `corpus_sha` maps indicator_id → the fingerprint of the corpus that producer ran (EV-PAIR §2/§3.1),
    so the delivered bundle records WHICH corpus backed each number."""

    measurements: tuple[Measurement, ...]
    probe_count: int
    error_count: int
    first_error: str | None
    corpus_sha: dict[str, str]
    # EV-R2 (--cases-out): the llm01_prompt_injection corpus + its ProbeResults, captured from the
    # FIRST injection producer's run (InjectionCatchRate) so the case contract re-adds to the SAME
    # aggregate this run's bundle reports. Empty when no injection producer ran (e.g. a corpus with
    # no llm01_prompt_injection subdir).
    injection_cases: tuple[CorpusCase, ...] = ()
    injection_results: tuple[ProbeResult, ...] = ()
    # 🔴 EV-CN-BASELINE 件4 — the BENIGN corpus + its ProbeResults, captured from the false_positive_rate
    # producer's run (llm01_benign for `en`, llm01_cn_benign for `cn`), for the benign-side case-level
    # table (--benign-cases-out). Empty when no benign producer ran.
    benign_cases: tuple[CorpusCase, ...] = ()
    benign_results: tuple[ProbeResult, ...] = ()
    # G1 — did PHASE 2 actually drain the async Tier-2 records? False ⇒ the Tier-2 rows are
    # UNMEASURED (n/a), never 0: "the judge scored below τ" and "we never looked" must not
    # collapse into the same number (the fail-open shape this ticket exists to close).
    tier2_drain_executed: bool = False
    # F7 (E3F §7.3-③) — the run's canary-set identity (sha256-of-salt handle, NOT the salt or any
    # canary string). Pins WHICH canary epoch this run used so two runs stay comparable (same
    # corpus_sha, different canaries). Empty when nothing was probed.
    canary_set_id: str = ""
    # 🔴 序8 件3 — the /admin/v1/audit:cursor readings taken BEFORE (pre-flight) and AFTER the Tier-2
    # drain, stored VERBATIM for R5's cross-check (the gateway's SELF-REPORTED guardrail_* counters vs
    # our WAL-MEASURED no_async — a mismatch is itself a finding). None when no admin cursor endpoint /
    # unreachable (a warning records which).
    guardrail_cursor_before: dict[str, Any] | None = None
    guardrail_cursor_after: dict[str, Any] | None = None


def collect_measurements(
    target: object,
    *,
    corpus_root: Path,
    warnings: list[str],
    corpus_set: str = "en",
) -> ActiveScan:
    """Run every curated producer against `target`. A producer exception is caught, noted
    in `warnings`, and skipped (best-effort collection — §5). Pure w.r.t. `target`: pass a
    fake Target in tests to exercise this without a gateway. Also tallies probe-level errors
    across the run for the whole-run guard (EV-PAIR-A2 §1).

    🔴 EV-CN-BASELINE 件2 — `corpus_set` selects the producer set (`en` default ⇒ CURATION, bit-identical
    to every existing run; `cn` ⇒ CURATION_CN). 件1 — the set is guarded for id↔subdir collisions first."""
    producers = curation_for(corpus_set)
    _assert_no_id_subdir_collision(producers)
    measurements: list[Measurement] = []
    probe_count = 0
    error_count = 0
    first_error: str | None = None
    corpus_sha: dict[str, str] = {}
    injection_cases: tuple[CorpusCase, ...] = ()
    injection_results: tuple[ProbeResult, ...] = ()
    benign_cases: tuple[CorpusCase, ...] = ()  # 件4 — the benign case-table source
    benign_results: tuple[ProbeResult, ...] = ()

    # 🔴 PHASE 0 — PRE-FLIGHT the drain path, in SECONDS, before spending hours probing.
    #
    # PHASE 2's drain necessarily runs at the END (its stop condition snapshots the WAL head once and
    # polls past it). So a broken drain used to surface only after the whole run: observed live, the
    # cursor read raised and the run finished 2.3 h later with tier2_drain_executed=False and every
    # Tier-2 row n/a — a wasted night, discovered at the end. Reading the cursor ONCE up front turns
    # that into a 2-second answer. It is a WARNING, not a refusal: a Tier-2-off run does not need the
    # drain, and refusing to start would make an unrelated admin hiccup block the whole collection.
    guardrail_cursor_before: dict[str, Any] | None = None
    guardrail_cursor_after: dict[str, Any] | None = None
    probe = getattr(target, "read_drain_cursor", None) or getattr(
        target, "_read_cursor", None
    )
    if callable(getattr(target, "drain_governance", None)) and callable(probe):
        try:
            cur = probe()
        except Exception as e:  # noqa: BLE001 — any failure is the same signal here
            cur = None
            warnings.append(
                f"pre-flight: drain cursor read raised {type(e).__name__}: {e}"
            )
        # 序8 件3 — store the pre-flight reading VERBATIM (null when unreachable — already warned above).
        guardrail_cursor_before = cur if isinstance(cur, dict) else None
        if not isinstance(cur, dict) or cur.get("wal_head_seq") is None:
            warnings.append(
                "🔴 pre-flight: the Tier-2 drain cursor is NOT readable "
                f"(got {cur!r}) — this run will finish with tier2_drain_executed=false and every "
                "Tier-2 row n/a. Fix the admin endpoint BEFORE spending the run, or accept a "
                "Tier-1-only result."
            )

    # 🔴 PHASE 1 — probe each corpus subdir ONCE, shared by every producer bound to it.
    #
    # It used to be one `run_corpus` PER PRODUCER: llm01_prompt_injection has six producers, so the
    # same 202 cases were probed six times (~1484 probes for ~406 cases, ~3.6× waste, ~139 min).
    # 🔴 But the wasted time was the SMALLER half of the problem: each producer then measured its OWN
    # pass, so `injection_catch_rate` (decision-side, deterministic) and `injection_success_rate`
    # (OUTPUT-side, reads the model's text) were computed over DIFFERENT probe executions of the same
    # corpus. Observed live: one run reported success 0.3333 (n=63) in the bundle and 0.2812 (n=64)
    # in its own case contract — two answers, one run. Probing once makes every producer over a corpus
    # read ONE observation, which is what "catch and success on one denominator" always claimed.
    by_subdir: dict[str, list[Producer]] = {}
    for prod in producers:
        by_subdir.setdefault(prod.corpus_subdir, []).append(prod)

    probed: dict[str, tuple[CorpusCase, ...]] = {}
    runs: dict[str, tuple[ProbeResult, ...]] = {}
    # F7 (E3F §7.3) — ONE run-level salt so every case's canary shares one epoch (one canary_set_id).
    # The salt is SECRET (never stored); only its sha256-derived set_id reaches provenance. corpus_sha is
    # taken from the ORIGINAL corpus (with {{canary}} placeholders) BEFORE injection, so canary rotation
    # never moves it. A no-op on the current literal corpus (inject returns identity) until 3c.
    run_salt = secrets.token_hex(32)
    canary_set_id = ""
    # 🔴 F5 (§5) — dedup at CASE-ID level, not directory level. Load every subdir, then MERGE all cases
    # into one unique-by-case_id set and probe it ONCE; dispatch results back per subdir by case_id. The
    # old per-directory probing relied on the COINCIDENCE that no case_id lives in two directories —
    # nothing guarded it, so a case referenced by two directories would be probed twice and the decision-
    # and output-side indicators would again read DIFFERENT executions (the two-runs bug in a new shape).
    subdir_ids: dict[str, list[str]] = {}
    unique_cases: dict[str, CorpusCase] = {}
    for subdir, prods in by_subdir.items():
        try:
            corpus = tuple(load_corpus(corpus_root / subdir))
        except (
            Exception
        ) as e:  # corpus load failure — record, keep going (this subdir absent)
            for prod in prods:
                warnings.append(
                    f"producer {prod.indicator_id} failed: {type(e).__name__}: {e}"
                )
            continue
        probed[subdir] = corpus
        subdir_ids[subdir] = [c.id for c in corpus]
        sha = corpus_fingerprint(
            corpus
        )  # per-subdir sha over its OWN cases (unchanged)
        for prod in prods:
            corpus_sha[prod.indicator_id] = sha
        for c in corpus:
            unique_cases.setdefault(
                c.id, c
            )  # a case in two subdirs ⇒ ONE probe (dedup)

    if unique_cases:
        cset = CanarySet.generate(unique_cases.values(), salt=run_salt)
        canary_set_id = cset.set_id
        all_results = run_corpus(list(unique_cases.values()), target, canary_set=cset)  # type: ignore[arg-type]
        _assert_probed_once(
            all_results
        )  # 🔴 F5 — a case_id probed >1 ⇒ RAISE, never warn
        by_case = {pr.case_id: pr for pr in all_results}
        for pr in all_results:
            probe_count += 1
            if pr.error is not None:
                error_count += 1
                if first_error is None:
                    first_error = pr.error
        for subdir, ids in subdir_ids.items():
            runs[subdir] = tuple(by_case[cid] for cid in ids if cid in by_case)

    # 🔴 PHASE 2 — drain the ASYNC Tier-2 governance records ONCE, after ALL probing (G1).
    #
    # The Tier-2 shadow judge writes its record ~2s AFTER the probe, so a run that never drains leaves
    # `governance_evidence` None on every result and `caught_by_tier2` returns False for BOTH "the
    # judge scored below τ" and "we never looked" — a check that cannot return True. Draining here (not
    # per corpus) is deliberate: the stop condition snapshots the WAL head ONCE and polls the drain
    # cursor past it, so it must run after the last probe. No admin_url / not a gateway ⇒ skipped, and
    # `tier2_drain_executed=False` travels into provenance so the Tier-2 rows read n/a, never 0.
    drain = getattr(target, "drain_governance", None)
    drained = False
    if callable(drain) and runs:
        order = list(runs)
        flat = [pr for subdir in order for pr in runs[subdir]]
        try:
            # 🔴 Re-split BY POSITION, never by id(): drain_governance rebuilds the attached results
            # with dataclasses.replace, so a drained ProbeResult is a NEW object — an identity map
            # would silently drop exactly the records the drain just found. Order IS preserved.
            back = list(drain(flat))
            if len(back) != len(flat):
                raise ValueError(
                    f"drain returned {len(back)} results for {len(flat)} probes"
                )
            at = 0
            for subdir in order:
                n = len(runs[subdir])
                runs[subdir] = tuple(back[at : at + n])
                at += n
            drained = True
        except Exception as e:  # a drain failure must not void the whole collection
            warnings.append(f"tier-2 drain failed: {type(e).__name__}: {e}")

    # 🔴 序8 件3 — read the cursor ONCE MORE after the drain: the AFTER snapshot of the before/after pair
    # R5 cross-checks (self-reported guardrail_* vs our WAL-measured no_async). Stored verbatim; null +
    # a warning when the endpoint is unreachable (never a silent omission).
    if callable(probe):
        try:
            after = probe()
        except Exception as e:  # noqa: BLE001 — any failure is the same signal
            after = None
            warnings.append(
                f"post-drain: guardrail cursor read raised {type(e).__name__}: {e}"
            )
        guardrail_cursor_after = after if isinstance(after, dict) else None

    # 🔴 PHASE 3 — measure. Every producer over a corpus reads the SAME results tuple.
    # Iterates the ACTIVE producer set (not the by-corpus grouping) so the bundle's measurement ORDER is
    # unchanged by this refactor — fixtures and diffs stay stable, and the one-aggregate-per-bound-id
    # invariant is still read straight off the set (件2: CURATION for `en`, CURATION_CN for `cn`).
    # 🔴 件2 fix — the ATTACK subdir is DERIVED from the active producer set, exactly like `benign_subdir`
    # below. It used to be hardcoded `"llm01_prompt_injection"`, which made the pair ASYMMETRIC: on a `cn`
    # run the benign table wrote and the attack contract silently skipped ("no results to serialize"), so
    # a run could satisfy every other void-condition while its attack rows — the ones the §3.1 recompute
    # guard re-adds — did not exist. Observed live on the first CN baseline run, which the pre-declared
    # conditions therefore VOIDED. Derive it, so a new corpus set can never lose the contract by omission.
    injection_subdir = next(
        (
            p.corpus_subdir
            for p in producers
            if p.indicator_id == "injection_catch_rate"
        ),
        None,
    )
    if injection_subdir is not None and injection_subdir in runs:
        # EV-R2 — the contract is built from the SAME single run the aggregates are measured over
        # (that identity is now structural, not a "capture the first pass" convention).
        injection_cases = probed[injection_subdir]
        injection_results = runs[injection_subdir]
    # 🔴 件4 — capture the BENIGN run (the FPR producer's corpus: llm01_benign for `en`, llm01_cn_benign
    # for `cn`) from the SAME single probe pass, so the benign case table re-reads exactly what FPR did.
    benign_subdir = next(
        (p.corpus_subdir for p in producers if p.indicator_id == "false_positive_rate"),
        None,
    )
    if benign_subdir is not None and benign_subdir in runs:
        benign_cases = probed[benign_subdir]
        benign_results = runs[benign_subdir]
    for prod in producers:
        shared = runs.get(prod.corpus_subdir)
        if shared is None:
            continue  # its corpus failed to load/probe — already warned in PHASE 1
        try:
            (m,) = prod.factory().measure(shared)
            measurements.append(_apply_declared_subject(prod, m))
        except Exception as e:
            warnings.append(
                f"producer {prod.indicator_id} failed: {type(e).__name__}: {e}"
            )
    return ActiveScan(
        tuple(measurements),
        probe_count,
        error_count,
        first_error,
        corpus_sha,
        injection_cases,
        injection_results,
        benign_cases,
        benign_results,
        drained,
        canary_set_id,
        guardrail_cursor_before=guardrail_cursor_before,
        guardrail_cursor_after=guardrail_cursor_after,
    )


def _write_case_contract(
    cases: tuple[CorpusCase, ...],
    results: tuple[ProbeResult, ...],
    tenant_id: str,
    path: str,
    *,
    warnings: list[str],
) -> None:
    """EV-R2 (--cases-out) — serialize + write the LLM01 injection Tier-0 case contract from THIS
    run, mirroring tools.eval_report._write_case_contract. `serialize_case_contract` runs the §3.1
    recompute guard, so a run whose rows can't re-add their own aggregates is reported (never a
    contract that lies). Best-effort (§5): a missing injection run / a fork is a warning, not a
    crashed collection. 🔴 Tier-0: POINTERS only (request_id + evidence_ref), never response
    content — disclosure_class=operator_only."""
    if not results:
        warnings.append(
            "--cases-out: no injection-arm results to serialize (contract skipped)"
        )
        return
    try:
        contract = serialize_case_contract(
            cases,
            results,
            target_kind="gateway",
            tenant_id=tenant_id,
            generated_at_ns=time.time_ns(),
            # E3F §8.2-3 — the run's口径; a hard_only (diagnostic) run refuses to emit a contract.
            arm_parity=_run_arm_parity(),
        )
    except CaseContractError as e:
        warnings.append(f"--cases-out: case contract did not re-add (not written): {e}")
        return
    import json

    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps(contract, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"wrote {dest}: EV-R2 case contract "
        f"(disclosure_class={contract['disclosure_class']}, {len(contract['cases'])} cases "
        "— operator_only, do NOT publish)",
        file=sys.stderr,
    )


def _write_benign_case_table(
    cases: tuple[CorpusCase, ...],
    results: tuple[ProbeResult, ...],
    tenant_id: str,
    path: str,
    *,
    warnings: list[str],
) -> None:
    """🔴 EV-CN-BASELINE 件4 (--benign-cases-out) — serialize + write the Tier-0 benign case-level table
    from THIS run, the mirror of `_write_case_contract`. It carries POINTERS + the decision-stage FPR/flag
    口径 per case (拦截来源 = decision_injection_source), so a blocked benign case is answerable by case_id.
    serialize_benign_case_table refuses to emit if any canary plaintext reached a row (§7.4-5). Best-effort
    (§5): a missing benign run is a warning, not a crashed collection."""
    if not results:
        warnings.append(
            "--benign-cases-out: no benign results to serialize (table skipped)"
        )
        return
    try:
        table = serialize_benign_case_table(
            cases,
            results,
            target_kind="gateway",
            tenant_id=tenant_id,
            generated_at_ns=time.time_ns(),
        )
    except CanaryLeakError as e:
        warnings.append(f"--benign-cases-out: refused (canary plaintext): {e}")
        return
    import json

    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(
        json.dumps(table, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        f"wrote {dest}: 件4 benign case table "
        f"(disclosure_class={table['disclosure_class']}, {len(table['cases'])} cases "
        "— operator_only, do NOT publish)",
        file=sys.stderr,
    )


def _resolve_target(args: argparse.Namespace) -> tuple[str, str] | None:
    """(target_url, target_kind) from the EV-FWD D3 CLI, or None after printing the error.

    `--gateway` is SUGAR for a gateway run (mutually exclusive with the explicit pair);
    `--target-kind` is NEVER inferred from the URL — a bare-model URL must not be silently
    mislabelled as a governed gateway (R1 honesty)."""
    gw = args.gateway
    url = getattr(args, "target_url", None)
    kind = getattr(args, "target_kind", None)
    if gw and (url or kind):
        print(
            "error: --gateway is sugar for a gateway run and is mutually exclusive with "
            "--target-url / --target-kind",
            file=sys.stderr,
        )
        return None
    if gw:
        return gw, "gateway"
    if url:
        if not kind:
            print(
                "error: --target-url requires --target-kind (gateway|raw_model|"
                "moderation_api) — the kind is never inferred from the URL",
                file=sys.stderr,
            )
            return None
        return url, kind
    print(
        "error: need --gateway (or TREVAL_EVAL_GATEWAY_URL), or --target-url + --target-kind",
        file=sys.stderr,
    )
    return None


def run_collect(args: argparse.Namespace) -> int:
    warnings: list[str] = []
    passive_only = getattr(args, "passive_only", False)
    pin_observed = getattr(args, "pin_observed_window", False)
    # E3-n ④ — the tested party's build fingerprint captured before/after a gateway run (None when no
    # --admin-url, or on a passive/raw_model run); citability compares them to verify zero-change.
    build_fp_before: dict | None = None
    build_fp_after: dict | None = None
    build_fp_before_err: str | None = None
    build_fp_after_err: str | None = None
    scan_start_ns: int | None = None
    admin_url_declared = bool(getattr(args, "admin_url", None))
    # C15 (source): the wall clock at INPUT-VALIDATION time — legal here — used ONLY to reject a
    # future --window-to-ns before any probe runs. This is a DIFFERENT moment from generated_at_ns
    # (the product-GENERATION clock, read AFTER the scan below): with --gateway --pin-observed-window
    # the probes CREATE records DURING the run, so the stamp must be taken after them. Two reads is
    # correct, not a smell.
    now_ns = time.time_ns()

    # EV-PIN: a run is PINNED only when the operator supplied BOTH window bounds — that is the
    # reproducibility claim (same WAL + same bounds ⇒ same records ⇒ same n and value). Parsed FIRST
    # so the C15/exclusivity refusals below happen at the SOURCE, before any probe is spent.
    raw_from = getattr(args, "window_from_ns", None)
    raw_to = getattr(args, "window_to_ns", None)
    window_from: int | None = int(raw_from) if raw_from is not None else None
    window_to: int | None = int(raw_to) if raw_to is not None else None

    # 🔴 C15 (source, primary): reject a FUTURE upper bound BEFORE probing. A window whose `to` has
    # not passed is NOT frozen — re-reading the same WAL later returns MORE records, so the pinned
    # number changes; reproducibility is the one thing `pinned` exists to guarantee. The clock is
    # legal HERE (source), so this refuses to even PRODUCE a fake-pinned bundle (not lean on downstream).
    if window_to is not None and window_to > now_ns:
        print(
            f"error: --window-to-ns {window_to} is in the future (now {now_ns}) — a window whose "
            "upper bound has not passed is NOT frozen: re-reading the same WAL later returns MORE "
            "records, so the pinned number changes. Pin with a CLOSED, past upper bound.",
            file=sys.stderr,
        )
        return EXIT_IO

    # C13: --pin-observed-window pins to whatever the passive scan covers, so explicit bounds make no
    # sense alongside it (they would filter the very scan it pins to). Reject the contradictory combo.
    if pin_observed and (window_from is not None or window_to is not None):
        print(
            "error: --pin-observed-window pins to the observed window — do not also pass "
            "--window-from-ns/--window-to-ns (they would filter the scan it pins to)",
            file=sys.stderr,
        )
        return EXIT_IO

    # C13: --passive-only reads the WAL and sends NO probes, so it needs no target — only a --wal to
    # read. The eval WAL is gateway-governed ⇒ its passive numbers are wal_anchored, so this is a
    # gateway-kind bundle with no active half. (It removes "re-pay the whole active side just to
    # change a WAL-read parameter".)
    if passive_only:
        if not args.wal:
            print(
                "error: --passive-only reads the WAL and sends no probes — it requires --wal DIR "
                "(plus --window-from-ns/--window-to-ns or --pin-observed-window to be citable)",
                file=sys.stderr,
            )
            return EXIT_IO
        target_url, target_kind, model = "", "gateway", None
        active = ActiveScan((), 0, 0, None, {})
    else:
        resolved = _resolve_target(args)
        if resolved is None:
            return EXIT_IO
        target_url, target_kind = resolved

        # EV-PAIR-A2 §2: `--model` is REQUIRED for a non-gateway target — `deepseek-v4-flash` is the
        # GATEWAY deployment's model id, no default is correct for an arbitrary endpoint (unset ⇒
        # near-certain 404 + a whole wasted run). Same discipline as D3's "never infer target_kind":
        # what can't be guessed isn't guessed. The gateway keeps its meaningful default.
        model = args.model
        if not model:
            if target_kind == "gateway":
                model = "deepseek-v4-flash"
            else:
                print(
                    f"error: --model is required for --target-kind {target_kind} (no default "
                    "for an arbitrary endpoint); it reads TREVAL_EVAL_MODEL",
                    file=sys.stderr,
                )
                return EXIT_IO

        # 🔴 EV-CN-BASELINE 架构师裁定三-② — a CN run measures ONLY the decision-side arm (catch / FPR /
        # benign_flag); CURATION_CN has NO injection_success_rate producer, so the bundle carries catch
        # WITHOUT success. Declare that scope UP FRONT — a reader who sees catch and no success would else
        # read the absence as "no attack succeeded" (false). Pre-run, never after-the-fact.
        if args.corpus_set == "cn":
            print(
                "🔴 作用域声明（跑前）：本批为中文诊断批，只测决策侧（injection_catch_rate / "
                "false_positive_rate / benign_flag_rate）；【本批不测输出侧成功率】—— 没有 "
                "injection_success_rate，catch 无 success 相伴不等于『没有攻击得逞』。",
                file=sys.stderr,
            )

        # Lazy — the targets pull httpx only when we actually collect.
        from treval.active_eval import GatewayTarget, OpenAITarget

        target: object
        if target_kind == "gateway":
            # E3-n ③ — DERIVE the client timeout from the tested party's DECLARED upstream request-
            # timeout: client = 2× upstream (not a guess). Platform pinned upstream = 60.0s hardcoded
            # (openai_request_timeout_s), so --upstream-timeout-s 60 ⇒ client 120s. Falls back to the
            # opt-in --timeout (EV-Coverage E3), else GatewayTarget's own 30.0 default.
            upstream = getattr(args, "upstream_timeout_s", None)
            timeout = getattr(args, "timeout", None)
            client_timeout = (
                2.0 * upstream
                if upstream is not None
                else (timeout if timeout is not None else 30.0)
            )
            gw = GatewayTarget(
                target_url,
                wal_dir=args.wal,
                tenant_id=args.tenant,
                user_id=args.user,  # MUST be provisioned (else all-unmeasurable)
                model=model,
                temperature=0.0,  # pin for the statistical verticals
                timeout=client_timeout,
                # E3-n ④ — the admin base (GET /admin/v1/buildinfo + the drain cursor).
                admin_url=getattr(args, "admin_url", None),
            )
            # E3-n ④ — snapshot the tested party's build fingerprint BEFORE any probe runs (None when
            # no --admin-url); the AFTER snapshot below must match it bit-for-bit or the run is void.
            build_fp_before, build_fp_before_err = gw.fetch_buildinfo()
            target = gw
        elif target_kind == "raw_model":
            # EV-FWD: a bare OpenAI-compatible model. NO wal_dir / NO tenant — it is not governed;
            # only the output-side indicators measure on it, the rest surface as availability=n/a.
            target = OpenAITarget(target_url, model=model, temperature=0.0)
        else:  # moderation_api
            print(
                "error: --target-kind moderation_api has no runtime in EV-FWD (its vendor-catch "
                "indicator lands with C2); only gateway | raw_model can be driven today",
                file=sys.stderr,
            )
            return EXIT_IO
        corpus_root = Path(args.corpus) if args.corpus else _DEFAULT_CORPUS
        # E3-n ② — bracket the active scan in wall-clock so probe_window (this run's probe span) is
        # distinguishable from observed_window (the whole WAL the passive scan read, incl. history).
        scan_start_ns = time.time_ns()
        active = collect_measurements(
            target,
            corpus_root=corpus_root,
            warnings=warnings,
            corpus_set=args.corpus_set,
        )
        # E3-n ④ — snapshot the build fingerprint AFTER the run (isinstance narrows target →
        # GatewayTarget for mypy). citability blocks the run if before != after (a mid-run change),
        # OR if --admin-url was declared but either snapshot could not be fetched (fail-closed).
        if isinstance(target, GatewayTarget):
            build_fp_after, build_fp_after_err = target.fetch_buildinfo()
        # EV-R2 (--cases-out): write the Tier-0 LLM01 injection case contract from THIS run.
        # Gateway-only — it carries WAL decision pointers a bare model has no record for. The
        # stamped tenant is args.tenant, the SAME value handed to GatewayTarget(tenant_id=...)
        # above (UI-3 §5.2 — one source, not a second drifting env read).
        cases_out = getattr(args, "cases_out", None)
        if cases_out:
            if target_kind != "gateway":
                print(
                    "error: --cases-out needs a gateway run (the contract carries WAL decision "
                    "pointers a bare model has no record for)",
                    file=sys.stderr,
                )
                return EXIT_IO
            _write_case_contract(
                active.injection_cases,
                active.injection_results,
                args.tenant,
                cases_out,
                warnings=warnings,
            )
        # 🔴 件4 (--benign-cases-out): the benign case-level table from THIS run. Gateway-only for the
        # same reason (it reads WAL decision records for the FPR/flag口径). Independent of --cases-out so
        # a benign-only diagnostic run can still emit it.
        benign_cases_out = getattr(args, "benign_cases_out", None)
        if benign_cases_out:
            if target_kind != "gateway":
                print(
                    "error: --benign-cases-out needs a gateway run (the table carries WAL decision "
                    "pointers a bare model has no record for)",
                    file=sys.stderr,
                )
                return EXIT_IO
            _write_benign_case_table(
                active.benign_cases,
                active.benign_results,
                args.tenant,
                benign_cases_out,
                warnings=warnings,
            )
    # EV-PAIR-A2 §1: did the WHOLE run get zero model responses? (every probe errored). Computed
    # here so the guard can shout at the top + exit non-zero, rather than leaving the only clue
    # in each indicator's `N error(s) excluded` notes.
    all_errored = active.probe_count > 0 and active.error_count == active.probe_count

    # The window bounds were parsed + validated (C15 / exclusivity) at the top, before probing.
    pinned = window_from is not None and window_to is not None

    # Passive (EV-5): read the same WAL the probes wrote under. GATEWAY-only — a raw_model /
    # moderation_api run has no governed WAL, so passive indicators do not apply (EV-FWD).
    scan = (
        scan_passive(
            args.wal,
            args.tenant,
            warnings=warnings,
            window_from_ns=window_from,
            window_to_ns=window_to,
        )
        if (args.wal and target_kind == "gateway")
        else PassiveScan((), None, 0)
    )
    passive = scan.measurements
    measurements = active.measurements + passive

    # C13: --pin-observed-window is an EXPLICIT operator declaration ("口径就是这一跑") — pin to the
    # window the passive scan actually covered. It stays an OWNED claim (NOT auto-pin, C12: the
    # operator named the flag). 🔴 C15 cannot wrongly fire because generated_at_ns is stamped AFTER
    # this scan (below), so it is >= every observed record — NOT because "the records already exist":
    # with --gateway the probes CREATE those records DURING the run (after the source-side now_ns).
    # Combinable with --gateway: the probes run ONCE, then the run pins to that observed passive window.
    if pin_observed and scan.observed_window is not None:
        pinned = True
        window_from, window_to = scan.observed_window

    # The window we RECORD: the pinned bounds when given, else the window actually observed
    # (half-open). Never (0,0) — a report that does not state its own window cannot be
    # reproduced, which is the entire defect EV-PIN exists to fix. A run with no passive read
    # (no --wal) has no observed window at all; say so with nulls rather than inventing zeros.
    if window_from is not None and window_to is not None:
        window = (window_from, window_to)
    else:
        window = scan.observed_window or (0, 0)
        if scan.observed_window is None and args.wal:
            warnings.append(
                "no records in the passive scan — window falls back to [0,0]; "
                "this run is NOT citable externally"
            )
    if not pinned:
        warnings.append(
            "unpinned run (no --window-from-ns/--window-to-ns): the window is a moving "
            "snapshot — do NOT cite these numbers in external documents (EV-PIN §1.4)"
        )

    # EV-PAIR §2: host:port only — 🔴 never the full URL (path/query), never the api_key. A
    # passive-only run probed nothing ⇒ no host to record (None).
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    target_url_host = parsed.netloc or target_url or None

    # C13: the run口径 — "passive" when nothing was probed, else the existing active(+passive) split.
    mode = "passive" if passive_only else ("active+passive" if passive else "active")

    # C12: the window the records occupy, for provenance. Normally the scan's own span; but if a
    # PINNED window caught NOTHING, an unfiltered read finds where the records really are — so the
    # citability blocker can hand the operator a window to re-pin (never "compute the ns yourself").
    prov_observed = scan.observed_window
    if pinned and scan.record_count == 0 and args.wal:
        prov_observed = _observed_window_unfiltered(args.wal, args.tenant)

    # 🔴 C15: generated_at_ns is the moment the product is GENERATED — read AFTER the scan, so it is
    # >= every record the window can cover. With --gateway --pin-observed-window the probes CREATE
    # records DURING this run (at times after the source-side now_ns); stamping now_ns instead would
    # make the just-observed window look "in the future" and wrongly block a legitimate citable run.
    generated_at_ns = time.time_ns()

    # E3-n ④ fail-CLOSED — a DECLARED admin endpoint that couldn't be reached is a check that FAILED
    # (not "no claim made"); surface which side + why so it is never silent (citability then blocks).
    if admin_url_declared:
        if build_fp_before_err:
            warnings.append(
                f"build_fingerprint: BEFORE snapshot could not be fetched — {build_fp_before_err}"
            )
        if build_fp_after_err:
            warnings.append(
                f"build_fingerprint: AFTER snapshot could not be fetched — {build_fp_after_err}"
            )
    # E3-n ② — this run's probe span [scan_start, generated_at), half-open; None when nothing was
    # probed. Active rates cite THIS, not observed_window, so a 430-probe number is not read as
    # standing on the whole WAL's (here 16.5h / 7837-record) history.
    probe_window = (
        (scan_start_ns, generated_at_ns)
        if (scan_start_ns is not None and active.probe_count > 0)
        else None
    )

    bundle = build_bundle(
        measurements,
        tenant_id=args.tenant,
        window=window,
        mode=mode,
        target_kind=target_kind,  # EV-FWD/R1: records WHAT was evaluated (drives availability)
        model=model,  # EV-PAIR §2: the config that determined the numbers, recorded WITH them
        temperature=0.0,  # pinned for the statistical verticals — recorded, not assumed
        target_url_host=target_url_host,
        corpus_sha=active.corpus_sha,
        corpus_set=args.corpus_set,  # 前置3 — derives the offline-recomputability tier
        pinned=pinned,
        provenance=build_provenance(
            wal_dir=args.wal,
            window=window if (pinned or scan.observed_window) else None,
            pinned=pinned,
            tenant_id=args.tenant,
            record_count=scan.record_count,
            observed_window=prov_observed,
            generated_at_ns=generated_at_ns,  # C15: stamped AFTER the scan (see above)
            # E3-h/E3-m §3.1/§5: operator-declared freeze-pack config (empty when not passed).
            # language_scope is the #1 scope axis (declared, never inferred). config_source is
            # "declared" — no queryable version/config endpoint exists yet ("queried" is reserved).
            language_scope=getattr(args, "language_scope", None),
            tested_version=getattr(args, "tested_version", None),
            detect_config=getattr(args, "detect_config", None),
            exec_mode=getattr(args, "exec_mode", None),
            # E3-n ③ — the detection-layer status + the tested party's DECLARED upstream timeout,
            # both folded into the missing_run_config citability criterion.
            detection_layer_status=getattr(args, "detection_layer_status", None),
            upstream_timeout_s=getattr(args, "upstream_timeout_s", None),
            # E3-n ② — collect does NOT drain the async Tier-2 layer (Platform froze it OFF), so the
            # freeze pack records whether PHASE 2 actually ran: False ⇒ the Tier-2 indicators read
            # n/a, never 0% ("scored below τ" and "we never looked" must not be the same number).
            tier2_drain_executed=active.tier2_drain_executed,
            # E3-n ④ — the before/after build fingerprints (verbatim evidence in the artifact).
            build_fingerprint_before=build_fp_before,
            build_fingerprint_after=build_fp_after,
            # E3-n ④ — whether --admin-url was DECLARED (the claim). Lets citability fail-close a
            # declared-but-unfetched check: both-None blocks only when the endpoint was actually named.
            admin_url_declared=admin_url_declared,
            # E3-n ② — this run's probe span; active rates cite it, passive/census keep observed_window.
            probe_window=probe_window,
            # E3F §4 (F4) — the arm-parity口径 both arms ran on. The curated producers all construct
            # via the zero-arg factory ⇒ DEFAULT_ARM_PARITY for catch AND benign; check_arm_parity
            # asserts that invariant (refusing a mismatched pair, §4.4-4) before it is stamped.
            arm_parity=_run_arm_parity(),
            # F7 (E3F §7.3-③) — the run's canary epoch (sha256-of-salt handle, no plaintext).
            canary_set_id=active.canary_set_id,
            # 🔴 序8 件3 — the guardrail cursor readings (before/after the drain), stored VERBATIM for
            # R5's self-reported-vs-measured cross-check. null when no admin cursor endpoint.
            guardrail_cursor_before=active.guardrail_cursor_before,
            guardrail_cursor_after=active.guardrail_cursor_after,
        ),
    )
    # F7 (E3F §7.4-5) — the collect bundle is a public artifact (aggregates + provenance, no response
    # content), so it must carry ZERO canary plaintext. Fail CLOSED before writing.
    assert_no_canary_plaintext(bundle, where="collect bundle")
    out = args.out or "bundle.json"
    try:
        import json

        Path(out).write_text(
            json.dumps(bundle, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except OSError as e:
        print(f"error: cannot write bundle {out}: {e}", file=sys.stderr)
        return EXIT_IO

    # EV-PAIR-A2 §1: the whole-run guard — SHOUT before the warnings (top of the output) when the
    # run got no model responses at all, and exit non-zero so a script never reads a wasted run as
    # success. A PARTIAL error stays quiet (each indicator already shows its own `N excluded`).
    if all_errored:
        print(
            "🔴 本次运行未取得任何模型响应 —— 指标不可测，非 0%"
            f"（{active.error_count}/{active.probe_count} 探针全部 error）",
            file=sys.stderr,
        )
        print(f"   首个 error: {active.first_error}", file=sys.stderr)
        print(
            "   排查：检查 --target-url / --model / 端点可达性",
            file=sys.stderr,
        )

    for w in warnings:
        print(f"  ⚠ {w}", file=sys.stderr)
    print(
        f"wrote {out}: {len(active.measurements)}/{len(curation_for(args.corpus_set))} active producer(s) + "
        f"{len(passive)} passive measurement(s)",
        file=sys.stderr,
    )
    return EXIT_IO if all_errored else EXIT_OK
