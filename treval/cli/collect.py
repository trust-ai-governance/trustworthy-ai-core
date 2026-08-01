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
import sys
from dataclasses import dataclass
from pathlib import Path

from treval.active_eval import (
    CorpusIndicator,
    InjectionCatchRate,
    InjectionCatchRateObservable,
    InjectionDeclinedByModelRate,
    InjectionHardBlockedRate,
    InjectionSoftFlagDeclinedRate,
    InjectionSuccessRate,
    SensitiveDisclosureRate,
    SystemPromptLeakRate,
    ToolScopeViolationRate,
    UnsafeOutputPassthroughRate,
    load_corpus,
    run_corpus,
)
from treval.active_eval.corpus import corpus_fingerprint
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
# produce real numbers (the same corpus↔indicator pairs eval_report already runs). NOTE: llm01 is
# driven twice (catch + success) — one run per producer is the existing table model (no grouping;
# not new logic). `within_cost_budget` is deliberately NOT here — it needs a budget arg while
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
)

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


def collect_measurements(
    target: object,
    *,
    corpus_root: Path,
    warnings: list[str],
) -> ActiveScan:
    """Run every curated producer against `target`. A producer exception is caught, noted
    in `warnings`, and skipped (best-effort collection — §5). Pure w.r.t. `target`: pass a
    fake Target in tests to exercise this without a gateway. Also tallies probe-level errors
    across the run for the whole-run guard (EV-PAIR-A2 §1)."""
    measurements: list[Measurement] = []
    probe_count = 0
    error_count = 0
    first_error: str | None = None
    corpus_sha: dict[str, str] = {}
    for prod in CURATION:
        try:
            corpus = list(load_corpus(corpus_root / prod.corpus_subdir))
            corpus_sha[prod.indicator_id] = corpus_fingerprint(corpus)
            results = run_corpus(corpus, target)  # type: ignore[arg-type]
            for pr in results:
                probe_count += 1
                if pr.error is not None:
                    error_count += 1
                    if first_error is None:
                        first_error = pr.error
            (m,) = prod.factory().measure(results)
            measurements.append(m)
        except Exception as e:  # env/transport/corpus failure — record, keep going
            warnings.append(
                f"producer {prod.indicator_id} failed: {type(e).__name__}: {e}"
            )
    return ActiveScan(
        tuple(measurements), probe_count, error_count, first_error, corpus_sha
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

    # Lazy — the targets pull httpx only when we actually collect.
    from treval.active_eval import GatewayTarget, OpenAITarget

    target: object
    if target_kind == "gateway":
        target = GatewayTarget(
            target_url,
            wal_dir=args.wal,
            tenant_id=args.tenant,
            user_id=args.user,  # MUST be provisioned (else all-unmeasurable)
            model=model,
            temperature=0.0,  # pin for the statistical verticals
        )
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

    warnings: list[str] = []
    active = collect_measurements(target, corpus_root=corpus_root, warnings=warnings)
    # EV-PAIR-A2 §1: did the WHOLE run get zero model responses? (every probe errored). Computed
    # here so the guard can shout at the top + exit non-zero, rather than leaving the only clue
    # in each indicator's `N error(s) excluded` notes.
    all_errored = active.probe_count > 0 and active.error_count == active.probe_count

    # EV-PIN: a run is PINNED only when the operator supplied BOTH window bounds — that is
    # the reproducibility claim (same WAL + same bounds ⇒ same records ⇒ same n and value).
    raw_from = getattr(args, "window_from_ns", None)
    raw_to = getattr(args, "window_to_ns", None)
    window_from: int | None = int(raw_from) if raw_from is not None else None
    window_to: int | None = int(raw_to) if raw_to is not None else None
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

    # EV-PAIR §2: host:port only — 🔴 never the full URL (path/query), never the api_key.
    from urllib.parse import urlparse

    parsed = urlparse(target_url)
    target_url_host = parsed.netloc or target_url

    bundle = build_bundle(
        measurements,
        tenant_id=args.tenant,
        window=window,
        mode="active+passive" if passive else "active",
        target_kind=target_kind,  # EV-FWD/R1: records WHAT was evaluated (drives availability)
        model=model,  # EV-PAIR §2: the config that determined the numbers, recorded WITH them
        temperature=0.0,  # pinned for the statistical verticals — recorded, not assumed
        target_url_host=target_url_host,
        corpus_sha=active.corpus_sha,
        pinned=pinned,
        provenance=build_provenance(
            wal_dir=args.wal,
            window=window if (pinned or scan.observed_window) else None,
            pinned=pinned,
            tenant_id=args.tenant,
            record_count=scan.record_count,
        ),
    )
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
        f"wrote {out}: {len(active.measurements)}/{len(CURATION)} active producer(s) + "
        f"{len(passive)} passive measurement(s)",
        file=sys.stderr,
    )
    return EXIT_IO if all_errored else EXIT_OK
