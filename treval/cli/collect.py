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
    ToolScopeViolationRate,
    load_corpus,
    run_corpus,
)
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
    """One curated active producer: bound id ← indicator over its canonical corpus."""

    indicator_id: str
    factory: type[CorpusIndicator]
    corpus_subdir: str


# The D3 curation map (§3). ACTIVE producers — one canonical corpus each.
CURATION: tuple[Producer, ...] = (
    Producer("injection_catch_rate", InjectionCatchRate, "llm01_prompt_injection"),
    Producer("tool_scope_violation_rate", ToolScopeViolationRate, "llm06_tool_scope"),
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


def collect_measurements(
    target: object,
    *,
    corpus_root: Path,
    warnings: list[str],
) -> tuple[Measurement, ...]:
    """Run every curated producer against `target`. A producer exception is caught, noted
    in `warnings`, and skipped (best-effort collection — §5). Pure w.r.t. `target`: pass a
    fake Target in tests to exercise this without a gateway."""
    measurements: list[Measurement] = []
    for prod in CURATION:
        try:
            corpus = load_corpus(corpus_root / prod.corpus_subdir)
            results = run_corpus(corpus, target)  # type: ignore[arg-type]
            (m,) = prod.factory().measure(results)
            measurements.append(m)
        except Exception as e:  # env/transport/corpus failure — record, keep going
            warnings.append(
                f"producer {prod.indicator_id} failed: {type(e).__name__}: {e}"
            )
    return tuple(measurements)


def run_collect(args: argparse.Namespace) -> int:
    if not args.gateway:
        print(
            "error: --gateway (or TREVAL_EVAL_GATEWAY_URL) is required for collect",
            file=sys.stderr,
        )
        return EXIT_IO

    # Lazy — GatewayTarget pulls httpx only when we actually collect.
    from treval.active_eval import GatewayTarget

    target = GatewayTarget(
        args.gateway,
        wal_dir=args.wal,
        tenant_id=args.tenant,
        user_id=args.user,  # MUST be provisioned on the target (else all-unmeasurable)
        model=args.model,
        temperature=0.0,  # pin for the statistical verticals
    )
    corpus_root = Path(args.corpus) if args.corpus else _DEFAULT_CORPUS

    warnings: list[str] = []
    active = collect_measurements(target, corpus_root=corpus_root, warnings=warnings)

    # EV-PIN: a run is PINNED only when the operator supplied BOTH window bounds — that is
    # the reproducibility claim (same WAL + same bounds ⇒ same records ⇒ same n and value).
    raw_from = getattr(args, "window_from_ns", None)
    raw_to = getattr(args, "window_to_ns", None)
    window_from: int | None = int(raw_from) if raw_from is not None else None
    window_to: int | None = int(raw_to) if raw_to is not None else None
    pinned = window_from is not None and window_to is not None

    # Passive (EV-5): read the same WAL the probes wrote under. Needs --wal; skipped otherwise.
    scan = (
        scan_passive(
            args.wal,
            args.tenant,
            warnings=warnings,
            window_from_ns=window_from,
            window_to_ns=window_to,
        )
        if args.wal
        else PassiveScan((), None, 0)
    )
    passive = scan.measurements
    measurements = active + passive

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

    bundle = build_bundle(
        measurements,
        tenant_id=args.tenant,
        window=window,
        mode="active+passive" if passive else "active",
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

    for w in warnings:
        print(f"  ⚠ {w}", file=sys.stderr)
    print(
        f"wrote {out}: {len(active)}/{len(CURATION)} active producer(s) + "
        f"{len(passive)} passive measurement(s)",
        file=sys.stderr,
    )
    return EXIT_OK
