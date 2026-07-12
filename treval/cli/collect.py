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
    ChainIntegrity,
    DurationP99,
    TerminalErrorRatio,
    UnclosedLoopRate,
)
from treval.models import Measurement
from treval.protocols import Indicator
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

# PASSIVE producers (EV-5): measured over the eval WAL's AuditEvidence stream. Distinct ids,
# so they never collide with the active ones. `block_rate` is intentionally NOT here — it's a
# production-traffic rate that would be meaningless over eval-attack probes (§6).
PASSIVE: tuple[Indicator, ...] = (
    ChainIntegrity(),
    UnclosedLoopRate(),
    DurationP99(),
    TerminalErrorRatio(),
)


def collect_passive(
    wal_dir: str, tenant: str, *, warnings: list[str]
) -> tuple[Measurement, ...]:
    """Read the eval WAL ONCE and measure every passive indicator over its AuditEvidence
    stream (EV-5, §6). Best-effort (§5): an unreadable WAL or a failing indicator is a
    warning, not a crash. The stream is materialized once — each indicator iterates it."""
    try:
        evidence = tuple(WalEvidenceReader(wal_dir).read_audit(tenant_id=tenant))
    except Exception as e:  # unreadable / undecodable WAL — record, keep going
        warnings.append(f"passive WAL read failed: {type(e).__name__}: {e}")
        return ()
    if not evidence:
        warnings.append(f"passive WAL had no records for tenant {tenant!r}")
        return ()
    measurements: list[Measurement] = []
    for ind in PASSIVE:
        try:
            measurements.extend(ind.measure(evidence))
        except Exception as e:
            warnings.append(
                f"passive {ind.indicator_id} failed: {type(e).__name__}: {e}"
            )
    return tuple(measurements)


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
    # Passive (EV-5): read the same WAL the probes wrote under. Needs --wal; skipped otherwise.
    passive = (
        collect_passive(args.wal, args.tenant, warnings=warnings) if args.wal else ()
    )
    measurements = active + passive

    bundle = build_bundle(
        measurements,
        tenant_id=args.tenant,
        window=(
            0,
            0,
        ),  # active-eval is not time-windowed; production passive path will set this
        mode="active+passive" if passive else "active",
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
