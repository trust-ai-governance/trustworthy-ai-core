"""`collect` — the operator path (EV-8 §3/§6): drive the live gateway through the
curated active corpora and emit a Measurement bundle.

The D3 curation map is the whole point: each bound `indicator_id` is produced from exactly
ONE canonical corpus, so the bundle holds one aggregate per id and the engine's
`DuplicateIndicatorError` net never trips. First version is ACTIVE-only (detection efficacy);
passive/production-scope producers are designed (§6) but deferred — never mixed in.

Errors aggregate (§5): a producer that fails (gateway down / not provisioned / timeout)
records a warning and the run continues; its indicator is simply absent from the bundle
(→ `report` renders insufficient_data, honest missing data, not a crash).
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
from treval.models import Measurement

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


# The D3 curation map (§3). ACTIVE-only this version; `block_rate` (passive/production
# scope) is intentionally omitted until the passive path lands (§6) — never co-run.
CURATION: tuple[Producer, ...] = (
    Producer("injection_catch_rate", InjectionCatchRate, "llm01_prompt_injection"),
    Producer("tool_scope_violation_rate", ToolScopeViolationRate, "llm06_tool_scope"),
)


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
    measurements = collect_measurements(
        target, corpus_root=corpus_root, warnings=warnings
    )

    bundle = build_bundle(
        measurements,
        tenant_id=args.tenant,
        window=(0, 0),  # active-eval is not time-windowed; passive path will set this
        mode="active",
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
        f"wrote {out}: {len(measurements)}/{len(CURATION)} producer(s) succeeded",
        file=sys.stderr,
    )
    return EXIT_OK
