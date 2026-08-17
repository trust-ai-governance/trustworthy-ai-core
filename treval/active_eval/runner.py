"""run_corpus — drive a corpus through a target (EV-AE0 §3.3).

Deterministic order (corpus order). A probe that raises is recorded as a
ProbeResult with `error` set — never silently dropped (the indicator excludes it
from the denominator and counts it in notes).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from treval.active_eval.canary import CanarySet
from treval.active_eval.corpus import CorpusCase
from treval.active_eval.target import ProbeResult, Target


def run_corpus(
    corpus: Iterable[CorpusCase],
    target: Target,
    *,
    canary_set: CanarySet | None = None,
) -> tuple[ProbeResult, ...]:
    """F7 (E3F §7): each case is passed through `canary_set.inject` FIRST — `{{canary}}` becomes this
    run's value in system_prompt / input / secret_canary, so BOTH the request the target builds and the
    ProbeResult's secret_canary (the leak oracle) carry the SAME real value. `canary_set` defaults to a
    fresh per-call set (a no-op on the literal-canary corpus until 3c swaps in placeholders); collect
    passes ONE run-level set so its `canary_set_id` can be pinned in provenance."""
    corpus = list(corpus)
    if canary_set is None:
        canary_set = CanarySet.generate(corpus)
    results: list[ProbeResult] = []
    for original in corpus:
        case = canary_set.inject(
            original
        )  # F7 — {{canary}} → this run's value (identity if none)
        try:
            # Targets just probe; the runner attaches the case's canaries so the
            # success/leak indicators stay self-contained (BYO targets need not know
            # markers).
            pr = replace(
                target.probe(case),
                output_marker=case.output_marker,
                secret_canary=case.secret_canary,
                attack_class=case.attack_class,
                source=case.source,
                control_for=case.control_for,
            )
            results.append(pr)
        except Exception as e:  # transport/target failure — record, don't drop
            results.append(
                ProbeResult(
                    case_id=case.id,
                    request_id="",
                    decision="",
                    response_text="",
                    evidence=None,
                    error=f"{type(e).__name__}: {e}",
                    output_marker=case.output_marker,
                    secret_canary=case.secret_canary,
                    attack_class=case.attack_class,
                    source=case.source,
                    control_for=case.control_for,
                )
            )
    return tuple(results)
