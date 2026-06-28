"""run_corpus — drive a corpus through a target (EV-AE0 §3.3).

Deterministic order (corpus order). A probe that raises is recorded as a
ProbeResult with `error` set — never silently dropped (the indicator excludes it
from the denominator and counts it in notes).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from treval.active_eval.corpus import CorpusCase
from treval.active_eval.target import ProbeResult, Target


def run_corpus(corpus: Iterable[CorpusCase], target: Target) -> tuple[ProbeResult, ...]:
    results: list[ProbeResult] = []
    for case in corpus:
        try:
            # Targets just probe; the runner attaches the case's canary so success
            # indicators stay self-contained (and BYO targets need not know markers).
            pr = replace(target.probe(case), output_marker=case.output_marker)
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
                )
            )
    return tuple(results)
