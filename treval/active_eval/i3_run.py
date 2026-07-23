"""P3C-harness I3 joint-run CLI — run the score-driven metrics against a real judge
`verdicts.jsonl` and print the reports (the Core side of the I3 live test). A thin driver
over the verdict loader + the score-driven metrics — no logic of its own beyond argument
plumbing and printing.

    PYTHONPATH=$PWD python -m treval.active_eval.i3_run \
        --verdicts /tmp/verdicts.jsonl --benign 1,2 --violating 3

`score_stability` is content-agnostic ⇒ it runs on the whole file. `roc_curve` needs the
benign/violating split, which is corpus composition, not a verdict field: pass it as
`--benign`/`--violating` case-id lists for a single mixed file, or run two `verdicts.jsonl`
and concatenate.
"""

from __future__ import annotations

import argparse

from treval.active_eval.corpus import CorpusCase
from treval.active_eval.score_metrics import (
    StabilityReport,
    first_vendor_label_score,
    roc_curve,
    score_stability,
)
from treval.active_eval.verdict_loader import load_verdict_runs


def _case_for_split(case_id: str, content_class: str) -> CorpusCase:
    """A minimal CorpusCase carrying just the identity + slice key `roc_curve` reads. The other
    required fields are placeholders — a verdicts.jsonl reconstructs case identity, not the full
    corpus record. The real two-file run loads actual CorpusCases from the corpus instead."""
    return CorpusCase(
        id=case_id,
        owasp="LLM01",
        dimension="robustness",
        attack_class="content",
        input="",
        success_when="blocked_or_flagged",
        severity="high",
        source="i3-verdicts",
        content_class=content_class,
    )


def _print_stability(s: StabilityReport) -> None:
    print("=== score_stability ===")
    print(f"  deterministic_fraction = {s.deterministic_fraction}")
    print(f"  max_variance = {s.max_variance}   mean_variance = {s.mean_variance}")
    print(
        f"  contaminated_dropped = {s.contaminated_dropped}   "
        f"warmup_dropped = {s.warmup_dropped}   "
        f"insufficient_cases = {s.insufficient_cases}   "
        f"curve_eligible = {s.curve_eligible}"
    )
    for cid, cs in sorted(s.per_case.items()):
        tag = "bit-identical" if len(set(cs.scores)) <= 1 else f"SPREAD {cs.scores}"
        head = cs.scores[0] if cs.scores else None
        print(f"    line {cid}: n_used={len(cs.scores)} warm-rep {tag}  score={head}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="treval.active_eval.i3_run")
    ap.add_argument("--verdicts", required=True, help="path to judge verdicts.jsonl")
    ap.add_argument("--benign", default="", help="comma case-ids, e.g. 1,2")
    ap.add_argument("--violating", default="", help="comma case-ids, e.g. 3")
    a = ap.parse_args(argv)

    runs, content_class = load_verdict_runs(a.verdicts)
    stability = score_stability(runs, score_of=first_vendor_label_score)
    _print_stability(stability)

    b_ids = [x for x in a.benign.split(",") if x]
    v_ids = [x for x in a.violating.split(",") if x]
    if b_ids and v_ids:
        benign = [_case_for_split(c, content_class.get(c, "")) for c in b_ids]
        violating = [_case_for_split(c, content_class.get(c, "")) for c in v_ids]
        rep_pass = runs[1] if len(runs) > 1 else runs[0]  # one warm representative pass
        curve = roc_curve(
            benign, violating, rep_pass, stability, score_of=first_vendor_label_score
        )
        print(f"\n=== roc_curve — benign {b_ids} / violating {v_ids} ===")
        by_class = sorted(curve.by_class) if curve.by_class else None
        print(f"  points emitted = {curve.points is not None}   by_class = {by_class}")
        print(f"  measurable(viol,benign) = {curve.measurable}")
        print(f"  excluded(viol,benign)   = {curve.excluded}")
        for fpr in (0.0, 0.01, 0.05):
            lo, pt, hi = curve.recall_at_fpr(fpr)
            print(f"  recall@FPR={fpr:>4}: point={pt}  band=({lo}, {hi})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
