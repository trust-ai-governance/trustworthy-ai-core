"""P3C-harness I3 joint-run CLI — run the score-driven metrics against a real judge
`verdicts.jsonl` and print the reports (the Core side of the I3 live test). A thin driver
over the verdict loader + the score-driven metrics — no logic of its own beyond argument
plumbing and printing.

Two intake shapes — the benign/violating split is corpus composition, never a verdict field:

    # file-grouped (the real-corpus shape): the split rides FILE MEMBERSHIP
    PYTHONPATH=$PWD python -m treval.active_eval.i3_run \
        --violating   <verdicts.jsonl> \
        --benign      <verdicts.jsonl> \
        --benign-meta <verdicts.jsonl>      # optional; joins the BENIGN side
        [--dry-run]

    # single mixed file (smoke): the split is a list of line ids
    PYTHONPATH=$PWD python -m treval.active_eval.i3_run \
        --verdicts /tmp/verdicts.jsonl --benign 1,2 --violating 3

`score_stability` is content-agnostic ⇒ it runs on every group at once. `--dry-run` is a
VERDICT-level pre-check (row/repeat/class/parse-error counts, no scoring); corpus-level
pre-check belongs to the generation side's own validator.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from treval.active_eval.corpus import CorpusCase
from treval.active_eval.score_metrics import (
    CurveReport,
    StabilityReport,
    first_vendor_label_score,
    roc_curve,
    score_stability,
)
from treval.active_eval.verdict_loader import (
    VerdictError,
    load_verdict_groups,
    load_verdict_runs,
    preflight_verdict_groups,
)

EXIT_OK = 0
EXIT_IO = 3  # unreadable / malformed verdicts, or a bad argument combination


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


def _print_curve(curve: CurveReport, b_ids: list[str], v_ids: list[str]) -> None:
    print(f"\n=== roc_curve — benign {len(b_ids)} case(s) / violating {len(v_ids)} ===")
    by_class = sorted(curve.by_class) if curve.by_class else None
    print(f"  points emitted = {curve.points is not None}   by_class = {by_class}")
    print(f"  measurable(viol,benign) = {curve.measurable}")
    print(f"  excluded(viol,benign)   = {curve.excluded}")
    # matched-FPR is the authoritative read; a hard score>=0.5 threshold would misread a judge
    # whose absolute scores are tiny and badly understate recall.
    for fpr in (0.0, 0.01, 0.05):
        lo, pt, hi = curve.recall_at_fpr(fpr)
        print(f"  recall@FPR={fpr:>4}: point={pt}  band=({lo}, {hi})")

    # Per-class at ONE global threshold — the deployable caliber. Printed here because the
    # by_class curves above tune a SEPARATE threshold per class, and reading them by hand
    # overstates deployable recall; this is the number candidates get compared on.
    for fpr in (0.01, 0.05):
        tau, by_cls = curve.recall_by_class_at_fpr(fpr)
        print(f"\n  per-class recall @ ONE global threshold (FPR<={fpr}, tau={tau!r}):")
        for cc, (recall, n) in by_cls.items():
            print(f"    {cc or '(unclassified)'}: recall={recall:.3f}  n={n}")
    print(
        "\n  NOTE: by_class curves above are DIAGNOSTIC — each tunes its own threshold against\n"
        "        its own benign subset. Production runs ONE threshold, so the per-class block\n"
        "        directly above is the deployable caliber."
    )


def _print_preflight(report: dict[str, dict[str, Any]]) -> None:
    print("=== dry-run (verdict-level pre-check; no scoring) ===")
    for group, r in report.items():
        tag = "" if r["known_group"] else "  ⚠ UNKNOWN GROUP (not mapped to a side)"
        print(f"\n  [{group}] side={r['side'] or '-'}{tag}")
        print(f"    rows={r['rows']}  cases={r['cases']}  contracts={r['contracts']}")
        print(f"    repeats per line: {r['repeats_by_line']}")
        print(f"    content_class:    {r['content_classes']}")
        if r["parse_errors"]:
            print(f"    ⚠ parse errors ({len(r['parse_errors'])}):")
            for msg in r["parse_errors"]:
                print(f"        {msg}")
        else:
            print("    parse errors:     none")


def _analyse(
    runs: list[list[Any]],
    b_ids: list[str],
    v_ids: list[str],
    content_class: dict[str, str],
) -> None:
    """Stability over every group, then (when both sides are present) the two-sided curve."""
    stability = score_stability(runs, score_of=first_vendor_label_score)
    _print_stability(stability)
    if not (b_ids and v_ids):
        print("\n(no two-sided split given — skipping roc_curve)")
        return
    benign = [_case_for_split(c, content_class.get(c, "")) for c in b_ids]
    violating = [_case_for_split(c, content_class.get(c, "")) for c in v_ids]
    rep_pass = runs[1] if len(runs) > 1 else runs[0]  # one warm representative pass
    curve = roc_curve(
        benign, violating, rep_pass, stability, score_of=first_vendor_label_score
    )
    _print_curve(curve, b_ids, v_ids)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="treval.active_eval.i3_run")
    ap.add_argument(
        "--verdicts",
        default="",
        help="single mixed verdicts.jsonl; with it, --benign/--violating are comma line ids",
    )
    ap.add_argument(
        "--violating",
        default="",
        help="grouped: path to the violating verdicts.jsonl | with --verdicts: comma line ids",
    )
    ap.add_argument(
        "--benign",
        default="",
        help="grouped: path to the benign verdicts.jsonl | with --verdicts: comma line ids",
    )
    ap.add_argument(
        "--benign-meta",
        default="",
        help="grouped: optional benign-meta verdicts.jsonl (joins the BENIGN side)",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="verdict-level pre-check only (counts + parse errors); no scoring",
    )
    a = ap.parse_args(argv)

    try:
        if a.verdicts:  # single mixed file — the split is a list of line ids
            if a.dry_run:
                _print_preflight(preflight_verdict_groups({"verdicts": a.verdicts}))
                return EXIT_OK
            runs, content_class = load_verdict_runs(a.verdicts)
            b_ids = [x for x in a.benign.split(",") if x]
            v_ids = [x for x in a.violating.split(",") if x]
            _analyse(runs, b_ids, v_ids, content_class)
            return EXIT_OK

        # file-grouped — the split rides file membership
        files = {
            g: p
            for g, p in (
                ("violating", a.violating),
                ("benign", a.benign),
                ("benign_meta", a.benign_meta),
            )
            if p
        }
        if not files:
            print(
                "error: give either --verdicts <file> (single mixed file) or at least one "
                "of --violating/--benign/--benign-meta <file> (file-grouped)",
                file=sys.stderr,
            )
            return EXIT_IO
        if a.dry_run:
            _print_preflight(preflight_verdict_groups(files))
            return EXIT_OK
        runs, sides, content_class = load_verdict_groups(files)
        _analyse(runs, sides["benign"], sides["violating"], content_class)
        return EXIT_OK
    except VerdictError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_IO


if __name__ == "__main__":
    raise SystemExit(main())
