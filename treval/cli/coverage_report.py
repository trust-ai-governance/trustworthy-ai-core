"""EV-COVERAGE §4.3-B — the `coverage` CLI: walk a corpus tree → the four-axis vector, human or json.

🔴 The `corpus_sha` is printed AT THE TOP of both formats, framing all four numbers (DISCLOSURE_POLICY
§6 hard-rule ①: a number travels with its口径). Human output lists `absent` categories and each
corpus's observable gap EXPLICITLY — the reader sees what is missing, not a single rolled-up score.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from treval.active_eval.corpus import CorpusCase, CorpusError, load_corpus_tree
from treval.active_eval.coverage import corpus_coverage

EXIT_OK = 0
EXIT_IO = 3
_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_CORPUS = _ROOT / "corpus"


def _split_holdout(
    by_dir: dict[str, tuple[CorpusCase, ...]], *, holdout: bool
) -> dict[str, list[CorpusCase]]:
    """The subset of each corpus with the requested holdout flag (§4.3-D — the report shows the
    tuning set and the hold-out set separately; their gap IS the overfit-to-our-detector measure)."""
    return {
        d: [c for c in cases if c.holdout == holdout] for d, cases in by_dir.items()
    }


def _render_human(cov: dict, by_dir: dict[str, tuple[CorpusCase, ...]]) -> str:
    lines: list[str] = []
    lines.append(f"corpus coverage — corpus_sha {cov['corpus_sha']}")
    cc = cov["case_count"]
    lines.append(f"  cases: {cc['attack']} attack + {cc['benign']} benign\n")

    cat = cov["category_coverage"]
    lines.append(f"① category coverage: {len(cat['present'])}/10 present")
    lines.append(f"    present: {', '.join(cat['present']) or '(none)'}")
    lines.append(f"    absent : {', '.join(cat['absent']) or '(none)'}\n")

    tech = cov["technique_coverage"]
    lines.append(
        f"② technique coverage: {tech['count']} distinct technique(s) — 🔴 count, NOT a %"
    )
    for d, names in tech["by_corpus"].items():
        if names:
            lines.append(f"    {d}: {len(names)}  ({', '.join(names)})")
    lines.append("")

    obs = cov["outcome_observable"]
    total = obs["total"]
    pct = f"{obs['observable'] / total:.0%}" if total else "n/a"
    lines.append(
        f"③ outcome-observable: {obs['observable']}/{total} attack cases ({pct})"
    )
    for d, (o, t) in obs["by_corpus"].items():
        gap = " 🔴 gap" if t and o < t else ""
        lines.append(f"    {d}: {o}/{t}{gap}")
    lines.append("")

    ho = cov["holdout"]
    lines.append(f"④ hold-out: {ho['holdout']}/{ho['total']} cases")
    if ho["holdout"]:
        tuning = corpus_coverage(_split_holdout(by_dir, holdout=False))
        held = corpus_coverage(_split_holdout(by_dir, holdout=True))
        lines.append(
            f"    tuning : {tuning['technique_coverage']['count']} techniques · "
            f"{tuning['outcome_observable']['observable']}/{tuning['outcome_observable']['total']} observable"
        )
        lines.append(
            f"    holdout: {held['technique_coverage']['count']} techniques · "
            f"{held['outcome_observable']['observable']}/{held['outcome_observable']['total']} observable"
        )
        lines.append(
            "    🔴 stratification (hold-out spans the same ①②③ distribution) is a HUMAN review item (§4.3-D)"
        )
    else:
        lines.append("    (no hold-out cases yet — axis ④ starts at 0%, §3)")
    return "\n".join(lines) + "\n"


def _emit(text: str, out: str | None) -> None:
    if out is None:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")
    else:
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)


def run_coverage(args: argparse.Namespace) -> int:
    root = Path(args.corpus) if args.corpus else _DEFAULT_CORPUS
    try:
        by_dir = load_corpus_tree(root)
    except CorpusError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_IO
    flat: dict[str, Sequence[CorpusCase]] = dict(by_dir)
    cov = corpus_coverage(flat)
    if args.format == "json":
        _emit(json.dumps(cov, indent=2, ensure_ascii=False), args.out)
    else:
        _emit(_render_human(cov, by_dir), args.out)
    return EXIT_OK
