"""Corpus-coverage gate (CI) — fail the build when the corpus grows n without growing COVERAGE.

**Why this exists.** We want to push injection n up (to narrow the 89% interval), but raising n by
writing the SAME technique a hundred times makes the number LESS trustworthy, not more: a detector
that only catches two coarse classes scores high on a corpus that only contains two. So growth must
be policed mechanically, not by a self-discipline clause that erodes in a month. This gate is the
mechanism (EV-COVERAGE §2.1 / §4.3-C), deliberately built in the SHAPE of tools/check_doc_disclosure.py
— same `file/rule/why` output, same exit-1-on-hit — because a consistent gate is easier to maintain
and harder to quietly route around.

**What it refuses (each rule is EV-COVERAGE §2.1):**
- rule 1  — a single `attack_technique` occupying > 20% of its corpus (domination = fake coverage).
- rule 1b — the small-corpus form: below n=10 a share is meaningless, so cap at ≤ 2 cases/technique.
- rule 2  — a batch of NEW cases (git-added) that brings fewer than new_cases÷3 NEW techniques.
- rule 3  — an attack case with no `attack_technique` (silent under-count), or a NEW batch under 80%
            outcome-observable (mark detection-only cases explicitly instead).

🔴 Every rule acts on `attack_technique` (a field whose value set GROWS with the corpus), NEVER on
`attack_class` (two values — a rate gate there always FAILs; §4.3-C.2). The rule MATH lives in
treval.active_eval.coverage (pure, unit-tested); this file is the git + IO wiring only.

Exit 1 on any violation, printing `corpus / rule / why / detail`. `--base REF` overrides the
git baseline used for rule 2 (default: HEAD) — e.g. `origin/main` in CI to police a whole branch.

🔴 This gate imports `treval`, and CI installs only requirements (never `pip install -e .`). Run it
the SAME way CI does — with the repo root on the path:

    PYTHONPATH=$PWD python tools/check_corpus_coverage.py

(`python -m tools.check_corpus_coverage` also works because `-m` puts cwd on sys.path, but that is
NOT how CI invokes it — don't rely on it. And do NOT make the tool mutate sys.path itself: that hides
an environment problem inside product code.)
"""

from __future__ import annotations

import argparse
import subprocess  # nosec B404 — git plumbing only; see _git()
import sys
from pathlib import Path

from treval.active_eval.corpus import CorpusCase, CorpusError, load_case
from treval.active_eval.coverage import (
    Violation,
    check_attack_metadata,
    check_new_coverage,
    check_occupancy,
    is_benign,
)

_ROOT = Path(__file__).resolve().parents[1]
_CORPUS = _ROOT / "corpus"


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run one git plumbing command (fixed argv, no shell, only git-sourced/literal args) — the
    single home for the bandit suppression, same discipline as tools/check_doc_disclosure.py."""
    return subprocess.run(  # nosec B603 B607 — fixed git argv, no shell, git-sourced args
        ["git", *args], capture_output=True, text=True, check=check, cwd=_ROOT
    )


def _added_case_paths(base: str) -> set[str]:
    """Repo-relative posix paths of corpus case files ADDED since `base` (working tree + staged) PLUS
    untracked-not-ignored ones — the same "what a commit could publish" surface the disclosure gate
    scans. On any git failure (no repo / no such base) → empty set: rule 2 is skipped, but the
    structural rules (1/1b/3) still gate. Never crashes the build on a git edge."""
    added: set[str] = set()
    try:
        diff = _git("diff", "--diff-filter=A", "--name-only", base, "--", "corpus")
        others = _git("ls-files", "--others", "--exclude-standard", "--", "corpus")
    except (subprocess.CalledProcessError, OSError) as e:
        print(
            f"⚠ corpus gate: git baseline unavailable ({e}); rule 2 skipped",
            file=sys.stderr,
        )
        return added
    for out in (diff.stdout, others.stdout):
        for line in out.splitlines():
            line = line.strip()
            if line.endswith(".yaml") and line.startswith("corpus/"):
                added.add(line)
    return added


def _load_tree() -> tuple[dict[str, list[CorpusCase]], dict[str, Path]]:
    """Every corpus case on disk, grouped by subdir, plus a case_id → path map (for baseline vs
    added partitioning). Fail-closed on a malformed case (a bad case must not slip the gate)."""
    by_dir: dict[str, list[CorpusCase]] = {}
    path_by_id: dict[str, Path] = {}
    for path in sorted(_CORPUS.glob("*/*.yaml")):
        case = load_case(path)
        by_dir.setdefault(path.parent.name, []).append(case)
        path_by_id[case.id] = path
    return by_dir, path_by_id


def collect_violations(base: str) -> list[Violation]:
    """All §2.1 violations over the worktree corpus. Rules 1/1b/3-empty scan the whole corpus; rule 2
    + the observable floor scan only the git-ADDED cases, with the pre-existing (non-added) cases as
    the technique baseline — so 'new technique' means new to THIS corpus, computed without reading
    HEAD blobs (the non-added worktree cases ARE the baseline)."""
    by_dir, path_by_id = _load_tree()
    violations = check_occupancy(by_dir) + check_attack_metadata(by_dir)

    added_paths = _added_case_paths(base)
    added_by_dir: dict[str, list[CorpusCase]] = {}
    old_techniques: dict[str, set[str]] = {}
    for d, cases in by_dir.items():
        for c in cases:
            rel = path_by_id[c.id].relative_to(_ROOT).as_posix()
            if rel in added_paths:
                added_by_dir.setdefault(d, []).append(c)
            elif not is_benign(c) and c.attack_technique:
                old_techniques.setdefault(d, set()).add(c.attack_technique)
    violations += check_new_coverage(added_by_dir, old_techniques)
    return violations


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_corpus_coverage", description=__doc__)
    ap.add_argument(
        "--base",
        default="HEAD",
        help="git ref the NEW cases are measured against for rule 2 (default: HEAD)",
    )
    args = ap.parse_args(argv)

    try:
        violations = collect_violations(args.base)
    except CorpusError as e:
        print(f"corpus gate: ERROR — malformed corpus: {e}", file=sys.stderr)
        return 1

    if not violations:
        print("corpus coverage gate: PASS —— 语料增长规则（§2.1）无违反")
        return 0

    print(f"corpus coverage gate: FAIL —— {len(violations)} 处违反\n", file=sys.stderr)
    for v in violations:
        print(f"[{v.rule}] corpus/{v.corpus}: {v.why}", file=sys.stderr)
        print(f"    {v.detail}", file=sys.stderr)
    print(
        "\n处置：分散手法（每手法 ≤20%）· 新增用例带新手法（≥ 新增数÷3）· "
        "攻击用例补 attack_technique · 新增用例带 output_marker/secret_canary（或显式标 detection-only）。"
        "详见 docs/issues/EV-COVERAGE.md §2.1。",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
