"""EV-COVERAGE §4.3 — the coverage vector (axes ①②③④) + the §2.1 growth rules, as pure functions
over a loaded corpus. No network, no IO (the CLI and the gate do the directory walk + git reads).

🔴 Two load-bearing disciplines live here:
- axis ② is reported as an absolute COUNT + the technique names, NEVER a rate (§1.1 — it has no
  external denominator; any invented one is fake precision);
- the occupancy / growth rules act on `attack_technique` (a HIGH-cardinality field whose value set
  grows with the corpus), NEVER on `attack_class` (two values — a rate gate there always FAILs;
  §2.1 / §4.3-C.2). The generalisation: rate-type gates only on fields that grow with the corpus.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from treval.active_eval.corpus import CorpusCase, corpus_fingerprint

# OWASP LLM Top-10 — axis ① is measured against this fixed list (a RANGE DECLARATION, not a score).
OWASP_LLM_TOP10 = tuple(f"LLM{i:02d}" for i in range(1, 11))

# §2.1 growth-rule thresholds — ONE source of truth (the report, the gate, and their tests all read
# these; changing a rule is a one-line, reviewable edit here, never a scattered constant).
MAX_TECHNIQUE_SHARE = (
    0.20  # rule 1 : a technique may occupy ≤ 20% of its corpus (20% INCLUSIVE)
)
SMALL_CORPUS_N = (
    10  # rule 1b: below this n, a share is meaningless — switch to a count cap
)
SMALL_CORPUS_MAX_COUNT = 2  # rule 1b: ≤ 2 cases per technique in a small (n<10) corpus
NEW_COVERAGE_DIVISOR = 3  # rule 2 : a batch's new techniques ≥ its new cases ÷ 3
MIN_OBSERVABLE_SHARE = (
    0.80  # rule 3 : ≥ 80% of NEW attack cases plant an outcome signal
)
_SHARE_EPS = 1e-9  # treat an exact 20% as passing (§4.3-C rule 1: "含 20%")


def is_benign(case: CorpusCase) -> bool:
    """A benign control — the SAME predicate corpus_export_jsonl.py uses for label derivation.
    Benign cases carry no attack_technique and are excluded from the technique/occupancy/observable
    axes (they have no attack to cover or to succeed)."""
    return case.attack_class.startswith("benign")


def _observable(case: CorpusCase) -> bool:
    """The case can tell whether the attack SUCCEEDED (not merely whether it was caught): it plants
    an output_marker or a secret_canary. A detection-only case (a posture attack with no single
    output signature, §2.1-3) is observable=False but stays in the denominator."""
    return bool(case.output_marker or case.secret_canary)


def corpus_coverage(by_dir: Mapping[str, Sequence[CorpusCase]]) -> dict:
    """The four coverage axes + per-corpus occupancy, in the FIXED shape the report (§4.3-B) and the
    gate (§4.3-C) both consume (so they never drift). `by_dir` maps each corpus subdir NAME → its
    cases; keeping this pure (the CLI walks the tree) means report and gate agree by construction.
    `corpus_sha` is over ALL cases flattened, so the four numbers travel WITH their fingerprint
    (§1 disclosure discipline). 🔴 Returns NO "total coverage %" (§1)."""
    all_cases = [c for cases in by_dir.values() for c in cases]
    n_benign = sum(1 for c in all_cases if is_benign(c))

    # ① category coverage — present/absent LISTS, never a 6/10 ratio: the reader sees WHICH
    # categories are missing, not a single number that hides them (§4.3-A).
    present = sorted({c.owasp for c in all_cases})
    present_set = set(present)
    absent = [cat for cat in OWASP_LLM_TOP10 if cat not in present_set]

    # ② technique coverage — distinct technique NAMES over attack cases: an absolute count + the list
    # (§1.1 — no rate). A technique shared across corpora (same name ⇒ same defence, §4.2.4) counts
    # once globally and appears in each corpus's by_corpus list.
    attack_by_dir = {
        d: [c for c in cases if not is_benign(c)] for d, cases in by_dir.items()
    }
    tech_by_dir = {
        d: sorted({c.attack_technique for c in cases if c.attack_technique})
        for d, cases in attack_by_dir.items()
    }
    all_techniques = sorted({t for names in tech_by_dir.values() for t in names})

    # ③ outcome-observable coverage — attack cases only (a benign case has no attack to succeed).
    obs_by_dir = {
        d: [sum(_observable(c) for c in cases), len(cases)]
        for d, cases in attack_by_dir.items()
    }

    # occupancy — each technique's share of its corpus's attack cases (§2.1-1 gate input).
    occupancy: dict[str, dict[str, float]] = {}
    for d, cases in attack_by_dir.items():
        n = len(cases)
        counts = Counter(c.attack_technique for c in cases if c.attack_technique)
        occupancy[d] = {t: k / n for t, k in sorted(counts.items())} if n else {}

    return {
        "corpus_sha": corpus_fingerprint(all_cases),
        "case_count": {"attack": len(all_cases) - n_benign, "benign": n_benign},
        "category_coverage": {"present": present, "absent": absent},
        "technique_coverage": {
            "count": len(all_techniques),
            "names": all_techniques,
            "by_corpus": tech_by_dir,
        },
        "outcome_observable": {
            "observable": sum(v[0] for v in obs_by_dir.values()),
            "total": sum(v[1] for v in obs_by_dir.values()),
            "by_corpus": obs_by_dir,
        },
        "holdout": {
            "holdout": sum(1 for c in all_cases if c.holdout),
            "total": len(all_cases),
        },
        "occupancy": occupancy,
    }


# --------------------------------------------------------------------------- #
# §2.1 growth rules — pure checkers the gate (tools/check_corpus_coverage.py) wires to git + IO.
# Kept pure and here (not in the tool) so the RULE LOGIC is unit-testable without a git repo.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Violation:
    """One growth-rule breach. `rule` is a stable slug; `corpus` the subdir; `why` the rule; `detail`
    the concrete numbers — so the gate prints `corpus / rule / why / detail`, like the disclosure
    gate prints `file:line / category / why`."""

    rule: str
    corpus: str
    why: str
    detail: str


def check_occupancy(by_dir: Mapping[str, Sequence[CorpusCase]]) -> list[Violation]:
    """Rules 1 / 1b — no single technique may DOMINATE a corpus. A small corpus (n < 10) uses a COUNT
    cap (≤2) instead of a share, because a 1/3 share on n=3 is not domination (§2.1-1b — a share gate
    there would FAIL legitimate corpora)."""
    out: list[Violation] = []
    for d, cases in by_dir.items():
        attack = [c for c in cases if not is_benign(c)]
        n = len(attack)
        if n == 0:
            continue
        counts = Counter(c.attack_technique for c in attack if c.attack_technique)
        small = n < SMALL_CORPUS_N
        for tech, k in sorted(counts.items()):
            if small:
                if k > SMALL_CORPUS_MAX_COUNT:
                    out.append(
                        Violation(
                            "rule1b",
                            d,
                            f"small corpus (n={n}<{SMALL_CORPUS_N}): ≤{SMALL_CORPUS_MAX_COUNT} cases per technique",
                            f"technique {tech!r} = {k} cases (> {SMALL_CORPUS_MAX_COUNT})",
                        )
                    )
            elif k / n > MAX_TECHNIQUE_SHARE + _SHARE_EPS:
                out.append(
                    Violation(
                        "rule1",
                        d,
                        f"single technique share ≤ {MAX_TECHNIQUE_SHARE:.0%}",
                        f"technique {tech!r} = {k}/{n} = {k / n:.0%} (> {MAX_TECHNIQUE_SHARE:.0%})",
                    )
                )
    return out


def check_attack_metadata(
    by_dir: Mapping[str, Sequence[CorpusCase]],
) -> list[Violation]:
    """Rule 3 (presence) — every ATTACK case must declare a non-empty attack_technique, else it falls
    into a 'no technique' bucket and silently under-counts coverage (§4.2.2). Benign cases exempt."""
    out: list[Violation] = []
    for d, cases in by_dir.items():
        for c in cases:
            if not is_benign(c) and not c.attack_technique:
                out.append(
                    Violation(
                        "rule3-empty",
                        d,
                        "attack case must declare attack_technique",
                        f"case {c.id!r} has empty attack_technique",
                    )
                )
    return out


def check_new_coverage(
    added_by_dir: Mapping[str, Sequence[CorpusCase]],
    old_techniques_by_dir: Mapping[str, set[str]],
) -> list[Violation]:
    """Rule 2 + rule-3-observable, on the NEWLY ADDED cases only (the gate reads git for these — the
    existing 28 llm01 cases are legitimately detection-only, §2.2, so the observable floor applies to
    NEW cases, not the back-catalogue). Rule 2: a batch's NEW techniques ≥ new cases ÷ 3, else it is
    piling n onto one technique (the exact fake-coverage this whole unit exists to stop)."""
    out: list[Violation] = []
    for d, added in sorted(added_by_dir.items()):
        attack_added = [c for c in added if not is_benign(c)]
        n_new = len(attack_added)
        if n_new == 0:
            continue
        old = old_techniques_by_dir.get(d, set())
        new_techs = {
            c.attack_technique for c in attack_added if c.attack_technique
        } - old
        if NEW_COVERAGE_DIVISOR * len(new_techs) < n_new:
            out.append(
                Violation(
                    "rule2",
                    d,
                    f"new techniques ≥ new attack cases ÷ {NEW_COVERAGE_DIVISOR}",
                    f"{n_new} new attack case(s) brought only {len(new_techs)} new technique(s) "
                    f"(need ≥ {math.ceil(n_new / NEW_COVERAGE_DIVISOR)})",
                )
            )
        observable = sum(_observable(c) for c in attack_added)
        if observable < MIN_OBSERVABLE_SHARE * n_new:
            out.append(
                Violation(
                    "rule3-observable",
                    d,
                    f"new attack cases ≥ {MIN_OBSERVABLE_SHARE:.0%} outcome-observable",
                    f"{observable}/{n_new} = {observable / n_new:.0%} observable "
                    f"(< {MIN_OBSERVABLE_SHARE:.0%}; mark detection-only cases explicitly)",
                )
            )
    return out
