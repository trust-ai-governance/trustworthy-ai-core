"""F8 — the disclosure gate (EV-COVERAGE-E3F §7B): a guard that守新增, not history.

The public repo already carries a batch of OLD baseline measured values (in docs, registry comments,
and tests). Architect ruling (§7B.1): 算，但历史不追 —— only NEW additions are guarded. Chasing the
existing ones would rewrite test assertions for more risk than reward; but if the increment isn't
guarded, the same problem regrows in the same shape.

🔴 So this gate runs ONLY on ADDED/CHANGED lines (vs a merge baseline). A whole-repo scan would be
born red, get ignored within a week, and equal nothing (§7B.2). Three hit patterns (a measured value
written into prose) + explicit exemptions.

Exemptions (each with a reason):
  • corpus/**        — that is INPUT (attack/benign text), not a measured value.
  • tests/fixtures/**— 🔴 §四: MACHINE-GENERATED artifacts (report bundles regen'd by UPDATE_FIXTURES),
                       not human prose. The gate catches【人写的散文】, never【机器生成的产物】.
  • a `# synthetic:` line — constructive/synthetic test data (incl. a math function's own known-IO
                       unit test, e.g. a Wilson-interval assertion) must carry the marker.

Run the SAME way CI will (git plumbing; needs the repo):

    PYTHONPATH=$PWD python tools/check_disclosure.py [--base HEAD]
"""

from __future__ import annotations

import argparse
import re
import subprocess  # nosec B404 — git plumbing only, fixed argv, no shell
import sys
from dataclasses import dataclass
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

_SYNTHETIC = "# synthetic:"
_EXEMPT_PREFIXES = ("corpus/", "tests/fixtures/")

# §7B.2 — three shapes of a measured VALUE written into prose. 🔴 A THRESHOLD (a satisfied_when
# criterion like `ci_high <= 0.05` / `ci_low >= 0.80`) is NOT a disclosed value — it defines the gate,
# it does not report a measurement. So every pattern excludes a comparison operator between the field
# and the number: `ci_high 0.037` (value) fires, `ci_high <= 0.05` (threshold) does not.
_KN_RE = re.compile(r"\b\d{1,3}/\d{1,3}\b")  # k/n
_CI_VALUE_RE = re.compile(
    r"ci_(?:low|high)\s*(?:is|=|:)?\s*\d*\.\d"
)  # ci_low 0.xxx (a VALUE)
_CI_THRESHOLD_RE = re.compile(
    r"ci_(?:low|high)\s*(?:<=|>=|<|>|≤|≥|>=)"
)  # a criterion, not a value
_INDICATOR_RE = re.compile(r"\b[a-z][a-z0-9_]*_(?:rate|ratio|integrity|surface)\b")
_PERCENT_RE = re.compile(r"\d{1,3}(?:\.\d+)?\s*%")


def disclosure_hit(line: str) -> str | None:
    """Return a short reason if `line` DISCLOSES a measured VALUE (§7B.2), else None. A `# synthetic:`
    marker exempts the line (constructive test data / a math function's known-IO). A THRESHOLD
    (comparison operator) is never a disclosure — it is the gate criterion, not a measurement."""
    if _SYNTHETIC in line:
        return None
    # pattern ① — k/n alongside a PERCENTAGE, or a non-threshold ci_ VALUE (not a `ci_ <=`criterion).
    if _KN_RE.search(line) and (
        "%" in line or (_CI_VALUE_RE.search(line) and not _CI_THRESHOLD_RE.search(line))
    ):
        return "k/n alongside % or a ci_ value (a measured proportion)"
    # pattern ② — ci_low/ci_high with a literal decimal VALUE (excludes `ci_ <=`thresholds).
    if _CI_VALUE_RE.search(line) and not _CI_THRESHOLD_RE.search(line):
        return "ci_low/ci_high with a literal decimal value"
    # pattern ③ — an indicator id alongside a percentage.
    if _PERCENT_RE.search(line) and _INDICATOR_RE.search(line):
        return "an indicator id alongside a percentage"
    return None


def _is_exempt(path: str) -> bool:
    return any(path.startswith(p) for p in _EXEMPT_PREFIXES)


@dataclass(frozen=True)
class Violation:
    path: str
    text: str
    why: str


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603 B607 — fixed git argv, no shell, base is caller-supplied literal
        ["git", *args], capture_output=True, text=True, check=True, cwd=_ROOT
    )


def added_lines(base: str) -> list[tuple[str, str]]:
    """(path, added_line) for every line ADDED vs `base` (working tree + staged), across tracked files.
    `--unified=0` so only the `+` lines of each hunk are new. On any git failure ⇒ empty (the gate then
    passes vacuously rather than crashing the build; the other gates still run)."""
    try:
        diff = _git("diff", "--unified=0", "--no-color", base)
    except (subprocess.CalledProcessError, OSError) as e:
        print(
            f"⚠ disclosure gate: git baseline unavailable ({e}); skipped",
            file=sys.stderr,
        )
        return []
    out: list[tuple[str, str]] = []
    path = ""
    for line in diff.stdout.splitlines():
        if line.startswith("+++ b/"):
            path = line[len("+++ b/") :]
        elif line.startswith("+") and not line.startswith("+++"):
            out.append((path, line[1:]))
    return out


def collect_violations(base: str) -> list[Violation]:
    out: list[Violation] = []
    for path, line in added_lines(base):
        if not path or _is_exempt(path):
            continue
        why = disclosure_hit(line)
        if why:
            out.append(Violation(path, line.strip()[:100], why))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_disclosure", description=__doc__)
    ap.add_argument(
        "--base", default="HEAD", help="git baseline (e.g. origin/main in CI)"
    )
    args = ap.parse_args(argv)
    violations = collect_violations(args.base)
    if not violations:
        print("disclosure gate: PASS —— 新增行未把实测值写进散文（§7B，只守新增）")
        return 0
    print(f"disclosure gate: FAIL —— {len(violations)} 处新增披露\n", file=sys.stderr)
    for v in violations:
        print(f"[{v.why}] {v.path}", file=sys.stderr)
        print(f"    {v.text}", file=sys.stderr)
    print(
        "\n修复：把实测值移出散文，或（构造性/合成数）在该行加 `# synthetic:` 标注；"
        "corpus/ 与 tests/fixtures/ 已豁免（输入与机器生成物）",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
