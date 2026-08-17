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
  • a marked line     — `# synthetic: <reason>` / `# disclosure-ok: <reason>` (markdown:
                       `<!-- disclosure-ok: <reason> -->`). 🔴 The REASON is mandatory: a bare marker
                       never exempts, so每一次豁免都是一个【被写下的决定】. Use it for our OWN corpus
                       composition, constructive test input, and a math function's known-IO.
  • a format template — `f"{a}/{b} ({r:.1%})"` renders at runtime; it discloses nothing at rest.

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

_EXEMPT_PREFIXES = ("corpus/", "tests/fixtures/")

# 🔴 §7B.2 (revised) — an explicit SAME-LINE marker that must carry a REASON. `synthetic` and
# `disclosure-ok` are aliases; `#` (code) and `<!-- -->` (markdown) both work. A bare marker with no
# reason does NOT exempt — a marker that needs no justification is a skeleton key, and the whole point
# is that每一次豁免都是一个【被写下的决定】. Markdown: put it INSIDE the cell (`… <!-- disclosure-ok: r -->`)
# so the table still renders.
_EXEMPT_MARK_RE = re.compile(
    r"(?:#|<!--)\s*(?:synthetic|disclosure-ok)\s*:\s*(\S[^\n]*?)\s*(?:-->|$)"
)

# 🔴 §7B.2 (revised) — an f-string/format PLACEHOLDER is a template, not a value: `f"{a}/{b} ({r:.1%})"`
# prints a proportion at RUNTIME, it discloses nothing at rest. The gate's OWN output code was flagged
# by the gate — a plain false positive. Strip placeholder spans before matching, so a LITERAL
# proportion still fires while the template that would render one does not.
_PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}")

# `@@ -a,b +c,d @@` — the NEW-side start line, for the adjacent-marker lookup.
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)")

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
    """Return a short reason if `line` DISCLOSES a TESTED-PARTY measured VALUE (§7B.2), else None.

    🔴 The question is NOT "does this look like k/n with a percent" — it is "is this a MEASURED value of
    the tested party". Three things are therefore not disclosures:
      • a THRESHOLD (`ci_high <= 0.05`) — it defines the gate, it does not report a measurement;
      • a format PLACEHOLDER (`f"{a}/{b} ({r:.1%})"`) — a template renders at runtime, it discloses
        nothing at rest (the gate flagged its OWN print statements — a plain false positive);
      • a line carrying an explicit `synthetic:` / `disclosure-ok: <reason>` marker — WITH a reason
        (our own corpus composition, constructive test input, a math function's known-IO). A bare
        marker never exempts."""
    if _EXEMPT_MARK_RE.search(line):
        return None
    line = _PLACEHOLDER_RE.sub(" ", line)  # a template is not a value
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


def added_lines(base: str) -> list[tuple[str, int, str]]:
    """(path, lineno, added_line) for every line ADDED vs `base` (working tree + staged), across tracked
    files. `--unified=0` so only the `+` lines of each hunk are new; the hunk header gives the NEW-side
    line number, which the adjacent-marker lookup needs. On any git failure ⇒ empty (the gate then
    passes vacuously rather than crashing the build; the other gates still run)."""
    try:
        diff = _git("diff", "--unified=0", "--no-color", base)
    except (subprocess.CalledProcessError, OSError) as e:
        print(
            f"⚠ disclosure gate: git baseline unavailable ({e}); skipped",
            file=sys.stderr,
        )
        return []
    out: list[tuple[str, int, str]] = []
    path = ""
    lineno = 0
    for line in diff.stdout.splitlines():
        if line.startswith("+++ b/"):
            path = line[len("+++ b/") :]
        elif line.startswith("@@"):
            m = _HUNK_RE.match(line)
            lineno = int(m.group(1)) if m else 0
        elif line.startswith("+") and not line.startswith("+++"):
            out.append((path, lineno, line[1:]))
            lineno += 1
    return out


def _marked_nearby(path: str, lineno: int) -> bool:
    """Is there an exemption marker on this line or an ADJACENT one (N-1 / N / N+1)?

    🔴 Same-line ONLY is fragile: an auto-formatter reflows a long statement and pushes the trailing
    comment onto the continuation line, silently voiding the exemption (observed live — `ruff format`
    did exactly this). The marker's REASON still has to be written; only its exact placement is relaxed.
    Read from the WORKING FILE, not the diff, so an unchanged marker line still counts."""
    try:
        lines = (_ROOT / path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for i in range(max(0, lineno - 2), min(len(lines), lineno + 1)):
        if _EXEMPT_MARK_RE.search(lines[i]):
            return True
    return False


def collect_violations(base: str) -> list[Violation]:
    out: list[Violation] = []
    for path, lineno, line in added_lines(base):
        if not path or _is_exempt(path):
            continue
        why = disclosure_hit(line)
        if why and not _marked_nearby(path, lineno):
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
    print(
        f"disclosure gate: FAIL —— {len(violations)} 处疑似【被测方实测值】进入新增行\n",
        file=sys.stderr,
    )
    for v in violations:
        print(f"[{v.why}] {v.path}", file=sys.stderr)
        print(f"    {v.text}", file=sys.stderr)
    print(
        "\n怎么办 —— 先判断它是不是【被测方】的实测值：\n"
        "  • 是   ⇒ 移出本仓（实测结果与设计文档分离）；\n"
        "  • 不是 ⇒ 在该行加标注并写明理由，例如\n"
        "           代码:      # disclosure-ok: 我方语料构成，可由本仓 corpus/ 自行导出\n"
        "           Markdown:  … <!-- disclosure-ok: 构造性测试输入，证明门有牙 -->\n"
        "  🔴 标注必须带理由 —— 光有标记不放行（无理由的豁免等于万能钥匙）。\n"
        "  已自动放行：格式占位符（f-string 模板不是值）· 门槛（ci_high <= 0.05 是判据不是测量）\n"
        "  · corpus/（输入）· tests/fixtures/（机器生成物）",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
