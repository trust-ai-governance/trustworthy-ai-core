"""Disclosure gate for the PUBLIC repo — fail the build on text that must not ship openly.

**Why this exists.** This repo is public; our work is not. Four times now, private material
reached (or nearly reached) a public file: restricted corpus text, an internal number↔config
table, conformance-fixture provenance, and — the one that actually got pushed — a private
source path plus a control weakness ("the ruleset version field is never bumped"). Every one
was caught by a person reading carefully. That is not a control; it is luck with a good
track record. This is the mechanical gate.

**What it refuses, and why each category is its own kind of harm:**

- `private_source`  — paths/line refs into the closed runtime. Maps our internals for anyone.
- `platform_commit` — commit SHAs of the private repo. Confirms *which* change did *what*.
- `vendor_named`    — a named vendor NEAR a negative judgement. Naming a vendor's defect in
                      public is a commercial-disparagement exposure and burns negotiating
                      position. Neutral mentions are fine; the pairing is what fails.
- `control_gap`     — us announcing our own gate does not actually run. The most damaging
                      category and the least obvious: it is self-inflicted, and it undercuts
                      exactly the story the product is built on.
- `internal_name`   — internal layer/SKU/doc names that leak roadmap and packaging posture.

**Scope.** Text files only, and only the ones a reader would find: docs, README, issue
templates. Source code is covered by the existing secret/licence scans.

Exit 1 on any hit, printing file:line and the matched category, so the failure is actionable
rather than a wall of red. `--all-history` additionally scans every commit — use it to answer
"did this ever ship?", not on every CI run (it is O(commits × files)).
"""

from __future__ import annotations

import argparse
import re
import subprocess  # nosec B404 — git plumbing only; see _git()
import sys
from pathlib import Path


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Run one git plumbing command, capturing text output.

    Every git call in this file goes through here so the bandit suppression lives in
    ONE place with ONE justification: the argv is a fixed literal list (`git` first,
    resolved via PATH by design for portability), never a shell string, and the only
    variable parts are git-sourced values — commit SHAs from `rev-list`, tracked paths
    from `ls-tree` — not external/user input. No injection surface."""
    return subprocess.run(  # nosec B603 B607 — fixed git argv, no shell, git-sourced args
        ["git", *args], capture_output=True, text=True, check=check
    )


# Each rule is (severity, category, why, pattern). Patterns are deliberately specific: a
# gate that cries wolf gets disabled, and a disabled gate is worse than none. Hence two
# severities — "error" fails the build; "warn" reports and passes. A bare cross-reference
# to an upstream document ("the contract lives in <private doc>") is legitimate and common
# in this repo's dev briefs; failing on it would make the gate unusable within a month.
# What must never ship is that document's CONTENT, which the other rules catch.
_NEG = r"(?:未见|没有|缺|无[^\w]|不支持|未提|通篇未|静默|漏|弱|缺陷|问题|风险|完全无|答不上|存疑|崩)"
_VENDORS = r"(?:数美|易盾|天净|天御|shumei|ishumei|dun\.163|fengkongcloud|网易易盾)"

RULES: list[tuple[str, str, str, re.Pattern[str]]] = [
    (
        "error",
        "private_source",
        "私有运行时的源码路径/行号 —— 对外等于给出内部实现地图",
        re.compile(
            r"\b(?:src/gateway|invoke_api\.py|pipeline\.py|guardrail\.py"
            r"|rule_compiler\.py|ir_runtime)\b"
        ),
    ),
    (
        "error",
        "platform_commit",
        "私有仓 commit 号 —— 坐实「哪一次改动造成了什么」",
        # GENERIC only, by design: a private SHA almost always appears with a private-repo
        # context word nearby (Platform / 上游 / 私有仓 / 提交). We deliberately do NOT
        # hardcode the actual private SHAs here — this file is PUBLIC, and listing them to
        # detect them would itself disclose them (the exact trap that motivated this gate).
        # A bare hex with no such context is indistinguishable from one of OUR OWN public
        # commit SHAs (e.g. "git 5b1d104" in the provenance docs), so it must NOT match.
        re.compile(
            r"(?:Platform|平台|私有仓|上游|上游仓|上游提交)[^\n]{0,24}\b[0-9a-f]{7,40}\b"
        ),
    ),
    (
        "error",
        "vendor_named",
        "具名厂商 + 负面判断 —— 商业诋毁面 + 暴露采购底牌（中性提及不算）",
        re.compile(rf"{_VENDORS}[^\n]{{0,80}}{_NEG}|{_NEG}[^\n]{{0,80}}{_VENDORS}"),
    ),
    (
        "error",
        "control_gap",
        "自曝我方管控门实际没在跑 —— 最伤，且是自己拆自己的台",
        re.compile(
            r"空门|实际没人跑|没在跑|门是空的|从未 ?bump|从来没 ?bump"
            r"|一行都没读|两端都空转"
        ),
    ),
    (
        "error",
        "internal_name",
        "内部分层/SKU/私有文档名 —— 泄露 roadmap 与包装姿态",
        re.compile(
            r"C-词库层|C-语义层|快线 ?SKU|合规 ?SKU|数字-配置对照表"
            r"|P3_CONTENT_[A-Z_]+|RESCOPE"
        ),
    ),
    (
        "warn",
        "private_doc_ref",
        "指向私有文档的裸交叉引用 —— 只暴露「有这么份文档」，不含其内容;可接受但要看得见",
        re.compile(r"PLATFORM_ASK[A-Z_]*"),
    ),
]

# Files that are ALLOWED to discuss these categories: the gate's own source and its doc.
_EXEMPT = {"tools/check_doc_disclosure.py", "docs/DISCLOSURE_POLICY.md"}
_TEXT_SUFFIXES = {".md", ".markdown", ".rst", ".txt"}


def scan_text(path: str, text: str) -> list[tuple[int, str, str, str, str]]:
    """Return (line_no, severity, category, why, offending_line) for each hit in `text`."""
    if path in _EXEMPT:
        return []
    hits: list[tuple[int, str, str, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for severity, category, why, pattern in RULES:
            if pattern.search(line):
                hits.append((lineno, severity, category, why, line.strip()[:140]))
    return hits


def _candidate_text_files() -> list[str]:
    """Tracked files PLUS untracked-but-not-ignored ones.

    The untracked half is not an extra — it is the main event. Every disclosure incident so
    far arrived in a NEW document, and a gate that only reads `git ls-files` gives a brand-new
    file a free pass right up until the moment it is committed, which is exactly too late.
    `--others --exclude-standard` adds new files while still honouring .gitignore."""
    out = _git("ls-files", "-z", "--cached", "--others", "--exclude-standard").stdout
    return sorted(
        {f for f in out.split("\0") if f and Path(f).suffix.lower() in _TEXT_SUFFIXES}
    )


def scan_worktree() -> list[tuple[str, int, str, str, str, str]]:
    """Scan text files on disk — tracked AND new — i.e. what a commit could publish."""
    findings: list[tuple[str, int, str, str, str, str]] = []
    for f in _candidate_text_files():
        try:
            text = Path(f).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for lineno, severity, category, why, line in scan_text(f, text):
            findings.append((f, lineno, severity, category, why, line))
    return findings


def scan_history() -> list[tuple[str, int, str, str, str, str]]:
    """Scan every commit's tree — answers 'did this ever ship?', not for routine CI."""
    revs = _git("rev-list", "--all").stdout.split()
    findings: list[tuple[str, int, str, str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for rev in revs:
        listing = _git("ls-tree", "-r", "--name-only", "-z", rev).stdout
        for f in listing.split("\0"):
            if not f or Path(f).suffix.lower() not in _TEXT_SUFFIXES:
                continue
            blob = _git("show", f"{rev}:{f}", check=False)
            if blob.returncode != 0:
                continue
            for lineno, severity, category, why, line in scan_text(f, blob.stdout):
                key = (f, category, line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    (f"{rev[:9]}:{f}", lineno, severity, category, why, line)
                )
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_doc_disclosure", description=__doc__)
    ap.add_argument(
        "--all-history",
        action="store_true",
        help="also scan every commit (slow; answers 'did this ever ship?')",
    )
    args = ap.parse_args(argv)

    findings = scan_history() if args.all_history else scan_worktree()
    if not findings:
        scope = "全历史" if args.all_history else "工作树（已跟踪文本文件）"
        print(f"disclosure gate: PASS —— {scope} 无命中")
        return 0

    errors = [f for f in findings if f[2] == "error"]
    warns = [f for f in findings if f[2] == "warn"]
    by_category: dict[str, list] = {}
    for f in findings:
        by_category.setdefault(f[3], []).append(f)

    out = sys.stderr if errors else sys.stdout
    verdict = "FAIL" if errors else "PASS(有 warn)"
    print(f"disclosure gate: {verdict}\n", file=out)
    for category, items in sorted(by_category.items()):
        tag = "ERROR" if items[0][2] == "error" else "warn "
        print(f"[{tag}] {category}: {items[0][4]}", file=out)
        for loc, lineno, _s, _c, _w, line in items:
            print(f"  {loc}:{lineno}: {line}", file=out)
        print(file=out)
    print(
        f"error {len(errors)} 处 · warn {len(warns)} 处。"
        "处置:搬去私有仓,或按 docs/DISCLOSURE_POLICY.md 中性化改写。",
        file=out,
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
