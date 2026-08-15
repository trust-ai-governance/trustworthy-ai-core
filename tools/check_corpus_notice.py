"""corpus/NOTICE attribution gate (CI) — EV-COVERAGE-E3 §10.2 / acceptance 18.

`corpus/` is a PUBLIC repo, so `git push` IS redistribution (§10.2): the moment the first external
attack set is copied in, the third-party attribution obligation has ALREADY triggered — not "will
trigger later". This gate turns that obligation into a build check, built in the SHAPE of the other
four gates (tools/check_corpus_coverage.py et al.): same `[rule] subject: why` + detail, exit-1-on-hit.

It enforces FOUR things — BOTH directions AND meaningfulness (§10.2 — 查有意义不只查存在):
  1. corpus -> NOTICE : a source that NEEDS attribution (its `source` prefix is EXTERNAL-NATIVE,
     whether taken verbatim or `(payload-neutralized)` — a neutralized case keeps its external prefix)
     but is NOT listed in corpus/NOTICE  =>  red.
  2. NOTICE -> corpus : a source listed in corpus/NOTICE that appears in ZERO corpus cases  =>  red.
  3. probe-pin        : a probe-tool source (garak et al. — a probe's OUTPUT changes with the tool
     version) whose entry lacks version / probe / export-date  =>  red.
  4. meaningfulness   : a source with >= 1 corpus case whose NOTICE `commit` is a PLACEHOLDER (empty,
     all-zeros, TODO, xxxxxxx, or not a hex sha)  =>  red. A `0000000` must NOT pass, even though the
     NOTICE itself states an un-pinned attribution is not a verifiable provenance claim. This is the
     load-bearing anti-Pattern-B check: a sibling mechanism's bidirectional gate verified EXISTENCE
     but not MEANING, so a placeholder sha sailed through green — this gate does not repeat that.

🔴 EXTERNAL_NATIVE_SOURCES is IMPORTED from treval.active_eval.coverage (never re-hardcoded here) so
this gate tracks that allowlist's single source of truth. Day-one this gate is GREEN vacuously: every
shipped corpus case is `core-authored` (nothing external to attribute) and NOTICE carries zero source
entries — it BITES only when the first external-sourced case arrives.

Run the SAME way CI does — this imports `treval`, and CI installs only requirements (never
`pip install -e .`), so without the repo root on the path it dies at IMPORT (a gate that reds the
build having evaluated NOTHING). Match the pytest / corpus-gate steps exactly:

    PYTHONPATH=$PWD python tools/check_corpus_notice.py
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from treval.active_eval.corpus import CorpusError, load_corpus_tree
from treval.active_eval.coverage import EXTERNAL_NATIVE_SOURCES, source_prefix

_ROOT = Path(__file__).resolve().parents[1]
_CORPUS = _ROOT / "corpus"
_NOTICE = _CORPUS / "NOTICE"

# The repo's known probe-tool source family (§10.1: garak = 通用探针工具集). A probe tool's OUTPUT
# changes with its version, so a bare repo commit does not pin what we exported — a probe entry must
# ALSO pin version + probe name + export date (§10.2). Kept here (not folded into coverage.py's
# EXTERNAL_NATIVE_SOURCES, which is an axis of a different check) so a probe tool cannot dodge the pin
# rule by simply omitting `type: probe-tool`; a NOTICE entry may ALSO opt in via that field for a
# future probe tool not named here.
_PROBE_TOOL_SOURCES = frozenset({"garak"})

# The pins a probe-tool entry must additionally carry (§10.2). Missing / empty any of these => red.
_PROBE_PINS = ("version", "probe", "export-date")

# A valid abbreviated-or-full git sha: 7–40 hex chars. Anything else (TODO / xxxxxxx / wrong length /
# non-hex) is a placeholder; an all-zeros string — though it IS hex — pins nothing either (checked
# separately). Matched case-insensitively via a lower()'d input.
_SHA_RE = re.compile(r"[0-9a-f]{7,40}")

# A NOTICE section header `[<source-id>]` anchored at column 0. The id charset excludes '<' and '>' so
# the ENTRY FORMAT example `[<source-id>]` in the file's own documentation is NOT parsed as an entry.
_HEADER_RE = re.compile(r"\[([a-zA-Z0-9][\w.\-]*)\]\s*$")

# A top-level `key: value` line. Anchored at a non-space char, so indented license-text paragraph
# lines (which start with whitespace) never match and never pollute an entry's fields.
_FIELD_RE = re.compile(r"([a-zA-Z][\w\-]*):\s?(.*)$")


@dataclass(frozen=True)
class NoticeEntry:
    """One parsed `[source-id]` block: its id + its flat key->value fields (`commit`, and for a probe
    tool `version` / `probe` / `export-date`; `type: probe-tool` optionally opts a non-garak tool in)."""

    id: str
    fields: Mapping[str, str]

    def is_probe_tool(self) -> bool:
        return self.id in _PROBE_TOOL_SOURCES or self.fields.get("type") == "probe-tool"


@dataclass(frozen=True)
class NoticeViolation:
    """One attribution breach — printed `[rule] subject: why` + detail, the disclosure-gate shape so
    one mental model covers this gate and its four siblings."""

    rule: str
    subject: str
    why: str
    detail: str


def _is_placeholder_commit(commit: str) -> bool:
    """A commit that pins NOTHING (§10.2 meaningfulness rule): empty, not a 7–40-char hex sha (TODO /
    xxxxxxx / wrong length / non-hex), or all-zeros (hex but vacuous)."""
    c = commit.strip().lower()
    if not _SHA_RE.fullmatch(c):
        return True
    return set(c) == {"0"}


def parse_notice(text: str) -> dict[str, NoticeEntry]:
    """Parse a NOTICE body into {source-id: NoticeEntry}. A block opens at a `[source-id]` header at
    column 0; the top-level `key: value` lines until the next header are that entry's fields (indented
    license-text paragraphs never match _FIELD_RE, so they are ignored). The preamble before the first
    header (the self-describing statement + format docs) is not an entry. A later duplicate `[id]`
    header wins (last definition), which the bidirectional gate then still holds to the same rules."""
    entries: dict[str, NoticeEntry] = {}
    cur_id: str | None = None
    cur: dict[str, str] = {}
    for raw in text.splitlines():
        header = _HEADER_RE.match(raw)
        if header:
            if cur_id is not None:
                entries[cur_id] = NoticeEntry(id=cur_id, fields=dict(cur))
            cur_id = header.group(1)
            cur = {}
            continue
        if cur_id is None:
            continue
        field = _FIELD_RE.match(raw)
        if field:
            cur[field.group(1)] = field.group(2).strip()
    if cur_id is not None:
        entries[cur_id] = NoticeEntry(id=cur_id, fields=dict(cur))
    return entries


def check_notice(
    entries: Mapping[str, NoticeEntry], sources: Iterable[str]
) -> list[NoticeViolation]:
    """The four §10.2 rules over parsed NOTICE entries + the corpus `source` strings. Pure — the IO
    (read NOTICE, load corpus) is the caller's, so the rule core is unit-testable without a filesystem.

    A case NEEDS attribution iff its source prefix is EXTERNAL-NATIVE (imported allowlist). A
    `(payload-neutralized)` external case is covered by the SAME test — it retains its external prefix
    (`deepset:...@v (payload-neutralized)` -> `deepset`), so it is not a separate branch."""
    out: list[NoticeViolation] = []
    used = {source_prefix(s) for s in sources}
    needs_attr = {p for p in used if p in EXTERNAL_NATIVE_SOURCES}

    # 1. corpus -> NOTICE : every external source actually used must be attributed.
    for prefix in sorted(needs_attr):
        if prefix not in entries:
            out.append(
                NoticeViolation(
                    "missing-attribution",
                    prefix,
                    "external source used by >= 1 corpus case but not attributed in corpus/NOTICE (§10.2)",
                    f"add a [{prefix}] entry (project / license / url / commit sha)",
                )
            )

    # 2. NOTICE -> corpus : nothing attributed may be unused (attribution is bidirectional, §10.2).
    for src_id in sorted(entries):
        if src_id not in used:
            out.append(
                NoticeViolation(
                    "unused-attribution",
                    src_id,
                    "source listed in corpus/NOTICE but used by ZERO corpus cases (§10.2 — attribution is bidirectional)",
                    f"remove the [{src_id}] entry, or add the case(s) that use it",
                )
            )

    # 3 + 4 — content rules, on entries that are actually USED (an unused entry already reds via #2,
    # so a second violation on it would just be noise).
    for src_id in sorted(entries):
        if src_id not in used:
            continue
        entry = entries[src_id]
        if entry.is_probe_tool():
            missing = [k for k in _PROBE_PINS if not entry.fields.get(k, "").strip()]
            if missing:
                out.append(
                    NoticeViolation(
                        "probe-pin-missing",
                        src_id,
                        "probe-tool source must pin version + probe + export-date (§10.2 — probe output changes with version)",
                        f"[{src_id}] is missing: {', '.join(missing)}",
                    )
                )
        commit = entry.fields.get("commit", "")
        if _is_placeholder_commit(commit):
            out.append(
                NoticeViolation(
                    "placeholder-commit",
                    src_id,
                    "attributed source's `commit` is a PLACEHOLDER — pins nothing (§10.2 — 查有意义不只查存在)",
                    f"[{src_id}] commit={commit!r} is not a verifiable sha "
                    "(an un-pinned attribution is not a provenance claim)",
                )
            )
    return out


def collect_violations(notice_path: Path, corpus_root: Path) -> list[NoticeViolation]:
    """Read NOTICE + load the whole corpus tree, then apply check_notice over every case's `source`.
    A missing NOTICE is treated as ZERO entries (not a crash): that can never produce a false PASS —
    an external source then reds via rule 1 (missing-attribution), so a deleted NOTICE is self-caught."""
    text = notice_path.read_text(encoding="utf-8") if notice_path.is_file() else ""
    entries = parse_notice(text)
    tree = load_corpus_tree(corpus_root)
    sources = [c.source for cases in tree.values() for c in cases]
    return check_notice(entries, sources)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_corpus_notice", description=__doc__)
    ap.add_argument(
        "--notice",
        type=Path,
        default=_NOTICE,
        help="path to the NOTICE file (default: repo corpus/NOTICE)",
    )
    ap.add_argument(
        "--corpus-root",
        type=Path,
        default=_CORPUS,
        help="corpus root to scan (default: repo corpus/)",
    )
    args = ap.parse_args(argv)

    try:
        violations = collect_violations(args.notice, args.corpus_root)
    except CorpusError as e:
        print(f"corpus NOTICE gate: ERROR — malformed corpus: {e}", file=sys.stderr)
        return 1

    if not violations:
        print("corpus NOTICE gate: PASS —— 第三方语料署名双向一致且已 pin（§10.2）")
        return 0

    print(f"corpus NOTICE gate: FAIL —— {len(violations)} 处违反\n", file=sys.stderr)
    for v in violations:
        print(f"[{v.rule}] {v.subject}: {v.why}", file=sys.stderr)
        print(f"    {v.detail}", file=sys.stderr)
    print(
        "\n处置：为语料用到的每一路外部来源在 corpus/NOTICE 补一条含 commit sha 的署名"
        "（探针类另钉 version + probe + export-date）· 删除语料中已不再使用的来源署名 · "
        "占位 commit（空 / 0000000 / TODO / 非 sha）必须换成真实 sha —— 未 pin 的署名不是可核验的来源证明。"
        "详见 docs/issues/EV-COVERAGE-E3.md §10.2。",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
