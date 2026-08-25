"""Outbound blind-review gate (EV-CN-BENIGN-N180 件⑦) — scan material BEFORE it is sent to a blind
reviewer / material author, and refuse to send anything that would break their blindness.

🔴 WHY THIS EXISTS, stated plainly: **a leak in a message cannot be withdrawn.** Once a reviewer has read
"the current mis-block count is k", or "case X was the one", they cannot un-read it — and every isolation
clause we wrote (「补件作者不看跑结果」·「取材人不读权重表」·「写族 C 的人 ≠ 写规则的人」) then protects
nothing, silently, with every downstream number still self-consistent. **Receiver-side discipline cannot
repair this in principle**: by the time the receiver could apply it, they have already read the message.

🔴 And the score so far: we built gates for the CORPUS (check_benign / check_cn_negative_list /
check_cn_two_arm), for DOCS (check_doc_disclosure), and for PRODUCTS (check_disclosure / check_egress) —
and **zero** for messages. The blind-review protocol has failed at the SENDING end three times. A control
that exists everywhere except the one place it has actually failed is not a control.

WHAT IT REFUSES (each category is a distinct way to un-blind a reviewer):
  • a measured VALUE — a rate / percentage / k-of-n count: tells them how well it is going ⇒ directional
    leak (「知道偏高就会写得更温和」, the failure the domain side self-reported);
  • a `ci_` interval — the same, dressed as rigour;
  • a per-case VERDICT — 命中 / 漏检 / 误拦 / caught / missed / blocked next to an id;
  • a CASE ID — 🔴 the worst of them: "which one" is the single fact that lets an author write AROUND the
    failing case, so the补件 gets better while the SYSTEM does not (EV-EN-BENIGN-HOLDOUT §1.2 头号污染源).

Shape copied verbatim from `check_disclosure.py`: same marker escape (`# outbound-ok: <reason>` — 🔴 the
REASON is mandatory; a bare marker is a silent hole), same `file:line + category` output, exit 1 on hit.

    PYTHONPATH=$PWD python tools/check_outbound.py <file> [<file> ...]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# 🔴 An escape must be a WRITTEN DECISION, never a bare flag (same rule as check_disclosure's marker).
_EXEMPT_RE = re.compile(r"(?:#|<!--|//)\s*outbound-ok\s*:\s*(\S[^\n]*?)\s*(?:-->|$)")

# A placeholder is a template, not a value ("k={k}" is a form, not a leak).
_PLACEHOLDER_RE = re.compile(r"\{[^{}]*\}")

# --- the categories, each with the reason it un-blinds ------------------------------------------------ #
_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "case_id",
        "🔴 具体是哪一条 —— 头号污染源：作者会绕开那一条写，补件变好看而系统没变（EV-EN §1.2）",
        re.compile(
            r"\b(?:cn\.(?:calib|holdout)|benign|attack|inj)[.\w-]*\.\d{2,}\b"
            r"|\bcase[_ ]?id\s*[:=]"
        ),
    ),
    (
        "per_case_verdict",
        "逐案判定（命中/漏检/误拦/caught/missed/blocked）—— 等于告诉盲评方哪一条出了问题",
        re.compile(
            r"(?:命中|漏检|误拦|误标|放行)\s*[:：]|"
            r"\b(?:caught|missed|blocked|flagged|mis-?block(?:ed)?)\s*[:=]",
            re.I,
        ),
    ),
    (
        "ci_value",
        "ci_ 区间 —— 与实测值同类，只是穿了严谨的外衣",
        re.compile(r"\bci_(?:low|high)\b\s*(?:is|=|:)?\s*-?\d*\.\d"),
    ),
    (
        "measured_value",
        "🔴 分数 / 比率 / k-of-n —— 方向性泄漏：知道当前偏高，作者就会写得更温和（领域侧自陈的失效）",
        re.compile(
            r"\b\d{1,3}(?:\.\d+)?\s*%"  # a percentage
            r"|\bk\s*[:=]\s*\d+"  # k = 2
            r"|\b\d{1,3}\s*/\s*\d{1,3}\b"  # 5/86
            r"|\b(?:rate|score|fpr|recall|precision)\s*[:=]\s*-?\d*\.?\d+",
            re.I,
        ),
    ),
)


# 🔴 ㈣2 — the question is not "does this text leak" but "is this a leak FOR THIS RECIPIENT". The same
# sentence is harmless to the party that produced the number and fatal to the author who must stay blind
# to it. A single global answer is wrong for at least one of them, and it is wrong in the direction that
# does damage: a text cleared for one audience gets forwarded to the other.
# 🔴 DEFAULT IS `author` — THE STRICTEST. A criterion's default must fail CLOSED: the caller who forgets
# the flag is exactly the caller most likely to be forwarding something they did not think about.
AUDIENCES = ("author", "tested_party", "operator")
DEFAULT_AUDIENCE = "author"

# Which categories are a leak FOR WHOM. 🔴 `author` sees the whole list (they must stay blind to results);
# the tested party produced the numbers themselves, so a measured value is not news to them — but a
# per-case verdict or a case id still identifies OUR corpus, which they must not have.
_AUDIENCE_CATEGORIES: dict[str, frozenset[str]] = {
    "author": frozenset({"case_id", "per_case_verdict", "ci_value", "measured_value"}),
    "tested_party": frozenset({"case_id", "per_case_verdict"}),
    "operator": frozenset({"case_id"}),
}


def scan_text(
    path: str, text: str, audience: str = DEFAULT_AUDIENCE
) -> list[tuple[int, str, str, str]]:
    """(line_no, category, why, offending_line) for each hit. A line carrying `outbound-ok: <reason>` is
    exempt — WITH a reason; a bare marker is not an escape."""
    hits: list[tuple[int, str, str, str]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        if _EXEMPT_RE.search(raw):
            continue
        line = _PLACEHOLDER_RE.sub(" ", raw)
        active = _AUDIENCE_CATEGORIES[audience]
        for category, why, pattern in _RULES:
            if category in active and pattern.search(line):
                hits.append((lineno, category, why, raw.strip()[:140]))
                break  # one category per line is enough to refuse it
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_outbound", description=__doc__)
    ap.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="material about to be SENT",
    )
    ap.add_argument(
        "--audience",
        choices=AUDIENCES,
        default=DEFAULT_AUDIENCE,
        help="who receives it. 🔴 default `author` = STRICTEST: a forgotten flag must fail closed",
    )
    args = ap.parse_args(argv)

    findings: list[tuple[str, int, str, str, str]] = []
    for f in args.files:
        try:
            text = f.read_text(encoding="utf-8")
        except OSError as e:
            print(f"outbound gate: ERROR — {e}", file=sys.stderr)
            return 2
        for lineno, category, why, line in scan_text(str(f), text, args.audience):
            findings.append((str(f), lineno, category, why, line))

    scope = (
        f"作用域：{len(args.files)} 个待发文件 · 收件人 {args.audience} · 类别 "
        + " / ".join(sorted(_AUDIENCE_CATEGORIES[args.audience]))
    )
    if not findings:
        print(
            "outbound gate: PASS —— 待发材料未见分数/比率/区间/逐案判定/case_id（件⑦）"
        )
        print(f"    {scope}")
        print(
            "    🔴 消息的泄漏不可撤回，接收端自律在原理上救不了它 —— 语料/文档/产物都有门，"
            "这一道补的是【发送端】那个零"
        )
        return 0
    print(
        f"outbound gate: FAIL —— {len(findings)} 处会破坏盲评（不得发出）\n",
        file=sys.stderr,
    )
    print(f"    {scope}\n", file=sys.stderr)
    for path, lineno, category, why, line in findings:
        print(f"[{category}] {path}:{lineno}: {why}", file=sys.stderr)
        print(f"    {line}", file=sys.stderr)
    print(
        "\n🔴 发出去就收不回来了。改材料，不要加豁免；确需保留请写 "
        "`# outbound-ok: <理由>`（理由必填，每一条都是一个被写下的决定）",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
