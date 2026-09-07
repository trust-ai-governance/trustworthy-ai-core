"""形状匹配门 —— 「答不出按哪个字段数，就是在按形状数」。

🔴 这条纪律已经栽过六次，每一次的形状都一样：**一个具名字段/枚举本来能回答这个问题，
而代码去匹配了字符串的形状。**

    ① `"control_" in case_id` 剔控制件            —— 在注入臂上剔掉 0 件，一直在跑、一直没生效；
                                                     换个臂又误剔了 6 件良性件
    ② `decision.made` 与枚举比对                  —— 字符串与 enum 名不是同一个东西
    ③ `"scored"` 命中 `"unscored"`                —— 子串把两个相反的结局并成一格
    ④ `[0-9a-f]{64}` 抓所有摘要                   —— 抓的是形状，不是"哪一个摘要"
    ⑤ 断言 `"llm01_benign_holdout_p1" in stderr`  —— 命中的是提示文案，不是解析后的路径
    ⑥ `POOL_V1.md:55-56` 明文写死不许用 id/文件名匹配 —— 而实现仍在用

而它至今只是一条纪律：**一条栽过六次的纪律，该有一道门。**

⚠️ 这道门拦不住全部六种（④⑤ 需要语义），但它拦得住**已经栽过两次的那一种**（对
`control_` 这类【字段值】做子串/前缀匹配），而那两次各花掉一条臂的正确性。

豁免与披露门同一条纪律：**光有标记不放行，理由是强制的** ——
每一次豁免都是一个【被写下的决定】。
"""

from __future__ import annotations

import argparse
import io
import re
import sys
import tokenize
from dataclasses import dataclass

from tools.check_disclosure import _ROOT, added_lines

_EXEMPT_PREFIXES = ("corpus/", "tests/fixtures/")

# 🔴 同行或相邻行的标记，必须带理由。`shape-ok` 与 `field-ok` 同义。
_EXEMPT_MARK_RE = re.compile(r"#\s*(?:shape-ok|field-ok)\s*:\s*(\S[^\n]*?)\s*$")

# 已知【字段值】的前缀 —— 它们各自都有一个具名字段可以判：
#   control_*     ⇒ attack_class          （不是 case_id / 文件名）
#   inj.tier2.*   ⇒ rule_id 全等，不是子串（`scored` 会命中 `unscored`）
#   AUDIT_RECORD_TYPE_* ⇒ record_type 枚举
_VALUE_PREFIXES = ("control_", "inj.tier2.", "AUDIT_RECORD_TYPE_")

# `"control_" in x` / `x.startswith("control_")` / `"control_" not in x`
_IN_RE = re.compile(r"""["']([A-Za-z0-9_.]+?)["']\s+(?:not\s+)?in\s+""")
_STARTSWITH_RE = re.compile(r"""\.startswith\(\s*["']([A-Za-z0-9_.]+?)["']""")

# 🔴 唯一的正解：对 `attack_class` 做前缀判。它【不是】违规，别把正确的那一行也报出来。
# 🔴 正解，不是违规：
#   · `attack_class.startswith("control_")` —— 剔控制件的唯一正确判据（POOL_V1 §1 写死）
#   · `rule_id.startswith("inj.tier2.")`    —— rule_id 就是具名字段，点分【命名空间】前缀是
#     全等语义的合法收窄；栽过的那次是 `"scored" in rule_id`（子串，会命中 `unscored`），
#     不是命名空间前缀。两者形状像，语义相反 —— 所以这里显式放行前者。
_SANCTIONED = re.compile(
    r"attack_class\s*\.\s*startswith|rule_id\s*\.\s*startswith|"
    r"\brid\s*\.\s*startswith"
)


@dataclass(frozen=True)
class Violation:
    path: str
    line: str
    why: str


# 🔴 第一版不剥注释/文档串，于是 6 处命中里 4 处是**在散文里描述这个错法**
# （本文件自己的模式表、以及测试 docstring 里的"什么让它红"）。
# **一道门如果主要在报自己的说明书，它会先被人关掉，再才可能拦住什么。**
# ⇒ 用 tokenize 求出"落在注释/字符串里的行号"，那些行不参与匹配 —— 按 token 判，
#   不按正则猜引号（后者正是这道门自己要禁的那种形状匹配）。
def _prose_lines(path: str) -> frozenset[int]:
    """文件里【整行都在注释或字符串里】的行号。tokenize 失败（语法错/编码）⇒ 空集，
    宁可多报也不漏报 —— 这道门宁噪不漏。"""
    try:
        src = (_ROOT / path).read_bytes()
    except OSError:
        return frozenset()
    out: set[int] = set()
    try:
        for tok in tokenize.tokenize(io.BytesIO(src).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                out.update(range(tok.start[0], tok.end[0] + 1))
    except (tokenize.TokenError, SyntaxError, UnicodeDecodeError):
        return frozenset()
    return frozenset(out)


def shape_hit(line: str) -> str | None:
    """这一行是不是在对一个【已知字段值】做形状匹配？命中则返回理由。"""
    if _SANCTIONED.search(line):
        return None  # 按 attack_class 前缀判 —— 这正是判据本身
    for rx, shape in ((_IN_RE, "子串"), (_STARTSWITH_RE, "前缀")):
        for lit in rx.findall(line):
            for pref in _VALUE_PREFIXES:
                if lit.startswith(pref) or pref.startswith(lit):
                    return (
                        f"对已知字段值 {lit!r} 做{shape}匹配 —— "
                        f"它有一个具名字段可以判（{pref!r} ⇒ 见模块头 §{pref}）"
                    )
    return None


def _marked_nearby(path: str, lineno: int) -> bool:
    """本行或相邻行有带理由的标记吗（与披露门同样放宽一行，防 formatter 把注释挤走）。"""
    try:
        lines = (_ROOT / path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    return any(
        _EXEMPT_MARK_RE.search(lines[i])
        for i in range(max(0, lineno - 2), min(len(lines), lineno + 1))
    )


def collect_violations(base: str) -> list[Violation]:
    out: list[Violation] = []
    prose: dict[str, frozenset[int]] = {}
    for path, lineno, line in added_lines(base):
        if not path or not path.endswith(".py") or path.startswith(_EXEMPT_PREFIXES):
            continue
        if lineno in prose.setdefault(path, _prose_lines(path)):
            continue  # 这一行整行在注释/字符串里 —— 是在【描述】这个错法，不是在犯它
        why = shape_hit(line)
        if why and not _marked_nearby(path, lineno):
            out.append(Violation(path, line.strip()[:100], why))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_shape_match", description=__doc__)
    ap.add_argument("--base", default="HEAD")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])
    bad = collect_violations(args.base)
    if not bad:
        print("shape gate: PASS —— 新增行没有对已知字段值做形状匹配")
        return 0
    print(f"shape gate: FAIL —— {len(bad)} 处疑似【按形状数】", file=sys.stderr)
    for v in bad:
        print(f"\n[{v.why}] {v.path}\n    {v.line}", file=sys.stderr)
    print(
        "\n怎么办 —— 先问一句：**我在按哪个字段数？**\n"
        "  • 答得出 ⇒ 改成对那个字段判（例：`attack_class.startswith('control_')`，"
        "不是 `'control_' in case_id`）\n"
        "  • 答不出 ⇒ 在该行加标注并写明为什么这里没有具名字段可用，例如\n"
        "           # shape-ok: 这是被测方的自由字符串，取值域是约定不是 schema\n"
        "  🔴 标注必须带理由 —— 光有标记不放行（无理由的豁免等于万能钥匙）。",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
