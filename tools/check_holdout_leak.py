#!/usr/bin/env python3
"""留出臂正文外泄门 —— 扫一份【要发出去的文本】，看它是否逐字含留出臂语料的正文。

🔴 存在的理由是一次实际违规（2026-09-16，Sr Core Engineer）：我在一段【指名发给规则专家】
的话里，逐字引了三条 W6 件的开头。W6 是留出臂，规则专家的硬隔离第一条就是不碰它的语料。
那是连续第四次接触，前三次是聚合数、这次是正文 —— **级别变了**。

⚠️ 规则专家的原话是这条工具存在的全部理由：
    「这一族已经连续四次靠发送端记得，那说明它需要一个结构，不是一次提醒。」
    ⇒ 四次都由发送端"记得"而其中一次没记住 —— 那不是注意力问题，是没有结构。

🔴 这道门【覆盖不了什么】，照规矩写出来，不冒充它是完整的：
  • 它扫【文件】。一段直接敲进聊天窗口的话不经过它 —— 那条路今天仍然靠发送端。
    ⇒ 配套的结构在另一半：跑 ⑥d 的脚本【只输出聚合数】，逐件正文不进任何可粘贴的位置。
      两半合起来才叫结构：一半让正文不出现在手边，一半在它真出现时拦住。
  • 它比的是【逐字片段】。改写过的转述抓不到 —— 而转述同样是接触。
  • 留出臂语料在仓外受控卷 ⇒ 卷不在时本门 **空过**，且【大声说出来】：
    一次空过的检查不许长得像一次通过。

用法：
    PYTHONPATH=$PWD python3 tools/check_holdout_leak.py <要发出的文件> [--corpus <留出臂目录>]...
退出码 0 = 没查到；1 = 查到逐字片段；2 = 一个留出臂目录都读不到（空过，不是通过）。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

# 🔴 留出臂的默认位置。写成【环境变量 + 显式参数】，不硬编码绝对路径：
# 语料在仓外受控卷，路径不进任何仓文件（本仓纪律）。读不到 ⇒ exit 2，不静默跳过。
_ENV = "TREVAL_HOLDOUT_DIRS"
# 一段多长才算"逐字引用"。取 24：一句中文短句约 12–20 字，英文一个从句约 24–40 字符。
# ⚠️ 这个数是【声明值】，不是从违规样本上调出来的 —— 调到刚好抓住已知那三句，
#    就是又一个"照着自己的测试集定义的判据"。
_SPAN = 24


def holdout_bodies(dirs: list[Path]) -> dict[str, str]:
    """{case_id: 正文} —— 只取作者可控的文本面（input + system_prompt + wire 消息）。"""
    out: dict[str, str] = {}
    for d in dirs:
        for p in sorted(d.glob("*.yaml")):
            c = yaml.safe_load(p.read_text(encoding="utf-8"))
            if not isinstance(c, dict):
                continue
            parts = [str(c.get("input") or ""), str(c.get("system_prompt") or "")]
            for m in c.get("messages") or []:
                ct = m.get("content")
                parts.append(
                    "".join(str(x.get("text", "")) for x in ct)
                    if isinstance(ct, list)
                    else str(ct or "")
                )
            out[str(c.get("id", p.name))] = " ".join(parts)
    return out


def leaks(
    text: str, bodies: dict[str, str], *, span: int = _SPAN
) -> list[tuple[str, str]]:
    """(case_id, 命中的片段) —— 正文里任意 `span` 长的连续片段出现在 `text` 中即算。"""
    hits: list[tuple[str, str]] = []
    for cid, body in bodies.items():
        b = " ".join(body.split())  # 归一空白：换行/缩进不该让逐字引用逃掉
        for i in range(0, max(len(b) - span + 1, 0)):
            frag = b[i : i + span]
            if frag in text:
                hits.append((cid, frag))
                break  # 一件报一次就够 —— 报 N 次只是把同一件事说 N 遍
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", type=Path, help="要发出去的文件")
    ap.add_argument("--corpus", type=Path, action="append", default=None)
    ap.add_argument("--span", type=int, default=_SPAN)
    args = ap.parse_args(argv)

    dirs = args.corpus or [
        Path(p) for p in (__import__("os").environ.get(_ENV, "").split(":")) if p
    ]
    dirs = [d for d in dirs if d.is_dir()]
    if not dirs:
        print(
            f"🔴 留出臂外泄门 **空过** —— 一个语料目录都读不到（--corpus 或 ${_ENV}）。\n"
            "   一次空过的检查不是一次通过：本门今天什么也没查。",
            file=sys.stderr,
        )
        return 2

    text = " ".join(args.target.read_text(encoding="utf-8").split())
    hits = leaks(text, holdout_bodies(dirs), span=args.span)
    if not hits:
        print(f"留出臂外泄门 ✅ {args.target}：未查到逐字片段（{len(dirs)} 个目录）")
        return 0
    print(
        f"🔴 留出臂外泄门：{args.target} 逐字含 {len(hits)} 件留出臂正文",
        file=sys.stderr,
    )
    for cid, frag in hits:
        print(f"   {cid}: …{frag}…", file=sys.stderr)
    print(
        "⚠️ 发送端负责：删掉正文，只发聚合数。转述同样是接触，本门抓不到转述。",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
