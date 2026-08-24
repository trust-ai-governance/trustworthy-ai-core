"""Send material through the file channel — 🔴 the ONE call site of the outbound gate (件⑦ / ㈢3).

WHY THIS FILE EXISTS AT ALL: `check_outbound.py` had no caller. This is the FOURTH time in this family —
`Producer.subject` declared but unenforced · `holdout_reread_blocker` defined but uncalled ·
`SpeechActShadowSeparationRate` built but unwired · and now a gate written specifically because the
protocol had failed at the sending end, itself never placed on the sending path. 🔴 A gate with no caller
never bites, and its tests stay green the whole time, so it reads exactly like a gate that works.

So sending is not "copy the file"; sending is THIS, and the gate is on the inside of it. There is no
supported path that copies material to the channel without passing through here.

🔴 Delivery is reported in RECIPIENT terms, never ours (㈤): "已送达（版本 X）" is a claim about our own
action and is true the moment we act, whether or not anything arrived. What matters is whether the other
side can take it, and WHICH VERSION they would take — so every delivery carries a content hash, and the
receipt says what is retrievable, not what we did.

    PYTHONPATH=$PWD python tools/send_material.py --audience author --to <dir> <file> ...
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
from pathlib import Path

from tools.check_outbound import AUDIENCES, DEFAULT_AUDIENCE, scan_text


def content_hash(path: Path) -> str:
    """The version coordinate. 🔴 Without it "we sent it" and "which version we sent" are the same
    sentence — and they are not the same fact: a copy taken minutes before an edit is a different
    document that answers to the same name."""
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def gate(files: list[Path], audience: str) -> list[tuple[str, int, str, str, str]]:
    """Every outbound finding across `files` for this recipient. Empty ⇒ safe to send."""
    out: list[tuple[str, int, str, str, str]] = []
    for f in files:
        for lineno, category, why, line in scan_text(
            str(f), f.read_text(encoding="utf-8"), audience
        ):
            out.append((str(f), lineno, category, why, line))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="send_material", description=__doc__)
    ap.add_argument("files", nargs="+", type=Path)
    ap.add_argument("--to", type=Path, required=True, help="channel directory")
    ap.add_argument(
        "--audience",
        choices=AUDIENCES,
        default=DEFAULT_AUDIENCE,
        help="🔴 default `author` = strictest; a forgotten flag must fail closed",
    )
    args = ap.parse_args(argv)

    findings = gate(args.files, args.audience)
    if findings:
        print(
            f"send: REFUSED —— {len(findings)} 处对收件人 `{args.audience}` 构成泄漏（件⑦）",
            file=sys.stderr,
        )
        for path, lineno, category, why, line in findings:
            print(f"[{category}] {path}:{lineno}: {why}", file=sys.stderr)
            print(f"    {line}", file=sys.stderr)
        print(
            "\n🔴 发出去就收不回来了 —— 改材料或改收件人，不要绕过本命令复制文件",
            file=sys.stderr,
        )
        return 1

    args.to.mkdir(parents=True, exist_ok=True)
    print(f"send: 通过盲评门（收件人 {args.audience}）—— 以下版本【对方可取】：")
    for f in args.files:
        dest = args.to / f.name
        shutil.copy2(f, dest)
        print(f"    对方可取：{f.name}（版本 {content_hash(dest)}）")
    print(
        "    🔴 状态以【对方能否取到 / 取到哪一版】表述 —— "
        "「我方已发出」是我方动作，做完不是状态，取到才是"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
