"""CN single-case leverage table (EV-CN-BENIGN-N180 件8.1) — 🔴 operator_only (Tier-0). For each family f,
the total FPR a SINGLE hypothetical mis-block in f would produce under three口径 (自然/先验/平权). Answers
「最坏情况下加权能把这个数搬多远」BEFORE the freeze run — the observed sensitivity band degenerates at k=0
and arrives too late; this needs no observation.

🔴 Input is ONLY prior weights + per-family COUNTS (from post-hoc labels) — ZERO detection results. The
operator input is out-of-repo (grouped counts are operator_only, §1.2). One JSON:

    {"family_counts": {"f1": 12, ...}, "prior_weights": {"f1": 0.2, ...}}

    PYTHONPATH=$PWD python tools/cn_leverage_table.py --input <table.json>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from treval.cn_family_leverage import leverage_swing, leverage_table


def _pct(x: float) -> str:
    return f"{x:.2%}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cn_leverage_table", description=__doc__)
    ap.add_argument(
        "--input", type=Path, required=True, help="JSON: family_counts + prior_weights"
    )
    args = ap.parse_args(argv)
    try:
        data = json.loads(args.input.read_text(encoding="utf-8"))
        counts = {str(k): int(v) for k, v in data["family_counts"].items()}
        weights = {str(k): float(v) for k, v in data.get("prior_weights", {}).items()}
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"leverage table: ERROR — {e}", file=sys.stderr)
        return 2

    rows = leverage_table(counts, weights)
    if not rows:
        print("leverage table: 无族计数输入 —— 无表可出")
        return 0
    print(
        "单件杠杆表（operator_only · 零检测结果 · 若恰有一件误拦落在该族，总 FPR 各口径）："
    )
    print("    族            n     自然口径    先验口径    平权口径")
    for r in rows:
        print(
            f"    {r.family:<12} {r.n:>4}   {_pct(r.natural):>8}  {_pct(r.prior):>8}  {_pct(r.equal):>8}"
        )
    print(
        f"    🔴 加权杠杆（最坏族 先验/自然）：{leverage_swing(rows):.1f}× —— "
        "「最坏情况下加权能把这个数搬多远」，不是「这次搬了多远」；表内零个检测结果，非边界图"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
