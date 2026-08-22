"""Survival-probe liveness gate (EV-CN-BASELINE 批C · 架构师裁定二) — every control_survival_probe MUST
have FIRED in the run (been caught: blocked_or_flagged). One probe per attack family, each a calibration
case (not a sample; it exits every denominator + the carrier gate) carrying a known-catchable literal in
that family's form.

Why it exists — a survival probe that never fires is a FOREVER-GREEN test:
  • fired  ⇒ the detection surface reaches this family's FORM ⇒ a 0-catch on the family's natural Chinese
             cases is a COVERAGE GAP (our cases are outside the figure the detector accepts);
  • NOT fired ⇒ EITHER the surface has no entry for this form at all (a finding — the 0-catch is "no
             surface"), OR the probe is mis-written. Either way it must SURFACE, never pass silently.

🔴 Two halves (架构师 "对照件必须在跑前被验证真的会响"):
  1. STATIC / pre-run — the probe TEXT is verified to match the rule config OUT-OF-BAND, by a config
     holder (the config never lands in this repo). Done before the run.
  2. RUN-side (this gate) — given the run's CAUGHT case_ids, EVERY control_survival_probe must be among
     them. Config-free (reads outcomes, not rules). Pre-run (no --caught) ⇒ not-verified, said LOUD.

    PYTHONPATH=$PWD python tools/check_survival_probes.py --corpus <cn_root> --caught <caught_ids.txt>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from treval.active_eval import load_corpus
from treval.active_eval.corpus import CorpusError
from treval.case_contract import is_control_attack_class

_ATTACK_SUBDIR = "llm01_cn_injection"
_PROBE_CLASS = "control_survival_probe"


def _load_ids(path: Path | None) -> set[str] | None:
    """The run's CAUGHT case_ids (one per non-comment line). None ⇒ no run yet (pre-run)."""
    if path is None:
        return None
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.add(s)
    return out


def survival_probes(cases) -> list:
    """The control_survival_probe cases (one per family)."""
    return [
        c
        for c in cases
        if is_control_attack_class(c.attack_class) and c.attack_class == _PROBE_CLASS
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_survival_probes", description=__doc__)
    ap.add_argument(
        "--corpus", type=Path, required=True, help="the CN corpus ROOT (out-of-repo)"
    )
    ap.add_argument(
        "--caught",
        type=Path,
        default=None,
        help="the run's CAUGHT case_ids (one per line), extracted from the run's WAL/results",
    )
    args = ap.parse_args(argv)
    attack_dir = args.corpus / _ATTACK_SUBDIR
    if not attack_dir.exists():
        print(
            "survival-probe gate: PASS —— 🔴 本批语料不在本仓，本项未校验"
            f"（作用域：{attack_dir}）"
        )
        print(
            "    只在跑前预检/真跑后校验；绿色公开 CI 不构成探针存活的证据（§6/§8.5）"
        )
        return 0
    try:
        probes = survival_probes(load_corpus(attack_dir))
    except (CorpusError, OSError) as e:
        print(f"survival-probe gate: ERROR — {e}", file=sys.stderr)
        return 2

    caught = _load_ids(args.caught)
    ids = sorted(p.id for p in probes)
    if caught is None:
        # 🔴 pre-run — the probes EXIST but their firing is UNVERIFIED. A green here would be the exact
        # forever-green trap the acceptance forbids. Say so; never a bare PASS.
        print(
            "survival-probe gate: 🔴 未校验 —— 本批有 "
            f"{len(probes)} 条存活探针，但没有 --caught（真跑结果）⇒ 无法确认它们真的会响"
        )
        print(f"    探针：{', '.join(ids)}")
        print(
            "    真跑后用 --caught 传入被拦的 case_id；每条探针都必须在其中，否则该族 0 命中不可解读"
        )
        return 0

    missed = [p.id for p in probes if p.id not in caught]
    if missed:
        print(
            f"survival-probe gate: FAIL —— {len(missed)}/{len(probes)} 条存活探针在真跑里没响\n",
            file=sys.stderr,
        )
        for pid in missed:
            print(
                f"[survival-miss] {pid}: 该族探针未被拦 ⇒ 要么检测面对这族没有入口（该族 0 命中是"
                "『没测到面』不是『用例在图形外』），要么探针写歪了。两者都必须查，不许当作过。",
                file=sys.stderr,
            )
        return 1
    print(
        f"survival-probe gate: PASS —— {len(probes)}/{len(probes)} 条存活探针在真跑里都响了"
        "（每族检测面都有入口，各族 0 命中方可解读为覆盖缺口）"
    )
    print(f"    探针：{', '.join(ids)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
