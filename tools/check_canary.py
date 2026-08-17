"""Canary hygiene gate (EV-COVERAGE-E3F §7.4-3 / §6.2-3, batch 3b) — two checks in the SHAPE of the
other corpus gates (`[rule] subject: why` + detail, exit-1-on-hit):

  1. residual-literal (§7.4-3) : a corpus file still holding a LITERAL `CANARY-…` (F7 requires the
     `{{canary}}` placeholder — a public literal is knowable to any GitHub-trained model, so it is
     not a valid leak detector). Defends the half-migrated tree.
  2. carrier-rate  (§6.2-3)    : the canary line's carrier rate on the ATTACK arm vs the BENIGN arm
     differs by > 20pp ⇒ the canary's PRESENCE carries class information (the F6 collinearity).

🔴 Wired into CI in 3c (`.github/workflows/ci.yml` "Canary hygiene gate"): both checks go green once
3c's `{{canary}}` placeholders + symmetric benign prompts land. `tools/check_canary.py --corpus <dir>`
runs the SAME check locally.

🔴 §8.5.1 — a GREEN gate prints what it measured (both arms' n/% + which dirs it read + threshold/gap),
not just "PASS": a gate that shows its work only on failure is an unfalsifiable assertion when green,
and "measured the wrong denominator but passed anyway" is exactly this family's hardest-to-see failure.

Run the SAME way CI will (imports `treval`; needs the repo root on the path):

    PYTHONPATH=$PWD python tools/check_canary.py
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from treval.active_eval.canary import (
    CarrierRateGap,
    carrier_rate_gap,
    residual_literal_canaries,
)
from treval.active_eval.corpus import CorpusError, load_corpus_tree
from treval.cli.collect import carrier_arm_dirs

_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_CORPUS = _ROOT / "corpus"
_CARRIER_THRESHOLD = 0.20  # §6.2-3 — 20 percentage points

# §6.2-3 / §8.5.2 — the carrier-rate gate's two arms are DERIVED from CURATION (`carrier_arm_dirs()`),
# not hand-listed: the attack arm is the injection indicators' corpus, the benign arm the benign
# indicators'. The leak/output verticals (llm07 system-prompt-leak, llm02 disclosure, llm05 output) are
# excluded STRUCTURALLY — they bind none of those indicators, so the derivation never puts them in an
# arm (llm07's canary IS the leak target ⇒ its 100% carrier is intrinsic, not a decoy). So the arms
# widen automatically the day a benign indicator is bound to a new corpus — nothing to hand-maintain.


@dataclass(frozen=True)
class Violation:
    rule: str
    subject: str
    why: str
    detail: str


# 🔴 §7.4-3 exemption — llm02_sensitive_disclosure's canary carries TWO ROLES whose shape requirements
# CONFLICT (EV-AE9), and this round keeps the DLP role:
#   • DLP-bait   : must look like a REAL secret (sk-… / AKIA…) so the PRODUCTION `secret-block-response`
#                  rule fires on a verbatim leak — used by the gateway.
#   • leak-oracle: must be UNKNOWABLE to the model (never a public literal) — used by OUR own
#                  `is_sensitive_disclosed` / `not_leaked`, which IS a leak detector.
# The generic F7 runtime value `CANARY-<hex>` (hyphen + lowercase) satisfies the oracle but breaks the
# sk-/AKIA regex, so the two cannot both hold. Keeping the DLP shape means llm02's `not_leaked` RETAINS
# the exact weakness F7 exists to remove — a public literal is knowable to any GitHub-trained model, so
# the canary's appearance can't be cleanly attributed to a system-prompt leak. 🔴 This is a DECLARED
# LIMITATION, not a solved problem: it rides WITH the sensitive_disclosure_rate citation_form
# (LEAK_CANARY_* in citability.py). F7's swap is therefore 144 files, not 158. BACKLOG (not this batch):
# a pattern-aware runtime value (`sk-` + 40 lowercase alnum / `AKIA` + 16 uppercase) that matches the
# DLP regex AND rotates per run would let llm02 rejoin F7 and retire the limitation.
_RESIDUAL_EXEMPT_SUBDIRS = ("llm02_sensitive_disclosure",)


def _residual_violations(corpus_root: Path) -> list[Violation]:
    """§7.4-3 — every corpus file still holding a literal `CANARY-…`, except the EV-AE9 exemption."""
    out: list[Violation] = []
    for path in sorted(corpus_root.rglob("*.yaml")):
        if path.parent.name in _RESIDUAL_EXEMPT_SUBDIRS:
            continue
        hits = residual_literal_canaries(path.read_text(encoding="utf-8"))
        if hits:
            rel = path.relative_to(_ROOT)
            out.append(
                Violation(
                    "residual-literal",
                    str(rel),
                    "文件仍含字面金丝雀，F7 要求改成 {{canary}} 占位符（公开字面量对任何含 GitHub 的模型不再是检漏器）",
                    f"命中 {len(hits)} 处：{', '.join(sorted(set(hits))[:5])}",
                )
            )
    return out


def _carrier_gap(
    corpus_root: Path,
    attack_dirs: tuple[str, ...],
    benign_dirs: tuple[str, ...],
) -> CarrierRateGap:
    """§6.2-3 — the two-arm carrier-rate gap over the DERIVED attack vs benign corpora. carrier_rate_gap
    classifies each case by its attack_class, so passing both arms' cases together is correct."""
    tree = load_corpus_tree(corpus_root)
    dirs = tuple(dict.fromkeys(attack_dirs + benign_dirs))  # de-dupe, order-stable
    cases = [c for sub in dirs for c in tree.get(sub, ())]
    return carrier_rate_gap(cases, threshold=_CARRIER_THRESHOLD)


def _carrier_report(
    gap: CarrierRateGap,
    attack_dirs: tuple[str, ...],
    benign_dirs: tuple[str, ...],
) -> tuple[str, str]:
    """(scope-line, measurement-line) — 🔴 §8.5.1: what the gate MEASURED and which dirs it READ. The
    scope is the SAME derived tuple used to select the cases, never a second hardcoded copy (§8.5.2③)."""
    scope = (
        f"作用域（从 CURATION 推导）：攻击臂 = {', '.join(attack_dirs)} · "
        f"良性臂 = {', '.join(benign_dirs)}"
    )
    meas = (
        f"携带率：攻击 {gap.attack[0]}/{gap.attack[1]} ({gap.attack_rate:.1%}) · "
        f"良性 {gap.benign[0]}/{gap.benign[1]} ({gap.benign_rate:.1%}) · "
        f"差 {gap.gap * 100:.1f}pp（阈值 {_CARRIER_THRESHOLD * 100:.0f}pp）"
    )
    return scope, meas


def _carrier_violation(gap: CarrierRateGap) -> list[Violation]:
    """§6.2-3 — a Violation iff the gap exceeds the threshold. The numbers themselves are printed
    UNCONDITIONALLY by _carrier_report, so this carries only the FAIL verdict."""
    if not gap.exceeds:
        return []
    return [
        Violation(
            "carrier-rate",
            "attack↔benign",
            f"金丝雀携带率两臂相差 {gap.gap * 100:.1f}pp > 20pp —— 金丝雀的【存在】携带了类别信息（F6 共线）",
            f"攻击臂 {gap.attack[0]}/{gap.attack[1]} ({gap.attack_rate:.1%}) vs "
            f"良性臂 {gap.benign[0]}/{gap.benign[1]} ({gap.benign_rate:.1%})",
        )
    ]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_canary", description=__doc__)
    ap.add_argument("--corpus", type=Path, default=_DEFAULT_CORPUS)
    args = ap.parse_args(argv)
    attack_dirs, benign_dirs = carrier_arm_dirs()
    try:
        residual = _residual_violations(args.corpus)
        gap = _carrier_gap(args.corpus, attack_dirs, benign_dirs)
    except (CorpusError, OSError) as e:
        print(f"canary gate: ERROR — {e}", file=sys.stderr)
        return 2
    scope, meas = _carrier_report(gap, attack_dirs, benign_dirs)
    violations = residual + _carrier_violation(gap)
    if not violations:
        # 🔴 §8.5.1 — a green gate STILL prints its measurement + scope (no early return before these
        # lines, even when both arms carry 0 ⇒ gap 0pp): green must be falsifiable, not a bare "PASS".
        print(
            "canary gate: PASS —— 无字面金丝雀残留，两臂携带率差 ≤ 20pp（§7.4-3 / §6.2-3）"
        )
        print(f"    {scope}")
        print(f"    {meas}")
        return 0
    print(f"canary gate: FAIL —— {len(violations)} 处违反\n", file=sys.stderr)
    print(f"    {scope}", file=sys.stderr)
    print(f"    {meas}", file=sys.stderr)
    for v in violations:
        print(f"[{v.rule}] {v.subject}: {v.why}", file=sys.stderr)
        print(f"    {v.detail}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
