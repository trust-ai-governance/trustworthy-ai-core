"""Registration gate (EV-CN-BENIGN-N180 件1 · EV-CN-BASELINE §1.2/§6) — the STRUCTURE + gate for the
two-arm registration entry, built now; the ENTRIES themselves arrive with the freeze pack (机制先建、
条目随冻结包). Two arms = two corpus ids = TWO separate registration entries, each with its OWN
`corpus_sha` + n; a calib arm and a holdout arm sharing one id/sha turns "哪些件参与过拟合" back into a
verbal promise (§1 / 件1).

🔴 Three states, and NEITHER edge may read as a green "PASS":
  • unregistered — the block (or an arm's entry) is ABSENT. The entries are legitimately deferred to the
    freeze pack, so this does NOT fail the build; but it prints「未登记·未校验」, NEVER "PASS" — a green
    that parsed nothing is worse than no line at all (EV-CN-BASELINE §6.1: 一行叫「已登记」而没读任何条目
    的绿，比没有这一行更坏). This is why EV-CN-BASELINE §6 marked these gates 「未建」 until this landed.
  • ok           — BOTH arms present, each a well-formed entry, and their corpus_sha DIFFER.
  • fail         — the block is present but UNPARSEABLE / MALFORMED, or the two arms share one corpus_sha,
    or (with --corpus) a registered corpus_sha / n disagrees with the actual corpus. 🔴 fail-CLOSED: a
    corrupt registration block is a red, never a silent skip.

    PYTHONPATH=$PWD python tools/check_registration.py [--doc <path>] [--corpus <cn_root>]
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from treval.active_eval.corpus import CORPUS_FINGERPRINT_ALGO

# The two N180 arms this gate registers (件1). Distinct ids ⇒ distinct denominators ⇒ the fit set is
# structurally separable from the measurement set (件2 makes the calib arm unreachable; this records it).
EXPECTED_ARMS: tuple[str, ...] = ("llm01_cn_benign_calib", "llm01_cn_benign_holdout")

# 🔴 一份文档只承载它自己那一批的臂。把期望臂写死成一对，会让这道门对【别的批次的文档】报出
# 一个假的「未登记」—— 而一个人们学会忽略的告警，比没有告警更坏：真的缺登记那天，它长得一模一样。
# ⇒ 期望臂由 --arms 指定；缺省仍是 CN 那一对（既有调用点行为逐字不变）。
ARM_SETS: dict[str, tuple[str, ...]] = {
    "cn-benign": ("llm01_cn_benign_calib", "llm01_cn_benign_holdout"),
    "en-benign": ("llm01_benign_calib", "llm01_benign_holdout"),
    "cn-baseline": ("llm01_cn_injection", "llm01_cn_benign"),
}

_DEFAULT_DOC = (
    Path(__file__).resolve().parent.parent / "docs/issues/EV-CN-BENIGN-N180.md"
)

_SHA_RE = re.compile(r"sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^corpus id\s*:\s*(\S+)\s*$")
_N_RE = re.compile(r"^n\s*:\s*(.+?)\s*$")
_SHA_LINE_RE = re.compile(r"^corpus_sha\s*:\s*(.+?)\s*$")
# 件4 — the holdout arm's read-once marker (the run that first consumed it); empty/absent ⇒ unread.
_CONSUMED_RE = re.compile(r"^holdout_consumed\s*:\s*(.*?)\s*$")
# 件④ — the fingerprint ALGORITHM version this entry's corpus_sha was computed under.
_ALGO_RE = re.compile(r"^sha_algo\s*:\s*(\S+)\s*$")
# 追加④ — the entry this one was REPLACED BY. Present ⇒ this is a superseded (historical) entry; it stays
# in the block and stays recomputable, it is not deleted.
_SUPERSEDED_RE = re.compile(r"^superseded_by\s*:\s*(\S+)\s*$")
_FENCE_RE = re.compile(r"```.*?\n(.*?)```", re.DOTALL)


class RegistrationError(Exception):
    """A registration block that is present but cannot be trusted ⇒ fail-closed (never a silent skip)."""


@dataclass(frozen=True)
class RegEntry:
    corpus_id: str
    n: int
    corpus_sha: str
    holdout_consumed: str = (
        ""  # 件4 — the run marker that first consumed this arm (holdout only)
    )
    sha_algo: str = ""  # 件④ — fingerprint algo version (cfp-vN); "" = a pre-件④ entry
    superseded_by: str = (
        ""  # 追加④ — the sha that replaced this entry; "" = this entry is current
    )


def _registration_blocks(text: str) -> list[str]:
    """EVERY fenced block carrying registration records (a `corpus id :` line). 🔴 ALL of them, not the
    first: entries legitimately accumulate into more than one block as arms are registered at different
    times, and reading only the first silently drops the rest — an entry that is present but unread is
    indistinguishable from one that was never written, and the gate then reports 未登记 for a registered
    arm. Empty list ⇒ genuinely unregistered (deferral, not corruption)."""
    return [body for body in _FENCE_RE.findall(text) if "corpus id" in body]


def parse_registration(text: str) -> list[RegEntry]:
    """Parse every registration entry in the doc's registration block. A record is a group of lines
    holding a `corpus id :` line; the trailing 作用域 line (no corpus id) is skipped. 🔴 A record that
    names a corpus id but is missing / malforms its n or corpus_sha ⇒ RegistrationError (fail-closed:
    a corrupt block must not pass). No block at all ⇒ [] (the unregistered state, handled by the gate)."""
    blocks = _registration_blocks(text)
    if not blocks:
        return []
    entries: list[RegEntry] = []
    for record in [r for b in blocks for r in re.split(r"\n\s*\n", b)]:
        lines = [ln for ln in record.splitlines() if ln.strip()]
        cid = n_raw = sha_raw = None
        consumed = algo = superseded = ""
        for ln in lines:
            if m := _ID_RE.match(ln):
                cid = m.group(1)
            elif m := _N_RE.match(ln):
                n_raw = m.group(1)
            elif m := _SHA_LINE_RE.match(ln):
                sha_raw = m.group(1)
            elif m := _CONSUMED_RE.match(ln):
                consumed = m.group(1)
            elif m := _ALGO_RE.match(ln):
                algo = m.group(1)
            elif m := _SUPERSEDED_RE.match(ln):
                superseded = m.group(1)
        if cid is None:
            continue  # not an entry (e.g. the 作用域 scope line)
        if n_raw is None or sha_raw is None:
            raise RegistrationError(
                f"登记条目 {cid!r} 缺 n 或 corpus_sha —— 条目残缺，失败关闭（不作 PASS）"
            )
        if not n_raw.isdigit() or int(n_raw) <= 0:
            raise RegistrationError(
                f"登记条目 {cid!r} 的 n={n_raw!r} 不是正整数 —— 失败关闭"
            )
        if not _SHA_RE.match(sha_raw):
            raise RegistrationError(
                f"登记条目 {cid!r} 的 corpus_sha={sha_raw!r} 不是 sha256:<64 hex> —— 失败关闭"
            )
        entries.append(RegEntry(cid, int(n_raw), sha_raw, consumed, algo, superseded))
    return entries


@dataclass(frozen=True)
class RegResult:
    status: str  # "ok" | "unregistered" | "fail"
    lines: tuple[str, ...]


def check_registration(
    text: str,
    *,
    expected_arms: tuple[str, ...] = EXPECTED_ARMS,
    actual: dict[str, tuple[int, str]] | None = None,
    bundle: dict[str, object] | None = None,
) -> RegResult:
    """The gate over parsed entries. `actual` (optional, from --corpus) maps arm → (n, corpus_sha) of the
    ACTUAL corpus, so a 跑完删一件 that moved the sha, or an n that disagrees, reds (§4 两条登记条目).
    `bundle` (optional, from --bundle) is a fresh FPR bundle: 🔴 件4 — this is the PRODUCTION CALL SITE for
    holdout_reread_blocker (the registry lives here). A second FPR on a holdout arm already marked consumed
    by a DIFFERENT run reds (read-once)."""
    try:
        entries = parse_registration(text)
    except RegistrationError as e:
        return RegResult("fail", (f"登记门：FAIL —— {e}",))

    # 🔴 件⑨ — one corpus_id may legitimately carry SEVERAL entries: a new corpus_sha (e.g. the 第八族
    # landing) is a NEW entry, not a revision, and the old one stays as the anchor the already-fitted
    # numbers bind to. The LAST entry for an id is the CURRENT one; earlier ones are history. 🔴 Say how
    # many there are — silently keeping one of several is exactly the drop this repo keeps catching.
    history: dict[str, int] = {}
    by_id: dict[str, RegEntry] = {}
    for en in entries:
        history[en.corpus_id] = history.get(en.corpus_id, 0) + 1
        # 🔴 追加④ — CURRENT is the entry that is NOT superseded, read from `superseded_by:`, not from
        # "whichever came last in the file". Position is not a fact; the pointer is. A superseded entry
        # STAYS (old numbers remain recomputable against it) — it is retired, never deleted.
        if not en.superseded_by:
            by_id[en.corpus_id] = en
        elif en.corpus_id not in by_id:
            by_id[en.corpus_id] = (
                en  # only superseded entries seen so far — keep one to report against
            )
    present = [by_id[arm] for arm in expected_arms if arm in by_id]
    hist_note = " · ".join(
        f"{cid} 有 {n} 条条目（1 当前 + {n - 1} 历史/已被 superseded_by 取代，只对【当前】条目核实跑；"
        "历史条目保留且仍可复算）"
        for cid, n in sorted(history.items())
        if n > 1
    )

    # 🔴 a SHIPPED arm must match the corpus even before its pair lands (标定臂先交也要与实跑一致): validate
    # every PRESENT arm's sha/n against `actual` up front, so a 跑完删/改件 reds regardless of completeness.
    if actual:
        mism = _actual_mismatch_lines(present, actual)
        if mism:
            return RegResult("fail", ("登记门：FAIL —— 登记条目与实跑不一致", *mism))

    missing = [arm for arm in expected_arms if arm not in by_id]
    if missing:
        # 🔴 未登记 ≠ PASS. A deferred arm does not fail the build, but it says so LOUD and never prints the
        # word PASS (§6.1: a green that read nothing is worse than no line). Any PRESENT arm is validated
        # above — so 标定臂先交 reads as 已登记(·已核) while 留出臂待 §6.3 reads as 缺条目.
        checked = "，已与实跑核对一致" if (actual and present) else ""
        return RegResult(
            "unregistered",
            (
                "登记门：未登记·未校验 —— 🔴 本项【未通过】（不是 PASS）；两臂尚未同时登记（留出臂待冻结包/§6.3）",
                f"    已登记：{', '.join(sorted(by_id)) or '无'}{checked} · 缺条目：{', '.join(missing)}",
                "    机制先建、条目随冻结包（件1）；绿色 CI 不构成"
                "「两臂登记已核」的证据 —— 两臂齐备后本门才转 PASS/FAIL",
            )
            + ((f"    {hist_note}",) if hist_note else ()),
        )

    arm_entries = [by_id[arm] for arm in expected_arms]
    shas = {en.corpus_sha for en in arm_entries}
    if len(shas) < len(arm_entries):
        # 🔴 §5-5 — two arms sharing one corpus_sha is a merged entry wearing two hats: the fit/measure
        # separation is fake. Two entries, each with its OWN sha, or it reds.
        return RegResult(
            "fail",
            (
                "登记门：FAIL —— 🔴 两臂共用同一 corpus_sha ⇒ 拟合/测量分离是假的（合成一条即红，§5-5）",
                f"    {' · '.join(f'{en.corpus_id}={en.corpus_sha}' for en in arm_entries)}",
            ),
        )

    # 🔴 件4 — the PRODUCTION call site: this gate holds the registry (holdout_consumed markers), so it is
    # where holdout_reread_blocker actually runs. A second FPR on an already-consumed holdout sha reds.
    if bundle is not None:
        from treval.citability import holdout_reread_blocker

        consumed = {
            en.corpus_sha: en.holdout_consumed
            for en in arm_entries
            if en.holdout_consumed
        }
        reread = holdout_reread_blocker(bundle, consumed=consumed)
        if reread:
            return RegResult("fail", (f"登记门：FAIL —— {reread}",))

    scope = " · ".join(f"{en.corpus_id}(n={en.n})" for en in arm_entries)
    return RegResult(
        "ok",
        (
            f"登记门：PASS —— 两臂各一条登记条目、corpus_sha 互异（{scope}）"
            + (
                "；已与实跑核对一致"
                if actual
                else "；结构核对（未带 --corpus，未与实跑比对）"
            ),
        )
        + ((f"    {hist_note}",) if hist_note else ()),
    )


def _actual_mismatch_lines(
    entries: list[RegEntry], actual: dict[str, tuple[int, str]]
) -> list[str]:
    """sha/n disagreements between registered entries and the ACTUAL corpus (§4 与实跑一致). An arm absent
    under --corpus (public CI has no corpus) is skipped — structure-only there, not a mismatch."""
    out: list[str] = []
    for en in entries:
        got = actual.get(en.corpus_id)
        if got is None:
            continue
        a_n, a_sha = got
        if a_sha != en.corpus_sha:
            # 🔴 件④ — a sha mismatch has TWO possible causes and they must not be conflated: the CORPUS
            # changed, or the fingerprint ALGORITHM changed (an algo bump moves every sha at once). The
            # entry records the algorithm it was computed under, so the diagnosis is mechanical, not a guess.
            if en.sha_algo and en.sha_algo != CORPUS_FINGERPRINT_ALGO:
                out.append(
                    f"    🔴 {en.corpus_id}: sha 对不上，且登记算法 {en.sha_algo} ≠ 当前 "
                    f"{CORPUS_FINGERPRINT_ALGO} ⇒ 这是【算法漂移】不是【语料被改】—— "
                    "用当前算法重算该条目的 sha（件④）"
                )
            else:
                out.append(
                    f"    🔴 {en.corpus_id}: 登记 sha {en.corpus_sha} ≠ 实跑 sha {a_sha}"
                    f"（算法同为 {en.sha_algo or '未登记'}）⇒ 语料被改过？跑完删/改了件？§4"
                )
        if a_n != en.n:
            out.append(
                f"    🔴 {en.corpus_id}: 登记 n={en.n} ≠ 实跑 n={a_n}（分母对不上，§1.2 配套约束）"
            )
    return out


def _actual_from_corpus(
    root: Path, expected_arms: tuple[str, ...] = EXPECTED_ARMS
) -> dict[str, tuple[int, str]]:
    """Compute (n, corpus_sha) for each expected arm that exists under `root` (out-of-repo precheck)."""
    from treval.active_eval import load_corpus
    from treval.active_eval.corpus import corpus_fingerprint

    out: dict[str, tuple[int, str]] = {}
    for arm in expected_arms:
        d = root / arm
        if d.exists():
            cases = list(load_corpus(d))
            out[arm] = (len(cases), corpus_fingerprint(cases))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_registration", description=__doc__)
    ap.add_argument(
        "--doc",
        type=Path,
        default=_DEFAULT_DOC,
        help="doc carrying the registration block",
    )
    ap.add_argument(
        "--corpus",
        type=Path,
        default=None,
        help="CN corpus ROOT (out-of-repo) — enables sha/n vs actual-run comparison",
    )
    ap.add_argument(
        "--arms",
        choices=sorted(ARM_SETS),
        default="cn-benign",
        help="which arm PAIR this doc is expected to carry (缺省 cn-benign，既有行为不变)",
    )
    ap.add_argument(
        "--bundle",
        type=Path,
        default=None,
        help="a fresh FPR bundle (JSON) — 件4: reds if it re-reads an already-consumed holdout arm",
    )
    args = ap.parse_args(argv)
    try:
        text = args.doc.read_text(encoding="utf-8")
        bundle = (
            json.loads(args.bundle.read_text(encoding="utf-8")) if args.bundle else None
        )
    except (OSError, ValueError) as e:
        print(f"登记门：ERROR — {e}", file=sys.stderr)
        return 2
    arms = ARM_SETS[args.arms]
    actual = (
        _actual_from_corpus(args.corpus, arms)
        if args.corpus and args.corpus.exists()
        else None
    )
    result = check_registration(text, actual=actual, bundle=bundle, expected_arms=arms)
    stream = sys.stderr if result.status == "fail" else sys.stdout
    for ln in result.lines:
        print(ln, file=stream)
    return 1 if result.status == "fail" else 0


if __name__ == "__main__":
    raise SystemExit(main())
