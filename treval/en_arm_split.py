"""EV-EN-BENIGN-HOLDOUT 件1 — the English benign arm's FIT/MEASURE split, as a REPLAYABLE artifact.

🔴 WHY THIS FILE EXISTS. The split was performed upstream. Had we simply copied the resulting file lists
into two directories, "which cases τ was fitted on" would be a fact recoverable only by running someone
else's code — and a split only they can reproduce is, for our purposes, no split at all: we could not tell
a corrected split from a silently altered one. That is the SAME argument as `CORPUS_FINGERPRINT_ALGO`
(件④), one level up: 只有跑别人代码才知道的切分，等于没有切分.

⇒ So the split is recorded here as a SEED + AN ALGORITHM + TWO EXPECTED ID-SET DIGESTS, and a gate replays
it on every run. Anyone can recompute it from the corpus alone.

    ids   = sorted(case.id for case in llm01_benign)          # n = 173
    random.Random(EN_SPLIT_SEED).shuffle(ids)                 # in place
    calib, holdout = ids[:EN_CALIB_N], ids[EN_CALIB_N:]       # 87 / 86

Digest encoding (`id_set_sha12`): the ids of one arm, SORTED, joined with "\\n", sha256, first 12 hex.
🔴 Sorted INSIDE the digest so it fingerprints the SET, not the shuffle order — the arms' membership is
the fact worth pinning; the order the shuffle happened to emit is not.

🔴 A ONE-OFF COST, stated plainly (施工单 件2): splitting the arm changes which corpus the English FPR
producer reads. Every historical English pack's FPR `corpus_sha` therefore stops matching. That is
CORRECT — those numbers really were produced on the merged arm, and the mismatch is the anchor doing its
job — but it is recorded here so it does not later read as an accident.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Iterable

# The upstream split, replayable from these three constants alone.
EN_SPLIT_SEED = 20260823
EN_CALIB_N = 87
EN_TOTAL_N = 173

EN_SOURCE_SUBDIR = (
    "llm01_benign"  # the pre-split merged arm (history; see the one-off cost above)
)
EN_CALIB_SUBDIR = "llm01_benign_calib"
EN_HOLDOUT_SUBDIR = "llm01_benign_holdout"

# 🔴 The REGISTERED id-set digests. A replay that disagrees with these fails CLOSED (see
# `assert_split_matches_registration`): either the corpus moved under us or the split algorithm did, and
# both are things we must be told about rather than absorb silently.
EN_ARM_ID_SET_SHA12: dict[str, str] = {
    EN_CALIB_SUBDIR: "7841efaf163a",
    EN_HOLDOUT_SUBDIR: "0d25cf13be24",
}


class SplitReplayError(Exception):
    """The replayed split does not match the registered digests ⇒ fail closed, never absorb."""


def id_set_sha12(ids: Iterable[str]) -> str:
    """Fingerprint an arm's MEMBERSHIP: sorted ids, "\\n"-joined, sha256, first 12 hex."""
    return hashlib.sha256("\n".join(sorted(ids)).encode("utf-8")).hexdigest()[:12]


def replay_split(all_ids: Iterable[str]) -> tuple[list[str], list[str]]:
    """Replay the seeded split over the FULL merged id list ⇒ (calib_ids, holdout_ids). Pure: same input,
    same output, on any machine, without our corpus directories existing."""
    ids = sorted(all_ids)
    # nosec B311 — a SEEDED, deliberately REPRODUCIBLE shuffle is the whole point here: the split must
    # replay identically on any machine. A cryptographic RNG would make it unreproducible, i.e. would
    # destroy the property this module exists to provide. Not used for any security decision.
    random.Random(EN_SPLIT_SEED).shuffle(ids)  # noqa: S311  # nosec B311
    return ids[:EN_CALIB_N], ids[EN_CALIB_N:]


# --------------------------------------------------------------------------- #
# 🔴 THE ARM'S PROVENANCE IS TWO LAYERS (裁定② path D)
# --------------------------------------------------------------------------- #
# An arm legitimately GROWS: new families are authored into the holdout arm. Two properties were being
# conflated by a single whole-arm digest, and separating them is the whole fix:
#
#   • the CONTAMINATION property — "no case in this arm was ever used to fit τ". Newly authored cases
#     satisfy it BY CONSTRUCTION: they did not exist when τ was fitted. Growth cannot break it.
#   • the AUDIT property — "the part of this arm that came from the seeded split still replays". THIS is
#     what a whole-arm digest was actually measuring, and it is the one growth breaks.
#
# 🔴 SO: the seed-derived SUBSET must replay; the authored remainder is recorded, not replayed.
#
# 🔴 AND THE ROAD EXPLICITLY CLOSED: never re-run the split over the grown id list to "make it match
# again". Re-splitting reshuffles ALL ids, so cases that already fitted τ — sitting in the calib arm —
# would wash into the holdout arm. That is precisely the contamination this whole片 exists to prevent, and
# it is far worse than a stale digest. A digest that no longer matches is visible; a fit case quietly
# rehomed into the measurement arm is not. `assert_never_resplit` below makes the refusal mechanical.
_SEED_MEMBERS_FILE = "en_seed_members.json"


def seed_members() -> dict[str, list[str]]:
    """The recorded seed-split membership per arm (the audit record). Read from the shipped manifest."""
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parent / _SEED_MEMBERS_FILE
    return json.loads(path.read_text(encoding="utf-8"))["seed_members"]


def assert_never_resplit(all_ids: Iterable[str]) -> None:
    """🔴 Refuse to replay the split over anything but the ORIGINAL id count. Re-splitting a GROWN arm set
    silently rehomes already-fitted cases into the measurement arm — the exact contamination this module
    exists to prevent, arriving disguised as a fix for a mismatched digest."""
    n = len(set(all_ids))
    if n != EN_TOTAL_N:
        raise SplitReplayError(
            f"拒绝在 {n} 条上重跑种子切分（原始为 {EN_TOTAL_N} 条）—— 重切会把【已拟合过 τ 的】标定件"
            "洗进留出臂，那正是本片要挡的污染，比一个对不上的摘要严重得多。"
            "臂长大了就用【子集重放】(assert_seed_subset_replays)，不要重切"
        )


def assert_seed_subset_replays(
    calib_ids: Iterable[str], holdout_ids: Iterable[str]
) -> None:
    """🔴 Fail-CLOSED on the AUDIT property: within each arm, the seed-derived subset must still be exactly
    what the recorded split produced. Catches a seed change, a case moved between arms, a case edited into
    a different id, and a seed-split case DELETED — while allowing the arm to grow by authoring.
    Never a warning: a fit case in the measurement arm is invisible after the run, so it must be caught
    before it."""
    recorded = seed_members()
    present = {EN_CALIB_SUBDIR: set(calib_ids), EN_HOLDOUT_SUBDIR: set(holdout_ids)}
    problems: list[str] = []
    for arm, seed_ids in recorded.items():
        missing = sorted(set(seed_ids) - present[arm])
        if missing:
            problems.append(
                f"{arm}: 种子切分件缺失 {len(missing)} 条（首个 {missing[0]}）"
            )
        # 🔴 WHAT THIS LINE ACTUALLY GUARDS — found by a mutation that SURVIVED. I wrote it believing
        # it checked the arms; with set semantics it cannot. If nothing is `missing`, the seed set is
        # a subset of what is present, so the intersection IS the seed set and the digest always
        # matches. Via the arms this branch is unreachable. What it really guards is the MANIFEST:
        # edit the recorded seed membership and this is the only thing that notices — and the
        # manifest is the one file the whole audit rests on.
        # 🔴 The general lesson, same family as「测试测的是不是它声称的东西」: a check you believe
        # guards A while it actually guards B passes every review, because both A and B sound right.
        # Only a surviving mutation says which one it is.
        got = id_set_sha12(set(seed_ids) & present[arm])
        if got != EN_ARM_ID_SET_SHA12[arm]:
            problems.append(
                f"{arm}: 种子子集重放 {got} ≠ 登记 {EN_ARM_ID_SET_SHA12[arm]}"
            )
        # a seed case of ONE arm must never appear in the OTHER
        other = EN_HOLDOUT_SUBDIR if arm == EN_CALIB_SUBDIR else EN_CALIB_SUBDIR
        crossed = sorted(set(seed_ids) & present[other])
        if crossed:
            problems.append(
                f"🔴 {arm} 的种子件出现在 {other}（{len(crossed)} 条，首个 {crossed[0]}）"
                "—— 拟合件跑到测量臂里去了"
            )
    if problems:
        raise SplitReplayError(
            "英文两臂【种子子集】重放与登记不一致 ⇒ 失败关闭。"
            + "；".join(problems)
            + f"。（种子 {EN_SPLIT_SEED} · 前 {EN_CALIB_N} 条为标定 · 编码 sorted(ids) 以 \\n 连接取 "
            "sha256[:12]）—— 拟合件落进测量臂在跑完之后是看不出来的，所以只能在跑之前拦"
        )


def assert_split_matches_registration(
    calib_ids: Iterable[str], holdout_ids: Iterable[str]
) -> None:
    """Back-compat name for the WHOLE-ARM check. 🔴 Prefer `assert_seed_subset_replays`: an arm that grew
    by authoring is not a defect, and this stricter form reds on legitimate growth."""
    actual = {
        EN_CALIB_SUBDIR: id_set_sha12(calib_ids),
        EN_HOLDOUT_SUBDIR: id_set_sha12(holdout_ids),
    }
    bad = {a: got for a, got in actual.items() if got != EN_ARM_ID_SET_SHA12[a]}
    if bad:
        detail = " · ".join(
            f"{arm}: 重放 {got} ≠ 登记 {EN_ARM_ID_SET_SHA12[arm]}"
            for arm, got in bad.items()
        )
        raise SplitReplayError(
            f"英文两臂切分重放与登记不一致 ⇒ 失败关闭。{detail}。"
            f"（种子 {EN_SPLIT_SEED} · 前 {EN_CALIB_N} 条为标定 · 编码 sorted(ids) 以 \\n 连接取 "
            "sha256[:12]）—— 拟合件落进测量臂在跑完之后是看不出来的，所以只能在跑之前拦"
        )
