"""跑批期间【规则内容】有没有变过 —— 按指纹，不按次数。

🔴 为什么按指纹：改一条 Tier-1 规则再跑一次，不需要判官、不需要真上游，
一次完整迭代可以是秒级 —— **那条路可能根本不产生一个"看起来像跑批"的动作**。
按次数记账会漏掉它；按指纹记不受速度影响：无论谁跑、怎么跑、多快，
只要检测内容变了又跑了，决策记录里就留下一个新的 `policy_snapshot_version`。

    policy_snapshot_version = ruleset.version=… ; ruleset.sha256=… ; registry.version=…

它由被测方在每条决策记录上盖章（`compose_policy_snapshot_version`），是**实测**，
不是操作者声明 —— 这正是它比 `detect_config`（人填的字符串）强的地方：
`detect_config` 填错了没人知道，指纹填不了错。

⚠️ 而在此之前，这个数【只在 WAL 里，不在产物里】：bundle 的 provenance 只有操作者声明的
`detect_config`。⇒ 想按指纹记账的人，得自己去翻 WAL —— 而记账要能从产物算出来，
否则它不是记账，是又一条靠人记得的纪律。
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from treval.active_eval.target import ProbeResult


class PolicyDriftError(Exception):
    """一跑之内规则内容变过 —— 这一跑测的不是同一套规则。

    🔴 fail-closed 的理由：分子分母来自不同的规则集，而合出来的那个率**看起来完全正常**。
    它是"冻结期零变更"那道门在【规则内容】这一侧的对应物，只不过那道门比对的是跑前跑后
    两个快照，这一条看的是**每一条探针自己盖的章**——粒度更细，且不依赖 admin 接口。
    """


def policy_snapshots(results: Iterable[ProbeResult]) -> tuple[str, ...]:
    """本批探针实际跑在哪些规则内容指纹上（去重、排序）。

    只读【决策记录】上的章：没有决策记录的探针（打不通 / 入口前就失败）没有章可读，
    跳过而不是记成空串 —— 空串会和"有章但内容为空"混成一格。
    """
    seen: set[str] = set()
    for pr in results:
        ev = pr.evidence
        if ev is None:
            continue
        psv = ev.record.decision.policy_snapshot_version
        if psv:
            seen.add(psv)
    return tuple(sorted(seen))


def assert_single_policy_snapshot(results: Iterable[ProbeResult]) -> tuple[str, ...]:
    """返回本批的指纹集合；多于一个 ⇒ 抛错（这一跑作废）。

    🔴 返回集合而不是布尔，是因为**记账要的就是这个集合** —— 把它写进 provenance 之后，
    "对这批语料改了检测内容又跑了几次"这个问题，第三方数产物里的不同指纹个数就能答，
    不必相信任何人的自述。
    """
    snaps = policy_snapshots(results)
    if len(snaps) > 1:
        raise PolicyDriftError(
            f"🔴 本跑期间规则内容变过 —— 决策记录上出现 {len(snaps)} 个不同的 "
            f"policy_snapshot_version，这一跑测的不是同一套规则：\n"
            + "\n".join(f"  · {s}" for s in snaps)
            + "\n  ⇒ 作废重跑。分子分母来自不同规则集，而合出来的率看起来完全正常"
        )
    return snaps
