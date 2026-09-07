"""🔴 冻结期零变更：比对【一个具名的面】，不是整块 buildinfo。

旧实现是 `before != after`，而 buildinfo 里含**我们自己发流量就会动**的计数器
（`arrival_evidence.egress_attempts` / `last_delivery_ok_at_ns`）⇒ **任何真的发过探针的跑
都会踩红**。两次真上游跑批逐次复现，唯二差异就是那两格。

⚠️ 这是本仓少见的【反向】实例：多数缺陷是"检查比它声称的更宽松"（假绿），这一处是**更严**（假红）。
假红一样贵 —— 它训练人去忽略这条门，而下一次真的变了就没人看了。

⚠️ 收窄不等于放松到"只留提示语里那三格"：`configured_base_url`（上游是谁）跑中变了，
这一跑就是在两个模型上测的 —— 它必须在面内。所以本文件同时守两侧：
噪声不许触发，而面内每一格都必须能单独触发。
"""

from __future__ import annotations

import copy

import pytest

from treval.citability import (
    CRITERIA_BLOCKERS,
    CRITERIA_VERSION,
    _FREEZE_SCOPE,
    freeze_drift,
    report_citability,
)

_FP = {
    "runtime": {
        "code_sha256": "a" * 64,
        "ruleset_sha256": "b" * 64,
        "ruleset_path": "deploy/system-test/config/ruleset.openai.yaml",
    },
    "detection_switches": {"tier2_injection_judge": True, "tier2_sample_rate": 1.0},
    "arrival_evidence": {
        "configured_base_url": "https://api.deepseek.com",
        "egress_attempts": 3,
        "last_delivery_ok_at_ns": 1,
    },
}


def _prov(before, after):
    return {
        "pinned": True,
        "window": [1, 2],
        "generated_at_ns": 3,
        "wal_segments": {"sha256": "sha256:" + "c" * 64},
        "admin_url_declared": True,
        "build_fingerprint_before": before,
        "build_fingerprint_after": after,
    }


def test_our_own_traffic_must_not_trip_the_freeze_gate() -> None:
    """🔴 本轮实测两次踩红的那一格：跑批自己把出域计数器推高了。

    什么让它红：把 `freeze_drift` 换回 `before != after`。
    """
    after = copy.deepcopy(_FP)
    after["arrival_evidence"]["egress_attempts"] = 13  # 我们自己发的 10 件 + 预检
    after["arrival_evidence"]["last_delivery_ok_at_ns"] = 999
    assert freeze_drift(_FP, after) == [], "自己发的流量把冻结门踩红了"


@pytest.mark.parametrize(
    "path,new",
    [
        (("runtime", "code_sha256"), "f" * 64),
        (("runtime", "ruleset_sha256"), "e" * 64),
        (("runtime", "ruleset_path"), "deploy/other.yaml"),
        (("detection_switches", "tier2_injection_judge"), False),
        (("arrival_evidence", "configured_base_url"), "https://elsewhere.example"),
    ],
)
def test_every_field_in_the_freeze_scope_trips_it_on_its_own(path, new) -> None:
    """🔴 面内每一格都必须能【单独】触发 —— 否则收窄就变成了开洞。

    `configured_base_url` 那一行是重点：它不在旧提示语点名的三格里，但跑中变了
    就意味着这一跑是在【两个模型】上测的。收窄的时候把它留在面内是一次有意的决定。

    什么让它红：从 `_FREEZE_SCOPE` 里删掉任意一格。
    """
    after = copy.deepcopy(_FP)
    cur = after
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = new
    # `detection_switches` 整块在面内（子键变化归到它名下）——面是按【格】定义的，不是按叶子
    expected = ".".join(
        path if tuple(path[:1]) != ("detection_switches",) else path[:1]
    )
    drift = freeze_drift(_FP, after)
    assert drift == [expected], f"{path} 变了却没被冻结门看见"


def test_the_blocker_names_which_field_changed() -> None:
    """🔴 一条只说"变了"的阻断，操作者无法判断该重跑还是该查门 —— 而本轮正是
    "假红"和"真变了"长得一模一样，才让两次跑批的 NOT CITABLE 被当成噪声读过去。

    什么让它红：把阻断文案换回不含字段名的常量。
    """
    after = copy.deepcopy(_FP)
    after["runtime"]["code_sha256"] = "f" * 64
    ok, blockers = report_citability(
        {
            "evidence_basis": "wal_anchored",
            "provenance": _prov(_FP, after),
            "report": {"integrity_summary": {"broken": 0, "unverified": 0}},
        }
    )
    assert not ok
    hit = [b for b in blockers if "冻结期间发生变更" in b]
    assert hit and "runtime.code_sha256" in hit[0], "阻断没说是哪一格变了"
    assert "冻结面：" in hit[0], "阻断必须写出它比对的是哪个面"


def test_a_clean_run_is_citable() -> None:
    """跑批只动了出域计数器 ⇒ 冻结期零变更 ⇒ 不因它阻断（本轮那份真数据就是这个形状）。"""
    after = copy.deepcopy(_FP)
    after["arrival_evidence"]["egress_attempts"] = 13
    ok, blockers = report_citability(
        {
            "evidence_basis": "wal_anchored",
            "provenance": _prov(_FP, after),
            "report": {"integrity_summary": {"broken": 0, "unverified": 0}},
        }
    )
    assert not [b for b in blockers if "冻结期间发生变更" in b]
    assert ok, blockers


def test_narrowing_the_gate_bumped_the_criteria_version() -> None:
    """🔴 本文件自己的规矩：更严 OR 更松都是【另一道门】，旧判决必须重判。

    收窄冻结面是一次变松 ⇒ 必须 bump。什么让它红：改了面却不 bump。
    """
    assert CRITERIA_VERSION >= 6
    assert (
        "build_fingerprint_changed" in CRITERIA_BLOCKERS
    )  # 身份不变，只是何时触发变了
    assert len(_FREEZE_SCOPE) == 5, (
        "改动冻结面 ⇒ 回来读一遍这条，并 bump CRITERIA_VERSION"
    )
