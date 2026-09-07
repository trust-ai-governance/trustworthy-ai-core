"""🔴 规则内容有没有变过 —— 按【实测指纹】，不按跑批次数。

`policy_snapshot_version` 是被测方在每条决策记录上盖的章（ruleset.version / ruleset.sha256 /
registry.version）。它比 `detect_config`（操作者声明的字符串）强的地方只有一条：
**声明填错了没人知道，指纹填不了错。**

⚠️ 而在此之前这个数【只在 WAL 里，不在产物里】—— 想按指纹记账的人得自己去翻 WAL，
而记账要能从产物算出来，否则它不是记账，是又一条靠人记得的纪律。

⚠️ 本文件守的是【一跑之内】那一半（跑批完整性）。跨跑去重计数是**另一件事**
（在积累起来的 provenance 上做的一次查询），不要因为基座落地就以为记账也有了。
"""

from __future__ import annotations

import pytest
from trustworthy_ai.v1 import request_context_pb2 as rc_pb

from treval.active_eval.target import ProbeResult
from treval.models import AuditEvidence, EvidenceRef, IntegrityStatus
from treval.policy_pin import (
    PolicyDriftError,
    assert_single_policy_snapshot,
    policy_snapshots,
)

_A = "ruleset.version=v1;ruleset.sha256=" + "a" * 64 + ";registry.version=r1"
_B = "ruleset.version=v1;ruleset.sha256=" + "b" * 64 + ";registry.version=r1"


def _pr(cid: str, psv: str | None) -> ProbeResult:
    ev = None
    if psv is not None:
        ctx = rc_pb.RequestContext()
        ctx.envelope.request_id = f"req-{cid}"
        ctx.decision.policy_snapshot_version = psv
        ev = AuditEvidence(
            ref=EvidenceRef(source="wal:x", seq=1, request_id=f"req-{cid}"),
            integrity=IntegrityStatus.VERIFIED,
            tenant_id="__eval__",
            received_at_ns=0,
            record=ctx,
        )
    return ProbeResult(
        case_id=cid,
        request_id=f"req-{cid}",
        decision="ALLOW",
        response_text="",
        evidence=ev,
    )


def test_one_ruleset_across_the_run_is_the_normal_case() -> None:
    assert assert_single_policy_snapshot([_pr("a", _A), _pr("b", _A)]) == (_A,)


def test_the_ruleset_changing_mid_run_voids_it() -> None:
    """🔴 分子分母来自不同规则集，而合出来的率**看起来完全正常** —— 所以是抛错不是警告。

    什么让它红：把 `assert_single_policy_snapshot` 改成返回而不抛。
    """
    with pytest.raises(PolicyDriftError, match="规则内容变过") as e:
        assert_single_policy_snapshot([_pr("a", _A), _pr("b", _B)])
    # 必须点名两个指纹，否则操作者不知道是哪一格变了
    assert _A in str(e.value) and _B in str(e.value)


def test_a_probe_with_no_decision_record_has_no_stamp_to_read() -> None:
    """没有决策记录的探针（打不通 / 入口前就失败）没有章可读 —— 跳过，不记成空串。

    🔴 记成空串会和"有章但内容为空"混成一格，而那是两件事。
    什么让它红：把 `ev is None` 那一支改成 `seen.add("")`。
    """
    assert policy_snapshots([_pr("a", _A), _pr("b", None)]) == (_A,)


def test_the_fingerprint_reaches_the_product_not_just_the_wal() -> None:
    """🔴 记账要能【从产物算出来】。这一条守的就是那句话。

    在此之前 provenance 只有操作者声明的 `detect_config`；实测指纹只在 WAL 里。
    什么让它红：从 `build_provenance` 里去掉 `policy_snapshots`。
    """
    from treval.provenance import build_provenance

    prov = build_provenance(
        wal_dir=None,
        window=(1, 2),
        pinned=True,
        tenant_id="__eval__",
        record_count=1,
        policy_snapshots=(_A,),
    )
    assert prov["policy_snapshots"] == [_A]
    # 未声明时是空列表，不是缺席 —— 缺席会让"没量过"和"量过、只有一个"分不开
    assert (
        build_provenance(
            wal_dir=None, window=(1, 2), pinned=True, tenant_id="t", record_count=0
        )["policy_snapshots"]
        == []
    )


def test_the_drift_error_maps_to_a_clean_exit_code(tmp_path, capsys) -> None:
    """🔴 声明了异常却没接退出码 ⇒ 它以 traceback 抛出，而不是一条可读的失败。

    ruff 的 F401（导入未用）是这条的第一现场：**导入了 `PolicyDriftError` 却没有任何
    except 分支** —— 又一次"指定了目的地，没修路"，本轮第四次。

    什么让它红：去掉 run_collect 里的 `except PolicyDriftError` 分支。
    """
    import treval.cli.collect as mod

    assert "except PolicyDriftError" in (
        __import__("pathlib").Path(mod.__file__).read_text(encoding="utf-8")
    ), "PolicyDriftError 没有接退出码 —— 会以 traceback 抛出"
