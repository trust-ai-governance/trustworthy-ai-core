"""C2A0 跑前基线比对 —— 一份对不上的输入，代价应该是 0 件语料。每条先说【什么输入让它红】。

🔴 存在理由：今天唯一会红的是 `pair.py` 的拒发门，而它在**配对那一刻**才红 —— 那时语料已经花掉。
这是 `denominator`（清单跑前读）· `policy_pin`（一跑之内规则变即作废）· `judge_imprint`（0 字节即拒）
这条纪律的第四个落点。

🔴 「代价」按臂分两种，不许合并：
    可重跑的公开臂   丢的是【可比性】—— 臂还在，重跑即可
    留出臂           技术上能重跑，但重跑得到的数**不再是留出臂的数** —— 丢的是留出性

🔴 而本门的两条设计彼此依赖，缺一条就会犯它原本要防的那个误读：
    ① 只比内容哈希、**不比路径** —— 路径是自述，哈希是测量
    ② `mismatch` **原样打印、绝不转述** —— 去掉路径后它不再能区分「漂移了」与「载入了另一份」
⇒ 成对成立。`citability` 里那条要求带路径的既有明文已同改，补上了它缺的作用域。
"""

from __future__ import annotations

import json

import pytest

from treval.cli.collect import (
    BASELINE_MATCHED,
    BASELINE_MISMATCH,
    BASELINE_NOT_DECLARED,
    BaselineError,
    _baseline_ruleset_sha,
    compare_baseline_ruleset,
)

_SHA_A = "a" * 64
_SHA_B = "b" * 64


def _fp(sha, *, egress=1, path="/etc/ruleset.yaml"):
    """一块 build_fingerprint。`egress` 模拟**我们自己发流量就会动**的那类计数器。"""
    return {
        "runtime": {
            "ruleset_sha256": sha,
            "ruleset_path": path,
            "code_sha256": "c" * 64,
        },
        "arrival_evidence": {"egress_attempts": egress},
    }


def _baseline_file(tmp_path, fp, name="baseline.json"):
    p = tmp_path / name
    p.write_text(json.dumps({"provenance": {"build_fingerprint_before": fp}}))
    return str(p)


# =========================================================================== #
# 三态 —— 三个词原样出，不转述
# =========================================================================== #
def test_the_three_states_are_the_three_words_verbatim():
    """🔴 什么让它红：把任何一个状态转述（"规则集已漂移" / "一致" / 布尔）。

    去掉路径之后，`mismatch` 不再能区分「漂移了」和「载入了另一份规则集」——
    转述就是替读者做那条**被去掉了消歧信息**的推断。
    """
    assert (BASELINE_NOT_DECLARED, BASELINE_MATCHED, BASELINE_MISMATCH) == (
        "not_declared",
        "matched",
        "mismatch",
    )


def test_matched_when_the_one_cell_is_equal():
    """验收 1 —— 🔴 什么让它红：比对没接上（恒返回 not_declared）。"""
    assert compare_baseline_ruleset(_SHA_A, _fp(_SHA_A)) == BASELINE_MATCHED


def test_mismatch_when_the_one_cell_differs():
    assert compare_baseline_ruleset(_SHA_A, _fp(_SHA_B)) == BASELINE_MISMATCH


def test_no_baseline_declared_is_not_declared_never_matched():
    """验收 3 / 线① —— 🔴 什么让它红：不传基线时返回 `matched`，或静默跳过不留格子。

    一次**没做**的比对必须留下一个空格子，否则半年后没人分得清
    「比过且一致」与「根本没比」—— 而两者在下游读起来一模一样。
    """
    assert compare_baseline_ruleset(None, _fp(_SHA_A)) == BASELINE_NOT_DECLARED
    assert _baseline_ruleset_sha(None) is None


@pytest.mark.parametrize(
    "fp", [None, {}, {"runtime": {}}, {"runtime": {"ruleset_sha256": ""}}]
)
def test_this_run_missing_the_cell_is_also_not_declared(fp):
    """🔴 本跑那一格取不到 ⇒ 同样是 `not_declared`，**不是 matched 也不是 mismatch**。

    它与「没声明基线」原因不同，却是同一个事实：**这一跑没有做过这个比对**。
    什么让它红：把"取不到"读成 mismatch（那会在无 admin-url 的跑上假红）
    或读成 matched（那会把没比过说成比过了）。
    """
    assert compare_baseline_ruleset(_SHA_A, fp) == BASELINE_NOT_DECLARED


# =========================================================================== #
# 🔴 验收 5（要害之一）—— 只比一格，防假红
# =========================================================================== #
def test_only_the_one_cell_is_compared_not_the_whole_fingerprint():
    """🔴 验收 5 —— **这条只有构造件能红**：两份只有 `egress_attempts` 不同的指纹。

    什么让它红：比了整块 fingerprint。那时**任何真的发过探针的跑都会踩红** ——
    而假红一样贵：它训练人去忽略这条门。本仓已因此收窄过一次白名单。
    """
    assert compare_baseline_ruleset(_SHA_A, _fp(_SHA_A, egress=999)) == BASELINE_MATCHED


def test_a_different_path_with_the_same_hash_is_still_matched():
    """🔴 线① —— 路径**不参与**判据。什么让它红：把路径加进比对。

    路径是自述、哈希是测量：产物记了路径，但那一格不可校验 ——
    拿一个校验不了的东西参与比对，只是多一个能悄悄错掉的格子。
    ⚠️ 代价是 `mismatch` 不再能消歧，而那正由「原样打印不转述」承担。
    """
    assert (
        compare_baseline_ruleset(_SHA_A, _fp(_SHA_A, path="/somewhere/else.yaml"))
        == BASELINE_MATCHED
    )


# =========================================================================== #
# 线③ —— 读不出基线是【停】，不是跳过
# =========================================================================== #
def test_an_unreadable_baseline_stops_the_run(tmp_path):
    """验收 4 —— 🔴 什么让它红：读失败被兜成"通过"（返回 None ⇒ not_declared ⇒ 照跑）。

    本项的全部用途是「确认可比」，而**一个读不出基线的跑恰恰是最不可比的那一种**。
    与 `judge_imprint` 的 0 字节拒收同形：**一次失败的读取不是一次通过的检查。**
    """
    missing = str(tmp_path / "nope.json")
    with pytest.raises(BaselineError, match="读不出"):
        _baseline_ruleset_sha(missing)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(BaselineError, match="读不出"):
        _baseline_ruleset_sha(str(bad))


@pytest.mark.parametrize(
    "prov",
    [
        {},
        {"build_fingerprint_before": None},
        {"build_fingerprint_before": {"runtime": {}}},
        {"build_fingerprint_before": {"runtime": {"ruleset_sha256": ""}}},
    ],
)
def test_a_baseline_without_the_cell_stops_the_run(tmp_path, prov):
    """🔴 什么让它红：缺那一格时返回 None（⇒ 记 not_declared ⇒ 照跑）。

    取不到判据 ⇒ 「本跑与基线是否可比」**无法回答**，而无法回答不等于可比。
    """
    p = tmp_path / "b.json"
    p.write_text(json.dumps({"provenance": prov}))
    with pytest.raises(BaselineError, match="取不到"):
        _baseline_ruleset_sha(str(p))


def test_a_readable_baseline_yields_the_one_cell(tmp_path):
    assert _baseline_ruleset_sha(_baseline_file(tmp_path, _fp(_SHA_A))) == _SHA_A


# =========================================================================== #
# 🔴 验收 6（要害之二）—— 停机发生在【任何语料探针之前】
# =========================================================================== #
def test_an_unreadable_baseline_stops_before_a_target_even_exists(
    tmp_path, capsys, monkeypatch
):
    """🔴 验收 6 —— 断言的是**什么都没被调用**，不是"抛了错"：
    「抛了错」与「零件语料下抛了错」在测试里长得一样。

    读基线在【本地】且在 `run_collect` 最开头 ⇒ 读不出时连**目标都还没被构造出来**，
    因此连那一件合成试探件也没发过（比"没发语料探针"更强的一句）。

    什么让它红：把读基线挪到 `fetch_buildinfo` 之后（那时试探件已经发出去了），
    或挪到跑后（那时语料已经花掉）。
    ⚠️ 第一版我造了一个计数 target 却**没有把它传进去**，于是 `calls == 0` 不可能失败 ——
    一个绿着的空断言。现在改成：任何一次目标构造 / 语料采集都直接炸。
    """
    import argparse

    from treval.cli import collect as _c

    def _boom(*a, **k):  # pragma: no cover - 本门下不该被走到
        raise AssertionError("基线读不出的跑不该构造目标、更不该采集语料")

    monkeypatch.setattr(_c, "_resolve_target", _boom, raising=False)
    monkeypatch.setattr(_c, "collect_measurements", _boom)
    monkeypatch.setattr(_c, "GatewayTarget", _boom, raising=False)

    rc = _c.run_collect(
        argparse.Namespace(
            baseline_bundle=str(tmp_path / "does-not-exist.json"),
            denominator_manifest=None,
            judge_imprint=None,
        )
    )
    assert rc == 3
    assert "停机" in capsys.readouterr().err


def test_the_boom_sentinel_really_would_fire(tmp_path, monkeypatch):
    """🔴 上一条的**反向锁**：证明那三个哨兵不是摆设。

    同样的哨兵、同样的入口，只把基线换成一份**读得出**的 ⇒ 流程会往下走 ⇒ 哨兵必须炸。
    什么让它红：哨兵打错了位置（那时上一条会因为"根本走不到"而恒绿，与"被门拦住"不可区分）。
    """
    import argparse

    from treval.cli import collect as _c

    def _boom(*a, **k):
        raise AssertionError("sentinel fired")

    monkeypatch.setattr(_c, "_resolve_target", _boom, raising=False)
    monkeypatch.setattr(_c, "collect_measurements", _boom)
    monkeypatch.setattr(_c, "GatewayTarget", _boom, raising=False)

    with pytest.raises(AssertionError, match="sentinel fired"):
        _c.run_collect(
            argparse.Namespace(
                baseline_bundle=_baseline_file(tmp_path, _fp(_SHA_A)),
                denominator_manifest=None,
                judge_imprint=None,
            )
        )


def test_the_mismatch_message_prints_the_word_and_refuses_to_interpret_it():
    """🔴 线② —— 门只摆出 `mismatch` 那个词，**不替读者判定它是「漂移」还是「载入了另一份」**。

    什么让它红：在停机文案里写"规则集已漂移" —— 那正是 `citability` 那条既有明文
    （要求带路径）原本要防的误读，而本门的判据里恰好没有路径。
    ⚠️ 断言落在**文案函数的返回值**上，不落在源码文本上（后者测的是源码不是行为）。
    """
    from treval.cli.collect import baseline_mismatch_message

    msg = baseline_mismatch_message()
    assert BASELINE_MISMATCH in msg  # 那个词原样出现
    assert "语料一件未动" in msg  # 代价说清
    assert "不替你判定" in msg and "路径是自述" in msg  # 明说它不作那条推断
    assert "已漂移" not in msg  # 🔴 绝不转述


def test_the_state_lands_in_provenance_verbatim():
    """🔴 什么让它红：那一格不进 provenance（于是这一跑做没做过比对，产物答不出来）。"""
    from treval.provenance import build_provenance

    base = dict(
        wal_dir="/tmp/wal", window=(0, 1), pinned=(), tenant_id="t", record_count=0
    )
    for state in (BASELINE_NOT_DECLARED, BASELINE_MATCHED, BASELINE_MISMATCH):
        assert (
            build_provenance(**base, baseline_compared=state)["baseline_compared"]
            == state
        )
    # 🔴 承重的不是形参默认值，是落盘时那一步兜底 —— 一发变异证明了这件事：
    # 把默认值从 "not_declared" 改成 "" **存活**，因为 `or "not_declared"` 把它兜住了。
    # ⇒ 那发变异改的是一处冗余声明（两处说同一件事），**它存活是对的，是靶打错了**。
    # 真正会让「没比过」在产物上读成空白的，是兜底那一步 —— 所以断言落在它上面：
    # 任何一种"空"的输入（不传 / 空串 / None），落盘都必须是那个词本身。
    assert build_provenance(**base)["baseline_compared"] == BASELINE_NOT_DECLARED
    for empty in ("", None):
        assert (
            build_provenance(**base, baseline_compared=empty)["baseline_compared"]
            == BASELINE_NOT_DECLARED
        ), empty
