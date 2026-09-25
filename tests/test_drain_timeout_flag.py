"""`--drain-timeout-s` —— 排空上限必须【能被操作者声明】，且四处一次落齐。

🔴 为什么需要它（2026-09-21 实测，同一条 p3 臂、同一套栈、同一批语料）：
    第一跑   判官 ~3.5 s/件  ⇒ 300 件 17.5 分钟，排空追平，3/3
    几跑之后 判官 ~9.5 s/件  ⇒ 25 分钟的默认上限差 103 件没排完，整跑 Tier-2 作废
`_DRAIN_PER_CASE_S = 5.0` 是在【中文认证跑那套栈】上按 median 2.84 s/件 标定的（target.py:30）。
一个在别处标定出来的常数，在这里是一个没有任何征兆的陷阱：失败不是报错，
是一个「本该有数的地方写着 not_measured」的产物。对可重跑臂白花 25 分钟，
🔴 对 read-once 臂就是把臂烧掉。

而本文件真正钉的是【四处落齐】：CLI 声明 · 函数签名 · 调用点 · drain 调用。
仓里紧挨着的那一行注释记着同族的上一次：`--benign-arm` 解析了、签名收了、重映射代码也在，
**唯独调用点没传** ⇒ 参数永远是默认值，那条路断在最后一米而没有任何东西吭声。
"""

from __future__ import annotations

import importlib
import inspect

from treval.cli import collect as C


def _parse(*extra: str):
    m = importlib.import_module("treval.cli.main")
    argv = [
        "collect",
        "--gateway",
        "http://127.0.0.1:8080",
        "--corpus-set",
        "p3",
        "--out",
        "/dev/null",
        *extra,
    ]
    return m.build_parser().parse_args(argv)


def test_flag_is_declared_and_parses() -> None:
    assert _parse("--drain-timeout-s", "7300").drain_timeout_s == 7300.0


def test_flag_defaults_to_none_not_a_number() -> None:
    """🔴 默认必须是 None（= 不声明 ⇒ 用按件数推导的那个），不是某个数字。
    给它一个数字默认值，等于把另一个常数偷偷塞进来，而操作者以为自己没设。"""
    assert _parse().drain_timeout_s is None


def test_collect_measurements_accepts_it() -> None:
    sig = inspect.signature(C.collect_measurements)
    assert "drain_timeout_s" in sig.parameters
    assert sig.parameters["drain_timeout_s"].default is None


def test_the_call_site_actually_passes_it() -> None:
    """🔴 本文件的核心，也是「断在最后一米」那一族的修法：
    光有 CLI 声明和函数签名不够 —— 调用点必须真的传。
    这里读源码断言那一行在，因为它一旦消失，所有其它测试照样绿。"""
    src = inspect.getsource(C)
    assert 'drain_timeout_s=getattr(args, "drain_timeout_s", None)' in src, (
        "collect_measurements 的调用点没有传 drain_timeout_s —— "
        "参数会被解析、被写进 --help、被写进跑单，然后永远不起作用"
    )


def test_the_drain_call_honours_it() -> None:
    """最后一段：collect_measurements 内部必须把它传给 drain_governance。
    签名收了而 drain 调用不带，是同一个断点往后挪了一层。"""
    src = inspect.getsource(C.collect_measurements)
    assert "drain_timeout_s is None" in src and "timeout=drain_timeout_s" in src, (
        "drain 调用没有使用 drain_timeout_s"
    )


def test_unset_still_uses_the_derived_default() -> None:
    """不传时行为不变 —— 小批次仍走 target 自己按件数推导的上限。
    一个"顺手把默认也改了"的参数，会让每一条既有跑的排空行为静默改变。"""
    from treval.active_eval.target import _DRAIN_FLOOR_S, _DRAIN_PER_CASE_S

    assert _DRAIN_PER_CASE_S == 5.0
    assert _DRAIN_FLOOR_S == 20.0
