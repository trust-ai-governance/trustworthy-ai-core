"""仓级门：公开仓的任何文件都不得写死【仓外语料卷】的路径。

🔴 存在的理由是一次实际外泄（语料作者 2026-09-17 复核出，我确认）：
`tests/test_arm_ab_case_fields.py` 里写着一个完整的宿主绝对路径，而本仓是 PUBLIC。

⚠️ 而更该记的是【为什么它能留到今天】：这条规矩一直在（"路径不硬编码进任何仓文件"），
并且有一处检查 —— `test_w2_product_revisions.py:335` —— 但那一处只查**一个字符串常量**，
不扫仓。**规矩在、门不在。** 于是下一处写在别的文件里的路径，没有任何东西会红。
🔴 一条只在一个点上执行的纪律，覆盖的就是那一个点，不是那条纪律。
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
# 仓外受控卷的标志性片段。🔴 不是"某个具体路径"的黑名单 —— 是【宿主绝对路径】这个形状。
_FORBIDDEN = (
    "/home/",
    "corpus-cn-financial",
    "corpus-en-p1",
    "/var/lib/docker",
)
# 本文件自身必然含这些词；点名豁免，不做通配。
_EXEMPT = {"tests/test_no_corpus_path_literals.py"}

# 🔴 既有外泄的【登记表】—— 本门 2026-09-17 建立时盘出的，逐条带理由与归属。
#
# 为什么是登记而不是就地改：这五处都在我不拥有的文件里，且与本轮改动无关；
# 一次把五个文件改掉，diff 里每一行都追不到任何人的请求。⇒ 登记 + 具名 + 定归属。
# 🔴 而登记表的危险是它会变成万能钥匙 —— 所以：① 逐条写理由，不写"历史原因"；
#    ② 新增一处即红（本表是白名单不是开关）；③ 有一条测试拒绝孤儿条目
#    （条目里的文件若已不含该串，说明修好了却没销条 ⇒ 表会越积越长、越来越没人看）。
_REGISTERED_LEAKS: dict[str, str] = {
    "tests/test_denominator.py": (
        "🔴 最重的一处：字面量指向【私有仓】trustworthy-ai-platform 的 evidence 路径。"
        "归属 Core；处置=改环境变量 + 未设即 skip。本轮未改，因为它与本轮改动无关，"
        "且改它要同时确认那条测试在 CI 上还跑不跑得起来。"
    ),
    "tests/test_pii_indicators.py": (
        "docstring 里写着开发机 WAL 目录。归属 Core；处置=删掉路径，只留"
        "「在真实 WAL 上另行验证过」这半句 —— 量的是什么要留，去哪量不留。"
    ),
    "tools/eval_report.py": (
        "用法示例里的 TREVAL_EVAL_WAL_DIR 默认值写成了开发机路径。归属 Core；"
        "处置=示例改成 <你的 WAL 目录> 占位符。"
    ),
    "tools/eval_variants.py": "同 eval_report.py，同一行用法示例。归属 Core。",
    "tools/diagnostics/response_block_repro.py": (
        "🔴 比上面两处重：它是 os.environ.get 的【默认值】，不是文档 —— "
        "环境变量没设时它会真的去读开发机路径。归属 Core；处置=默认改为 None 并 fail-closed。"
    ),
}


def _tracked_text_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "tests", "tools", "treval"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [f for f in out if f.endswith((".py", ".sh"))]


@pytest.mark.parametrize("needle", _FORBIDDEN)
def test_no_host_absolute_path_is_hardcoded(needle: str) -> None:
    """🔴 红条件：任何被跟踪的 .py/.sh 里出现宿主绝对路径片段。

    正确写法：从环境变量取，未设即声明式跳过（tests/test_label_freeze.py:30）。
    """
    hits = []
    for rel in _tracked_text_files():
        if rel in _EXEMPT:
            continue
        p = _ROOT / rel
        if not p.is_file():
            continue
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if needle in line and "test_w2_product_revisions" not in rel:
                hits.append(f"{rel}:{i}")
    hits = [h for h in hits if h.split(":")[0] not in _REGISTERED_LEAKS]
    assert not hits, (
        f"公开仓里写死了仓外语料路径（{needle}）：{hits}\n"
        "⇒ 改成 os.environ.get(...)，未设即 pytest.skip"
    )


def test_the_gate_actually_scans_the_repo_not_one_constant() -> None:
    """🔴 判据的判据：证明这道门扫的是【仓】，不是一个字符串。

    红条件：有人把扫描面缩回单个常量（那正是它取代的那种检查）——
    届时被扫文件数会掉到个位数，而所有别的断言仍然全绿。
    """
    assert len(_tracked_text_files()) > 50, "扫描面塌了 ⇒ 它又变回一处点检"


def test_registered_leaks_have_no_orphans() -> None:
    """🔴 红条件：某一处修好了却没从登记表销条。

    一张只增不减的豁免表会越积越长，最后没人看 —— 而那正是它取代的那种状态。
    """
    stale = []
    for rel in _REGISTERED_LEAKS:
        p = _ROOT / rel
        text = p.read_text(encoding="utf-8") if p.is_file() else ""
        if not any(n in text for n in _FORBIDDEN):
            stale.append(rel)
    assert not stale, f"这些已经不含宿主路径了，请从登记表里删掉：{stale}"


def test_the_registry_is_a_whitelist_not_a_switch() -> None:
    """🔴 红条件：有人把登记表改成通配/前缀匹配 ⇒ 新增一处不再红。

    表里必须是【具体文件的相对路径】，一条一条。
    """
    for rel in _REGISTERED_LEAKS:
        assert rel.endswith((".py", ".sh")) and "*" not in rel, rel
        assert len(_REGISTERED_LEAKS[rel]) > 30, (
            f"{rel} 的理由太短 —— 无理由的豁免等于万能钥匙"
        )
