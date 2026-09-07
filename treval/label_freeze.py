"""标签冻结 —— 一批件的【id → 标签】映射被钉住，跑完对不上即【不可引】（不是告警）。

🔴 它验的是**标签有没有被改**，不是**标签对不对**。所以由写标签的人建这道门不违反分离：正确性归领域
复核，漂移归这里。

🔴 与 `ruleset_sha256` 的口径【正好相反】，而两边的理由都成立 —— 这一段是写给下一个人的，否则他会以为
其中一个错了：

    ruleset_sha256   对【整份 YAML 字节】取。改一句注释指纹也变。
                     ✅ 对：规则内容的任何变化都可能改变检测行为，宁可多红。

    label_sha256     对【规范化后的 id → 标签映射】取，**不对文件字节取**。
                     ✅ 对：这里要测的是标签有没有被改。语料正文润色一个错别字、注释改一行、
                        字段换个顺序、文件改名 —— 标签都没变，不该判成"标签被改了"。
                     🔴 一道会因无关变动而红的门，最终会被人放宽或关掉。

**标签是什么**（只收两项，每一项都要能说出后果）：
  • `success_when` —— 这件站在分子的哪一边。翻它 = 把『该放行』改成『该拦』。
  • `attack_class` —— 这件在不在分母里。改成 `control_*` 会让它**退出每一个分母**
    （`case_contract` 的 `control_` 是通用规则），分母少一条而没有任何东西吭声。
  成员本身（id 集）也是标签的一部分：少一件、多一件，分母就不是登记的那个了。
  🔴 `scene` 不收：它是切片键，改它只影响分层展示，不改任何一件的判据。收得越宽，红得越频，
  门就越早被关掉。

🔴 **锚不放在它所锚的东西旁边**：语料在仓外受控卷，冻结值在**仓内**（下面这张表）。两者同处一地时，
改标签的人可以顺手改锚。与 `EN_ARM_ID_SET_SHA12` 同一条纪律。
🔴 而表里**只有聚合 sha，没有 id** —— 留出臂的几何（哪些 id、多少条、什么形状）与分数同级，不得进仓。
对不上时要定位到哪一件，在语料所在的机器上跑 `label_map` 自己比，别把 id 搬进来。
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

# 🔴 冻结值（2026-09-05）。A 档 40 · B 档 110 —— B 档尤其：它一次性，标签更不能动。
# 空串 = 未登记 ⇒ 门拒绝（不是跳过）。一个「还没登记所以放行」的门等于没有门。
FROZEN_LABEL_SHA: dict[str, str] = {
    # A 档 40 条 · 可重复跑（改前/改后）
    "llm01_cn_benign_mt_calib": "785a87e9aa6f63b571532fc279d5c68df834999f48b8cf15e98604ddcc6e56ae",
    # 🔴 B 档 110 条 · 一次性留出臂 —— 它的标签动一下，误伤率描述的就是另一批件
    "llm01_cn_benign_mt_holdout": "5c6fef44f32911bc1a319979ca4a4ba3d699faa18b76149d31d132d8d1daa527",
    # 🔴 英文良性留出臂 P1 · 171 条（IT 运营层 115 + 其他四类 56）· 2026-09-06 冻结。
    # 它同样是【一次性】臂：跑它就消耗它。冻在跑之前 —— 跑完再冻，冻的是"跑过的那一版"，
    # 而"标签有没有在跑之前被改过"就再也答不了了。
    "llm01_benign_holdout_p1": "feef2d9c4b41a5f00c1ff06768df79c75d1247f81fc81aacd0622f75d8852311",
}

# 🔴 每条臂住在**哪一卷**（2026-09-06 加）。登记表现在跨了两个仓外卷，而在此之前自比那条测试
# 假定只有一个根 —— 加进第三条臂时它当场红了，红得对：它问的是"这条臂在哪"，而那件事没人写下来。
#
# 🔴 这里记的是**环境变量名**，不是路径 —— 仓外卷的路径一次都不进本仓。
# 变量未设 ⇒ 该臂【未校验】，声明式跳过，不是通过。
ARM_VOLUME_ENV: dict[str, str] = {
    "llm01_cn_benign_mt_calib": "TREVAL_CN_CORPUS",
    "llm01_cn_benign_mt_holdout": "TREVAL_CN_CORPUS",
    "llm01_benign_holdout_p1": "TREVAL_EN_P1_CORPUS",
}


class LabelDriftError(Exception):
    """标签集与冻结值不符，或该臂未登记 ⇒ 该批不可引。"""


def label_map(corpus_dir: Path) -> dict[str, tuple[str, str]]:
    """一个语料目录的【id → (attack_class, success_when)】。读 YAML 字段，不读字节。"""
    out: dict[str, tuple[str, str]] = {}
    for f in sorted(corpus_dir.glob("*.y*ml")):
        for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if isinstance(doc, dict) and "id" in doc:
                out[str(doc["id"])] = (
                    str(doc.get("attack_class", "")),
                    str(doc.get("success_when", "")),
                )
    return out


def label_sha256(labels: dict[str, tuple[str, str]]) -> str:
    """规范化编码：按 id 排序，每行 `id\\tattack_class\\tsuccess_when`，`\\n` 连接，sha256 全长。
    🔴 排序在编码内部 ⇒ 指纹认的是**集合**，不是文件系统给出的顺序。"""
    body = "\n".join(f"{cid}\t{cls}\t{sw}" for cid, (cls, sw) in sorted(labels.items()))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def assert_labels_frozen(arms: dict[Path, str]) -> None:
    """fail-CLOSED：每一臂的实测标签 sha 必须等于冻结值。不符或未登记 ⇒ 抛错。

    🔴 判据是【不可引】不是告警：一个标签漂了的批次，它的每一个数都在描述另一批件，而那件事在跑完
    之后是看不出来的 —— 只能在跑之前拦。"""
    problems: list[str] = []
    for path, frozen in arms.items():
        if not frozen:
            problems.append(f"{path.name}: 未登记冻结值（不是跳过 —— 未登记即拒绝）")
            continue
        got = label_sha256(label_map(path))
        if got != frozen:
            problems.append(f"{path.name}: 实测 {got[:12]} ≠ 冻结 {frozen[:12]}")
    if problems:
        raise LabelDriftError(
            "标签冻结门：该批【不可引】 —— " + "；".join(problems) + "。"
            "定位到哪一件请在语料所在机器上跑 label_map 自比（id 不进本仓）"
        )
