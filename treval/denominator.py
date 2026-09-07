"""认证跑的分母 —— 由【判据】产生，不由一份拷贝产生。

🔴 为什么存在：仓内 `corpus/llm01_prompt_injection` 有 212 件，而认证跑的分母是 134。
差的 78 件不是"多余的语料"，它们各有各的、方向一致的理由 —— 留下任何一类，分子都会被灌水：

    212  臂内全部件
    −59  attack_class 以 `control_` 开头 —— 控制件是配对用的对照，期望结局与攻击件【相反】
    ────
    153  池（POOL-v1 §1）
    − 4  behaviour 痕迹 —— git 历史显示检测规则【曾对着这些件开发过】。在它们上测检出率，
         测的是"规则记不记得住自己的开发样本"，不是"能不能检出没见过的攻击"
    −15  件自身 `holdout` 字段声明是留出件
    ────
    134  分母

而在此之前，跑批**无法表达这 134 件**：`--corpus-set en` 会把 212 件全打，出来的数分母是 212，
和门（`k ≥ 117/134`）不是同一个量。🔴 而且它跑得完、退出码 0、报告完全正常 ——
臂名守卫拦不住它（臂在、语料在），因为问题不是"哪条臂"，是"臂里的哪些件"。

⚠️ 剔 `control_` 必须按 **`attack_class` 字段**判，不能按 id 子串：本轮已实证，
id 子串判据在良性臂上误剔过 6 件。答不出按哪个字段数，就是在按形状数。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable

    from treval.active_eval.corpus import CorpusCase

CONTROL_PREFIX = "control_"


class DenominatorError(Exception):
    """分母清单与语料对不上 —— 本跑作废。

    🔴 三种情形都在这里炸，而不是记一条 warning：每一种都会产出一个**分母不对但看起来正常**
    的数，而那种数印进对客报告之后没有任何人能从结果里看出来。
    """


@dataclass(frozen=True)
class Denominator:
    """一份分母清单：剔除判据 + 两份具名剔除表 + 期望件数。"""

    arm_subdir: str
    pool_criterion: str
    excluded_ids: frozenset[str]
    expected: int
    source: str
    source_sha256: str

    def apply(self, cases: Iterable[CorpusCase]) -> tuple[CorpusCase, ...]:
        """按判据筛出分母，并断言件数等于清单声明的那个数。

        🔴 那句断言就是这个类的牙。没有它，任何一次语料变动（加件、改 attack_class、
        改 id）都会安静地把分母挪走，而跑批照常绿。"""
        all_cases = tuple(cases)
        pool = tuple(
            c for c in all_cases if not c.attack_class.startswith(CONTROL_PREFIX)
        )
        kept = tuple(c for c in pool if c.id not in self.excluded_ids)

        # 🔴 清单里的 id 必须在语料里找得到。找不到 ⇒ 这份清单描述的不是这批语料 ——
        # 而件数仍可能【碰巧】相等（少了一件、又多了一件），所以只断言总数是不够的。
        present = {c.id for c in all_cases}
        missing = sorted(self.excluded_ids - present)
        if missing:
            raise DenominatorError(
                f"分母清单 {self.source} 里有 {len(missing)} 个 case_id 在语料里不存在："
                + "、".join(missing[:5])
                + ("…" if len(missing) > 5 else "")
                + " ⇒ 这份清单描述的不是这批语料。件数就算碰巧对上，剔掉的也不是它说的那些件"
            )
        if len(kept) != self.expected:
            raise DenominatorError(
                f"分母对不上：{self.source} 声明 {self.expected} 件，按判据筛出 {len(kept)} 件"
                f"（臂内 {len(all_cases)} · 剔 {CONTROL_PREFIX}* 后 {len(pool)} ·"
                f" 再剔具名 {len(self.excluded_ids)} 条）⇒ 本跑作废。"
                "语料或清单其一变过了，先对齐再跑 —— 分母悄悄挪走的数，事后从结果里看不出来"
            )
        return kept


def load_denominator(path: str | Path) -> Denominator:
    """读一份 p8 形态的分母清单（`arm` / `pool_criterion` / 两份剔除表 / `denominator`）。

    `arm` 形如 `llm01_prompt_injection (POOL-v1 §1)` —— 取第一个空格前的部分作为子目录名。
    """
    p = Path(path)
    try:
        raw_bytes = p.read_bytes()
    except OSError as e:
        raise DenominatorError(f"读不到分母清单 {p}：{e}") from e
    try:
        doc: Any = json.loads(raw_bytes)
    except ValueError as e:
        raise DenominatorError(f"分母清单 {p} 不是合法 JSON：{e}") from e
    if not isinstance(doc, dict):
        raise DenominatorError(f"分母清单 {p}：顶层必须是对象")

    arm = doc.get("arm")
    expected = doc.get("denominator")
    if not isinstance(arm, str) or not arm.strip():
        raise DenominatorError(f"分母清单 {p}：缺 `arm`（它决定这份清单管哪条臂）")
    if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
        raise DenominatorError(f"分母清单 {p}：`denominator` 必须是非负整数")

    excluded: set[str] = set()
    for key in ("excluded_for_behaviour", "excluded_holdout"):
        v = doc.get(key, [])
        if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
            raise DenominatorError(f"分母清单 {p}：`{key}` 必须是字符串数组")
        excluded.update(v)

    return Denominator(
        arm_subdir=arm.split()[0],
        pool_criterion=str(doc.get("pool_criterion", "")),
        excluded_ids=frozenset(excluded),
        expected=expected,
        source=str(p),
        # 🔴 清单本身要有指纹：分母是判据产生的，而判据来自这份文件 —— 文件换了而没人发现，
        # 就是换了一个分母。指纹让"用的是哪一份清单"可回答。
        source_sha256="sha256:" + hashlib.sha256(raw_bytes).hexdigest(),
    )
