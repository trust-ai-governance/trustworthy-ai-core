"""口径门 (W2 良性 / W6 业务伪装) —— 一批**自撰**英文件的拼写口径，是否泄漏了它自己的类别。

🔴 判据只有一条：**拼写口径不得预测类别。** 在一批件内部，各族之间的口径分布必须无差别 —— 用拼写去猜
族的准确率不得显著高于随机（置换检验，α 是惯例值）。这一条有天然阈值，不需要任何人挑数。

🔴 **密度不设红线，只测不拦。** 「整批统一即是签名」是真的，但把那句话变成一个数要挑一个切点，而由看过数
的人挑一个能让手里语料过门的数，就是把门拟合到语料上。密度照实报，等有一个非拟合的依据再说。

🔴 **两条判据会互相作用，这是本门最该被读到的一句**：把密度压到既有臂的量级（一百多件里几件带标记），
类别相关检验就**没有功效** —— 即使把那几件全堆进同一族也到不了 α。所以本门自己算功效：把观测到的标记
摆成最极端后仍到不了 α，判定叫 `underpowered`，**不叫 ok**。一个不可能失败的检查，绿了不构成证据。

🔴 它在既有臂上量出了一件比「批次签名」更重的事，写在这里以免被当成新件的问题：**良性臂与攻击臂的拼写
口径是分开的**（同一载体的孪生对，良性那侧与攻击那侧用了相反的拼法），于是光看拼写就能猜中类别。批次签名
让人认出这一批；类别相关的签名让人猜中标签。这是既有语料的既存缺陷，不是本轮新件造成的 —— 由
`test_spelling_predicts_the_class_in_the_existing_arms` 钉住可复算。

🔴 两层，只有一层进判据：
  • **法域术语**（MLRO / four-eyes / DoA / vulnerable customer）—— ✅ 照锚点留。那是素材侧唯一的领域贡献，
    去掉就没有真实感了。本门**只数不判**：它产生领域价值，不产生签名。
  • **拼写口径**（authorise/authorize · centre/center · behaviour/behavior）—— 判据只看它。

🔴 它量不到什么（必须写在这里，否则这些数会被当成「作者口径」读）：
  ① **照抄进来的外部文本**（越狱提示原文、引用的第三方条款）机械上分不出来。所以本门数的是**候选标记**，
     不是**作者标记**。既有攻击臂的美式标记里，相当一部分是 DAN 提示原文这类外部照抄 —— 这道门在既有臂上
     **会高估**。而 W2/W6 是自撰、无外部载荷 ⇒ 候选 = 作者，本门正是为这种批建的。
  ② **表外的口径词未测，不是不存在。** 标记表是声明值（下面 `_PAIRS`），不是一份完备的英美拼写差异表。
  ③ **单向词**（cheque / licence / programme —— 美式那半是通用词，数它会打到所有人）不进判据，只作诊断。
     把它们算进去，这道门就会对英式更敏感，那它自己就带了一个方向。
  ④ **族标签必须由外部侧表给**（`--labels`）。没有侧表 ⇒ `not_measured`，不许当成过了。而侧表**只在这里
     读**：族标签不落语料（带族标签的语料本身就是一张边界图）。

    PYTHONPATH=$PWD python tools/check_en_register.py --corpus <dir> [--labels <side_table.json>] [--enforce]
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import yaml

from tools.check_cn_two_arm import family_field_hits

BRITISH = "british"
AMERICAN = "american"

# --------------------------------------------------------------------------- #
# 判据 —— 只有惯例值，没有挑出来的数
# --------------------------------------------------------------------------- #
ALPHA = 0.05  # 显著性水平：统计学惯例值，不是照手里的语料挑的切点
PERMUTATIONS = 20000  # 置换次数：只影响 p 的分辨率（下限 1/20001），不影响判据
PERMUTATION_SEED = 20260901  # 固定种子 ⇒ 同输入同判定。跑两次给两个答案的门不能当门用

# 🔴 只收**成对**、可判方向的拼写对 —— 表本身必须是方向对称的，否则这道门会对一种口径更敏感。
_ISE_STEMS = (
    "author",
    "organ",
    "recogn",
    "util",
    "apolog",
    "priorit",
    "summar",
    "standard",
    "minim",
    "maxim",
    "final",
    "real",
    "categor",
    "special",
    "normal",
    "central",
)
_ISE_TAIL = r"(?:e|es|ed|ing|ation|ations)"
_PAIRS: tuple[tuple[str, str], ...] = (
    (
        rf"(?:{'|'.join(_ISE_STEMS)})is{_ISE_TAIL}",
        rf"(?:{'|'.join(_ISE_STEMS)})iz{_ISE_TAIL}",
    ),
    (r"analys(?:e|es|ed|ing)", r"analyz(?:e|es|ed|ing)"),
    (
        r"(?:behaviour|favour|labour|colour|honour|neighbour|endeavour)(?:s|ed|ing|al)?",
        r"(?:behavior|favor|labor|color|honor|neighbor|endeavor)(?:s|ed|ing|al)?",
    ),
    # 🔴 metre/meter 不在表内：meter（计量器具）在两种口径里都通用，数它是假阳性。
    (
        r"(?:centre|centres|centred|centring|litre|litres|fibre|fibres)",
        r"(?:center|centers|centered|centering|liter|liters|fiber|fibers)",
    ),
)
_BR_RE = re.compile(r"\b(?:" + "|".join(b for b, _ in _PAIRS) + r")\b", re.IGNORECASE)
_AM_RE = re.compile(r"\b(?:" + "|".join(a for _, a in _PAIRS) + r")\b", re.IGNORECASE)

# 单向词：只作诊断输出，**不进分子**（见模块头 ③）。
_UNPAIRED_BR_RE = re.compile(
    r"\b(?:cheques?|licences?|practis(?:e|es|ed|ing)|defences?|offences?|programmes?|grey)\b",
    re.IGNORECASE,
)

# 法域术语 —— 声明值，不是完备表。只数不判。
JURISDICTION_TERMS: tuple[str, ...] = (
    "MLRO",
    "four-eyes",
    "DoA",
    "vulnerable customer",
)
_JURIS_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(t) for t in JURISDICTION_TERMS) + r")\b",
    re.IGNORECASE,
)

# 排除项 —— 每一条都来自既有臂上实测出的一类假阳性。
_ENCODED_RE = re.compile(
    r"[A-Za-z0-9+/]{16,}={0,2}"
)  # 载荷：里面的字母不是作者写的散文
_IDENT_RE = re.compile(
    r"[_\d]"
)  # 字段名 / 政策号：ticket_authorization_claim · SEC-114


@dataclass(frozen=True)
class Marker:
    case_id: str
    token: str
    variety: str  # BRITISH | AMERICAN


@dataclass(frozen=True)
class DensityReport:
    """密度 —— **测量，不是判据**（本轮裁定：不设红线）。"""

    status: str  # not_measured | measured
    rate: float  # 带标记的【件数】占比
    carrying: tuple[str, ...]
    variety: str  # british | american | mixed | none
    lines: tuple[str, ...]


@dataclass(frozen=True)
class ClassPrediction:
    """🔴 判据 —— 拼写口径能不能预测族。"""

    status: str  # not_measured | underpowered | ok | fail
    accuracy: float  # 用拼写猜族的准确率
    chance: float  # 随机基准（最大族占比）
    p: float  # 置换检验 p 值
    max_reachable_p: float  # 把观测到的标记摆成最极端后的 p —— 功效指标
    by_family: tuple[tuple[str, int, int], ...]  # (族, 件数, 带标记件数)
    lines: tuple[str, ...]
    # 🔴 `not_measured` 的**理由**，因为它有两种而处置相反（见 enforce_exit_code）：
    #   「缺族标签侧表」= 没法量   ⇒ 拦
    #   「本批零口径标记」= 没东西可量，判据按构造成立 ⇒ 放行
    # 只带 status 不带理由，调用方就只能把两者当成一件事 —— 而那正是本门 2026-09-06 的失效。
    why: str = ""


def _strip_uncountable(text: str) -> str:
    """去掉作者没有在其中做口径选择的部分：编码载荷、字段名/政策号这类标识符。🔴 载荷先去 ——
    base64 是字母数字，后去会把它当成散文。"""
    t = _ENCODED_RE.sub(" ", text)
    return " ".join(w for w in t.split() if not _IDENT_RE.search(w))


def _is_proper_noun(text: str, start: int, token: str) -> bool:
    """专名判据：命中词首字母大写，且**紧邻前一个词**也是大写开头（Helmholtz Center）。拼法由那家机构
    自己定，不是我们的口径选择。句首大写不满足前置条件 ⇒ 仍然计入（那确实是作者写的）。"""
    if not token[:1].isupper():
        return False
    before = text[:start].split()
    return bool(before) and before[-1][:1].isupper()


def register_markers(case_id: str, text: str) -> list[Marker]:
    """一件正文里的**候选**拼写口径标记（排除项已应用）。空表 ⇒ 这件不带口径标记。"""
    cleaned = _strip_uncountable(text)
    out: list[Marker] = []
    for variety, pat in ((BRITISH, _BR_RE), (AMERICAN, _AM_RE)):
        for m in pat.finditer(cleaned):
            if _is_proper_noun(cleaned, m.start(), m.group(0)):
                continue
            out.append(Marker(case_id, m.group(0), variety))
    return out


_ID_SPLIT_RE = re.compile(r"[^A-Za-z]+")


def id_register_markers(case_id: str) -> list[Marker]:
    """🔴 case id 里的拼写口径标记。散文那条路走不到这里：`_strip_uncountable` 会把带 `_`/数字的 token
    整个丢掉（那对字段名是对的），而 case id 恰好长成那样 ⇒ id 里的口径标记会**静默漏掉**。

    🔴 为什么 id 也要查：新规则说的是「不引入任何与类别相关的口径信号」，而 id 是随件一起发出去的。
    这一条是人眼先看见的 —— 一个 slug 写成 `utilisation_…` 逃过了整道门。写下来的规矩没拦住它。"""
    words = " ".join(w for w in _ID_SPLIT_RE.split(case_id) if w)
    out: list[Marker] = []
    for variety, pat in ((BRITISH, _BR_RE), (AMERICAN, _AM_RE)):
        out += [Marker(case_id, m.group(0), variety) for m in pat.finditer(words)]
    return out


def jurisdiction_hits(text: str) -> list[str]:
    """法域术语命中（诊断用）—— 领域价值的可见证据，从不进判据。"""
    return _JURIS_RE.findall(_strip_uncountable(text))


def unpaired_british_hits(text: str) -> list[str]:
    """单向英式词（诊断用）—— 见模块头 ③：进分子会让这道门自带一个方向。"""
    return _UNPAIRED_BR_RE.findall(_strip_uncountable(text))


def density_report(markers: list[Marker], total: int) -> DensityReport:
    """密度 —— **测量，不设红线**（本轮裁定）。total 为 0 ⇒ `not_measured`：占比 0 与「一件都没量」长得
    一模一样，合并它们就等于让一批没跑过的件读起来像过了门。"""
    if total <= 0:
        return DensityReport(
            "not_measured",
            0.0,
            (),
            "none",
            ("口径密度：not_measured —— 本批零件，未量",),
        )
    carrying = tuple(sorted({m.case_id for m in markers}))
    kinds = {m.variety for m in markers}
    variety = (
        "none" if not kinds else ("mixed" if len(kinds) > 1 else next(iter(kinds)))
    )
    rate = len(carrying) / total
    return DensityReport(
        "measured",
        rate,
        carrying,
        variety,
        (
            f"口径密度：{rate:.1%}（{len(carrying)}/{total} 件带拼写口径标记）· 方向 {variety}"
            "　🔴 只测不拦、不设红线 —— 没有一个非拟合的依据能定那条线",
        ),
    )


def _variety_of(markers: list[Marker]) -> dict[str, str]:
    """case_id ⇒ 该件的口径方向。同件两种方向并存记 `mixed`（罕见，但不许静默归一边）。"""
    out: dict[str, str] = {}
    for m in markers:
        prev = out.get(m.case_id)
        out[m.case_id] = m.variety if prev in (None, m.variety) else "mixed"
    return out


def _accuracy(groups: list[list[str]], totals: dict[str, int], n: int) -> float:
    """用「口径 ⇒ 该口径下最常见的族」这条规则猜族能达到的准确率。`groups` 是各**带标记**口径桶里的族
    标签；剩下的件自成一桶 —— 「不带标记」本身也是规则的一部分，可能就是某个族的特征。"""
    rest = dict(totals)
    correct = 0
    for grp in groups:
        c = Counter(grp)
        correct += max(c.values(), default=0)
        for fam, k in c.items():
            rest[fam] -= k
    correct += max(rest.values(), default=0)
    return correct / n


def class_prediction(
    labels: dict[str, str],
    markers: list[Marker],
    *,
    alpha: float = ALPHA,
    trials: int = PERMUTATIONS,
    seed: int = PERMUTATION_SEED,
) -> ClassPrediction:
    """🔴 判据：拼写口径不得预测族。

    统计量 = 用口径猜族的最优准确率；零假设 = 口径与族无关，由**置换族标签**给出（不假设任何分布）。
    p = 置换中达到或超过观测准确率的比例 ⇒ p < α 即红。α 是惯例值，不是照手里的语料挑的。

    🔴 `underpowered` 是独立第三态，不许并进 ok：把**观测到的这些标记**摆成最极端（全部堆进最大的族）
    后重跑同一个检验，若连那样都到不了 α，则这道门在当前密度下**不可能红** —— 那样的绿不构成证据。
    功效是**算出来的**，不是一个写死的件数下限：它随族大小和标记数一起变。"""
    variety = _variety_of(markers)
    carrying = [cid for cid in labels if cid in variety]
    # 侧表为空时 carrying 也必为空（carrying 由 labels 迭代得来），所以这一个条件同时管住两种未测。
    if not carrying:
        why = "缺族标签侧表" if not labels else _ZERO_MARKER_WHY
        return ClassPrediction(
            "not_measured",
            0.0,
            0.0,
            1.0,
            1.0,
            (),
            (f"口径×族：not_measured —— {why}，这一条没有量过（不是量出了零相关）",),
            why=why,
        )

    fams = dict(Counter(labels.values()))
    n = len(labels)
    chance = max(fams.values()) / n
    vals = [labels[cid] for cid in sorted(labels)]

    def _groups(assign: list[tuple[str, list[str]]]) -> list[list[str]]:
        return [g for _, g in assign]

    observed_groups: dict[str, list[str]] = {}
    for cid in carrying:
        observed_groups.setdefault(variety[cid], []).append(labels[cid])
    sizes = [len(g) for g in observed_groups.values()]
    accuracy = _accuracy(_groups(sorted(observed_groups.items())), fams, n)

    def _p(observed: float, group_sizes: list[int]) -> float:
        """置换 p：固定「哪些件带标记、各口径桶多大」，只打乱族标签。等价于从全部族标签里**无放回**
        抽出 m 个分给带标记的位置 —— 所以每次试验是 O(m) 而不是 O(n)，两万次才跑得动。"""
        rng = random.Random(seed)  # noqa: S311  # nosec B311 — 可复算是本函数的全部意义
        m = sum(group_sizes)
        hit = 0
        for _ in range(trials):
            picked = rng.sample(vals, m)
            at = 0
            groups = []
            for size in group_sizes:
                groups.append(picked[at : at + size])
                at += size
            if _accuracy(groups, fams, n) >= observed:
                hit += 1
        return (hit + 1) / (trials + 1)

    p = _p(accuracy, sizes)

    # 🔴 功效：把**同样多**的标记全部堆进【某一个】族，取能达到的最高准确率。
    # 🔴 必须遍历所有族，不能想当然取最大的那个 —— 堆进最大的族恰恰几乎没有增益：那些件本来就会被
    # 「不带标记 ⇒ 猜最大族」这条规则猜对，换个桶并不多猜对几件。增益最大的是堆进**非多数**族。
    # （这一条是一次存活的变异逼出来的：原实现取「最大的族」，名字叫「最极端」，量的却近乎最不极端。）
    m = len(carrying)
    best_acc = max(
        _accuracy([[f] * min(m, fams[f])], fams, n) for f in fams if fams[f] > 0
    )
    max_reachable_p = _p(best_acc, [m])

    by_family = tuple(
        (f, fams[f], sum(1 for cid in carrying if labels[cid] == f))
        for f in sorted(fams)
    )
    dist = " · ".join(f"{f} {c}/{n}" for f, n, c in by_family)
    lines = [
        f"口径×族：猜中率 {accuracy:.1%}（随机基准 {chance:.1%}）· p={p:.4f} · α={alpha}"
        f"　带标记件数按族：{dist}"
    ]
    if max_reachable_p >= alpha:
        lines.append(
            f"🔴 underpowered —— 把这 {len(carrying)} 件标记全堆进最大的族，p 也只到 "
            f"{max_reachable_p:.4f} ≥ α ⇒ 本密度下这道门**不可能红**。这不是「查过没问题」，"
            "是「查不动」。要么接受未测，要么先把密度提上去再查（🔴 而提密度本身是另一个签名）"
        )
        return ClassPrediction(
            "underpowered",
            accuracy,
            chance,
            p,
            max_reachable_p,
            by_family,
            tuple(lines),
        )
    if p < alpha:
        lines.append(
            "🔴 FAIL —— 拼写口径预测得了族：语料自己带了一张边界图。"
            "改法是把带标记的件按族大小铺匀，不是把标记删光（删光只会变成 not_measured）"
        )
        return ClassPrediction(
            "fail", accuracy, chance, p, max_reachable_p, by_family, tuple(lines)
        )
    return ClassPrediction(
        "ok", accuracy, chance, p, max_reachable_p, by_family, tuple(lines)
    )


def case_prose(doc: dict) -> str | None:
    """一件里作者写的全部正文（`input` 与 `messages[].content` 合并），没有任何正文字段则 None。

    🔴 作者正文有两种落法，只扫 `input` 会把多轮件**静默漏掉** —— 漏掉的件既不带标记也不进分母，两边
    一起消失，于是占比的分母是假的而报告读起来完全正常。`system_prompt` 不扫：全批同一句，扫它等于给
    每件加一个常数。

    🔴 `content` 有两种形状：字符串，或 parts 数组 `[{type: text, text: …}]`（EV-AE11 D7）。形状照
    `treval/active_eval/corpus.py::_parse_content` 抄，不自造 —— 本仓真有件是 parts 形态，只认字符串
    会把它读成空。"""
    parts: list[str] = []
    if isinstance(doc.get("input"), str):
        parts.append(doc["input"])
    for turn in doc.get("messages") or ():
        if not isinstance(turn, dict):
            continue
        content = turn.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            parts += [
                p["text"]
                for p in content
                if isinstance(p, dict)
                and p.get("type") == "text"
                and isinstance(p.get("text"), str)
            ]
    return "\n".join(parts) if parts else None


# --------------------------------------------------------------------------- #
# 🔴 唯一入口 —— 建池与取正文各只有一条路
# --------------------------------------------------------------------------- #
# 本轮出了两次同形缺陷，都不是"忘了调用"，是**手工重写了一条已存在的链路**：
#   ① 建池时手工列目录名 ⇒ 绕开 `is_control_attack_class` ⇒ 59 件控制件混进"既有攻击件"基线（占 28%），
#      于是那条臂的大写率报成 85.8% 而不是 94.1%；
#   ② 取正文时直调 `case_prose` 再 `if p` 过滤 ⇒ 绕开 `unreadable` ⇒ 静默丢件，分母少一。
# 两次都靠事后复核才发现。⇒ 修法不是加注释提醒，是**让第二条路不存在**：
#   • 建池只有 `case_pool()`，控制件过滤在它内部，调用方无从跳过；
#   • 取正文只有 `CasePool.texts`，而它在有 unreadable 未处置时**直接拒绝** —— 「只拿正文、不看丢件」
#     这个写法因此写不出来，不是不推荐。
class PoolError(Exception):
    """池子里有读不到正文的件而调用方没有处置 ⇒ 拒绝交出正文。"""


@dataclass(frozen=True)
class CasePool:
    docs: tuple[dict, ...]
    unreadable: tuple[str, ...]
    dropped_control: tuple[str, ...]

    @property
    def texts(self) -> tuple[str, ...]:
        """🔴 有 unreadable 未处置就拒绝 —— 这一句是「让第二条路不存在」的落点。要照旧取，
        显式调 `texts_acknowledging_unreadable()`，那时丢件是**写下来的选择**，不是默认。"""
        if self.unreadable:
            raise PoolError(
                f"池中有 {len(self.unreadable)} 件读不到正文（首个 {self.unreadable[0]}）—— "
                "它们既不带标记也不进分母，两边一起消失，占比会是假的而报告读起来完全正常。"
                "先修正文字段，或显式调 texts_acknowledging_unreadable()"
            )
        return self.texts_acknowledging_unreadable()

    def texts_acknowledging_unreadable(self) -> tuple[str, ...]:
        return tuple(p for d in self.docs if (p := case_prose(d)) is not None)


def case_pool(*corpus_dirs: Path, drop_control: bool = True) -> CasePool:
    """🔴 建池的唯一入口。`drop_control` 内部走 `is_control_attack_class`（控制件的标记在
    `attack_class` 上，**不在 id 上** —— 按 id 匹配 `control_` 一件都剔不掉，那正是既有基线把 59 件
    控制件算进"攻击臂"的成因）。"""
    from treval.case_contract import is_control_attack_class

    docs: list[dict] = []
    unreadable: list[str] = []
    dropped: list[str] = []
    for d in corpus_dirs:
        for f in sorted(d.glob("*.y*ml")):
            for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
                if not isinstance(doc, dict) or "id" not in doc:
                    continue
                if drop_control and is_control_attack_class(
                    doc.get("attack_class", "")
                ):
                    dropped.append(str(doc["id"]))
                    continue
                if case_prose(doc) is None:
                    unreadable.append(f.name)
                    continue
                docs.append(doc)
    return CasePool(tuple(docs), tuple(unreadable), tuple(dropped))


def scan_corpus(
    corpus_dir: Path, *, drop_control: bool = False
) -> tuple[list[Marker], int, list[str]]:
    """扫一个语料目录 ⇒ (候选标记, 件数, 无正文字段的文件名)。🔴 第三个返回值不许丢：一件读不到正文时
    它既不带标记也不进分母，两边一起消失 ⇒ 报告读起来完全正常，而分母是假的。

    建池走 `case_pool`（唯一入口）。缺省 `drop_control=False` 保持既有口径不变；要量「既有攻击件长
    什么样」这类基线时必须传 True —— 控制件是形态异常的一群，混进去会把基线整体拉偏。"""
    pool = case_pool(corpus_dir, drop_control=drop_control)
    markers = [
        m
        for doc in pool.docs
        for m in register_markers(str(doc["id"]), case_prose(doc) or "")
    ]
    return markers, len(pool.docs), list(pool.unreadable)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_en_register", description=__doc__)
    ap.add_argument(
        "--corpus", type=Path, required=True, help="目标语料目录（可在仓外）"
    )
    ap.add_argument(
        "--labels",
        type=Path,
        help='Tier-0 案级侧表 JSON：{"families": {case_id: family}}。缺省 ⇒ 口径×族 not_measured',
    )
    ap.add_argument(
        "--enforce",
        action="store_true",
        help="按【口径×族】那一条拦截（密度不设红线，任何时候都只报）",
    )
    ap.add_argument(
        "--no-register-signal",
        action="store_true",
        help="本批不得引入任何拼写口径信号（正文与 case id 都算）—— 零标记是规则的结果，不是一个数",
    )
    args = ap.parse_args(argv)

    if not args.corpus.exists():
        # 🔴 与 cn-two-arm 同一条纪律：本批语料不在本仓时，绿色公开 CI 不构成本项已核的证据。
        print(f"口径门：PASS —— 🔴 目标目录不存在，本项未校验（{args.corpus}）")
        print("    只在指向仓外受控卷预检时校验；公开 CI 绿不等于这批件过了这道门")
        return 0

    markers, total, unreadable = scan_corpus(args.corpus)
    labels: dict[str, str] = {}
    if args.labels and args.labels.exists():
        labels = json.loads(args.labels.read_text(encoding="utf-8"))["families"]
    dens = density_report(markers, total)
    cls = class_prediction(labels, markers)
    docs = _docs(args.corpus)
    prose = [p for p in (case_prose(d) for d in docs) if p]
    juris = sum(len(jurisdiction_hits(p)) for p in prose)
    unpaired = sum(len(unpaired_british_hits(p)) for p in prose)
    id_marks = [m for d in docs for m in id_register_markers(str(d["id"]))]
    fam = family_field_hits(args.corpus)

    for line in cls.lines + dens.lines:
        print(line)
    print(f"    法域术语命中 {juris} 处（只数不判 —— 领域价值的证据，不是签名）")
    print(f"    单向英式词 {unpaired} 处（诊断：不进判据，进了这道门就自带一个方向）")
    print(
        f"    case id 里的口径标记：{'🔴 ' + str(len(id_marks)) + ' 处' if id_marks else '0 处'}"
        "（id 随件一起发出去，也是信号；散文那条路查不到它）"
    )
    print(
        f"    族字段扫描：{'🔴 ' + str(len(fam)) + ' 处' if fam else '0 处'}"
        "（族标签只进 Tier-0 案级侧表，按 case.id join —— 带族标签的语料本身就是一张边界图）"
    )
    hard = dens.status == "not_measured" or bool(fam) or bool(unreadable)
    if args.no_register_signal and (dens.carrying or id_marks):
        hard = True
        print(
            f"🔴 本批声明【不引入任何拼写口径信号】，实测正文 {len(dens.carrying)} 件 · "
            f"id {len(id_marks)} 处 —— 零是规则的结果，不是一个可以商量的数",
            file=sys.stderr,
        )
        for m in (id_marks + [Marker(c, "", "") for c in dens.carrying])[:5]:
            print(f"      · {m.case_id} {m.token}".rstrip(), file=sys.stderr)
    if dens.status == "not_measured":
        print("🔴 not_measured —— 目录里没有可读正文，这不是「过了」", file=sys.stderr)
    if unreadable:
        print(
            f"🔴 {len(unreadable)} 件读不到正文（首个 {unreadable[0]}）—— 它们不在上面那个分母里，"
            "占比因此是假的",
            file=sys.stderr,
        )
    for name, key in fam[:5]:
        print(f"      · {name}: {key}", file=sys.stderr)
    if not args.enforce:
        print("（只测不拦。--enforce 打开【口径×族】那一条的拦截；密度任何时候都不拦）")
        return 1 if hard else 0
    return 1 if (hard or enforce_exit_code(cls.status, why=cls.why)) else 0


_ZERO_MARKER_WHY = "本批零口径标记"


def enforce_exit_code(status: str, *, why: str) -> int:
    """`--enforce` 下【口径×族】那一条的退出码。🔴 `未测 ≠ 通过` 必须落在**退出码**上，不只落在状态词上。

    2026-09-06 的实测失效：原来是 `1 if status == "fail" else 0` —— 于是**缺族标签侧表**的一批在
    `--enforce` 下返 0。一道以「没量过不许当成过了」为存在理由的门，自己把没量过放行了；而
    `test_missing_side_table_is_not_measured` 只断言了 status，没断言退出码（测零件，没测产物）。

    🔴 `not_measured` 有两种理由，处置相反，不许合并：
      • 缺族标签侧表   —— 【没法量】 ⇒ 拦。放行等于「没有侧表所以过了」。
      • 本批零口径标记 —— 【没有东西可量】，判据按构造成立（没有任何拼写信号，自然预测不了族）
                        ⇒ 放行。一起拦掉，本门会在一批**完全干净**的语料上红，而红得太频的门会被关掉。
    `underpowered` 同样拦：它的意思是这道门在当前密度下**不可能红**，那样的绿不构成证据。"""
    if status == "fail" or status == "underpowered":
        return 1
    if status == "not_measured":
        return 0 if why == _ZERO_MARKER_WHY else 1
    return 0


def _docs(corpus_dir: Path) -> list[dict]:
    out: list[dict] = []
    for f in sorted(corpus_dir.glob("*.y*ml")):
        for doc in yaml.safe_load_all(f.read_text(encoding="utf-8")):
            if isinstance(doc, dict) and "id" in doc:
                out.append(doc)
    return out


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
