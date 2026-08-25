"""CN benign-arm DEPTH proxies (EV-CN-BENIGN-N180 件3.1) — MACHINE proxies for a failure the hard-negative
COUNT floor cannot catch: 110 cases can ALL count as hard negatives and ALL sit at the shallowest layer
(九成套交付方点名的那两个母形态 —— 占比满分、深度贫瘠). The count answers "写了多少简单例"; the failure is
"下意识少去找难件" —— a question a countable quantity can't answer.

🔴 FIRST ROUND = MEASURE ONLY, NO GATE (same discipline as citability.FIRST_MEASUREMENT_*): these have
NEVER been measured, so gating them is 拍脑袋; and setting a gate first, then rewriting the corpus to pass,
fits the corpus to the gate — the same disease as reporting FPR on the fit set. ⇒ if a number runs high,
ask the SOURCE for more material; never let someone who has seen the numbers rewrite. A gate-less number
reads as "passed" when ABSENT, so every measured number MUST appear.

What each proxy measures — 🔴 the name and the thing must match (① was once mis-built to measure near-dup
rate under a name that claimed "did they use the two molds"):
  • 母形态覆盖 —— the share of cases hitting either of the TWO NAMED mother-patterns from the dated §8.3
    (delivery side NAMED them: ①「以 X 为准」② 「原样/原文/誊 —— 转录不代办」). 🔴 NOT an auto-clustered
    top-2 skeleton (that measures near-duplicate rate, a DIFFERENT and more reassuring number); the
    signatures are the delivery side's named say-forms, read from the dated doc, not derived from the 110.
  • 骨架去重率 —— distinct skeletons / n, GLOBAL and PER-WORKFLOW. 🔴 DECLARED LIMITATION: it collapses
    only LITERAL near-duplicates, NOT paraphrases of one mold — 110 rewrites of two molds can score ~100%.
    So "did they use the two molds" is answered by 母形态覆盖 above, NOT by this.
  • 贴边特征种类数 —— per-case count of DISTINCT boundary-feature types. 🔴 NOT_MEASURED without a vocab
    derived from the dated §8.3 by someone who has NOT read the 110 cases: a hand-written / same-source
    vocab measures the vocab-corpus GAP, not the corpus. A can't-judge must not masquerade as a judged数.

🔴 All are PROXIES: depth has no direct machine criterion; they only make the cheapest fakes expensive. The
real control is 人的分离 (取材人 ≠ 标注人；标定臂由没看过任何数的人扩，天然对照).

    PYTHONPATH=$PWD python tools/check_cn_depth.py --corpus <cn_root> [--boundary-vocab <file>]
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

_ARMS = ("llm01_cn_benign_calib", "llm01_cn_benign_holdout")

_FIRST_MEASUREMENT_BANNER = (
    "🔴 无门槛·首测（件3.1，复用 citability.FIRST_MEASUREMENT_* 的纪律）：这些代理此前从未在任何语料上测过"
    " —— 没测过就设门是拍脑袋。本轮【只测不拦】：算出来、进 Tier-0、随数走；门在拿到首测之后单独裁定。"
    "🔴 更硬的一条：先立门再让人改语料改到过门，就是把语料拟合到门上 —— 若首测偏高，修法是向取材人要更多"
    "材料，不是让看过数的人去改写。"
)
# 🔴 件6 (EV-EN-BENIGN-HOLDOUT §3.2.4) — 口径 LABEL. These proxies match on SURFACE FORMS (字面/词面):
# regex over literals and masked skeletons. They do NOT parse meaning. A human (or another tool) that
# estimates the same quantity PRAGMATICALLY (语用 — "is this case really performing that act") will get a
# different number, and the two are NOT comparable. Stating the口径 is what keeps someone from reading our
# 44.3% against their pragmatic 60% as if one refuted the other.
_KOJING_LABEL = (
    "🔴 口径：本工具实现的是【词面】（正则/骨架匹配，不解析语义）—— 只与【同口径】的估计比较；"
    "与【语用】口径的估计（人读出来的「这条真的在做那件事吗」）不可直接对齐，两者不是同一个量"
)
_PROXY_CAVEAT = (
    "🔴 都是【深度】的代理：深度没有直接机器判据，只把最便宜的造假法变贵；全过仍可能在没想到的维度上是浅的"
    " ⇒ 真正的控制是人的分离（取材人 ≠ 标注人，标定臂由没看过数的人扩）。"
)
# 🔴 declared limitation of the dedup proxy — it is NOT the 母形态 check.
_DEDUP_LIMITATION = (
    "🔴 局限（声明）：骨架去重只塌【逐字近重复】，塌不掉【同一母形态的改写】—— 110 条对两个模子的改写可以"
    "报满分去重。「用没用那两个模子」看【母形态覆盖】，不看这里。"
)

# --------------------------------------------------------------------------- #
# 母形态覆盖 — the TWO NAMED mother-patterns from the dated §8.3 (read from the delivery doc, NOT clustered)
# --------------------------------------------------------------------------- #
# 🔴 signatures derived from §8.3's NAMED say-forms (delivery side named them), auditable one-for-one:
#   ① the 指令覆盖 mold — its defining literal is 「…为准」;  ② the 转录不代办 mold — 原样 / 原文 / 誊.
#   🔴 the molds' FULL delivered wording is NOT reproduced here (件⑦: the 34 anchors live out-of-repo,
#   `<corpus-root>/meta/holdout_material.json`). Only the DETECTION literals are in-repo — they are the
#   regex, not the corpus text, the same line the injection ruleset literals sit on.
_MOTHER_PATTERNS: tuple[tuple[str, str], ...] = (
    ("①以X为准", r"为准"),
    ("②原样转录", r"原样|原文|誊"),
)
_MOTHER_RE = tuple((name, re.compile(p)) for name, p in _MOTHER_PATTERNS)


# --------------------------------------------------------------------------- #
# 🔴 批一 — DEVIATION FROM THE SOURCE IS TWO-SIDED, and a one-sided criterion is half a criterion.
#   • corpus ABOVE the anchors  ⇒ 偷懒套模子: more concentrated than the material the source actually gave;
#   • corpus BELOW the anchors  ⇒ 🔴 造了交付方没给的语言: we invented phrasing the source never delivered —
#     just as much a departure from the material, and the one an author "diversifying" produces.
# Both are 偏离素材源. Reporting only the high side lets the other failure through silently.
# 🔴 The BAND has no evidence behind it (nobody has measured what a normal gap looks like), so this stays
# MEASURE-ONLY: the band exists to make the direction readable, it is NOT a gate.
_DRIFT_BAND = 0.10  # 声明值·无证据 —— 只为把方向读出来，不设门


def drift_direction(corpus: float, anchor: float, band: float = _DRIFT_BAND) -> str:
    """'above' (更集中/套模子) · 'below' (更发散/造了没给的语言) · 'aligned'. Two-sided by construction."""
    delta = corpus - anchor
    if delta > band:
        return "above"
    if delta < -band:
        return "below"
    return "aligned"


_DRIFT_LABEL = {
    "above": "🔴 高于锚点（偷懒套模子：比交付素材更集中）",
    "below": "🔴 低于锚点（造了交付方没给的语言：比交付素材更发散）",
    "aligned": "与锚点同量级",
}


def mother_pattern_coverage(texts: list[str]) -> tuple[float, list[tuple[str, int]]]:
    """🔴 件3.1 (corrected) — the share of cases hitting EITHER named mother-pattern (§8.3), plus each
    pattern's own hit count. This reads the delivery side's NAMED say-forms; it does NOT auto-cluster
    skeletons (that measured near-duplicate rate — the wrong, reassuring number)."""
    n = len(texts)
    if not n:
        return 0.0, [(name, 0) for name, _ in _MOTHER_RE]
    per = [(name, sum(1 for t in texts if rx.search(t))) for name, rx in _MOTHER_RE]
    union = sum(1 for t in texts if any(rx.search(t) for _, rx in _MOTHER_RE))
    return union / n, per


# --------------------------------------------------------------------------- #
# 骨架去重率 — variety proxy (declared limitation above)
# --------------------------------------------------------------------------- #
# 🔴 「去掉业务名词/数字后的骨架」— EVERY business noun masks to one ⟨N⟩ (a mold is a mold regardless of the
# noun in its slot); a declared, INCOMPLETE vocabulary (a proxy).
_NOUN_RE = re.compile(
    r"账户|账号|余额|卡号|存款|资金|转账|汇款|付款|交易|支付|收款|划扣|额度|限额|上限|利率|费率|门槛|"
    r"客户|用户|户主|持卡人|会员|对方|工单|发票|合同|报销|单据|凭证|流水|申请|系统|平台|后台|工作台|"
    r"控制台|门户|审批|审核|复核|授权|权限|风控|名单|清单|白名单|黑名单|列表|目录|版本|政策|规定|制度|"
    r"条款|流程|规则"
)
_BRACKETED = re.compile(r"[【「《（(\[][^】」》)\]]*[】」》）)\]]")
_DIGITS = re.compile(r"\d+")
_ASCII = re.compile(r"[A-Za-z]+")
_WS = re.compile(r"\s+")


def skeleton(text: str) -> str:
    """The phrasing scaffold: mask bracketed slots, digits, ASCII, and every business noun (all to one
    ⟨N⟩), then collapse whitespace. 🔴 Collapses LITERAL near-duplicates only, NOT paraphrases (declared)."""
    s = _BRACKETED.sub("▢", text)
    s = _NOUN_RE.sub("⟨N⟩", s)
    s = _DIGITS.sub("0", s)
    s = _ASCII.sub("x", s)
    return _WS.sub("", s)


def group_of(case_id: str) -> str:
    """The workflow (holdout: cn.holdout.wfA.NN → cn.holdout.wfA) or family (calib) an id belongs to."""
    parts = case_id.split(".")
    if len(parts) >= 2 and parts[-1].isdigit():
        return ".".join(parts[:-1])
    return case_id


def dedup_rate(skeletons: list[str]) -> float:
    return len(set(skeletons)) / len(skeletons) if skeletons else 0.0


# --------------------------------------------------------------------------- #
# 🔴 语用行为集中度 (件③) — the FOURTH proxy, and the reason it exists is an ADMITTED BLIND SPOT of the
# other three: on the pre-③ holdout all three PASSED (mother-pattern under the line, dedup ~100%, boundary
# not_measured) while a human reading the 110 cases found them MONOTONE — every case the same speech act
# (登记/录入/别改), question marks 0/110. 🔴 So this is not a patch bolted on; it is the demonstrated gap the
# other three are blind to: they measure WHICH WORDS and HOW REPEATED, none of them measures WHAT THE
# SENTENCE IS DOING. A corpus can vary its nouns and skeletons perfectly and still be one speech act.
#
# 🔴 Measured RELATIVE TO THE DELIVERY ANCHORS, per workflow — the anchors (§8.3's 3-4 real sayings per
# workflow, from the dated doc) are the non-circular reference: they show the variety the SOURCE exhibited.
# Corpus concentration MUCH HIGHER than anchor concentration = the implementation flattened it. An absolute
# threshold would be another 拍脑袋 number; a delta against the source is not.
_SPEECH_ACTS: tuple[tuple[str, str], ...] = (
    ("interrogative", r"？|\?|是不是|能不能|要不要|还是|怎么|哪版|哪个|多少|吗|呢"),
    ("consultative", r"对吧|可以吗|行吗|好吗|这样行|是这样吗"),
    ("prohibitive", r"别|不要|勿|不得|先不|不用|不归"),
    (
        "directive",
        r"把|帮我|请|照.{0,4}(念|做|来)|按.{0,6}(来|算|走|办)|原样|原文|摘|提炼|录入|登记|誊",
    ),
)
_SPEECH_RE = tuple((name, re.compile(p)) for name, p in _SPEECH_ACTS)


def speech_acts(text: str) -> frozenset[str]:
    """The SET of speech acts a case performs (a declared, INCOMPLETE proxy taxonomy). A case matching none
    is `assertive` — a plain statement. The SET (not a forced primary act) is the unit, because monotony is
    'every case does the same combination of things', which a primary-act collapse would hide."""
    hits = frozenset(name for name, rx in _SPEECH_RE if rx.search(text))
    return hits or frozenset({"assertive"})


def act_concentration(texts: list[str]) -> float:
    """Share of cases carrying the MOST COMMON act-set. 1.0 = every case does exactly the same thing."""
    if not texts:
        return 0.0
    counts = Counter(speech_acts(t) for t in texts)
    return counts.most_common(1)[0][1] / len(texts)


def speech_act_vs_anchors(
    corpus_groups: dict[str, list[str]], anchor_groups: dict[str, list[str]]
) -> list[tuple[str, float, float, int]]:
    """Per group (workflow/family): (group, corpus_concentration, anchor_concentration, n). Only groups the
    ANCHORS cover are compared — a group with no delivered anchors has no non-circular reference."""
    out: list[tuple[str, float, float, int]] = []
    for g in sorted(corpus_groups):
        anchors = anchor_groups.get(g)
        if not anchors:
            continue
        texts = corpus_groups[g]
        out.append(
            (g, act_concentration(texts), act_concentration(anchors), len(texts))
        )
    return out


# --------------------------------------------------------------------------- #
# 贴边特征种类数 — NOT_MEASURED unless a non-circular vocab is supplied
# --------------------------------------------------------------------------- #
def boundary_feature_types(
    text: str, vocab: tuple[tuple[str, str], ...]
) -> frozenset[str]:
    """The SET of boundary-feature types the case carries under `vocab` (variety = len of this set). 🔴
    `vocab` is REQUIRED and has no in-tool default: a hand-written / same-source vocab measures the vocab-
    corpus gap, not the corpus (件3 ②). Supply one derived from the dated §8.3 by a non-reader, or don't
    measure this at all (measure_depth reports not_measured)."""
    compiled = ((name, re.compile(p)) for name, p in vocab)
    return frozenset(name for name, rx in compiled if rx.search(text))


# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class DepthReport:
    arm: str
    n: int
    mother_union: float  # share hitting either NAMED mother-pattern
    mother_per_pattern: list[tuple[str, int]]
    # 批一 — the ANCHORS' own mother-pattern coverage + the two-sided drift reading (None ⇒ no anchors)
    mother_anchor: float | None
    mother_drift: str | None
    dedup_global: float
    dedup_worst_group: float
    worst_group: str
    boundary_measured: bool  # False ⇒ not_measured (no non-circular vocab)
    boundary_mean: float | None
    boundary_min: int | None
    single_type_share: float | None
    # 件③ 语用行为集中度 — None ⇒ not_measured (no delivery anchors supplied)
    act_rows: list[tuple[str, float, float, int]] | None
    act_drift: (
        str | None
    )  # 批一 — two-sided direction of the pooled act-concentration gap


def measure_depth(
    arm: str,
    texts_by_id: dict[str, str],
    *,
    boundary_vocab: tuple[tuple[str, str], ...] | None = None,
    anchors: dict[str, list[str]] | None = None,
) -> DepthReport:
    """Compute the proxies for one arm. Pure — no gate, no exit, no threshold. Boundary features are
    NOT_MEASURED unless a (non-circular) vocab is supplied."""
    ids = sorted(texts_by_id)
    texts = [texts_by_id[i] for i in ids]
    skels = [skeleton(t) for t in texts]
    n = len(ids)
    union, per = mother_pattern_coverage(texts)

    groups: dict[str, list[str]] = {}
    for i, sk in zip(ids, skels):
        groups.setdefault(group_of(i), []).append(sk)
    per_group = {g: dedup_rate(gs) for g, gs in groups.items()}
    worst_group = min(per_group, key=lambda g: per_group[g]) if per_group else "∅"
    worst_dedup = per_group.get(worst_group, 0.0)

    if boundary_vocab is None:
        b_measured, b_mean, b_min, b_single = False, None, None, None
    else:
        variety = [len(boundary_feature_types(t, boundary_vocab)) for t in texts]
        b_measured = True
        b_mean = (sum(variety) / n) if n else 0.0
        b_min = min(variety) if variety else 0
        b_single = (sum(1 for v in variety if v <= 1) / n) if n else 0.0
    # 批一 — the anchors' OWN mother-pattern coverage, so the mother proxy is read as a two-sided
    # deviation from the source rather than against an invented absolute line.
    mother_anchor = mother_drift = None
    act_drift = None
    # 🔴 only compare against anchors that actually COVER this arm's groups. The calib arm was built from a
    # DIFFERENT anchor set (§8.2), so measuring it against the holdout's §8.3 anchors would be apples-to-
    # oranges dressed as a finding — the same rule the act proxy already applies (无可比组 ⇒ not_measured).
    _groups = {group_of(i).split(".")[-1] for i in ids}
    if anchors:
        # 🔴 ONE guard, not two: pool only the anchors whose group this arm actually contains. An arm the
        # anchors do not cover yields an EMPTY pool ⇒ mother_drift stays None ⇒ not_measured.
        pooled = [t for g, texts_ in anchors.items() if g in _groups for t in texts_]
        if pooled:
            mother_anchor = mother_pattern_coverage(pooled)[0]
            mother_drift = drift_direction(union, mother_anchor)
    # 件③ — per-group speech-act concentration vs the DELIVERY ANCHORS (the non-circular reference).
    act_rows = None
    if anchors:
        by_group: dict[str, list[str]] = {}
        for i in ids:
            by_group.setdefault(group_of(i).split(".")[-1], []).append(texts_by_id[i])
        act_rows = speech_act_vs_anchors(by_group, anchors)
        if act_rows:
            act_drift = drift_direction(
                sum(r[1] for r in act_rows) / len(act_rows),
                sum(r[2] for r in act_rows) / len(act_rows),
            )
    return DepthReport(
        arm=arm,
        n=n,
        mother_union=union,
        mother_per_pattern=per,
        mother_anchor=mother_anchor,
        mother_drift=mother_drift,
        dedup_global=dedup_rate(skels),
        dedup_worst_group=worst_dedup if groups else 0.0,
        worst_group=worst_group,
        boundary_measured=b_measured,
        boundary_mean=b_mean,
        boundary_min=b_min,
        single_type_share=b_single,
        act_rows=act_rows,
        act_drift=act_drift,
    )


def _load_vocab(path: Path) -> tuple[tuple[str, str], ...]:
    """Load a boundary vocab (JSON: [[name, regex], ...]) — supplied out-of-repo, derived from §8.3."""
    import json

    raw = json.loads(path.read_text(encoding="utf-8"))
    return tuple((str(name), str(pat)) for name, pat in raw)


def _load_anchors(path: Path) -> dict[str, list[str]]:
    """Load delivery anchors (JSON {group: [sayings]}) — supplied OUT-OF-REPO, from the dated §8.3. 🔴 The
    anchor TEXTS are delivery corpus material and never enter this repo (§0); the tool takes a path."""
    import json

    raw = json.loads(path.read_text(encoding="utf-8"))
    return {str(k): [str(t) for t in v] for k, v in raw.items()}


def _case_text(c: object) -> str:
    parts = [getattr(c, "input", "") or "", getattr(c, "system_prompt", "") or ""]
    for m in getattr(c, "messages", None) or ():
        parts.append(
            m.content
            if isinstance(m.content, str)
            else " ".join(p.text for p in m.content)
        )
    return " ".join(parts)


def _print_report(r: DepthReport) -> None:
    print(f"  臂 {r.arm}（n={r.n}）：")
    per = "、".join(f"{name} {c}件" for name, c in r.mother_per_pattern)
    drift_note = (
        f" · 锚点 {r.mother_anchor:.1%} ⇒ {_DRIFT_LABEL[r.mother_drift]}"
        if (r.mother_drift is not None and r.mother_anchor is not None)
        else " · 锚点未提供 ⇒ 偏离方向 not_measured"
    )
    print(
        f"    母形态覆盖（命中 §8.3 两个具名母形态之一）：{r.mother_union:.1%}（{per}）"
        f"{drift_note} —— 无门槛·首测"
    )
    print(
        f"    骨架去重率：全局 {r.dedup_global:.1%} · 最差工作流 {r.dedup_worst_group:.1%}"
        f"（{r.worst_group}）—— 无门槛·首测"
    )
    if r.boundary_measured:
        print(
            f"    贴边特征种类数：均值 {r.boundary_mean:.2f} · 下尾 min={r.boundary_min} · "
            f"单一种占比 {r.single_type_share:.1%} —— 无门槛·首测"
        )
    else:
        print(
            "    贴边特征种类数：not_measured —— 🔴 词表须由不读 110 条的人从有日期的 §8.3 派生；"
            "手写/同源词表量的是词表与语料的落差，不是深度（--boundary-vocab 缺省 ⇒ 不测，不伪装成已测）"
        )
    if r.act_rows is None:
        print(
            "    语用行为集中度：not_measured —— 🔴 需要交付锚点（有日期的 §8.3 逐工作流真实说法）作非循环"
            "参照；绝对阈值又是一个拍脑袋的数（--anchors 缺省 ⇒ 不测，不伪装成已测）"
        )
    elif not r.act_rows:
        print("    语用行为集中度：无可比组（锚点未覆盖本臂任何组）—— 无门槛·首测")
    else:
        worst = max(r.act_rows, key=lambda x: x[1] - x[2])
        _drift = r.act_drift or "aligned"
        avg_c = sum(x[1] for x in r.act_rows) / len(r.act_rows)
        avg_a = sum(x[2] for x in r.act_rows) / len(r.act_rows)
        print(
            f"    语用行为集中度（逐组·相对交付锚点）：语料均值 {avg_c:.1%} vs 锚点均值 {avg_a:.1%}"
            f"（Δ{avg_c - avg_a:+.1%} ⇒ {_DRIFT_LABEL[_drift]}）· 最扁平组 {worst[0]} "
            f"{worst[1]:.1%} vs {worst[2]:.1%}（n={worst[3]}）—— 无门槛·首测"
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="check_cn_depth", description=__doc__)
    ap.add_argument(
        "--corpus", type=Path, required=True, help="CN corpus ROOT (out-of-repo)"
    )
    ap.add_argument(
        "--boundary-vocab",
        type=Path,
        default=None,
        help="JSON [[name, regex], ...] derived from the dated §8.3 by a non-reader; absent ⇒ not_measured",
    )
    ap.add_argument(
        "--anchors",
        type=Path,
        default=None,
        help="JSON {group: [anchor sayings]} from the dated §8.3 (out-of-repo); absent ⇒ not_measured",
    )
    args = ap.parse_args(argv)

    present = [
        (arm, args.corpus / arm) for arm in _ARMS if (args.corpus / arm).exists()
    ]
    if not present:
        print(
            "cn-depth 首测：本批语料不在本仓，未测量（作用域："
            + " · ".join(str(args.corpus / a) for a in _ARMS)
            + "）"
        )
        print(f"    {_FIRST_MEASUREMENT_BANNER}")
        return 0

    from treval.active_eval import load_corpus
    from treval.active_eval.corpus import CorpusError

    vocab = _load_vocab(args.boundary_vocab) if args.boundary_vocab else None
    anchors = _load_anchors(args.anchors) if args.anchors else None
    print("cn-depth 首测（深度代理，只测不拦）：")
    try:
        for arm, d in present:
            cases = list(load_corpus(d))
            _print_report(
                measure_depth(
                    arm,
                    {c.id: _case_text(c) for c in cases},
                    boundary_vocab=vocab,
                    anchors=anchors,
                )
            )
    except (CorpusError, OSError, ValueError) as e:
        print(f"cn-depth 首测：ERROR — {e}", file=sys.stderr)
        return 2
    print(f"    {_DEDUP_LIMITATION}")
    print(f"    {_FIRST_MEASUREMENT_BANNER}")
    print(f"    {_KOJING_LABEL}")
    print(f"    {_PROXY_CAVEAT}")
    return 0  # 🔴 measure-only: never a threshold FAIL this round


if __name__ == "__main__":
    raise SystemExit(main())
