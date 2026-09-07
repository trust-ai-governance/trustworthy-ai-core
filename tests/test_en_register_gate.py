"""W2/W6 口径门 —— each test names the input that reds it.

🔴 判据是【拼写口径不得预测类别】，不是密度。密度只测不拦、不设红线（没有一个非拟合的依据能定那条线，
而由看过数的人挑一个能让手里语料过门的数，就是把门拟合到语料上）。类别相关那一条有天然阈值：**不得显著
高于随机** —— 用置换检验判，α 是惯例值不是挑出来的。

🔴 两条判据会互相作用，这一点必须由测试钉住：把密度压到既有臂的量级，类别相关检验就【没有功效】——
一个不可能红的门，绿了不构成证据。所以 `underpowered` 是独立第三态，绝不并进 `ok`。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.check_en_register import (
    JURISDICTION_TERMS,
    PoolError,
    case_pool,
    case_prose,
    class_prediction,
    density_report,
    id_register_markers,
    jurisdiction_hits,
    register_markers,
    scan_corpus,
)

_REPO = Path(__file__).resolve().parents[1]
_FAMS = ("family_a", "family_b", "routine")


def _labelled(spec: list[tuple[str, int, int]]) -> tuple[dict[str, str], list]:
    """spec = [(family, n_cases, n_carrying)] ⇒ (labels, markers)。载体文本同一句，测的是分布不是措辞。"""
    labels: dict[str, str] = {}
    markers: list = []
    for fam, n, carrying in spec:
        for i in range(n):
            cid = f"{fam}.{i}"
            labels[cid] = fam
            if i < carrying:
                markers += register_markers(cid, "who authorised this limit")
    return labels, markers


# --------------------------------------------------------------------------- #
# 🔴 主判据 —— 拼写口径不得预测类别
# --------------------------------------------------------------------------- #
def test_markers_concentrated_in_one_family_reds():
    """🔴 什么让它红：口径标记全落在族 A 上 ⇒ 看拼写就能猜出族 ⇒ 语料自己带了一张边界图。"""
    labels, markers = _labelled(
        [("family_a", 35, 30), ("family_b", 35, 0), ("routine", 45, 0)]
    )
    got = class_prediction(labels, markers)
    assert got.status == "fail"
    assert got.p < 0.05
    assert got.accuracy > got.chance


def test_markers_spread_in_proportion_pass():
    """按族大小成比例铺开 ⇒ 拼写对族没有信息 ⇒ 准确率不高于随机。"""
    labels, markers = _labelled(
        [("family_a", 35, 9), ("family_b", 35, 9), ("routine", 45, 12)]
    )
    got = class_prediction(labels, markers)
    assert got.status == "ok"
    assert got.p >= 0.05


def test_the_criterion_is_family_independence_not_direction():
    """🔴 方向不是判据：整批统一挂英式但按族铺匀 ⇒ 过；单一族集中 ⇒ 红。判定只随分布变，不随口径变。"""
    even, _ = (
        _labelled([("family_a", 35, 9), ("family_b", 35, 9), ("routine", 45, 12)]),
        None,
    )
    skew = _labelled([("family_a", 35, 30), ("family_b", 35, 0), ("routine", 45, 0)])
    assert class_prediction(*even[0:2]).status == "ok"
    assert class_prediction(*skew).status == "fail"


# --------------------------------------------------------------------------- #
# 🔴 功效 —— 绿了不一定是干净，可能是量不动
# --------------------------------------------------------------------------- #
def test_too_few_markers_is_underpowered_not_ok():
    """🔴 标记太少时，即使把它们**全部**堆进最有利的一族，置换检验也到不了 α ⇒ 这道门【不可能红】。
    那样的绿必须叫 underpowered，不叫 ok，否则「我们查过口径没问题」就是一句由不可能失败的检查撑起来的话。

    什么让它红：有人把 underpowered 并进 ok。"""
    labels, markers = _labelled(
        [("family_a", 35, 3), ("family_b", 35, 0), ("routine", 45, 0)]
    )
    got = class_prediction(labels, markers)
    assert got.status == "underpowered"
    assert got.max_reachable_p >= 0.05


def test_power_is_computed_not_declared():
    """🔴 功效不是一个拍出来的件数下限 —— 它随**族结构**变，同样的标记数可以一边有功效一边没有：
    三族 35/35/45 上 4 个集中标记能到显著；两族 50/50 上同样 4 个到不了（两族时"四件同族"本来就常见）。
    什么让它红：把 underpowered 改成任何一个只看件数的常数门限。"""
    three = class_prediction(
        *_labelled([("family_a", 35, 4), ("family_b", 35, 0), ("routine", 45, 0)])
    )
    two = class_prediction(*_labelled([("family_a", 50, 4), ("routine", 50, 0)]))
    assert three.max_reachable_p < 0.05 <= two.max_reachable_p
    assert three.status == "fail" and two.status == "underpowered"


def test_the_extreme_arrangement_is_searched_not_assumed():
    """🔴 一次存活的变异逼出来的：功效要问「摆成最极端能到多显著」，而**堆进最大的族几乎没有增益** ——
    那些件本来就会被「不带标记 ⇒ 猜最大族」猜对。若只试最大的族，功效会被系统性低估，于是一批真该红的
    件被判成 underpowered 放过去。

    什么让它红：把遍历各族取最大改成只取最大的那一族。"""
    labels, markers = _labelled(
        [("family_a", 35, 6), ("family_b", 35, 0), ("routine", 45, 0)]
    )
    got = class_prediction(labels, markers)
    assert got.status == "fail"  # 只试 routine（最大族）时这里会退化成 underpowered


def test_no_markers_at_all_is_not_measured():
    """🔴 零标记 ⇒ not_measured。零相关与没量过长得一模一样。"""
    labels, markers = _labelled(
        [("family_a", 35, 0), ("family_b", 35, 0), ("routine", 45, 0)]
    )
    assert class_prediction(labels, markers).status == "not_measured"


def test_missing_side_table_is_not_measured():
    """🔴 没有族标签就判不了这条 —— 缺侧表时必须说未测，不许当成过了。"""
    _, markers = _labelled(
        [("family_a", 35, 9), ("family_b", 35, 9), ("routine", 45, 12)]
    )
    assert class_prediction({}, markers).status == "not_measured"


# --------------------------------------------------------------------------- #
# 🔴 状态说了未测，**退出码**也得说 —— 上面三条测的是零件（status），下面测的是产物（rc）。
# 这一格是 2026-09-06 在真语料上跑本门时自己撞出来的：`--enforce` 只在 `fail` 时返 1，
# 于是【缺侧表】+【--enforce】返 0 —— 一条以「未测 ≠ 通过」为存在理由的门，自己把未测放行了。
# 与 M9/M10 同一个形状：测了零件、没测产物。
# --------------------------------------------------------------------------- #
def test_enforce_refuses_when_the_side_table_is_missing():
    """🔴 什么让它红：`return 1 if (hard or cls.status == "fail")` —— 那样缺族标签的一批
    在 --enforce 下返 0，而这道门存在的全部理由就是不让「没量过」变成「过了」。"""
    from tools.check_en_register import enforce_exit_code

    assert enforce_exit_code("not_measured", why="缺族标签侧表") == 1


def test_enforce_refuses_an_underpowered_verdict():
    """🔴 `underpowered` = 这道门在当前密度下**不可能红** —— 那样的绿不构成证据，不许当通过。
    什么让它红：把它并进 ok。"""
    from tools.check_en_register import enforce_exit_code

    assert enforce_exit_code("underpowered", why="") == 1


def test_enforce_lets_a_zero_marker_batch_through_but_says_why():
    """🔴 这一半同样重要（门的边界要两个方向都测）：**零口径标记**也报 not_measured，但它与缺侧表
    不是一回事 —— 一个是【没法量】，一个是【没有东西可量，判据按构造成立】。

    把它一起拦掉，本门就会在一批**完全干净**的语料上红 —— 而红得太频的门会被关掉。
    什么让它红：只按 status 判，不看 not_measured 的两种理由。"""
    from tools.check_en_register import enforce_exit_code

    assert enforce_exit_code("not_measured", why="本批零口径标记") == 0


def test_enforce_still_blocks_a_real_failure():
    """一道对什么都放行的门不是门。"""
    from tools.check_en_register import enforce_exit_code

    assert enforce_exit_code("fail", why="") == 1
    assert enforce_exit_code("ok", why="") == 0


def test_verdict_is_deterministic():
    """置换检验用固定种子 ⇒ 同输入同判定。一个跑两次给两个答案的门不能当门用。
    🔴 取点必须落在 p 的**中间带**：p 贴到 1/(trials+1) 的下限时，不设种子也会两次都给同一个数，
    那样这条测试就测不到种子（这是一次存活的变异指出来的）。"""
    args = _labelled([("family_a", 35, 6), ("family_b", 35, 3), ("routine", 45, 4)])
    first, second = class_prediction(*args), class_prediction(*args)
    assert 0.05 < first.p < 0.95  # 中间带，噪声看得见
    assert first.p == second.p


# --------------------------------------------------------------------------- #
# 密度 —— 只测不拦，不设红线
# --------------------------------------------------------------------------- #
def test_density_has_no_red_line():
    """🔴 密度不设判据：整批 115 件全挂英式，密度报告照样只是一个【测量】。"""
    markers = [
        m for i in range(115) for m in register_markers(f"c{i}", "who authorised this")
    ]
    got = density_report(markers, 115)
    assert got.status == "measured"
    assert got.rate == 1.0


def test_density_empty_batch_is_not_measured():
    """🔴 没有件 ⇒ not_measured。占比 0 与「一件都没量」绝不许合并。"""
    assert density_report([], 0).status == "not_measured"


# --------------------------------------------------------------------------- #
# 排除项 —— 每一条都来自既有臂上实测出的一类假阳性
# --------------------------------------------------------------------------- #
def test_field_name_is_not_a_register_choice():
    """🔴 ticket_authorization_claim 是字段名，不是散文 —— 作者没有在这里做口径选择。"""
    assert register_markers("c", "attach the ticket_authorization_claim value") == []


def test_proper_noun_is_not_a_register_choice():
    """🔴 Helmholtz Center 是机构专名 —— 拼法由该机构自己定，不是我们的口径。"""
    assert register_markers("c", "cite the Helmholtz Center advisory") == []


def test_marker_inside_an_encoded_payload_is_not_a_register_choice():
    """🔴 载荷里的字母不是作者写的散文 —— 既有攻击臂的美式标记里相当一部分是这一类。"""
    body = "decode this: VGhlIGF1dGhvcml6YXRpb24gaXMgZ3JhbnRlZA=="
    assert register_markers("c", body) == []


def test_prose_marker_after_a_lowercase_word_still_counts():
    """排除项不许把真正的散文口径一起吃掉 —— 否则这道门永远绿。"""
    got = register_markers("c", "the limit was authorised yesterday")
    assert [m.token for m in got] == ["authorised"]


# --------------------------------------------------------------------------- #
# 两层：法域术语留，拼写口径归拼写口径
# --------------------------------------------------------------------------- #
def test_jurisdiction_terms_are_never_spelling_markers():
    """🔴 MLRO / four-eyes / DoA 是素材侧唯一的领域贡献，照锚点留 —— 它们不进拼写口径。"""
    body = "MLRO sign-off plus four-eyes under the DoA"
    assert register_markers("c", body) == []
    assert len(jurisdiction_hits(body)) >= 3


def test_declared_terms_are_a_declared_list_not_a_claim_of_completeness():
    """这张表是声明值 —— 表外的术语【未测】，不是【不存在】。"""
    assert "MLRO" in JURISDICTION_TERMS


# --------------------------------------------------------------------------- #
# 既有三条臂 —— 扫描面必须完整，否则分母是假的
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "arm", ["llm01_benign_calib", "llm01_benign_holdout", "llm01_prompt_injection"]
)
def test_every_existing_case_has_readable_prose(arm):
    """🔴 一件读不到正文时，它既不带标记也不进分母 —— 两边一起消失，占比因此是假的而报告读起来正常。
    什么让它红：新增一种正文字段（或改名），而扫描器没跟上。"""
    _, total, unreadable = scan_corpus(_REPO / "corpus" / arm)
    assert unreadable == [], f"{arm}: {unreadable[:3]}"
    assert total == len(list((_REPO / "corpus" / arm).glob("*.y*ml")))


def test_multi_turn_prose_is_scanned():
    """🔴 只扫 `input` 会静默漏掉多轮件。"""
    doc = {
        "id": "x",
        "messages": [
            {"role": "user", "content": "who authorised the limit"},
            {"role": "assistant", "content": "checking"},
        ],
    }
    assert [m.token for m in register_markers("x", case_prose(doc) or "")] == [
        "authorised"
    ]


# --------------------------------------------------------------------------- #
# 🔴 实测发现（既有臂，非本轮新件）—— 拼写口径与【类别】相关
# --------------------------------------------------------------------------- #
def test_spelling_predicts_the_class_in_the_existing_arms():
    """🔴 这条测的是一个【已经存在的缺陷】，不是一条判据：既有良性臂说 Summarise，攻击臂说 Summarize，
    同一载体的孪生对逐对如此。在带成对标记的那批件上，「英式⇒良性 / 美式⇒攻击」的多数类正确率 > 80%。
    批次签名让人认出这一批；**类别相关的签名让人猜中标签**，后者严重得多。

    🔴 待裁（2026-09-01 单列，不挡任何在建臂）：把口径判据【升格到语料层面】—— 从「批内各族之间无差别」
    升到「拼写不得预测良性/攻击」。该做，但它要连既有臂一起改 ⇒ `corpus_sha` 变 ⇒ τ 重标定 ⇒ 留出臂
    再推一次。代价链已知，所以是一次决定，不是一次顺手。在它落地之前，本条只钉住事实可复算。

    什么让它红：有人动了既有臂的口径分布。"""
    counts = {}
    for label, arms in (
        ("benign", ("llm01_benign_calib", "llm01_benign_holdout")),
        ("attack", ("llm01_prompt_injection",)),
    ):
        ms = [m for a in arms for m in scan_corpus(_REPO / "corpus" / a)[0]]
        for variety in ("british", "american"):
            counts[label, variety] = len(
                {m.case_id for m in ms if m.variety == variety}
            )
    majority = counts["benign", "british"] + counts["attack", "american"]
    assert majority / sum(counts.values()) > 0.80, counts


# --------------------------------------------------------------------------- #
# W2 锚点来源 —— 挡住一个「看起来像进步」的误读
# --------------------------------------------------------------------------- #
def test_w2_anchor_note_says_unmeasured_not_mitigated():
    """🔴 什么让它红：把 `unmeasured` 写成 `mitigated`。用了领域锚点看着像把「我方自造的件偏温和」修好了，
    而交付人如实声明那 36 条锚点**同样是内部自造** —— 偏差只是上移了一层，没有任何东西测过它。"""
    from treval.citability import W2_ANCHOR_PROVENANCE_NOTE as note

    assert "unmeasured" in note and "mitigated" not in note.replace(
        "不是 mitigated", ""
    )


def test_w2_anchor_note_states_the_direction():
    """🔴 一个未测的偏差必须带方向，否则读者会默认它对称。温和 ⇒ 误拦率偏低、偏乐观。"""
    from treval.citability import W2_ANCHOR_PROVENANCE_NOTE as note

    assert "偏低" in note and "偏乐观" in note


def test_w2_anchor_note_keeps_unknown_separate_from_unobtainable():
    """🔴 「机构侧能否取得真实原话」是未知，不是拿不到 —— 把未知写成拿不到，会把一条待办变成一条永久约束。"""
    from treval.citability import W2_ANCHOR_PROVENANCE_NOTE as note

    assert "未知" in note and "不是拿不到" in note


# --------------------------------------------------------------------------- #
# 🔴 case id 也是信号 —— 一个 slug 逃过了整道门，是人眼先看见的
# --------------------------------------------------------------------------- #
def test_id_marker_is_invisible_to_the_prose_path():
    """🔴 为什么必须单开一条路：散文扫描会把带 `_`/数字的 token 整个丢掉（对字段名是对的），而 case id
    正好长成那样 ⇒ id 里的口径标记在散文那条路上【静默为零】。"""
    cid = "benign.hard.utilisation_against_limits.506"
    assert register_markers(cid, cid) == []  # 散文路：看不见
    assert [m.token for m in id_register_markers(cid)] == ["utilisation"]


def test_id_marker_direction_is_symmetric():
    """id 这条路同样方向盲 —— 英式美式都认。"""
    uk = id_register_markers("benign.hard.centralised_report.1")
    us = id_register_markers("benign.hard.centralized_report.1")
    assert uk[0].variety == "british" and us[0].variety == "american"


def test_clean_id_has_no_marker():
    """排除项不许把普通 slug 也算成口径标记，否则这道门永远红。"""
    assert id_register_markers("benign.hard.drawn_against_limits.506") == []


# --------------------------------------------------------------------------- #
# 🔴 工单 2 —— parts 形态的正文 + 让「只拿正文」写不出来
# --------------------------------------------------------------------------- #
def test_content_parts_array_is_read_as_prose():
    """🔴 `content` 有两种形状：字符串，或 parts 数组 `[{type: text, text: …}]`。只认字符串会把
    parts 形态的件读成空 —— 它于是既不带标记也不进分母，两边一起消失。
    什么让它红：去掉 parts 分支。"""
    doc = {
        "id": "x",
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "who authorised it"}]}
        ],
    }
    assert case_prose(doc) == "who authorised it"


def test_the_parts_case_now_enters_the_denominator():
    """🔴 用门自己的报告定位到的那一件（不是按路径找）。修完它必须进分母，该目录 unreadable 归零。
    什么让它红：parts 分支没了，或建池又绕开了 unreadable。"""
    _, total, unreadable = scan_corpus(_REPO / "corpus" / "llm01_indirect_benign")
    assert unreadable == []
    assert total == len(
        list((_REPO / "corpus" / "llm01_indirect_benign").glob("*.y*ml"))
    )


def test_pool_refuses_to_hand_over_prose_while_cases_are_unreadable(tmp_path):
    """🔴 本轮两次同形缺陷的修法：不是加注释提醒，是让「只拿正文、不看丢件」**写不出来**。
    池里有读不到正文的件时，`.texts` 直接拒绝；要照旧取必须显式说出来。
    什么让它红：把 `.texts` 改回静默返回。"""
    (tmp_path / "a.yaml").write_text("id: ok\ninput: hello\n", encoding="utf-8")
    (tmp_path / "b.yaml").write_text("id: blind\nowasp: LLM01\n", encoding="utf-8")
    pool = case_pool(tmp_path)
    assert len(pool.unreadable) == 1
    with pytest.raises(PoolError, match="读不到正文"):
        _ = pool.texts
    assert pool.texts_acknowledging_unreadable() == ("hello",)  # 显式，才拿得到


def test_pool_drops_control_cases_by_attack_class_not_by_id():
    """🔴 控制件的标记在 `attack_class` 上，**不在 id 上** —— 按 id 匹配 `control_` 一件都剔不掉，
    那正是"既有攻击件"基线混进 59 件控制件的成因（大写率因此报成 85.8% 而非 94.1%）。
    什么让它红：建池函数漏掉控制件过滤，或改回按 id 匹配。"""
    d = _REPO / "corpus" / "llm01_prompt_injection"
    kept = case_pool(d, drop_control=True)
    allc = case_pool(d, drop_control=False)
    assert len(kept.dropped_control) > 0
    assert len(kept.docs) == len(allc.docs) - len(kept.dropped_control)
    assert all("control_" not in cid for cid in kept.dropped_control)  # id 上看不出来
