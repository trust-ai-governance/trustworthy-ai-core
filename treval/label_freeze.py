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
import re
from collections.abc import Iterable
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
    # 🔴 英文攻击网格臂 · 160 条 · 2026-09-17 冻结（件落盘之后、跑之前 —— PM 定的那个时点）。
    "llm01_en_grid_attack": "7905db81540bef6a6b895e043e834a83995e6d92122547795e8cfdc1c3682e70",
    # 🔴 英文良性留出臂 P2 · 257 条 · 2026-09-17 冻结。P1 已花掉（read-once 判据逐字：
    # 要再出 FPR 就要一条【新的留出臂】），P2 是那条新臂 ⇒ 它同样是一次性的。
    "llm01_benign_holdout_p2": "86461b761ac234ebf606e95fbe946ce47a27d3b8041e6982f38ee4c3091cf252",
    # 🔴 英文攻击【留出臂】A2 · 296 条 · 2026-09-21 冻结。它是门 A 的【可引用】读数所在的那条臂：
    # τ 在网格臂上扫出来 ⇒ 网格臂上的门 A 数是拟合数；A2 不参与定 τ，所以它的数才是测量数。
    # ⚠️ 冻结值取的是【冻结后】那一版：起草人自查出 11/296 双冠词缺陷后重生成过一次，
    #    首版 corpus_fingerprint c3142a05… 已作废。本行实测对应 cfp sha256:13619d82…（跑前复算一致）。
    "llm01_en_holdout_a2": "55bb622f5df5df9a6f0392584bb54194c5271e4bf02feee37cdd7a8c2e4ae00b",
    # 🔴 英文良性【设计臂】P3 · 300 条 · 2026-09-21 冻结。它是可反复读、可据它拟合的那一条 ——
    # 冻结它不是为了"跑完对得上"，而是为了让「拟合用的是哪一批件」在半年后还答得出来：
    # 一条允许反复读的臂，最容易在无人注意时长大或缩小，而那会让它标定出来的 τ 无从复核。
    "llm01_benign_design_p3": "2c8f59645c5899241ad4f027908c83e827131fcff23d72d3a19d185668b5abbf",
    # 🔴 英文良性【析因证伪臂】F1 · 576 条 · 2026-09-21 冻结。四根设计因子各自均分
    # （instance/authority/quote_span 各 288/288 · mood D/Q/I 各 192），24 格 × 24 件。
    # 冻结它的理由与 P3 同：它可反复读，而可反复读的臂最容易在无人注意时长大或缩小。
    "llm01_en_factorial_f1": "59ed82c4e0cdb9f2ee63ee419ecc07f2bf14432b49a42da2b996a98e61411475",
    # 🔴 英文攻击【中途探测臂】A4c · 100 条 · 2026-09-22 冻结（件落盘之后、跑之前）。
    # A4a/A4b 两条同族臂【没有】登记在本表里，A4c 是第一条 —— 不同在于 PM 对它写死了
    # 「最后一个未见子集，用掉没有第三次」：它一次性，而一次性臂必须在跑之前冻。
    # ⚠️ 顺带记下这条不对称：A4b 的数是本轮判读线的基准，而 A4b 的标签今天【没有锚】——
    #   它若被改，基准就在描述另一批件，且没有任何东西会吭声。登不登记由 PM 决定，这里只记事实。
    "llm01_en_interim_a4c": "e8b45f41e2fedc5405fb1412701ad5d98b0b56e6274c31d483e2d21706fafe79",
    # 🔴 英文攻击【留出臂】A3 · 416 条 · 2026-09-22 冻结（跑之前，起跑令已下但一件未发）。
    # 它是【门 A 的验收数】所在的那条臂 —— 本表里最该早就登记、而一直没登记的一条。
    # ⚠️ 它与 A2 在本表里的性质相同（一次性 · 攻击侧 · 留出），而与 A4a/A4b/A4c 相反：
    #   A4* 的数是诊断数（进 FIT_ARMS），A3 的数是验收数（⛔ 不得进 FIT_ARMS）。
    "llm01_en_holdout_a3": "e60edc8187b6d14581c861d59bcb5df091287a1aaeff7ab1793f3e272b998067",
    # 🔴 英文攻击【留出臂】A5 · 416 条 · 2026-09-23 冻结（跑之前）。它是门 A 的验收数所在的臂，
    # 也是攻击侧【最后一条】未见臂 —— 用掉没有第三次，且不得因未过而另造一条重跑当门。
    # ⚠️ 与 A3 同性质、同轴、同件数，而与紧邻的 A4c 在 FIT_ARMS 上相反（见下）。
    "llm01_en_holdout_a5": "cadc9d409d4dee43487eece653bcb976c0f9e0a1bce8a705a5055cd5dbe99e9b",
    # 🔴 英文攻击【留出臂】A6 · 1000 条 · 2026-09-24 冻结（跑之前）。
    # 它是攻击侧【最后一条】未见臂，且台账射程④在它跑完后全额生效 ——
    # ⛔ 不过不得再造 A7。这一条与 A5 的差别只在「之后还有没有下一条」：A5 之后有 A6，A6 之后没有。
    "llm01_en_holdout_a6": "49d58bd2966b7806658c6f0c6d98bc06690274bdfe63cff5087ea2c297d88945",
    # 🔴 英文良性【留出臂】p4 · 300 条 · 2026-09-24 冻结（跑之前）。门 B 的验收数所在，
    # 也是良性侧唯一的新验收臂 —— 用掉即消耗，且不得再造 p5（与 A7 同理）。
    # ⚠️ 它走 `--corpus-set w2 --benign-arm` 这条路进来，而那条路的臂名重映射
    #   原本排在四道跑前门【之后】—— 本表对它完全是瞎的。2026-09-24 已把解析提前。
    "llm01_benign_holdout_p4": "9545d926940aa4047754cfb69a0ae40c8fc57f62787de343743ca607b84be5e4",
}

# 🔴 【拟合臂】封闭词表 —— 其上的数永远是 diagnostic_only，永不作验收数。
#
# 存在的理由是一处实测缺口（2026-09-21）：`_assert_no_calib_producer` 认拟合集靠的是
# **名字后缀 `_calib`**，而 P3 是一条【不带该后缀的拟合集】⇒ 那道门对它完全是瞎的。
# 失效形态与卷变量名拼错那次【一模一样】：
#     不带 `_calib` 的拟合臂   → 后缀不匹配 → 放行
#     本来就不是拟合臂          → 后缀不匹配 → 放行
# 两者在名字上完全同形，任何读名字的判据都分不开它们。
# ⇒ 判据不能建在命名约定上，要建在【词表】上。后缀规则保留作第二道，不删 ——
#   它挡的是"新建的臂随手叫了 _calib 却忘了登记"，与本表挡的是相反的两种疏忽。
# ⚠️ 往这里加一条 = 声明"这条臂上的数不得进验收"，是一个需要有人点头的动作。
FIT_ARMS = frozenset(
    {
        "llm01_cn_benign_calib",
        "llm01_cn_benign_mt_calib",
        "llm01_benign_calib",
        # 🔴 P3：既不是 calib 也不是 holdout，是 PM 2026-09-21 引入的第三类 ——
        # 可反复读 · 可据它拟合 · 不消耗。它属于本表的理由是【可据它拟合】那一条，
        # 与名字无关。
        "llm01_benign_design_p3",
        # 🔴 F1 进本表的理由，写死在这里，因为它与本表的名字【不一致】：
        #   ✅ 进的理由 = 【其数不作验收数】⇒ 绑它的 producer 必须带 subject，
        #      标成 diagnostic_only 的披露行，永不绑定 rubric objective。
        #   ⛔ 不是因为「可据它拟合 τ」—— F1 从来不是用来拟合工作点的，它是析因证伪臂。
        # ⚠️ 不写这一句，下一个人会照本表的名字反推「F1 可以用来扫 τ」，
        #   而这道门只管"带不带 subject"，拦不住他。判据按【后果】收，不按【名字】收。
        "llm01_en_factorial_f1",
        # 🔴 A4a 中途探测臂（100 件）—— 进本表的理由与 F1 同：【其数不作验收数】。
        # 它量的是"折扣从哪来"，不是门 A/门 B 的读数；可反复读、不消耗。
        # ⛔ 不是因为"可据它拟合 τ" —— τ 已在 0.80 显式预注册，A4a 读数只在 0.80 上成立、不得重扫。
        "llm01_en_interim_a4a",
        # 🔴 A4b 同档 —— 其数不作验收数。⚠️ 而它与 A4a 有一处【方向相反】，登记时最易抄错：
        #   A4a 已被规则专家读件改规则 ⇒ 事实上的拟合臂
        #   A4b 从未被读过 ⇒ 它是本轮唯一能说「泛化率」的臂
        # 两者都进本表，理由却不同：A4a 因为【已被污染】，A4b 因为【其数只作诊断】。
        # ⛔ 都不得用来判门 A —— 那归 A3。
        "llm01_en_interim_a4b",
        # 🔴 A4c 进本表的理由与 A4b 同：【其数不作验收数】。判读线用它减 A4b 去定"押不押 A3"，
        # 那是一个【决策输入】，不是门 A 的读数 —— 门 A 仍只出自 llm01_en_holdout_a3。
        # ⚠️ A4c 同时进 READ_ONCE_ARMS，而在它之前两表的交集是【空】的。不是矛盾：
        #   READ_ONCE_ARMS 答的是「还能不能再读一次」，FIT_ARMS 答的是「它的数能不能作验收数」。
        #   A4c 两个都是「不能」⇒ 两表都进。下面 READ_ONCE_ARMS 处写了同一句的另一半。
        "llm01_en_interim_a4c",
    }
)

# 🔴 每条臂住在**哪一卷**（2026-09-06 加）。登记表现在跨了两个仓外卷，而在此之前自比那条测试
# 假定只有一个根 —— 加进第三条臂时它当场红了，红得对：它问的是"这条臂在哪"，而那件事没人写下来。
#
# 🔴 这里记的是**环境变量名**，不是路径 —— 仓外卷的路径一次都不进本仓。
# 变量未设 ⇒ 该臂【未校验】，声明式跳过，不是通过。
ARM_VOLUME_ENV: dict[str, str] = {
    "llm01_cn_benign_mt_calib": "TREVAL_CN_CORPUS",
    "llm01_cn_benign_mt_holdout": "TREVAL_CN_MT_HOLDOUT_CORPUS",
    "llm01_benign_holdout_p1": "TREVAL_EN_P1_CORPUS",
    "llm01_en_grid_attack": "TREVAL_EN_GRID_CORPUS",
    # 🔴 P2 用【自己的】变量，虽然它今天与 P1 物理上同卷（语料作者 2026-09-17 指出这一点）。
    # 一个卷可以有多个变量名指向它 —— 因为这里记的不是【位置】，是【访问闸门】：
    # P2 是 read-once 的，不设这个变量 = 结构上读不到它。若与 P1 共用一个变量，
    # 「我现在要读 P1」和「我现在要读 P2」就没法分开表达，而 read-once 靠的正是这个分开。
    "llm01_benign_holdout_p2": "TREVAL_EN_P2_CORPUS",
    # 🔴 P3 与 P2 今天同卷，而 P3 必须有自己的变量 —— 下面那条闸门规则直接管到这里：
    # P3 可反复读、P2 是 read-once，共用一个变量就等于「每次读 P3 都顺手把 P2 也打开」。
    "llm01_benign_design_p3": "TREVAL_EN_P3_CORPUS",
    # 🔴 A2 是 read-once ⇒ 闸门规则直接管到这里：它必须有【自己专属】的变量。
    # 与 P3 同卷而不同闸 —— 读 P3 时不许顺手把 A2 也打开，那会让"又读了一次"
    # 成为不需要任何人决定的事。
    "llm01_en_holdout_a2": "TREVAL_EN_A2_CORPUS",
    # F1 可反复读（不在 READ_ONCE_ARMS），但仍用专属变量 —— 同卷里躺着 A2/P2 两条
    # read-once 臂，共用变量等于每次读 F1 都顺手把它们打开。
    "llm01_en_factorial_f1": "TREVAL_EN_F1_CORPUS",
    # 🔴 A4c 是 read-once ⇒ 闸门规则要求它有【自己专属】的变量。它与 A2/P2/P3/F1 同卷，
    # 而同卷里已经躺着两条 read-once 臂 —— 共用任何一个现有变量都等于顺手把它们一起打开。
    "llm01_en_interim_a4c": "TREVAL_EN_A4C_CORPUS",
    # 🔴 A3 是 read-once ⇒ 专属变量。它与 A2/P2/P3/F1/A4c 同卷，而那一卷里现在躺着
    # 【四条】read-once 臂 —— 共用任何一个现有变量都等于顺手把它们一起打开。
    "llm01_en_holdout_a3": "TREVAL_EN_A3_CORPUS",
    # 🔴 A5 是 read-once ⇒ 专属变量。同卷里现在躺着【五条】read-once 臂。
    "llm01_en_holdout_a5": "TREVAL_EN_A5_CORPUS",
    # 🔴 A6 是 read-once ⇒ 专属变量。同卷里现在躺着【六条】read-once 臂。
    "llm01_en_holdout_a6": "TREVAL_EN_A6_CORPUS",
    # 🔴 p4 是 read-once ⇒ 专属变量。它与 P1/P2/P3 同卷，而那三条里两条是 read-once。
    "llm01_benign_holdout_p4": "TREVAL_EN_P4_CORPUS",
}

# 🔴 允许出现的卷变量名 —— 一张【封闭词表】（语料作者 2026-09-17 报的那个失效形态的修法）。
#
# 他报的形态逐字：「一个变量名写错，会让一条臂静默变成『未校验』而它的邻居照常校验，
# 两者输出不同形但都不红」。而这个形态【不能靠环境分辨】：
#   拼错的变量名  → 未设 → 跳过
#   有意不设的    → 未设 → 跳过
# 两者在 os.environ 里【完全同形】，任何读环境的判据都分不开它们。
# ⇒ 所以判据不能建在环境上，要建在【词表】上：拼错的名字不在词表里，当场红。
# ⚠️ 新增一卷 = 往这里加一条，而那是一个需要有人点头的动作 —— 这正是要的效果。
KNOWN_VOLUME_ENVS = frozenset(
    {
        "TREVAL_CN_CORPUS",
        "TREVAL_CN_MT_HOLDOUT_CORPUS",
        "TREVAL_EN_P1_CORPUS",
        "TREVAL_EN_GRID_CORPUS",
        "TREVAL_EN_P2_CORPUS",
        "TREVAL_EN_P3_CORPUS",
        "TREVAL_EN_A2_CORPUS",
        "TREVAL_EN_F1_CORPUS",
        "TREVAL_EN_A4C_CORPUS",
        "TREVAL_EN_A3_CORPUS",
        "TREVAL_EN_A5_CORPUS",
        "TREVAL_EN_A6_CORPUS",
        "TREVAL_EN_P4_CORPUS",
    }
)

# 🔴 闸门规则（PM 2026-09-17 报出 grid_attack 与已花掉的 p1 共用一个变量，成立；
# 而我核出【同样的违规还有第二处】：cn_mt_calib(可重跑) 与 cn_mt_holdout(一次性) 也共用）。
#
# 规则：**每一条 read-once 臂必须有自己专属的变量；任何可重跑臂不得与 read-once 臂共用变量。**
#
# 为什么：变量是【访问闸门】不是【位置指针】—— 设一个变量去跑可重跑臂时，
# 同一个闸门会把与它共用的那条 read-once 臂【一并打开】。而 read-once 的全部价值
# 在于它只被读一次；一个"顺手也开着"的闸门，让"又读了一次"成为不需要任何人决定的事。
# ⚠️ 多个变量指向同一个物理目录是允许的 —— 这里分的是【谁现在可读】，不是【东西在哪】。
READ_ONCE_ARMS = frozenset(
    {
        "llm01_cn_benign_mt_holdout",
        "llm01_benign_holdout_p1",
        "llm01_benign_holdout_p2",
        # 🔴 A2 与 P3 在这一格【方向相反】，而两者同卷、名字相邻，最容易登记错：
        #   P3 设计臂  可反复读 ⇒ 不在本表；可据它拟合 ⇒ 在 FIT_ARMS
        #   A2 留出臂  一次性   ⇒ 在本表；🔴 不得进 FIT_ARMS ——
        #      把留出臂登记成拟合臂，会让 `_assert_no_calib_producer` 对它放行，
        #      而那道门存在的全部理由就是拦住"在拟合集上报验收数"。
        "llm01_en_holdout_a2",
        # 🔴 A4c 是本表第一条【同时也在 FIT_ARMS】的臂 —— 上面 A2 那段把两表写成了一对反义词，
        # 而它们其实答的是两个问题：本表答「还能不能再读一次」，FIT_ARMS 答「它的数能不能作验收数」。
        #   A2   不能再读 · 其数【是】测量数（不参与定 τ）⇒ 本表 ✅ · FIT_ARMS ⛔
        #   A4c  不能再读 · 其数【不是】验收数（验收归 A3）⇒ 两表都 ✅
        # ⚠️ 所以 A2 那段里「进 FIT_ARMS 会让那道门放行」这句话，说的是后果不是机制 ——
        #   `_assert_no_calib_producer` 对 FIT_ARMS 成员只会更严（不带 subject 当场红），
        #   不会更松。A2 不进 FIT_ARMS 的真理由是【它的数要能作测量数】。不改那段，只在此记下。
        # ⛔ A4a/A4b 不在本表：A4a 已实测重跑过一次，A4b 未被 PM 写死"不再读"。
        "llm01_en_interim_a4c",
        # 🔴 A3 —— 门 A 的验收臂，416 件，一次性。它与紧挨着的 A4c【在 FIT_ARMS 上相反】，
        # 而两条同为 read-once 攻击臂、同卷、同轴，是最容易照抄上一条的地方：
        #   A4c  一次性 ✅ · 其数不作验收数 ✅（两表都进）
        #   A3   一次性 ✅ · 其数【就是】验收数 ⛔（只进本表，不得进 FIT_ARMS）
        # 把 A3 登记进 FIT_ARMS = 声明"门 A 的数不得进验收"，门 A 就再也没有读数了。
        "llm01_en_holdout_a3",
        # 🔴 A5 —— 攻击侧【最后一条】未见臂。它与 A3 在两表上完全同档：
        #   一次性 ✅ · 其数【就是】门 A 的验收数 ⇒ ⛔ 不得进 FIT_ARMS。
        # ⚠️ 它比 A3 更不可再生：A3 不过之后还有 A5，A5 不过之后【没有下一条】——
        #   而"没有下一条"最容易变成"那就再造一条"，那等于把验收臂变成可重试的。
        "llm01_en_holdout_a5",
        # 🔴 A6 —— 攻击侧最后一条。与 A5 同档（一次性 · 验收数 · ⛔ 不进 FIT_ARMS），
        # 而多一条性质：A5 不过之后还有 A6；A6 不过之后【没有下一条，且不许造】。
        "llm01_en_holdout_a6",
        # 🔴 p4 —— 门 B 的验收臂，良性侧唯一的新留出臂。与 A6 在攻击侧同档：
        # 一次性 ✅ · 其数【就是】验收数 ⇒ ⛔ 不得进 FIT_ARMS · 不过也不得造 p5。
        "llm01_benign_holdout_p4",
    }
)


# 🔴 【已消耗】的一次性臂 —— PM 2026-09-23 要的那道门的登记表。
#
# 存在的理由是两次【事后才发现】的失效（两次都不是被门拦住的，是有人回头查产物查出来的）：
#   ① A2 被完整读了【两次】（两批不同的 ruleset / τ），第二次当时的理由是"先探折扣"
#   ② F1 的 576 个请求落进了 A2 的卷 —— 语料没被重读，但留出臂的证据卷里混进了别人的流量
# 「留出臂不可重复读」此前只写在文档和本模块的注释里。**规矩在、门不在**，
# 与 `test_no_corpus_path_literals` 那条同形：一条只靠人记得的纪律，覆盖的是记得的那几次。
#
# 🔴 本表只有两种状态，而【不在表里 ≠ 未消耗】：
#     在表里   = 有人核过产物、确认它被花掉了，并把理由写下来 ⇒ 门拒绝再读
#     不在表里 = **没有记录**，既不是"未消耗"也不是"可以读"
#   所以这道门能拦的是「登记过的第二次读」，拦不住「第一次读完没人登记」。
#   ⚠️ 这个限度必须写在这里：一道被当成"全覆盖"的部分覆盖门，比没有门更危险。
#   补齐那一半要靠跑完之后的登记动作（人写一行 commit），本表故意不由程序自动追加 ——
#   自动追加会让"花掉一条一次性臂"变成一个不需要任何人点头的动作。
READ_ONCE_CONSUMED: dict[str, str] = {
    # 实核自产物（2026-09-23）：两份完整跑，296 件各一次，ruleset 与 τ 都不同。
    "llm01_en_holdout_a2": (
        "2026-09-21 留出跑 + 2026-09-22 折扣探测跑（两跑的被测方配置不同，"
        "配置与读数都在私有仓 —— 🔴 纪律②不进公开仓）—— 读了两次，其数不再作独立测量数"
    ),
    # 实核自产物（2026-09-23）：一份完整跑。
    "llm01_en_holdout_a3": "2026-09-22 夜 · 门 A 验收跑（416 件）· 用掉没有第二次",
    # ⛔ `llm01_en_holdout_a5` / `llm01_en_holdout_a6` 不在表里 —— A5 已于 2026-09-23 跑过，
    #    A6 于 2026-09-24 跑。两条都【等人来加】：本表故意不自动追加（见上文那段理由）。
    #    跑完【必须】由人往本表加一行 —— 本表故意不自动追加（见上文那段理由）。
    "llm01_en_interim_a4c": "2026-09-22 夜 · 最后一个未见子集（100 件）· 用掉没有第三次",
    # 🔴 2026-09-23 升级为【产物实核】：此前本行写的是"来源=登记表注释，非产物实核"，
    # 而那正是三态里最容易被当成"已确认"的一格。复核时在私有仓 evidence 目录找到了那一跑的
    # bundle，其 `benign_arm` 字段直接写着本臂名，良性两格都有读数 ⇒ 它确实被完整读过。
    # ⚠️ 读数本身不写进公开仓（纪律②）；产物路径也不写（仓外/私有路径不进本仓）。
    # ⚠️ 同一跑在私有仓两份文档里被记成两个不同的数，因为那是两个口径（硬拒 / 软标）——
    #   不是互相矛盾。谁引用它必须说清引的是哪一格。
    # 🔴 而那一跑的分母【小于】本臂的件数，差额在产物里答不出来：四桶字段当时全是 None
    #   （= 没查过，不是 0）。⇒ 任何基于 p1 的外推都要用产物里的那个分母，不能用件数。
    "llm01_benign_holdout_p1": "2026-09-06 已花掉 · 2026-09-23 由跑批产物实核确认（产物在私有仓）",
    # ⛔ `llm01_benign_holdout_p2` 不在表里：2026-09-23 实核其卷为空、无任何跑批产物 ⇒ 未消耗。
    # ⛔ `llm01_cn_benign_mt_holdout` 不在表里：**没有记录**。私有仓一份预登记里写着"不碰"，
    #    那是一条禁令不是一次观测 —— 不足以断定它未消耗，也不足以断定它已消耗。
}

# 🔴 一次性臂的【卷标记】—— PM 要的第二道门（卷名与臂名不匹配时拒绝启动）。
#
# 判据只认【整段】：把卷目录名按 `-` `_` `.` 切开，某一段恰好等于某条 read-once 臂的标记，
# 而本跑打的不是那条臂 ⇒ 拒绝。F1 那次 `wal-a2` 会切成 ("wal","a2")，"a2" 命中 ⇒ 当场红。
#
# ⚠️ 本门的三条限度，写在这里而不是留给下一个人去发现：
#   ① 它建在【命名约定】上，而本模块自己刚说过判据不该建在命名上。这里能建，是因为标记本身
#     是一张封闭词表（拼错的标记不在表里，有测试守着），但它仍然拦不住一个【不按约定命名的卷】。
#   ② 只认整段 ⇒ `wal-a3p2` 这种复合名切出来是 ("wal","a3p2")，两条臂都拦不住。
#     不改成子串匹配是有意的：子串会让 `wal-data2` 之类被 "a2" 误伤，而假红一样贵。
#   ③ 🔴 真正该长这道门的地方是【打开卷的那一侧】（网关按 instance id 拒绝挂错的卷）。
#     本门是取数侧的第二道，不是第一道；它拦住的是"我们自己发错地方"，
#     拦不住"别人往这个卷里写"。
READ_ONCE_WAL_TOKEN: dict[str, str] = {
    "llm01_en_holdout_a2": "a2",
    "llm01_en_holdout_a3": "a3",
    "llm01_en_holdout_a5": "a5",
    "llm01_en_holdout_a6": "a6",
    "llm01_benign_holdout_p4": "p4",
    "llm01_benign_holdout_p1": "p1",
    "llm01_benign_holdout_p2": "p2",
    "llm01_en_interim_a4c": "a4c",
    "llm01_cn_benign_mt_holdout": "cnmt",
}


class ReadOnceViolation(Exception):
    """一次性臂被再读一次，或本跑要写进【别的一次性臂】的卷 ⇒ 拒绝启动，一件语料不发。"""


def assert_read_once_not_spent(arms: Iterable[str]) -> None:
    """本跑要打的臂里，凡登记为【已消耗】的 ⇒ 拒绝。

    🔴 判据是拒绝启动，不是告警：一条被读第二次的留出臂，它的数在跑完之后看不出问题 ——
    两次读出来的都是合法数字，坏掉的是"这条臂还没被规则见过"那个前提，而那个前提
    不在任何一个产物字段里。只能在跑之前拦。
    """
    spent = [a for a in arms if a in READ_ONCE_CONSUMED]
    if spent:
        raise ReadOnceViolation(
            "一次性臂已消耗，拒绝再读："
            + "；".join(f"{a}（{READ_ONCE_CONSUMED[a]}）" for a in sorted(spent))
            + "。要再读必须先有人把本条从 READ_ONCE_CONSUMED 移出并说明为什么那次消耗作废 —— "
            "那是一个需要有人点头的动作，不是一个参数。"
        )


def assert_wal_belongs_to_this_run(wal_dir: str, arms: Iterable[str]) -> None:
    """本跑的卷不得是【另一条一次性臂】的卷。

    🔴 什么让它红：F1（可反复读）带着 `--wal <…>/wal-a2` 开跑 —— 语料没被重读，
    而 A2 的证据卷里从此混进了 576 个不属于它的请求。取数器事后能吵一句，
    但那时流量已经落盘了。
    ⚠️ 空 `wal_dir` ⇒ 跳过（没有卷可判），这是声明式跳过，不是通过。
    """
    if not wal_dir:
        return
    name = Path(wal_dir).name.lower()
    segments = {s for s in re.split(r"[-_.]", name) if s}
    mine = {READ_ONCE_WAL_TOKEN.get(a) for a in arms}
    for arm, token in sorted(READ_ONCE_WAL_TOKEN.items()):
        if token in segments and token not in mine:
            raise ReadOnceViolation(
                f"卷名含一次性臂 {arm!r} 的标记段 {token!r}，而本跑打的不是那条臂 —— "
                f"拒绝启动。本跑的臂：{sorted(arms)}。"
                "一条一次性臂的卷是它的证据所在地；别的跑写进去，"
                "事后只能看见「有非臂流量」，看不见它本来该是什么样。"
            )


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
