# EV-CITE — 可引用性闸 + 两种 None 的分辨

> **Problem（普通话）：** 两件事，同一个病根 —— **一个数出了门，读的人不知道它能不能被引用、也不知道它为什么是空的。**
>
> **件一：** 一次跑的数字，今天**没有任何一处**回答"这些数能不能出这个房间"。
> 判据其实都在：`pinned`（[bundle.py:45](../../treval/cli/bundle.py#L45)）、
> 段哈希、`evidence_basis`、`insufficient_data`、区间判据 ——
> **就是没有一个地方把它们合成一句话。**
> 🔴 而 `citable` / `citable_blockers` 这套机制**在配对那条路径上已经完整存在**
> （[pair.py:318](../../treval/cli/pair.py#L318)），**报告面一个字都没有。**
> **又是那句「建成 ≠ live」——第二次。**
>
> **件二：** 报告里 `measured_ceiling = None` 有**两种完全不同的成因**，
> 而页面把它们压成同一个符号 `—` 加同一句「无实测信号」。
> 🔴 **实测：强鲁棒性有 5 条实测目标、详情页白纸黑字 `89% n=28`，Dashboard 却说它"未采到实测数据"。**
> 引擎和 CLI 都分得清（[render.py:62](../../treval/cli/render.py#L62) 的注释逐字写着这个区分），
> **Web 视图把它丢了** —— **"没测到"和"测了没达标"混为一谈，正是这个仓存在的理由本身。**
>
> **Value:** 件一让**任何一个数出门前都过同一道闸**（白皮书 / NDA / 售前 / 客户自算，一视同仁）；
> 件二把"我们没做到"变成"**这条缺这个证据**"——一线拿到的是可照着说的事实，不是要自己圆的空白。
> 🔴 **两件共用同一套判据**（"这个数能不能引 / 为什么不能"），所以合成一单。
>
> Dev brief. **归属：** Implementer 编码 + 测试。**规模：中（件一中，件二小）。**
> **前置：** 无外部依赖 —— 判据机制大半已建成，本单是**接线**。
> 🔴 **本单不为 POC 而建**：它是任何对外引用都要过的门，**批准它不等于批准任何 POC 方案**。

---

## 0. 一条先划清的边界（否则件一会做歪）

🔴 **`citable` 说的是"这个数能不能出门"，不是"这个结论好不好看"。**

| | 判 |
|---|---|
| `injection_catch_rate 89% (n=28)`，**按判据未达标** | ✅ **可引用** —— 一个诚实的"未达标"正是 measured > attested 的卖点 |
| 同一个数，**跑是 unpinned 的** | ❌ **不可引用** —— 窗口是移动快照，别人复算不出同一个数 |

**"不达标"不是 blocker；"站不住"才是。**
把 `unmet` 做成 blocker，就等于建了一个"只有好看的数才能出门"的闸 —— **那正好是我们批评的那种东西。**

---

## 件一 — 可引用性闸

### 1.1 复用既有词汇，不新造

配对那条路径已经定了形状（[pair.py:318](../../treval/cli/pair.py#L318)、[:348](../../treval/cli/pair.py#L348)）：

```python
"citable": not blockers,          # 披露判定：产物照发，只是说清能不能引
"citable_blockers": blockers,     # list[str]，每条都点名"怎么修"
```

🔴 **报告面逐字复用这两个字段名与这个语义**：`list[str]`、**每条 blocker 必须包含修法**，
**产物照发**（[EV-PAIR §5.4](EV-PAIR.md) 的既有姿态：**披露不是拒发**）。
**不许新造 `quotable` / `publishable` / 打分制** —— 第二套词汇迟早和第一套打架。

### 1.2 🔴 只有**报告级**一层（更正，2026-08-05 评审后）

**初稿仿照配对做了"维度级 + 报告级"两层。错了 —— 层级要跟着判据的作用域走。**

| | |
|---|---|
| 配对为什么是 per-delta | **它的 blocker 本来就是 per-delta**（每个 delta 有自己的可比性门） |
| 报告为什么是 report-level | 🔴 **它的 blocker 全是 report-wide 属性**（`pinned` / 段哈希 / `evidence_basis` / integrity）—— 没有一条是某个维度私有的 |

**⇒ 可引用性只有一层：报告级。** 维度上带的是件二的 `measured_state` + `measured_gap` ——
**那才是维度真正有的信息**（§2.3）。

🔴 **不许保留一个恒真的维度级 `citable`**：它什么都没判，却会被读成"本维度经核可引用"的**背书** ——
同一条纪律，不判定的 `[GATED]` 标签比没有标签更误导（[GATE-CONSISTENCY 件一](GATE-CONSISTENCY.md)）。

### 1.3 blocker 清单（**只列站不住的，不列不好看的**）

**全部是报告级**（命中即整份不可引）：

| blocker | 判据落点 | 报文里必须有的修法 |
|---|---|---|
| 🔴 **unpinned** | `provenance.pinned == false` | `补 --window-from-ns/--window-to-ns 重跑；unpinned 的窗口是移动快照，第三方复算不出同一个数` |
| 🔴 **pin 了空窗口**（C12） | `provenance.pinned == true` **且** `provenance.record_count == 0` | 🔴 **报文必须直接给出本次观测到的窗口**：`固定窗口内没有任何 WAL 记录 —— 该窗口锚不住本报告的任何数字。本次实际观测到的窗口是 [X, Y)，用它重新 pin。` **让操作者照抄，永远不必自己算纳秒** |
| **段哈希缺失** | `provenance.wal_segments.sha256` 空 | 同上（pinned 的意义就是它） |
| **证据基不是链锚定** | `evidence_basis != "wal_anchored"` | `换 WAL 证据源；索引来源不可链校验` |
| 🔴 **完整性破损** | `report.integrity_summary` broken > 0 | `链断则其下所有结论不成立 —— 先查 WAL` |

🔴 **`unmet` 不是 blocker**（§0）。**`sample_size` 不足导致的 `unmet` 也不是** ——
它可以被引用成"我们测了、区间下界 0.728、按 0.80 判未达标"，那是**最诚实的一句话**。

### 1.3.1 🔴 `insufficient_data` **也不是** blocker（C6，评审后更正）

**初稿把"该维度任一 measured objective 为 `insufficient_data`"设成维度级 blocker。错了，而且是硬错：**
库里那份真报告里 `rob.l4.drift_alerting` 与 `sec.l3.guardrail_blocking` 都是 `insufficient_data`
⇒ **这份报告 pin 了也永远报告级不可引**，与 §7-② / §7-③ 直接矛盾。
**每一份真报告总有某个指标本次没采到 —— 那就等于建了一个"只有【完整】报告才能出门"的闸，
"只有【好看】的数才能出门"的表亲。**

🔴 **更硬的理由：它已经被扣过一次了。**
`_ceiling` 是"某级只要有一条不是 `met` 就 break"，而 `insufficient_data` 不是 `met` ——
**一个没采到的指标已经把该维度的 ceiling 压下来了。**
再做成可引 blocker，是**同一个事实收两次费**，而且**第二次收的是错的币种**：
第一次扣"等级高度"（对），第二次扣"能不能出门"（无关）。

**这也顺带证明不存在"漏引风险"**：
"某维度有指标没采到、却被引成已认证 L4"这条路 **梯子已经堵死** ——
`insufficient_data` 使该级 break，ceiling 永远不会被缺失的测量抬高。**闸不必再拦一次。**

**⇒ `below_floor` / `blocked_no_data` / `not_measured` **三者都可引**，各带件二的诚实 form（§2.3）。

### 1.4 🔴 `citation_form` —— 让数字自带口径

**光有"能不能引"不够** —— 真正的失手一直是**把 `89%` 单独摘出去**。
所以每条 measurement 附一句**可以照抄的引用形式**：

```
"citation_form": "injection_catch_rate 89.3% (25/28, 95% CI [72.8%, 96.3%], pinned run
                  <window>, wal_anchored) —— 按 ci_low >= 0.80 判定：未达标（样本不足，非能力低）"
```

**规则**：

- **率必带 `n` 与区间**（README 那条纪律的机器形式）；
- 🔴 **分层测量必须点名分层**（`subject` 非空即写进 form），**并带既有的偏差注**：
  `injection_catch_rate@outcome_observable` 实测 **8/8 = 100%**，而全体是 **25/28 = 89.3%** ——
  三条漏检 **marker 与 canary 皆空**，落在这 8 条之外 ⇒ **这一层按构造必然好看**。
  一句丢掉 `subject` 的 `citation_form` 读起来就是「**注入拦截率 = 100%**」，
  **那是全仓最不该裸引的数**。偏差注**复用 [pair.py](../../treval/cli/pair.py) 的
  `_OBSERVABLE_BIAS_NOTE` 同一常量** —— 抄第二份迟早与第一份分叉；
- **区间按机制适用**（[EV-CIGATE §1.5](EV-CIGATE.md)）：普查与默认拒绝全函数**不给区间**，
  改写 `（普查 173/173，无抽样不确定性）` —— 🔴 **给普查加区间和给检测器不加，一样错**；
- 已有的口径注记**继续搭车**（如 [EV-R2 §9.7](EV-R2.md) 的可观测子集偏差 —— 配对侧已经这么做了）；
- **不可引时**，`citation_form` 仍然生成，但**前缀 `🔴 NOT CITABLE — `** 加首要 blocker。
  **不是留空**：留空会让人回去引裸数字。

### 1.5 落在哪

- **自包含 bundle 顶层**加 `citable` / `citable_blockers`；每个 dimension 加同名两字段；
  每条 measurement 加 `citation_form`。**跟着产物走**，客户手上那份也带着；
- `treval report --format human` **在最前面**打一行结论（不可引时**打在最前**，不是页尾）；
- **treval-web**：Dashboard 顶部条已经有"⚠ 未固定窗口"，把它升级成完整的可引用性条 ——
  🔴 **可引/不可引都要显示**（只在不可引时显示，等于把"可引"变成默认，那是错的方向）。

### 1.6 🔴 C12 — **"声明"与"声明是对的"是两件事，今天只检查了前者**

**现场（2026-08-06 Live 实证）**：一次 `collect` 传了两个手写边界，窗口宽 21.4 秒、
落在探针发出**之前**关闭 ⇒ `record_count: 0`、被动指标 0 条、`chain_integrity` 消失，
**而 `citable = true`、blockers 空**。同一份 WAL 上，**不 pin** 的那次跑有 867 条记录。

**根因**（[collect.py:389](../../treval/cli/collect.py#L389)）：

```python
pinned = window_from is not None and window_to is not None
```

🔴 **它量的是"人有没有输入两个数字"，不是"这个窗口能不能复算"。**

**而工具其实早就知道那个可复算的窗口** —— [collect.py:173](../../treval/cli/collect.py#L173) 的
docstring 逐字写着 `observed_window` 是
*"the HALF-OPEN [min, max+1) of the records read — **the interval that re-selects exactly these records**"*。

| | `pinned` | 记录的窗口能否重选出本报告的证据 | 今天的判定 |
|---|---|---|---|
| 不 pin 的跑（`record_count=867`） | `false` | ✅ **能** | ❌ **被拦** |
| pin 了空窗口（`record_count=0`） | `true` | ❌ **重选出 0 条** | ✅ **放行** |

**⇒ 代理放过了更差的产物，拦住了更好的产物。**

> 🔴 **本轮第四次同一个病**：不判定的 `[GATED]` 标签冒充判定 · "没有 POST" 冒充"不写数据" ·
> "`ci is None`" 冒充"普查" · 现在 **"人传了参"冒充"窗口可复算"**。
> **代理不是判据 —— 每次都要说出让它返回 False 的输入。**

**裁定（两条）：**

1. **不自动 pin。** "运营方**声明**口径"有真价值：对外引用时，"这些数覆盖窗口 W"应当是
   **有人做出的陈述并为之负责**，不是时钟碰巧走到哪。自动 pin 会把这层责任抹掉。
2. 🔴 **但声明必须被机械校验** —— 见 §1.3 新增的那条 blocker。
   **报文里直接把观测窗口给出来**，操作者照抄即可。

### 1.7 与既有告警的关系

`collect` 今天在 **stderr** 打过一次 unpinned 警告（[collect.py:422](../../treval/cli/collect.py#L422)）。
🔴 **stderr 不跟着产物走** —— 文件被转发一次，警告就没了。
本单**不删那条**（跑的时候看见是好事），但**判定权归产物里的字段**。

---

## 件二 — 两种 `None` 分辨（guardrail-3 事实输出）

### 2.1 现场（实核，取自库里那份真报告）

```
robustness         measured_ceiling=None
  rob.l2.injection_rule_detection   unmet              ← 测了，没过
  rob.l2.injection_false_positive   unmet              ← 测了，没过
  rob.l3.unified_risk_score         met
  rob.l4.breach_baseline            met
  rob.l4.drift_alerting             insufficient_data

security_alignment measured_ceiling=None
  sec.l3.oauth_scope                met
  sec.l3.guardrail_blocking         insufficient_data  ← 这次没采到
```

`measured_ceiling` 是**梯子不是分数**（[engine.py:224](../../treval/rubric/engine.py#L224)）：
低往高爬，某级有一条不 met 就 break，上面爬过的不算。
⇒ robustness **断在 L2**（L3/L4 的两个 `met` 永远轮不到）；
security_alignment 的 measured 目标**只在 L3**，L3 断 ⇒ 也是 None。

### 2.2 🔴 缺陷：Web 把两种 None 说成同一种，而且说的那句是假的

[view.py:145](../../treval/web/view.py#L145)：`elif not measured: pill = "无实测信号"`，
配 [dashboard.html:137](../../treval/web/templates/dashboard.html#L137) 的
「**该维度本次未采到实测数据**」。

**强鲁棒性采到了 5 条。** 而 CLI 侧 [render.py:62](../../treval/cli/render.py#L62) 的
`_is_not_measured` 注释逐字写着：

> *"**Distinct from measured-but-failing** (some data, below threshold), which is **NOT** tagged NotMeasured (EV-7 §0)."*

实算：这两个维度在该判据下**都返回 False**。
🔴 **同一份报告，CLI 拒绝说的那句话，Web 说了。**

**根因不是文案写错，是判据被复制了两份**：CLI 有一份对的，Web 自己derive 了一份错的。
⇒ **修法必须是合并定义，不是改文案**（同 `_logo.html` 的共享 include、同"不存在第二条求和路径"）。

### 2.3 改法

**① 判据上移到引擎，只留一份**

`_is_not_measured` 从 `treval/cli/render.py` **移进 `treval/rubric/`**，
CLI 与 Web **都从那里取**。🔴 **带牙：改那一个定义，CLI 与 Web 的测试必须同时红。**

**② 维度多一个 `measured_state`（🔴 **四态**，由**断点原因**驱动 —— C9 更正）**

> **初稿是三态，且判据按"该维度有没有实测数据"切。错了，而且当前那份真报告就中招：**
> `security_alignment` 断在 **L3**，该级唯一的非 met 是 `guardrail_blocking` = `insufficient_data`；
> 但它有 `oauth_scope` = `met` ⇒ 按旧定义落进 `below_floor` ⇒ 会说 **"实测未达 L3"**。
> **真相是那一级的另一条根本没产出。**
> 🔴 **而本节下面的示例写的正是对的那句** —— **定义与例子在同一节里冲突，实现者会照定义写代码。**
> 这是件二正在修的病（"没测到"当成"测了没达标"）**在 ceiling 断点上的第三次复发。**

**断点级** = 梯子 break 的那一级（该级存在非 `met` 的 measured objective）。

| 值 | 何时 | 页面文案 | 🔴 一线要做的事 |
|---|---|---|---|
| `certified` | `measured_ceiling` 非空 | 现状 | — |
| `below_floor` | 断点级**有** `unmet` | **实测未达 `L<N>`** | 扩样本 / 补能力 |
| 🆕 `blocked_no_data` | 断点级非 met **全是** `insufficient_data`，**且该维度有 `met` 数据** | **`L<N>` 缺 `<indicator>`，本次未产出** | **查那个指标为什么没产出** |
| `not_measured` | 该维度**没有任何**实测数据（全 `insufficient_data`，或没有 measured objective） | **无实测信号** | 这维度这次没测 |

**优先级**：`not_measured` > `blocked_no_data`（前者是更强的陈述）。

🔴 **为什么 `security_alignment` 不能塞进 `not_measured`**：它测了 `oauth_scope` 且过了。
说它"无实测信号"**就是原来那个 bug 的翻版**。
**四个状态对应四个不同的行动项 —— 不是过度建模，是那四件事本来就不同。**

**③ 每个非 `certified` 维度产一句事实**（`measured_gap`）

**成因不同，措辞必须不同：**

```
below_floor      : 强鲁棒性 实测未达 L2 —— injection_catch_rate 89.3% (n=28)，ci_low 0.728 < 0.80；
                   false_positive_rate 0% (n=19)，ci_high 0.168 > 0.05。
                   🔴 两条都是样本不足，不是能力不足。
blocked_no_data  : 安全与价值对齐 达 L2；L3 缺 guardrail_blocking —— 本次未产出该指标
                   （同级 oauth_scope 已达标）。
```

#### 2.3.0 🔴 `measured_gap` 是**逐条**，不是由 state 派生的模板（C10）

**断点级可以同时有 `unmet` 与 `insufficient_data`** —— 真报告只是恰好没出现这种。
若让 `measured_gap` 从 `measured_state` 派生，混合断点就被迫二选一，**选哪个都是半句假话**。

**⇒ `measured_gap` = 断点那一级上【每条非 met 目标各一句】**：

| 断点级情形 | 读起来 |
|---|---|
| 全 `unmet` | 「实测未达 `L<N>` —— `<metric> <point> n=<n>`, ci_low … < …」 |
| 全 `insufficient_data` | 「达 `L<N-1>`；`L<N>` 缺 `<indicator>`（本次未产出）」 |
| 🔴 **混合** | **两句都出**，各带自己的证据（`unmet` 那条带区间，`insufficient_data` 那条**不带**） |

🔴 **`measured_state` 与 `measured_gap` 谁也不许从谁派生**：
state 是给 pill / 雷达用的**粗分类**，gap 是**那句事实**。
让 gap 从 state 派生，混合断点必然被压成半句假话。

🔴 **这两句对客户是完全不同的行动项**：前者"再跑一批语料就有"，后者"这次没测到"。
**压成一个 `—`，一线就只能自己猜怎么讲** —— 这正是 guardrail-3 要解的。

#### 2.3.1 🔴 "还要多少 n" 必须写成条件式，且**门限非单调**（评审附录，采纳）

初稿写的是"**n≈81 / 良性 n≈74 可过线**"。**那读起来是承诺，而它不是。** 实算（p 固定 89.2857%）：

```
n=68 ci_low 0.8024 过   n=70 0.7904 未过 ←掉回去   n=74 0.8009 过
n=80 0.7998 未过 ←又掉回去              n=81 0.8021 过（此后稳定）
```

🔴 **门限非单调** —— 68/70/74/80/81 来回穿越（`round(p·n)` 整数化所致）。

**定版措辞（`measured_gap` 与文档一律照此）：**

> **若新增用例的命中率维持在 ~89%**，区间下界自 **n≈81 起稳定**过 0.80
> （**68–80 之间会来回穿越，不可作阶段目标**）；
> 🔴 **n 是必要非充分**：扩的是**新样本**，点估计会动 —— **扩到 81 而 p 下移，照样不过。**

**这不是措辞打磨**：把 81 当阶段目标去扩语料，很可能扩到 70 就以为该过了、结果没过，
**然后回头怀疑判据**。**非单调本身要写在纸上。**

**🔴 良性侧是另一种形状 —— 不是非单调，是【门限随误拦数跳档】**：

```
误拦 k=0 ⇒ 需 n>= 73     k=1 ⇒ n>=110     k=2 ⇒ n>=142     k=3 ⇒ n>=173
```

**对固定的 k，`ci_high` 随 n 严格单调下降**，良性侧没有攻击侧那种来回穿越。
问题在别处：**扩样本时 k 会长，而 k 每 +1 门限就跳一档。**
⇒ 「扩到 73」**只在一个误拦都不出的前提下成立**；出一个就得 110。
**把 73 当阶段目标排期，等于赌良性语料一条都不误拦。**
（细粒度实算是 **73**；此前按步长采样报的 74 已更正。）

#### 2.3.2 🔴 "可引" ≠ "可以只引好的那部分"

三个非 `certified` 态都可引（§1.3.1），但若只写到这里，
**一个维度 5 条实测目标、4 条没采到，照样 `citable=true`** ——
于是"我们测了 robustness"这句话就能出门了。

**⇒ `measured_gap` 是必填，不是可选字段。**

| 状态 | 可引 | **必须同时出现** |
|---|---|---|
| `certified` | ✅ | 正常 |
| `below_floor` | ✅ | 🔴 断在哪一级、差多少、还要多少 n（按 §2.3.1 的条件式） |
| `blocked_no_data` | ✅ | 🔴 达到了哪一级 + **点名**断点级缺哪个 indicator（**不带区间**） |
| `not_measured` | ✅ | 🔴 **点名**该维度全部未产出的 indicator |

**这是选择性引用的唯一机械防线** —— 拦不住人只念半句，
但能让**那半句自带另外半句**。（与 `citation_form` 让率自带 `n` 与区间，同一条纪律。）

**④ 雷达图**：`below_floor` 的维度**不再画成灰虚线"无信号"** ——
它有数据，只是不到线。**画出来，并标"未达 L2"。**

> 🔴 **口径归 PM 与一线**：本件只保证那句话是**事实**（哪个指标、差多少、要多少 n）。
> **怎么讲**（roadmap / 如实标 / 别的说法）**不在本单，也不该在本单**。

---

## 3. 非目标

- **不改**任何指标计算、判据阈值、梯子逻辑（`_ceiling` 一个字不动）；
- **不新造**披露词汇（`citable`/`citable_blockers` 复用，`measured_state` 复用既有状态词）；
- **不把** `unmet` 做成 blocker（§0）；
- **不做** POC 手册、不合成任何 Demo 数据；
- **不改**配对那条路径的既有行为（它是范本，不是改造对象）；
- **不拍**对客话术（§2.3 末）。

---

## 4. 开工前必裁

| # | 决策 | 判 | 归属 |
|---|---|---|---|
| **C1** | `unmet` 算不算 blocker | ✅ **不算**（§0）—— 否则闸变成"只放好看的数" | 架构师定 |
| **C2** | 不可引时产物发不发 | ✅ **照发** —— 披露不是拒发，沿用 [EV-PAIR §5.4](EV-PAIR.md) | 架构师定 |
| **C3** | 不可引时 `citation_form` 给不给 | ✅ **给，带 `🔴 NOT CITABLE —` 前缀**（§1.4）—— 留空会把人赶回去引裸数字 | 架构师定 |
| **C4** | `_is_not_measured` 放哪 | ✅ **上移到引擎，单一定义**（§2.3-①） | 架构师定 |
| **C5** | 🔴 良性语料 n=19 ⇒ 上界 16.8% | **本单不解，登记**：`false_positive_rate` 要过 `ci_high ≤ 0.05` 需 **n≈74**（同样是条件式，§2.3.1）。**良性侧扩样与攻击侧同等紧要**，而它一直排在后面 —— 归 **序6 / [EV-COVERAGE](EV-COVERAGE.md)**，本单只负责**把这个事实印在报告上** | 登记 |
| ✅ **C6** | 维度含 `insufficient_data`，算不算件一的可引 blocker | 🔴 **不算**（§1.3.1）。它归件二（None 分类），不进件一 blocker；可引用性只卡报告级 provenance。`below_floor` 与 `not_measured` **都可引**，各带诚实 form。**否则每份真报告 pin 了也不可引，反 §0 立意、撞 §7-②** | **已定**（评审提出，架构师采纳） |
| ✅ **C7** | C6 之后维度级 `citable` 怎么办 | 🔴 **整层删掉**（§1.2）—— 移走 `insufficient_data` 后它**结构性恒为 true**，一个恒真的 `citable ✅` 会被读成背书。**层级跟着判据的作用域走** | **已定** |
| ✅ **C8** | `measured_gap` 是不是可选 | 🔴 **必填**（§2.3.2）—— 否则"可引"退化成"可以挑着引" | **已定** |
| ✅ **C9** | `measured_gap` 要不要区分断点是 `unmet` 还是 `insufficient_data` | 🔴 **要**（§2.3-②）。措辞由**断点原因**驱动，不由"该维度有无数据"驱动；新增 `blocked_no_data` 态。**否则在 ceiling 断点重犯"没测到 = 没达标"，且无区间可填**。🔴 **当前真报告已中招**（`security_alignment` 断在 L3 的 `insufficient_data`） | **已定**（评审提出，架构师采纳并上调严重度） |
| ✅ **C10** | 混合断点（同级既有 `unmet` 又有 `insufficient_data`）怎么办 | 🔴 **`measured_gap` 逐条出，不从 state 派生**（§2.3.0）——二选一必是半句假话 | **已定**（评审与初稿均漏，架构师补） |
| ✅ **C11** | 断点是 `unverified_evidence` 怎么办（文档原先没有这第 4 种状态） | 🔴 **按成因拆两支**：**A `BROKEN`（链断）** —— 报告级已经是 blocker，维度层**不新增状态、不编等级故事**，`measured_gap` 只出一句指向语；**B `UNVERIFIED` + `requires_integrity`（来源不可链校验）** —— 报告级**一个字都没有**（`evidence_basis` 只从 `target_kind` 推，看不到单条 measurement 的 integrity）⇒ **新增 `evidence_unverified` 态**，行动项是"换一个可链校验的证据源"。**不折进 `blocked_no_data`**（会把人打发去查"为什么没输出"，而它输出了）；**不归 `below_floor`**（那会宣称一个我们没有的值） | **已定**（Implementer 提出，架构师裁） |
| ✅ **C12** | `pinned` 该不该自动、空窗口算不算站不住 | 🔴 **不自动 pin**（声明式口径有责任归属，抹掉它是损失）；🔴 **但声明必须被机械校验** —— `pinned && record_count == 0` **是 blocker**，且报文**直接给出观测窗口**供照抄（§1.6）。今天的 `pinned` 量的是"人传了参"，不是"窗口可复算" ⇒ **放过了空窗口，拦住了可复算的观测窗口** | **已定**（Live 实证，架构师裁） |

**无需外部裁定。**

---

## 5. 验收（每条先说什么输入让它红）

| # | 断言 | 🔴 让它红的输入 |
|---|---|---|
| 1 | 字段形状与配对一致 | 报告顶层与每个 dimension 有 `citable`(bool) + `citable_blockers`(list[str])；**新造字段名即红** |
| 2 | 🔴 unpinned 即不可引 | 一份 `provenance.pinned=false` 的 bundle ⇒ 报告级 `citable=false`，blocker 里**含 `--window-from-ns` 这个修法**（只说"unpinned"不含修法 ⇒ 红） |
| 3 | 🔴 **不达标仍可引** | 构造一份全部 pinned/wal_anchored、但 `injection_rule_detection` 为 `unmet` 的报告 ⇒ **`citable=true`**。**这条是本单最容易做反的地方** |
| 4 | 🔴 **没有维度级 citable**（C7） | dimension 上**不存在** `citable` / `citable_blockers` 字段，**且 Web 渲染里不存在任何等价徽章** —— 后端或前端**任一侧**加回去即红（前端自己 derive 一个 ✅ 活下来，正是"第二份定义"那类病） |
| 5 | 🔴 **真报告 pin 后必须可引**（C6） | 用**库里那份真报告**（含 `rob.l4.drift_alerting` 与 `sec.l3.guardrail_blocking` 两条 `insufficient_data`）：补 pin ⇒ **`citable=true`**。**这是 C6 的现场，不是构造用例** |
| 6 | 链断即全灭 | `integrity_summary` broken>0 ⇒ 报告级不可引，且 blocker 排在**第一条** |
| 7 | `citation_form` 带 n 与区间 | 任一率的 `citation_form` 缺 `n` 或缺区间 ⇒ 红 |
| 8 | 🔴 普查不给区间 | `chain_integrity` 173/173 的 `citation_form` **不含区间**，改含"普查"字样（给它加区间 ⇒ 红） |
| 9 | 不可引时仍有 form | `citable=false` 的产物里 `citation_form` **非空**且以 `🔴 NOT CITABLE` 开头 |
| 10 | 🔴 判据单一定义 | 改引擎里那一个 `_is_not_measured` ⇒ **CLI 与 Web 的测试同时红**（只红一边 ⇒ 说明还有第二份定义） |
| 11 | 🔴 两种 None 分开 | 用真报告：robustness ⇒ `below_floor` + 文案含 **"实测未达 L2"**；security_alignment ⇒ `not_measured` + 点名 **`guardrail_blocking`**。**任一说成"无实测信号" ⇒ 红** |
| 12 | 事实句可核 | `measured_gap` 里的 `ci_low`/`ci_high`/所需 n **与 `treval.stats` 现算的一致**（硬编码数字 ⇒ 红） |
| 13 | 雷达图 | `below_floor` 维度**不画成灰虚线无信号**，且标出未达的级 |
| 14 | 页面两态都显示 | 可引的报告，Dashboard 顶部**也要显示"可引用"** —— 只在不可引时显示 ⇒ 红 |
| 15 | 🔴 **`measured_gap` 必填**（C8） | 任一维度 `measured_state != certified` 而 `measured_gap` 为空 ⇒ **红** |
| 16 | 🔴 **n 的措辞是条件式**（§2.3.1） | `measured_gap` 里出现"n≈81 **可过线**"这类无条件断言 ⇒ 红；必须含"若点估计维持在 ~89%"与"68–80 之间会来回穿越"；良性侧必须写成**随误拦数跳档**（73/110/142/173），写成"扩到 73 就过" ⇒ 红 |
| 17 | 🔴 **断点是 `insufficient_data` 时不许说"未达标"**（C9） | 用**当前真报告的 `security_alignment`**（断点 L3 = `guardrail_blocking` insufficient_data）：`measured_state` 必须是 `blocked_no_data`，`measured_gap` **不含"实测未达"、不含任何 `ci_low`/`ci_high`**，且**点名 `guardrail_blocking`**。**这是现场，不是构造用例** |
| 18 | 🔴 **混合断点两句都出**（C10） | 构造一级同时含 `unmet` 与 `insufficient_data` ⇒ `measured_gap` **两句都在**，`unmet` 那条带区间、`insufficient_data` 那条不带。**只出一句 ⇒ 红** |
| 19 | 🔴 **B 不说成"没产出"**（C11） | 断点级唯一非 met 为 `unverified_evidence`、链**未**断 ⇒ state = `evidence_unverified`，gap **含"不可链校验的来源"、不含"未产出"、不含 `ci_low/ci_high`** |
| 20 | 🔴 **A 不双重计费**（C11） | `integrity broken>0` ⇒ 报告级 `citable=false`；各维度 `measured_gap` **只出指向语**，**不得**出现"实测未达 L\<N\>"或"缺 \<indicator\>"式的等级故事 |
| 21 | 🔴 **pin 空窗口即不可引**（C12） | 就用 Live 里那份 `record_count=0` 的 pinned bundle ⇒ **`citable=false`**，且 blocker 报文**含本次观测到的窗口数值**（只说"空窗口"不给数值 ⇒ 红——那就等于还要人自己算） |
| 22 | 🔴 **分层测量必须点名分层** | `injection_catch_rate` 的 `subject="outcome_observable"` 那条，其 `citation_form` **必须含 `outcome_observable`**，且**必须带可观测子集偏差注**（复用 [pair.py](../../treval/cli/pair.py) 的 `_OBSERVABLE_BIAS_NOTE` 同一常量，**抄第二份文案 ⇒ 红**）。🔴 **它是全仓最不该裸引的数**：8/8=100% vs 全体 25/28=89.3%，三条漏检 marker 与 canary 皆空 ⇒ **按构造必然好看** |

---

## 6. 施工单（三个提交）

| # | 提交 | 文件 | 验证 |
|---|---|---|---|
| **T1** | 判据单一定义 + `measured_state` + `measured_gap` | `treval/rubric/engine.py`（`_is_not_measured` 上移、`measured_state`、`measured_gap`）、`treval/rubric/serialize.py`（进 JSON）、`treval/cli/render.py`（改为引用引擎定义）、`treval/web/view.py` + `treval/web/radar.py` + `treval/web/templates/dashboard.html`（两态文案 + 雷达）、`tests/` | 验收 10–13 |
| **T2** | 可引用性闸 | 新 `treval/citability.py`（**纯 stdlib，判据集中一处**）、`treval/rubric/serialize.py`（顶层与维度字段）、`treval/cli/render.py`（human 首行）、`tests/test_citability.py` | 验收 1–6 |
| **T3** | `citation_form` + 页面条 | `treval/citability.py`（form 生成，区间按机制）、`treval/rubric/serialize.py`、`treval/web/view.py` + `dashboard.html`（可引用性条，两态都显示）、`docs/CLI_USAGE.md` + `README.md` | 验收 7–9、14 |

**顺序**：T1 先 —— 件二的 `insufficient_data` 判据是件一维度级 blocker 的输入。
🔴 **T2 单独成一个纯 stdlib 模块**：它是本单唯一的**判定**代码，必须能脱离渲染与 HTTP 单测
（同 [UI-3](UI-3.md) 把 `cases_auth` 独立出来的理由）。

---

## 7. Live Test

```bash
export PYTHONPATH=$PWD

# ① 现有那份 unpinned 报告 —— 期望：不可引，且 blocker 点名修法
python -c "
import json; from treval.report_store import ReportStore
st=ReportStore('reports/store'); d=json.loads(st.read_bytes(st.list()[0]))
print('citable:', d['citable']); [print(' -', b) for b in d['citable_blockers']]"

# ② 补 pin 重跑，再看一次
python -m treval.cli collect --gateway $GATEWAY --wal $WAL \
  --window-from-ns $FROM --window-to-ns $TO --out /tmp/pinned.json
python -m treval.cli report --measurement-bundle /tmp/pinned.json \
  --posture /tmp/posture.yaml --self-contained --out-dir reports/store
```

**必须看到：**

1. ① 里 `citable=false`，blocker 含 **`--window-from-ns`** 这个具体修法（不是只说 unpinned）；
2. ② 之后 `citable` 翻 **true** —— 🔴 **尽管 robustness 仍然 `unmet`**（§0）
   **且这份报告有两条 `insufficient_data`**（`rob.l4.drift_alerting` / `sec.l3.guardrail_blocking`，
   C6/§1.3.1）。**这两点同时成立，才说明闸拦的是"站不住"，不是"不好看 / 不完整"**；
3. 🔴 Dashboard 上 **强鲁棒性不再写"无实测信号"**，改写 **"实测未达 L2"**，
   并给出 `injection_catch_rate 89.3% (n=28)、ci_low 0.728 < 0.80、n≈81 可过线`；
4. 🔴 安全与价值对齐写 **"达 L2；L3 缺 `guardrail_blocking`，本次未产出"**（`blocked_no_data`）——
   **不是"无实测信号"**（它测了 `oauth_scope` 且过了），**也不是"实测未达 L3"**（那一级没测）。
   **三个维度三种文案，一种都不许串**；
5. 任一率的 `citation_form` 都带 `n` 与区间；`chain_integrity` 那条**不带区间**、写"普查"。

> 🔴 **第 2 与第 3 项是这一跑的意义**：
> 第 2 项证明闸拦的是"站不住"，不是"不好看"；
> 第 3 项证明我们终于不在自己的首页上，把"没测到"和"测了没达标"说成同一件事。
