# EV-JUDGE-UNION —— 多判官并集落地前的两件事：**代价要看得见，数不许乱并**

> 🔴 **受众：Platform / 架构侧。不得转给补件作者。**
> 本文含判据推导所需的区间与门限值；作者用件另出（只含族定义 · 场景 · 件数 · 隔离条款）。
> —— 记于 2026-08-23：发送端门对本文报 `measured_value` 命中，**属受众错配而非泄漏**，
> 以本行声明的受众为准放行；`--audience` 维度落地后由门自行区分。


> **问题（说人话）：** Tier-2 判官从"一个"变成"几个取并集"。并集**只会多打标、不会少打标**，
> 所以它在良性分母上的代价是可以量的 —— 但它在**"引用/讨论攻击手法"那条臂**上多打的标，
> **不落进任何一个分母**，于是**在我们现在的产物里根本看不见**。
>
> **价值：** 这件事只有**在并集第一次跑之前**做才有用。跑完再补，那一跑的 before 就没有了 ——
> 和"基线是一次性的"是同一条。做完之后：并集的收益与代价**同一张表上一起出现**，
> 而且**不同判官形态的数再也不能悄悄并排**。

---

## 0. 披露边界

本文档**不含**：被测方与任何候选判官的**型号、版本、阈值、开关状态**；任何**实测数字**；
任何"某缺陷已知 / 已排期"的表述。判官筛查的实测结果**只进私有记录**。
本文只写**本仓的判据与机制**。

---

## 1. 🔴 判据先写死 —— **在看到并集的第一个数之前**

### 1.1 三条结构事实（已核实，不是推测）

| # | 事实 | 在哪核的 |
|---|---|---|
| **S-1** | 并集**单调**：任一判官命中即算 ⇒ 命中集合 ⊇ 任一单判官的命中集合，**只增不减** | 定义即得 |
| **S-2** | 🔴 `control_speech_act_mention` 带 `control_` 前缀 ⇒ **结构性退出每一个分母**（FPR / 良性打标率 / catch / 携带率门） | `case_contract.is_control_attack_class` + E3F 的通用排除 |
| **S-3** | `speech_act_separation_rate` 是**无门·首测**（`citability.FIRST_MEASUREMENT_NO_GATE_IDS`） | `treval/citability.py` |

**S-2 的后果值得单独说：** 判官在 mention 件上多打的标，**即使判官跑在 enforce 里也不进 FPR 分母** ——
因为那些件是对照件，本来就不在分母里。**⇒ shadow 和 enforce 两种模式下，这份代价都看不见。**
所以本文的要求**与判官跑在哪一层无关**。

**S-3 的后果：** 🔴 **一个无门的数，缺席时读起来和"通过"一样。** "记得同报"是一句没有守卫的承诺，本仓不接受这种形状。

### 1.2 🔴 但**不能**直接把"必报 `speech_act_separation_rate`"接成门 —— 那是又一个 proxy

`SpeechActSeparationRate` 的四态是用 `evaluate(_LLM01_CRITERION, pr)` 判的，
**那读的是网关的终态（拦没拦）**。判官若在 shadow 里跑（只出 hint、不扣响应），
mention 件**不会被拦** ⇒ 它的 `over_blocks` **一个都不会动**。

**⇒ 把这个指标当见证人，等于拿一台看不见目标的仪器去作证。**
这正是本program 反复踩的那一条：**一个比它声称的东西更容易为真的检查。**

**⇒ 必须先有【判官侧】的孪生指标（件1），"必报"才有东西可报。**

---

## 2. 施工件

### 件1 · 言语行为分离率的**判官侧孪生**

现状：`SpeechActSeparationRate` 一个配对循环，判据是"网关拦没拦"。
**改法是参数化，不是复制** —— 把配对循环抽成一个函数，唯一的参数是 `flagged(pr) -> bool`，实例化两次：

| 实例 | 判据 | 指标 id |
|---|---|---|
| 决策侧（现有，行为不变） | `evaluate(_LLM01_CRITERION, pr)` | `speech_act_separation_rate` |
| 🔴 **判官侧（新）** | `caught_by_tier2(pr)`（标定 τ 下的 hint，**从不读原始分**） | `speech_act_shadow_separation_rate` |

五态与现有**同构**，一个都不合并：`separated` / `over_flags` / `under_flags` / `inverted` / `unpaired` / `errored`；
**分母 = separated + over_flags**（只有判官在 use 半边响过，"它是不是把孪生的 mention 也打了标"才是个问题）。

🔴 **三条不许省：**
1. **drain 没跑 / 没有 async 记录 ⇒ `not_measured`，绝不是 0** —— 同 `BenignShadowFlagRate` 那条。
2. **`STATISTICAL`** —— 判官非确定性，逐跑会抖，小 n 尤甚；必须带区间。
3. **新指标同样 UNBOUND、同样 `无门槛·首测`** —— 没测过就设门是拍脑袋（同 `τ 不因一次结果而改`）。

**验收（什么输入让它红）：**
- 🔴 **重构前后，决策侧那条 measurement 逐字节相同**（同"`--corpus-set` 默认 `en` 逐位不变"那条）⇒ 差一个字节即红；
- 造一对"判官把 use 与 mention 都打了标"⇒ 必须落 `over_flags`、进分母；把它算进 `separated` 即红；
- 造一对"判官两边都没打标"⇒ 必须落 `under_flags`、**退出分母**；折进 `0% separated` 即红；
- 全组无 async 记录 ⇒ `not_measured`；给出 `0.0` 即红。

### 件2 · 同报门：**判官可动的数**缺了 mention 臂 ⇒ `not_citable`

```python
JUDGE_MOVABLE_IDS = frozenset({
    "tier2_shadow_recall_lift", "benign_shadow_flag_rate", "injection_combined_recall",
})
```

**规则：** 一份产物里出现上表任一个数，而**没有** `speech_act_shadow_separation_rate` ⇒
**这些数的 `citation_form` 前缀 `not_citable`**，并说明缺的是什么。
形状照抄前置3：一对 `derive_judge_coreport` / `assert_judge_coreport_derived`，**派生不存储**。

🔴 **条件是"发布了判官可动的数"，不是"声明了并集"。** 两个理由：
1. 挂在声明上，就等于**把门交给了声明人** —— `Producer.subject` 那一课（声明了没人核，就不是声明）；
2. **单判官同样看不见 mention 代价**（§1.1 S-2 与判官形态无关）。⇒ 无条件更简单，也更强。

⚠️ **CN 侧零影响，别去"修"它：** `CURATION_CN` 里**没有任何 Tier-2 producer** ⇒ 这道门在 CN 跑上永不触发。

**验收：** 造一份带 `tier2_shadow_recall_lift`、不带 mention 臂的产物 ⇒ 那个数必须带 `not_citable`；
带上 mention 臂 ⇒ 前缀消失。去掉这条判断即红。

### 件3 · **判官形态**进 run-config 作用域轴（**声明 + 观测 + 第三态**）

同一个数在"单判官"和"并集"下是**两台仪器量出来的**，不可比。

**(a) 声明侧** —— `judge_form` 加进 `citability` 的 `_config_keys`，与 `detection_layer_status` **同形**：
判据是**字段在不在**，与"值怎么来的"无关。
🔴 **因此不新增 blocker identity，`CRITERIA_VERSION` 保持不变，不触发再判浪** —— 这是选这个落点的理由。
取值形如 `single` / `union:<判官数>`。**不写型号**（§0）。

**(a2) 🔴 第二根轴：测量路径** —— `measurement_path ∈ {offline_judge_harness, in_product_gateway}`。

同一条 mention 臂，**离线工装量出来的数**与**网关跑量出来的数**回答的不是同一个问题：
工装不过产品链路，**喂给判官的输入不必等于产品实际发送的输入**，也没有产品那一层的前后处理。
⇒ **离线工装的数不得作为产品能力被引用**，两种路径的数**不得并排进同一张无标注的表**。

这一轴与 `judge_form` **必须分开两个字段**：判官形态相同、测量路径不同的两个数，一样不可比。
（与 §1.3「可复算 / 不可复算不得并排」是同一道门的第三个轴。）

**(b) 观测侧** —— `judge_form_observed`，从记录**派生**。

**(c) 🔴 第三态** —— Platform 尚未发出逐记录的判官清单之前，观测值是 **`unobservable`**，
**正面记录，不许由"没看到并集的证据"推出 `single`**。
这就是 `unattributable` / `not_scored` / `no_verdict` 的同一条纪律，换了个位置。

**(d) 守卫** —— `declared != observed` 且 `observed != unobservable` ⇒ **raise**。

**验收：** 缺 `judge_form` 或缺 `measurement_path` ⇒ 引用被拦（且旧包诊断为 DRIFT 而不是缺陷）；
声明 `single` 而记录里有多判官 ⇒ 必须抛错；观测不可得时给出 `single` 而不是 `unobservable` ⇒ 红；
两种 `measurement_path` 的数进一张无标注的表 ⇒ 红。

### 件4 · 🔴 **降级的并集不是并集** —— 判官超时/出错要成为正面的第三态

Platform 已定死记录形状（§3 P-2）：**每一个被配置了的判官，每一次都出一行**，
`matched=false` + `tags["outcome"] ∈ {scored, timeout, judge_error}`。
⇒ 行**缺席**只有一个含义：这个部署根本没配这个判官。

**这让一件此前不可观测的事第一次可观测：某一请求上，实际参与的判官比声明的少。**
本仓现有的 Tier-2 指标（`caught_by_tier2` 一族）把它读成"判官看了、没打标" —— **那是取反读法，会把超时算成漏检。**

**逐请求判读（写死）：**

| 情形 | 判读 | 理由 |
|---|---|---|
| 命中 **且** 有降级行 | **仍算命中** | 更少的判官都抓到了 —— 这是**更强**的结果，不是更弱 |
| 🔴 未命中 **且** 有降级行 | **`degraded_miss`：退出并集召回分母，单独计数** | 这一件量的**不是声明的那台仪器**；折进"并集漏了"就是把时钟的账记到判官头上 |
| 无降级行 | 正常判读 | —— |
| 🔴 **行数 ≠ 配置的判官数** | **整跑判官侧 `not_measured`** | P-2 的约定是"配了就必出行"；行数对不上 ⇒ **约定被破坏 ⇒ 我们不知道自己在读什么**。这不是降级，是记录不完整 |

**验收：** 造一件"一个判官 timeout、其余未命中" ⇒ 必须落 `degraded_miss` 且**退出分母**；算成 miss 即红。
造一件"一个判官 timeout、另一个命中" ⇒ 必须仍算命中；退出分母即红。
把配置数改成比行数大 1 ⇒ 整跑必须 `not_measured`；照常出数即红。

### 件5 · 🔴 `decided_by` 路径丢了 `matched` —— **fail-closed 超时拦截会被算成注入检测**

实核 [checks.py:306-317](treval/active_eval/checks.py#L306-L317)：`decision_injection_source` 在 `decided_by` 这条路上
把每个 rule id 映射成**只有 tags**（`by_id.get(rid, {})`），**`matched` 被丢掉了**。
另一条 fallback 路（无 `decided_by`）反而过滤了 `_reacting`。

今天没事，是因为 `decided_by` 里只会出现真的匹配了的规则。
🔴 **但 `enforce_on_timeout = fail_closed` 一上线，"判官没答上来"就成了一种新的拦截原因** ——
那条规则会进 `decided_by` 而 `matched=false`；它的 tags 若带注入族标记，
**这一拦就会被归因成注入检测**：攻击侧记成 catch，良性侧记成注入误拦。

**⇒ 这就是 F1 那条的第三次：「网关拦住了」≠「检测器抓到了」，这次拦它的是【时钟】。**

**改法：** `decided_by` 路上把 `matched` / `outcome` 一起带上；
决策者 `matched=false`（或 outcome ∈ {timeout, judge_error}）⇒ **不是注入检测**，
返回一个**独立命名的来源**（如 `fail_closed_timeout`）而不是 `None` ——
🔴 **返回 None 会让它悄悄退出分子，看起来像"我们判对了"，实际是又一次静默。**

**同族另一处一并查：** `injection_attribution_source`（决策 ∪ 响应）是否有同样的丢弃。

**验收：** 造一条 `decided_by` 指向 `matched=false` 且 tags 带注入族标记的记录 ⇒
必须返回 `fail_closed_timeout` 且**既不进注入分子、也不静默消失**；返回 `tag_owasp` 即红；返回 `None` 即红。

---

## 3. Platform 输入 —— **三样已全部采纳（2026-08-23）**

| # | 要什么 | 落点 |
|---|---|---|
| **P-1** | 逐跑的**配置字面量**（每判官 τ / 型号 / 位宽 / digest） | A 侧：报告**必填字段**，与结果同一文件（跑完不可补）· B 侧：`detection_switches.tier2_judge` |
| **P-2** | 逐记录「**哪些判官评了 · 谁响了**」 | 复用既有的 `rules_evaluated`，并集只是多 `.add()` 几次 |
| **P-3** | τ 进印记 | 连同 `enforce_enabled` / `enforce_on_timeout` / `enforce_latency_budget_ms` 一并补进 `detection_switches`；`tau` 按"可以是多个"设计 |

🔴 **P-2 的行形状由 Platform 定死，本仓照此读，不许自创：**

> **每一个被配置了的判官，每一次都必须出一行**，哪怕它超时或挂了。
> 那一行：`matched=false` + `tags["outcome"] ∈ {scored, timeout, judge_error}`。
> ⇒ **行【缺席】只有一个含义：这个部署根本没配这个判官** —— 而那由 P-1 的配置回答。

**这正是白名单读法**：`rules_evaluated` 当初帮我们发现某类排除是错的，靠的就是 `matched:false` **这一行存在**。
判官侧照抄。本仓的读法必须是"读 `outcome` 白名单"，**不是"没打标 ⇒ 判官看过了"**（件4）。

### 3.1 🔴 P-3 的落点选对了 —— 说清楚它为什么比 `detect_config` 强

| 落点 | 性质 | 本仓怎么对待它 |
|---|---|---|
| `detect_config` | **声明**（自由文本，操作者填） | 只查**在不在**，从不核内容 |
| 🔴 `detection_switches` | **指纹**（`/admin/v1/buildinfo` 抓） | **跑前 + 跑后各抓一次，逐位比对；任一位变了 ⇒ 整跑作废** |

实核 [citability.py:282-291](treval/citability.py#L282-L291)：比对是 `before != after` 打在**整个指纹对象**上。
⇒ 🔴 **τ / enforce 三件放进 `detection_switches`，就自动获得「跑中被改 ⇒ 自动作废」，本仓零代码。**
放进 `detect_config` 则只会得到"填了没填"。**这四件放对了地方。**

### 3.2 仍需一个确认（很小）

`enforce_on_timeout = fail_closed` 触发的拦截，落到记录里时：
**① 它进不进 `decided_by`？② 若进，那条判官规则的 `matched` 是 `false` 吗？**
—— 见件5：本仓的归因在 `decided_by` 这条路上**丢掉了 `matched`**，这个洞会被这条开关激活。

### 3.3 本仓不等 Platform 的部分

件2、件3(a)(a2) **先落**（它们只读产物形状）；件3 的观测侧记 `unobservable`。
**不许用"没看到并集证据"去补一个 `single`。** 件1/件4/件5 跟 B 侧走（§6）。

---

## 4. 门

| 门 | 判据 | 什么输入让它红 | 在哪跑 |
|---|---|---|---|
| **同报** | 出现判官可动的数而无 mention 判官侧臂 ⇒ 那些数 `not_citable` | 造一份缺 mention 臂的产物，断言前缀在 | 单元测试 + 公开 CI ✅ |
| **形态声明** | `judge_form` 缺失 ⇒ 引用被拦 | 造一个不带该键的包 | 公开 CI ✅ |
| **声明=观测** | 声明与观测冲突 ⇒ raise | 声明 `single`，记录里放两个判官 | 单元测试 ✅ |
| 🔴 **不同形态不得并排** | 一张表里出现两种 `judge_form` 而无标注 ⇒ 红 | 把两种形态的数放进一张无标注的表 | 公开 CI ✅ |
| 🔴 **不同路径不得并排** | 一张表里出现两种 `measurement_path` 而无标注 ⇒ 红 | 把离线工装的数与网关跑的数放进一张无标注的表 | 公开 CI ✅ |
| 🔴 **降级不算漏** | 有降级行的未命中件必须退出并集召回分母并单独计数 | 把 `timeout` 件算成 miss | 单元测试 ✅ |
| 🔴 **超时拦截不是检测** | `decided_by` 指向未匹配的规则 ⇒ 独立来源，不进注入分子 | 造一条 fail-closed 超时拦截记录 | 单元测试 ✅ |

**⇒ 这四道全在公开 CI 里真的会咬人** —— 它们只读产物形状，不读语料内容，与 CN 那两道门相反（`EV-CN-BASELINE` §6.1）。

---

## 5. 验收总表（每条先说什么输入让它红）

1. 重构后**决策侧 measurement 逐字节不变** ⇒ 差一字节即红；
2. 判官两边都打标 ⇒ `over_flags` 且进分母；算进 `separated` 即红；
3. 判官两边都不打标 ⇒ `under_flags` 且**退出分母**；折进 `0% separated` 即红；
4. 判官只打了 mention 那半 ⇒ `inverted`，退出分母且**单独计数**；静默丢弃即红；
5. 无 async 记录 ⇒ `not_measured`；给 `0.0` 即红；
6. 新指标带 Wilson 区间且标 `STATISTICAL` ⇒ 缺任一即红；
7. 新指标的 `citation_form` 带「无门槛·首测」⇒ 缺即红；
8. 判官可动的数缺 mention 臂 ⇒ `not_citable`；补上后前缀消失；判断去掉即红；
9. 同报门**不看** `judge_form` ⇒ 把它改成"只在声明并集时才要求"即红；
10. CN 跑（`--corpus-set cn`）不触发同报门 ⇒ 触发即红；
11. 缺 `judge_form` ⇒ 引用被拦；🔴 **旧包（键整个不存在）诊断为 DRIFT 而非缺陷** ⇒ 诊断成缺陷即红；
12. 加 `judge_form` **不新增 blocker identity、`CRITERIA_VERSION` 不变** ⇒ 变了即红（那意味着一次不必要的再判浪）；
13. 声明 `single` 而观测到多判官 ⇒ raise；静默以声明为准即红；
14. 观测不可得 ⇒ `unobservable`；给出 `single` 即红；
15. 一张表混两种 `judge_form` 而无标注 ⇒ 红；
16. 缺 `measurement_path` ⇒ 引用被拦；一张表混 `offline_judge_harness` 与 `in_product_gateway` 而无标注 ⇒ 红；
17. 离线工装的数被当作产品能力引用 ⇒ 引用形态必须拦住它；能裸引即红；
18. 一个判官 `timeout` + 其余未命中 ⇒ `degraded_miss`，**退出并集召回分母且单独计数**；算成 miss 即红；
19. 一个判官 `timeout` + 另一个命中 ⇒ **仍算命中**；退出分母即红；
20. 判官行数 ≠ 配置的判官数 ⇒ **整跑判官侧 `not_measured`**；照常出数即红；
21. `outcome` 按**白名单**读（`scored` / `timeout` / `judge_error`）⇒ 改成"不是 scored 就当没打标"即红；
22. `decided_by` 指向 `matched=false` 且 tags 带注入族标记的记录 ⇒ 必须返回 `fail_closed_timeout`
    且既不进注入分子、也不静默消失；返回 `tag_owasp` 即红，返回 `None` 即红。

---

## 6. 时序 —— 🔴 **"并集第一次跑之前"是两个时点，不是一个**

**本节修正本文档初稿的一处归属错误。** 初稿把 mention 臂的 before 窗口整体挂在"并集第一次跑"上，
**没有分清那是哪一跑** —— 而两条跑线 owner 不同、窗口不同，混着说会盖住更急的那一个。

| | 哪一跑 | before 窗口何时关 | 关键产出方 | 本仓对应件 |
|---|---|---|---|---|
| **A · 测量侧** | 离线跑（语料 + 判官工装），不过产品链路 | 🔴 **英文那半一开跑就关 —— 就在眼前** | 报告格式（含 mention 臂 + `config_literal`） | 件3(a)(a2) |
| **B · 生产侧** | 网关跑 | 上线时 | type-3 记录形状（P-2 的行 + P-3 的四个开关） | 件1 · 件4 · 件5 |

🔴 **我举的那个例子（mention 臂的判官侧数据）属于 A，而 A 的产出方不是本仓。**
本仓的 `speech_act_shadow_separation_rate` 读的是 `caught_by_tier2`，
数据来自**网关跑**（`governance_evidence`）⇒ 它是 **B**。
**⇒ 我把急迫性挂错了对象：最急的是 A 侧的报告格式，不是件1。**

**但件3 的两根作用域轴在 A 侧【立刻】有用** —— 跨路径、跨形态的并排**现在就会发生**
（本轮的跨语言比较已经发生过一次）。⇒ **件3(a)(a2) 提前，其余跟 B。**

```
件3(a)(a2) 形态轴 + 路径轴     ← 🔴 A 侧窗口，就在眼前
件2       同报门               ← 随件3 一起（只读产物形状）
—— 以下跟 B 侧（记录形状到位后）——
件1       判官侧孪生指标
件4       降级并集第三态         ← P-2 的行落地后才可观测
件5       decided_by 补 matched  ← 🔴 fail_closed 上线【之前】必须落，否则第一跑就把超时算成检测
件3(b)(d) 观测侧 + 守卫         ← P-2 到位后
```

🔴 **件5 的时点单独强调**：它不是"并集"的前置，是 **`enforce_on_timeout` 的前置**，
而那条开关**今天单判官下就可能打开**。这一件比并集本身更早。

---

## 修订记录

| 日期 | 变更 |
|---|---|
| 2026-08-23 | **承 Platform 对账单回执（三样全采纳），本文四处改、两件新增。** 🔴 **① §6 时序修正本文初稿的归属错误**：初稿把 mention 臂的 before 窗口整体挂在"并集第一次跑"，**没分清是哪一跑**。拆成 **A · 测量侧（离线跑，窗口就在眼前，产出方是报告格式）** 与 **B · 生产侧（网关跑，窗口在上线时，产出方是记录形状）**；我举的 mention 例子属于 **A**，而本仓的判官侧孪生指标读 `caught_by_tier2`（网关数据）⇒ 属于 **B**。**⇒ 最急的不是件1。** 但件3 的作用域轴在 A 侧立刻有用（跨路径并排现在就会发生）⇒ **件3(a)(a2) 提前**。**② 件3 新增第二根轴 `measurement_path`**（离线工装 / 网关跑）：工装不过产品链路，**喂给判官的输入不必等于产品实际发送的输入** ⇒ 两种路径的数不可并排、离线数不得当产品能力引用；与 `judge_form` **必须是两个字段**（形态相同、路径不同一样不可比）。🔴 **③ 新增件4「降级的并集不是并集」**：Platform 定死"每个被配置的判官每次都出一行（含 `timeout`/`judge_error`）"⇒ **"实际参与的判官比声明的少"第一次可观测**，而本仓现有 Tier-2 指标会把它读成"看了没打标"。写死四条判读：命中+降级仍算命中（更少判官都抓到是更强结果）· **未命中+降级 = `degraded_miss`，退出分母单独计数**（否则把时钟的账记到判官头上）· 行数 ≠ 配置数 ⇒ **整跑 `not_measured`**（约定被破坏，我们不知道自己在读什么）。🔴 **④ 新增件5：实核出 `decision_injection_source` 在 `decided_by` 这条路上丢掉了 `matched`** —— 今天无害（`decided_by` 只装匹配了的规则），但 **`enforce_on_timeout = fail_closed` 一上线，"判官没答上来"就成了新的拦截原因**，那条规则会带 `matched=false` 进 `decided_by`，其注入族 tags 会让这一拦被归因成注入检测（攻击侧记成 catch、良性侧记成误拦）。**这是 F1 那条的第三次：拦它的这次是【时钟】。** 改法返回独立命名来源，**不许返回 `None`**（None 会让它悄悄退出分子，看起来像判对了）。**件5 是 `enforce_on_timeout` 的前置，比并集更早。** **⑤ §3.1 说清 P-3 落点为什么选对了**：`detect_config` 是声明（只查在不在），`detection_switches` 是**跑前跑后逐位比对的指纹**，实核比对打在整个对象上 ⇒ 四个开关放进去**自动获得"跑中被改即作废"，本仓零代码**。**⑥ §3.2 留一个小确认**：fail-closed 超时拦截进不进 `decided_by`、进的话 `matched` 是不是 `false`。验收 15 → 22 条，门 4 → 7 道。 |
| 2026-08-22 | Core 架构师起草，承 `EV-CN-BASELINE` §9 的 **F-1 / F-5**（Platform 已开工实现并集，两条从 backlog 升为在建）。**① §1.1 三条结构事实**：并集单调；🔴 mention 件带 `control_` 前缀 ⇒ **结构性退出每一个分母**，因此 **shadow 与 enforce 两种模式下代价都看不见**，本文要求与判官跑在哪一层无关；无门的数缺席时读起来和"通过"一样。**② 🔴 §1.2 自我否决了最直白的做法**：现有 `speech_act_separation_rate` 的四态读的是**网关终态**，判官跑 shadow 时它**一个都不会动** ⇒ 直接把它接成"必报"是**拿看不见目标的仪器当见证人**，又一个 proxy。**⇒ 先建判官侧孪生（件1），"必报"才有东西可报。** **③ 件1 用参数化而不是复制**（唯一参数是 `flagged` 判据），并把"决策侧逐字节不变"写成头号验收。**④ 件2 的触发条件挂在「发布了判官可动的数」而不是「声明了并集」** —— 挂在声明上就是把门交给声明人（`Producer.subject` 那一课），且单判官同样看不见这份代价。**⑤ 件3 判官形态取 `_config_keys` 落点**，与 `detection_layer_status` 同形（fields-present 判据）⇒ 🔴 **不新增 blocker identity、`CRITERIA_VERSION` 不变、不触发再判浪**；观测侧未到位时是 **`unobservable` 第三态，不许由"没看到证据"推出 `single`**。**⑥ §3 列出必须由 Platform 出的三样**（逐跑配置字面量快照 · 逐记录判官清单 · 每判官 τ），其中逐记录清单**与 `rules_evaluated` 同形**且有实证背书。**⑦ §6 写死"必须在并集第一次跑之前"** —— 那一跑就是 before，当时没留的数据永远没有。 |
