# EV-PAIR — 配对评测：把"治理前 vs 治理后"变成可复算的一张图

> **Problem（普通话）：** EV-FWD 把轨铺好了 —— `collect` 已能驱动裸模型（`OpenAITarget` 已接线），
> 指标级 `availability` 也会诚实标注哪些维度在裸模型上不存在。**但产品里跑不出裸模型的输出侧数字**：
> `collect` 的生产者清单里**一个输出侧指标都没有**（只有两个决策侧的），所以 `--target-kind raw_model` 永远只出 `n/a`。
> 架构师用 `python -c` 拼产品 API 才拿到裸模型 `injection_success_rate = 83%` —— **能力在，产品路径不在。**
>
> **Value:** 让"治理前 → 治理后"这条**唯一 apples-to-apples 的轴**成为产品能跑、且**可复算**的结果：
> 裸模型 X% 攻击抵达输出 → 网关 Y% 抵达输出，**delta = 治理买到了什么**。
> 并把"两跑可比"从**纪律**变成**代码强制**（不满足即拒绝出 delta，而不是靠人记得）。
>
> **归属：** Implementer 编码 + 测试；架构师出本规格。
> **承：** [EV-FWD](EV-FWD.md)（`OpenAITarget` + `availability`，已 merged）· [EV-PIN](EV-PIN.md)（窗口冻结，已 merged）
> · [PROV-CLOSEOUT](PROV-CLOSEOUT.md)（🔴 **流量口径政策的母版 —— 本 issue 套用，不重裁**，见 §0.1）。

---

## 0. 规模判定（对着代码量的，不是估的）

**结论：小-中。三件里第一件很小、第三件是真活。** 因此**不必单独立项为大 issue**，
但**需要本设计文档** —— 因为第三件（配对诚实性）是**契约性的**，不写清会被做成"两个报告并排显示"那种不可复算的东西。

| 件 | 现状（已核实） | 要做 | 规模 |
|---|---|---|---|
| **① 输出侧生产者** | 🟢 `collect` **已能建 `OpenAITarget`**（`collect.py:234`）、已用 `run_corpus`（附 marker/canary）、五份 canonical 语料**都在**（28/14/12/14/12 条） | 往 `CURATION` 表加输出侧 `Producer` | **很小** ⇒ 🔵 **已拆出为可立即下发的 [EV-PAIR-A](EV-PAIR-A.md)**（收 4 条；`within_cost_budget` 因 `Producer.factory` 是无参调用而需结构改动，留本主体） |
| **② 标的元数据入 bundle** | 🔴 bundle 顶层**无 `model` / `temperature` / `corpus_sha`**（实测键只有 8 个） | 补记"决定这次结果的配置" | **小** |
| **③ 配对可比性强制** | 🔴 **完全不存在** —— 今天没有任何东西阻止你拿两份不可比的 bundle 出 delta | 见 §3，**本增量的真活** | **中** |

---

## 0.1 🔴 套用流量口径政策（PROV 母版，不重裁）

配对 delta 与 `block_rate`/`duration_p99` 是**同一类量：流量相关量**（离开"在什么流量上测的"就没意义）。
PROV 已为这类量定了政策，**本 issue 直接套用**：

| 档 | 用法 | 对外口径 |
|---|---|---|
| **(a) 真实流量** | 最终权威 | 可引，**带下界标注**（n 不足时尤其） |
| **(b) 代表性语料（assumed-mix）** | 可复算、今天能做 | 🔴 **比例必须当口径公开**；标签写死「assumed-mix vX · 攻击占比 Y% · 非生产实测」；**只在 NDA/下界口径下给，不进白皮书 headline** |
| **(c) 标「未测定」** | 零成本、完全诚实 | 格子空着 |

**两条硬纪律（同 PROV）**：① **数字自带流量口径**；② **绝不拿评测攻击流量的值当治理系统属性**。

⇒ **配对 delta 默认落在 (b)**：它跑的是**评测语料**，因此 delta 的正确表述是
「**在 <语料 sha> 这份攻击语料上，治理把得逞率从 X% 压到 Y%**」，
**不是**「治理把生产得逞率压了 Z 个百分点」。**语料 sha + 构成必须与 delta 同框出现。**

---

## 1. 件一：输出侧生产者进 `CURATION`

`collect` 的 `CURATION` 现在只有两条，**都是决策侧** ⇒ raw_model 下恒 `n/a`（EV-FWD 派生表使然）。补输出侧：

| 生产者 | canonical 语料 | `evidence_requirement` |
|---|---|---|
| `injection_success_rate` | `llm01_prompt_injection` | `output_only` |
| `sensitive_disclosure_rate` | `llm02_sensitive_disclosure` | `output_only` |
| `system_prompt_leak_rate` | `llm07_system_prompt_leak` | `output_only` |
| `unsafe_output_passthrough_rate` | `llm05_improper_output` | `output_only` |
| `within_cost_budget` | `llm10_unbounded_consumption` | `output_only`（D1） |

- **两种标的都跑**：`gateway` 与 `raw_model` 用**同一批生产者**（输出侧对两者都 `measured`）—— 这正是可比的前提。
- **决策侧生产者保持不变**：raw_model 下继续 `n/a_needs_gateway`（EV-FWD 已验）。
- 🔴 **不改任何指标实现**（输出侧指标本就只读 response/canary，EV-FWD §7.3 已证在 `evidence=None` 上可测）。

---

## 2. 件二：把"决定结果的配置"记进 bundle

配对要可复算，必须知道两跑各自是什么配置。bundle 现在**一个都没记**。补：

```
model            标的模型标识（raw_model 侧 = OpenAI 兼容的 model id；gateway 侧 = 其部署模型）
temperature      已钉死 0.0，但要显式记录（"钉了"必须可核，不能靠约定）
corpus_sha       本次实际跑的语料指纹 —— 见 §3.1
target_url_host  仅主机名/端口，🔴 不记完整 URL、绝不记 api_key
```
**纪律**：与 EV-PIN 的 `wal_segments.sha256` 同源 —— **决定数字的东西必须随数字一起被记录**。

---

## 3. 件三（真活）：配对可比性 = 代码强制，不是纪律

**问题的本质**：delta 只有在"**除了标的以外，其它一切都相同**"时才有意义。
否则采样差异/非确定性/版本漂移会被读成"治理的效果"。

### 3.1 `corpus_sha`：证明"两跑是同一份语料"

- 对**实际参与该指标的 case 集**（不是目录）算指纹：`sha256(sorted(case_id + 内容规范化))`。
- 逐生产者记录（不同指标跑不同语料 ⇒ 每条 measurement 自带其 `corpus_sha`）。
- 🔴 **配对时逐指标比对**：两侧 `corpus_sha` 不同 ⇒ **该指标不出 delta**（并说明为何）。

### 3.2 配对门（fail-closed）

出 delta 前**逐条校验**，任一不满足即**拒绝该指标的 delta 并给出可读原因**：

| # | 门 | 不满足时 |
|---|---|---|
| 1 | 两侧 `target_kind` 一为 `raw_model`、一为 `gateway` | 拒绝（配对的定义） |
| 2 | 该指标两侧 `availability == measured` | 拒绝 —— 🔴 **`n/a` 侧绝不参与 delta**（否则又是"把不存在当 0"） |
| 3 | 两侧 `corpus_sha` 相同 | 拒绝（不是同一份语料） |
| 4 | 两侧 `model` / `temperature` 已记录 | 缺失即拒绝。🔴 **两侧 `model` 不同时，仅"披露"不够 —— 必须与 delta 同框【标注混入模型差异】**（§4.1） |
| 5 | 两侧 `sample_size` 均 > 0 且**披露** | 小 n 不拒绝，但 delta 必带 n |
| 6 | 🔴 两侧均**声明了流量口径档**（(a)/(b)/(c)，§0.1）且**相同** | 拒绝 —— 拿 (a) 的一侧配 (b) 的另一侧，delta 无意义 |
| **7** | 🔴 **网关侧确实产生了裁决** —— 见 §3.2.1 | 拒绝**全部**输出侧 delta：*"网关未产生任何裁决 —— 输出侧的 0% 无法与「治理生效」区分"* |

🔴 **拒绝是默认行为**：宁可"这条不出 delta 并说明原因"，也不要一个不可复算的数。

### 3.2.1 🔴 第 7 门：网关侧输出侧 0% 的意义**完全依赖**"网关确实在治理"

**为什么单独一门（live 实证，2026-07-29）：** 一次配对跑里 **1–6 门全过、delta 照常产出**：

```
injection_success_rate:  raw 75%  →  gateway 0%      Δ=+75 点   ← 看起来是完美治理
```
**真相**：网关处在**未治理**状态（评测身份未开通 ⇒ 108 条探针零规则评估、全 UNDECIDED），
上游没被正常调用 ⇒ **响应是空的** ⇒ 空响应里当然没有 canary ⇒ 输出侧全 0%。

🔴 **「网关完美拦截」与「网关根本没返回内容」在输出侧指标上长得一模一样。**
唯一戳穿它的是**决策侧**：`injection_catch_rate` 当时是 `insufficient_data`（notes：*28 undecided，no gateway decision*）。
**1–6 门只检查"两个数可比"，检查不了"网关侧那个数有没有意义"。**

**判据（fail-closed，2026-07-29 收紧）：**
- 要求网关侧 **`injection_catch_rate`（护栏信号）`availability == measured` 且 `sample_size > 0`**。
  否则（缺失 / 非 measured / n=0）⇒ 护栏本次**未运行** ⇒ **拒绝该 bundle 的全部输出侧 delta**。
- 🔴 **为什么钉死护栏这一条，而不是"任一决策侧指标 n>0"**：实测一份无身份 bundle 是**部分治理** ——
  `tool_scope_violation_rate`（**authz 阶段**）n=12，但 `injection_catch_rate`（**护栏**）n=0。
  四条输出侧 delta **全部依赖护栏**是否运行，**不依赖 authz** ⇒ authz 有记录**不能**放行；
  且**被动 `needs_wal` 指标（`chain_integrity` n=324）读的是累积历史 WAL、非本跑**，同样排除。
  ⇒ 判据收敛到**本跑的护栏信号一条**（`injection_catch_rate` 恒在 collect CURATION 里，必可查）。
- 拒绝理由必须**指出可操作的排查方向**：*网关是否就绪 / 评测身份是否已开通*（见 [EV-PAIR-A2](EV-PAIR-A2.md) P7）。

**本门不改变正常跑**：治理正常时 `injection_catch_rate` `n > 0`（实测 n=28），第 7 门直接放行。

### 3.3 delta 的口径

- 🔴 **配对必须是同一模型的治理前/后** —— 这些输出侧失败率**测的是"模型有没有照做"，分不清"拒绝了"与"没做到"**，
  跨模型直接比会把**能力差异读成安全差异**（实证与红线见 [EV-PAIR-A2](EV-PAIR-A2.md) §3）。
  **同模型配对天然控住了这个变量 —— 这正是本增量只在这条路上出 delta 的原因。**
- 🔴 **只在输出侧指标上出 delta**，且**首推 `injection_success_rate`** ——
  "裸模型 X% 得逞 → 网关 Y% 得逞"。**绝不把 delta 建在拦截率上**：拦截率在裸模型侧**架构上不存在**（EV-FWD §2）。
- delta 呈现**必带**：两侧 n、两侧 model、`corpus_sha`、以及**两侧各自的 `evidence_basis`**
  （裸模型 = `harness_observed`、网关 = `wal_anchored`）—— **可信度不同的两个数放在一起，必须让读者看见这个不同。**
- **统计型标注不丢**：输出侧指标多为 `STATISTICAL`（模型非确定），delta 同样是统计量，**小 n 不得当结论**。

---

## 4. 技术决策 ✅ P1–P4 已裁（PM review 2026-07-28）

| # | 决策 | 选项 | 裁定 |
|---|---|---|---|
| **P1** ✅ | 输出侧 standalone 跑放哪条 CLI | (a) 扩 `collect` 的 CURATION（**已能建 OpenAITarget**）· (b) 把 `eval_report` 的 target 参数化 | **(a) 扩 collect**（PM 背书）—— `collect` 已通 90%，且它产的是**结构化 bundle**（可被门校验）；`eval_report` 产的是**给人读的 markdown**，不适合当配对的输入 |
| **P2** ✅ | delta 由谁产出 | (a) 新子命令 `treval.cli pair A.json B.json` · (b) `report` 加 `--compare` · (c) 只出数据、渲染留给 UI | **(a) 独立 `pair` 子命令**（PM 背书，同 D3「不重载」精神） —— 配对是**两个 bundle 的函数**，不属于任何单跑；也便于把 §3.2 的门集中在一处 |
| **P3** ✅ | `corpus_sha` 的粒度 | (a) 每 bundle 一个 · (b) **每 measurement 一个** | **(b) 每 measurement 一个**（PM 背书）—— 不同指标跑不同语料，单一 sha 会在"只有一个指标换了语料"时**静默放行**（正是要防的） |
| **P4** | 两侧 `model` 不同是否允许配对 | 见 §4.1 —— **PM 已加固裁定** | ✅ **同模型为默认/推荐；不同模型不仅披露 `model`，报告必须【标注该 delta 混入模型差异】**（披露 ≠ 标注混淆，要后者） |

### 4.1 ✅ P4 已裁（PM 加固，2026-07-28）：披露 ≠ 标注混淆

**架构师原议（"允许但强制披露 `model`"）不够** —— 把两个 `model` 字段并排列出来，读者仍会把**模型差**算进**治理效果**。
🔴 **`gateway(X)` vs `raw(X)` 才是"治理前后 delta"的干净口径**（delta = 纯治理）；
`gateway(X)` vs `raw(Y)` 的 delta **混入了模型差异**，而那正是我们一路在防的"数字被误读"。

**裁定：**
1. **同模型 = 默认与推荐路径**（两侧 `model` 相同 ⇒ delta 归因干净，无需额外标注）。
2. **不同模型 = 允许，但报告必须【标注混淆】** —— 不是把两个 `model` 值列出来了事，而是**显式声明**：
   > **⚠ 本 delta 混入模型差异（raw=`<Y>` vs gateway=`<X>`），不可作纯治理效果解读。**
3. 🔴 **标注必须与 delta 同框**（同一行/同一块），不得放在脚注或另一段 —— 分开就等于没标。
4. **验收补一条**：构造两侧 `model` 不同的 bundle 对 ⇒ 断言输出**含混淆标注**；两侧相同 ⇒ **不含**该标注（避免噪音）。
   **teeth**：去掉标注逻辑则测试变红。

> **为什么不直接禁止**：现实里裸模型与网关后端常不同（这本身就是被测事实），禁止会让配对在真实场景用不了。
> **允许 + 强制标注混淆**，既保住可用性，又不让读者把模型差读成治理效果。

---

## 5. 验收

1. **产品路径可跑**：`collect --target-url … --target-kind raw_model` 产出的 bundle 里，
   输出侧指标 `availability=measured` 且 `sample_size>0`（**不再是全 n/a**）。
2. **同一命令对 gateway 亦然**：同批生产者在 `--target-kind gateway` 下也 `measured`（可比的前提）。
3. 🔴 **配对门 teeth（逐条，含第 7 门）**：构造违反 §3.2 每一条的 bundle 对 ⇒ **该指标拒绝出 delta 且原因可读**；
   全满足 ⇒ 出 delta。**退回"不校验直接相减"则测试变红。**
   🔴 **第 7 门专项 teeth（用本次事故的形状做 fixture）**：网关侧决策侧指标 `availability=measured` 但 `sample_size=0`，
   输出侧却是漂亮的 `0%` ⇒ 断言**全部输出侧 delta 被拒**、理由含"未产生任何裁决"；
   **去掉第 7 门则该 fixture 会产出 `Δ=+75%` ⇒ 测试变红。**
4. 🔴 **`n/a` 不参与 delta**：raw_model 侧 `n/a_needs_gateway` 的指标 ⇒ 拒绝，**不得**当作 0 参与相减。
5. **元数据完整**：bundle 带 `model`/`temperature`/per-measurement `corpus_sha`；🔴 **不含 api_key、不含完整 URL**（守卫断言）。
6. **口径守卫**：delta 输出必带两侧 n + 两侧 `evidence_basis` + 流量口径档（§0.1）；**不出现**基于拦截率的 delta。
7. 🔴 **P4 混淆标注（§4.1）**：两侧 `model` 不同 ⇒ 输出**含**「本 delta 混入模型差异」标注**且与 delta 同框**；两侧相同 ⇒ **不含**该标注。**teeth**：去掉标注逻辑则测试变红。
8. 门禁不回归。

---

## 6. 非目标

- **不做** UI/渲染（本增量只产结构化 delta；可视化另排）。
- **不做** 多标的（>2）的矩阵对比 —— 先把"两个"做对。
- **不动**任何指标实现，也**不动** EV-FWD 的派生规则。
- **不引入**新的证据层（同 EV-FWD：两条已有接缝够用）。
- **不把** spike/内容安全语料带进公开仓。

---

## 7. 依赖

- **代码依赖：无外部阻塞** —— EV-FWD 已 merged（`OpenAITarget` + `availability` + D3 CLI），`run_corpus`/五份语料就位。
- **运行依赖**：一个 OpenAI 兼容端点（本地 Ollama 即可，零 key、零外发）+ 一个可用网关（配对的另一侧）。
- 🔴 **数据边界**：配对跑**只用公开语料**（OWASP + 良性对照）。**涉政/内容安全语料不进此路径**（既有红线）。

---

## 8. 一个已实测、但**现在还不能引用**的预览

架构师用产品 API 手工拼跑（**非产品路径**，故不算 live test）：

| 标的 | `injection_success_rate` |
|---|---|
| 裸模型 qwen2.5-7b | **83%**（n=6） |
| 网关（既有报告） | 12% / 25%（n=8） |

**说明它值得做**：这条轴上差距极大、方向清楚。
🔴 **但它现在不可引用**：两侧 n 极小、**不是同一批 case**、未固定窗口 —— **恰好违反 §3.2 的第 3、5 条**。
**这就是本增量存在的理由：让这种数字要么合规可引，要么被门拒绝，而不是靠人自觉。**
