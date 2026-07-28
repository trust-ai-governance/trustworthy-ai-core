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
> **承：** [EV-FWD](EV-FWD.md)（`OpenAITarget` + `availability`，已 merged）· [EV-PIN](EV-PIN.md)（窗口冻结的同款纪律）。

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
| 4 | 两侧 `model` / `temperature` 已记录且**披露**（不要求相同 —— 裸模型与网关后端本就可能不同，但**必须显形**） | 缺失即拒绝 |
| 5 | 两侧 `sample_size` 均 > 0 且**披露** | 小 n 不拒绝，但 delta 必带 n |

🔴 **拒绝是默认行为**：宁可"这条不出 delta 并说明原因"，也不要一个不可复算的数。

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

## 4. 技术决策（要裁）

| # | 决策 | 选项 | 架构师建议 |
|---|---|---|---|
| **P1** | 输出侧 standalone 跑放哪条 CLI | (a) 扩 `collect` 的 CURATION（**已能建 OpenAITarget**）· (b) 把 `eval_report` 的 target 参数化 | **(a)** —— `collect` 已通 90%，且它产的是**结构化 bundle**（可被门校验）；`eval_report` 产的是**给人读的 markdown**，不适合当配对的输入 |
| **P2** | delta 由谁产出 | (a) 新子命令 `treval.cli pair A.json B.json` · (b) `report` 加 `--compare` · (c) 只出数据、渲染留给 UI | **(a)** 独立子命令 —— 配对是**两个 bundle 的函数**，不属于任何单跑；也便于把 §3.2 的门集中在一处 |
| **P3** | `corpus_sha` 的粒度 | (a) 每 bundle 一个 · (b) **每 measurement 一个** | **(b)** —— 不同指标跑不同语料，单一 sha 会在"只有一个指标换了语料"时**静默放行**（正是要防的） |
| **P4** | 两侧 `model` 不同是否允许配对 | (a) 禁止 · (b) **允许但强制披露** | **(b)** —— 现实里裸模型与网关后端常不同（这本身就是被测事实）；禁止会让配对在真实场景中用不了。**但必须显形**，否则读者会以为控制住了模型变量 |

---

## 5. 验收

1. **产品路径可跑**：`collect --target-url … --target-kind raw_model` 产出的 bundle 里，
   输出侧指标 `availability=measured` 且 `sample_size>0`（**不再是全 n/a**）。
2. **同一命令对 gateway 亦然**：同批生产者在 `--target-kind gateway` 下也 `measured`（可比的前提）。
3. 🔴 **配对门 teeth（逐条）**：构造违反 §3.2 每一条的 bundle 对 ⇒ **该指标拒绝出 delta 且原因可读**；
   全满足 ⇒ 出 delta。**退回"不校验直接相减"则测试变红。**
4. 🔴 **`n/a` 不参与 delta**：raw_model 侧 `n/a_needs_gateway` 的指标 ⇒ 拒绝，**不得**当作 0 参与相减。
5. **元数据完整**：bundle 带 `model`/`temperature`/per-measurement `corpus_sha`；🔴 **不含 api_key、不含完整 URL**（守卫断言）。
6. **口径守卫**：delta 输出必带两侧 n + 两侧 `evidence_basis`；**不出现**基于拦截率的 delta。
7. 门禁不回归。

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
