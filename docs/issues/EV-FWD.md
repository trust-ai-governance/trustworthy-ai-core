# EV-FWD — standalone 标的抽象（`OpenAITarget` + 指标能力声明 + `availability` 运行时）

> **Problem（普通话）：** 今天 Core 只能评测**网关**：`collect` 强制 `--gateway`，`eval_report` 只驱动 `GatewayTarget`。
> 想拿它评一个**裸模型**（任意 OpenAI 兼容端点、治理之前）做不到 —— 而"治理前 vs 治理后"的配对正是本项目最强的那张图，
> 也是开源推广的总开关（装上就能跑，不必先有网关）。
> R1 已把**报告级** `target_kind` + 派生 `evidence_basis` 落进 schema；**运行时那一半仍空**。
>
> **Value:** 落三件：① **`OpenAITarget`** —— 一个最小转发客户端，把 harness 指向任意 OpenAI 兼容端点；
> ② **指标能力声明 `evidence_requirement`** —— 每个指标声明它需要什么证据；
> ③ **指标级 `availability`** —— 由 (`target_kind` × `evidence_requirement`) 派生，让报告**逐指标**如实说"这条在本模式下不适用"。
> **一句话：让 Core 能独立评裸模型，并且诚实地说清哪些维度在裸模型上根本不存在。**
>
> **归属：** Implementer 编码 + 测试；架构师出本规格。**逐字实现已裁形状，不重新设计**（承 R1 同款纪律）。
> **承：** [R1-TARGET-KIND-SCHEMA](R1-TARGET-KIND-SCHEMA.md)（报告级两字段已 merged）· [GATE-LASTMILE](GATE-LASTMILE.md) P4（见 §2.1，它改变了本 issue 的风险面）。

---

## 0. 归属与边界

| 落 | 不落（本增量外） |
|---|---|
| `OpenAITarget`（实现既有 `Target` Protocol） | 生产被动读路径（第三个 reader + 租户隔离 + PII 面）—— 另一个 issue |
| 指标级 `evidence_requirement` 声明 | 新的证据抽象层 🔴 **明令不建 `EvidenceSource`**（§1） |
| 指标级 `availability` 派生 + 序列化 | rubric 判级逻辑（`availability` 是**序列化叠加**，判级不动） |
| `collect` 的 `--gateway` 改可选 | 配对报告的渲染/对比视图（后续 increment；本增量只保证两跑可比） |

🔴 **红线（四条护栏，缺一不可）：**
1. **转发器永远是最小测试客户端，绝不是治理路径** —— 不带规则、不带 PII 处理、不写审计 WAL。"Core 量、Platform 治"的边界不许糊。
2. **报告必须标注标的/模式** —— R1 的 `target_kind` 已落；本增量补**指标级** `availability`。
3. **公开仓只带公开语料**（OWASP LLM + 良性对照）。
4. 🔴 **"可验证审计 / WAL 锚定"话术仅属网关模式** —— standalone 报告不得借用其可信度。因无 WAL 而不可算的维度渲染成 **"N/A —— 需网关"** + 一行说明"这一维讲的是可验证审计，是受治理路径的属性"。**缺口是产品事实，不是残缺功能。**

---

## 0.1 🔴 贯穿原则：`availability` 与 `evidence_basis` 是两根**正交**的轴

本增量最容易犯、也最贵的错，是让一根轴去承担另一根的活。显式钉死：

| 轴 | 层级 | 回答的问题 | 取值 |
|---|---|---|---|
| **`availability`**（本增量新增） | 指标级 | **这个指标在本模式下能不能测?**（机制轴） | `measured` / `n/a_needs_gateway` / `n/a_self_reported` |
| **`evidence_basis`**（R1 已落） | 报告级 | **测出来的东西多可信、可否复算?**（证据轴） | `wal_anchored` / `harness_observed` / `self_reported` |

🔴 **一个"能测但不可审计"的指标 = `measured` + `evidence_basis=harness_observed/self_reported`，绝不是 `n/a`。**
把**测得出来**的东西标成 `n/a`，是 §2.1 那条错的**镜像**：`n/a` 的含义是"架构性缺席、跑一万次也不会有"，
而它明明这一次就测出来了。⇒ **可信度差异一律交给 `evidence_basis`，`availability` 只管有没有可读的东西。**

（此原则由 PM review 提出并采纳，2026-07-27；D1 的最终裁定即由它推出 —— 见 §4.2。）

---

## 1. 架构：挂在已有的主动侧接缝上（不新建层）

```
主动侧 = ProbeResult          ← 🔵 EV-FWD 挂这里
  harness 自抓 response/canary/decision/evidence
     ├── GatewayTarget   ：decision=BLOCK/ALLOW，evidence=WAL 记录
     └── OpenAITarget    ：decision=""，evidence=None   ← 本增量新增

被动侧 = AuditEvidenceReader  ← 生产被动读挂这里（不在本增量）
```

**已裁：不新造 `EvidenceSource` 抽象。** harness 自抓（请求/响应对）与 WAL 被动读（治理记录）是**两种形状的证据**，共不了一条缝。
`ProbeResult` 这条缝**已经存在且够用** —— `OpenAITarget` 只是它的第二个实现。⇒ **本增量真正的活是 `OpenAITarget` + 能力声明，缝本身不用改。**

---

## 2. 🔴 最要紧的一条：standalone 测的不是"拦截"，是"得逞/输出泄露"

**裸模型没有"拦不拦"这个决策** —— 它只返回一段补全。所以：

| 侧 | 指标 | standalone |
|---|---|---|
| **输出侧** | `injection_success_rate` · `sensitive_disclosure_rate` · `system_prompt_leak_rate` · `unsafe_output_passthrough_rate` | ✅ **逐字复用**（只读 `response_text`/`secret_canary`/`output_marker`，已代码核实**零次**引用 evidence） |
| **决策/WAL 侧** | `injection_catch_rate` · `wire_indirect_catch_rate` · `false_positive_rate` · `benign_flag_rate` · `tool_scope_violation_rate` · `cost_runaway_caught` · Tier-2 两条 · `output_neutralize_*` | ❌ **架构上不存在** ⇒ `n/a_needs_gateway` |

🔴 **配对报告的唯一 apples-to-apples 轴 = `injection_success_rate`（两侧都是输出侧）：**
裸模型 X% 攻击抵达输出 → 网关 Y% 抵达输出，**delta = 治理把"得逞率"压了多少**。
**把 delta 建在"拦截率"上是范畴错误**（拦截率在裸模型侧不存在）。

### 2.1 P4 已经改变了本 issue 的风险面（2026-07-27，须写清）

设计定稿时的担忧是："standalone 若仍跑 `injection_catch_rate`，每个 case 判 not caught ⇒ **结果 0%**"，即把"裸模型无治理"显示成"0% 拦截 = 治理崩了"。
**该致命误读现已被 GATE-LASTMILE P4 挡住**（实测：`evidence=None` 的 20 条探针 ⇒ `n=0` + `insufficient_data`，不再是 `0%`）。

⇒ **EV-FWD 的闸门因此从"正确性抢救"降级为"语义精确化"**，但**价值不减**：
- `insufficient_data` 说的是"**这次没测到**"（听起来像数据不够、跑一次多的就有了）；
- `n/a_needs_gateway` 说的是"**这条在本模式下不适用**"（架构性缺席，跑一万次也不会有）。

**两者必须区分**，否则读者会以为换个语料/多跑几次就能补上。**这是本增量的核心表达。**

---

## 3. 件一：`OpenAITarget`

实现既有 `Target` Protocol（`target_id: str` + `probe(case) -> ProbeResult`）。

- **发**：`POST {base_url}/chat/completions`，携带 `case.messages`（EV-AE11 wire 数组）或单轮 `case.input`；`temperature=0` 钉死（统计型指标要求）。
- **产**：`ProbeResult(decision="", evidence=None, response_text=..., raw_response=..., output_marker/secret_canary 透传, token 字段从 `usage` 解析)`。
- 🔴 **绝不做**：规则评估、PII 处理、写审计记录（护栏 1）。它是**测试客户端**，不是网关的简化版。
- **配置**：`base_url` / `model` / `api_key`（env）/ `timeout`。**`api_key` 绝不进报告、不进日志。**
- 复用 `GatewayTarget` 已有的 wire 构造与 usage 解析逻辑（提取共用助手，**不复制**）。

---

## 4. 件二：指标能力声明 `evidence_requirement`

每个指标声明它需要什么证据：`output_only | needs_decision | needs_wal`。

### 4.1 🔴 分类必须按"运行时实际读什么"，不能扫类体文本

对着代码核实（2026-07-27），有**三处陷阱**，逐条写死：

| 指标 | 陷阱 | 正确分类 |
|---|---|---|
| **`wire_indirect_catch_rate`** | 🔴 **类体是空的** —— 它 `继承 InjectionCatchRate` 并**继承 measure()**。任何"grep 类体是否出现 `pr.evidence`"的分类法都会把它误判成 `output_only`（架构师第一版正则就漏了它） | **`needs_decision`** |
| **`output_neutralize_inert_rate` / `_fidelity_rate`** | 它们读 `pr.response_evidence.record.audit.hint_variables`（**type-2 WAL 记录**的 A2 标记）。设计定稿时 EV-AE13 尚未存在，**原清单里没有它们** | **`needs_wal`** |
| **`within_cost_budget`** | **WAL 优先 + HTTP 回退**：`_content_tokens` 先读 `response_evidence...completion_tokens`，缺失时回退 `pr.completion_tokens`（HTTP 解析）⇒ **standalone 下仍可测（降级）** | **`output_only`**（§4.2 已裁） |

**验收要求**：分类**逐指标由实现者读代码确定**并写进声明；🔴 **加一条机械守卫**：断言"声明为 `output_only` 的指标，在 `evidence=None` 的探针集上 `sample_size > 0`"——
即**声明与实际行为一致**，防止分类漂移（同"靠门不靠人眼"纪律）。

### 4.2 ✅ D1 已裁：`within_cost_budget` = `output_only`

**裁定（PM review 2026-07-27，架构师原倾向被推翻）：归 `output_only`。**

**实证（两次无 WAL live 跑，真数据）：**
```
within_cost_budget = 40%  (n=10)     ← 无 WAL 跑 ①
within_cost_budget = 60%  (n=10)     ← 无 WAL 跑 ②
```
**没有 WAL 它照样测出真数**（HTTP 回退生效）⇒ 按 §0.1 原则，它就是 `measured`。

🔴 **架构师原倾向（归 `needs_wal`、但仍计算、用 notes 标降级）是错的，原因有二：**
1. **自相矛盾**：派生表里 `needs_wal × raw_model = n/a`，可指标又确实产出一个数 ⇒ 报告里出现"**一个数、却标着 n/a**"。
2. **破坏单一真值源**：§5 要求 `availability` **纯派生、永不独立设置**；"标 n/a 但仍算"等于在派生之外开后门。

**WAL 与 HTTP 的差别是"可审计性"，不是"能不能测"** —— 而可审计性已由报告级 `evidence_basis=harness_observed` 如实承担。
**附带收益**：`needs_wal` 因此收紧为"**WAL 独有、HTTP 无等价物**"（`output_neutralize_*` 读 type-2 的 `hint_variables` 才是真 `needs_wal`），语义更准。

---

## 5. 件三：`availability` 派生 + 序列化

**派生规则**（`target_kind` × `evidence_requirement`），与 R1 的 `evidence_basis` 同为"序列化叠加、单一真值源"：

| `evidence_requirement` \ `target_kind` | `gateway` | `raw_model` | `moderation_api` |
|---|---|---|---|
| `output_only` | `measured` | `measured` | `measured` |
| `needs_decision` | `measured` | `n/a_needs_gateway` | **`n/a_self_reported`**（§5.1） |
| `needs_wal` | `measured` | `n/a_needs_gateway` | **`n/a_self_reported`** |

> 📌 **一个便于实现的代码事实（已核实）：当前 `needs_decision` 与 `needs_wal` 都要 WAL** ——
> 判据 `_caught_at_decision(ev: AuditEvidence | None)` 收的是 **WAL 记录**；全仓 `grep 'pr.decision'` 在指标层**零命中**。
> 二者的差别只在**记录类型**（type-1 决策 vs type-2/3 响应·治理），这个区分仍有意义，
> 但**在 `raw_model` / `moderation_api` 两列下二者结果相同** ⇒ 派生表因此规整。

- 🔴 **必须补第二个 n/a 值 `n/a_self_reported`**（设计文档 F 项，已记待补）：`moderation_api` 也没有 WAL，
  但 `n/a_needs_gateway` 对它**词不达意** —— 它不是"缺网关"，是"厂商自报、本就不可复算"。
- **单一真值源** = (`target_kind`, `evidence_requirement`)；`availability` **永不独立设置**，序列化时计算写入；
  **校验器断言派生成立，不一致即 FAIL**（与 R1 的 `assert_evidence_basis_derived` 同款机械门）。
- **rubric 判级逻辑不动** —— `availability` 是报告序列化的叠加。
- **schema 影响**：`docs/REPORT_JSON_SCHEMA.md`（真源）+ `docs/report.schema.json` 同批改 + **升 `SCHEMA_VERSION`** + 同步 golden fixtures + 对账单，**schema 单独一次提交**（§8.7 纪律，R1 已照此办）。

### 5.1 ✅ D2 已裁：现有指标 `n/a_self_reported`；厂商 catch 由 **C2 新指标**承担

**争点**：moderation API 确实返回一个判定（厂商标签）。按 §0.1 原则，"能测但不可复算"应是 `measured` + `self_reported`，
而不是 `n/a` —— **PM 的原则正确**。但落到**现有指标**上，代码给出一个决定性事实：

```
_caught_at_decision(ev: AuditEvidence | None)   ← 收的是 WAL 记录,不是 pr.decision
grep 'pr.decision'  (indicators.py)             → 零命中
```
⇒ **现有所有 `needs_decision` 指标读的都是 WAL 记录**，没有任何一个能从非 WAL 源取决策。
moderation_api **没有 WAL** ⇒ 把 `injection_catch_rate` 套上去**不是"测得出"**，而是**全部 fail-closed 记成未捕获 ⇒ 假 0%**。

🔴 **这正是本仓已裁过的坑**（P3C-HARNESS §C2-2 原文）：
> **新 `success_when` 判据**，读厂商自报标签（`pr.decision`），**不读 WAL** ——
> 现有判据套上去会**全部 fail-closed 记成"未捕获"，静默产出假的 0%**。

**⇒ 裁定 = 两条路分别归类，PM 的实务担忧（C2 必须可比）照样满足：**

| 指标 | `moderation_api` 下 | 理由 |
|---|---|---|
| **现有** `injection_catch_rate` 等（读 WAL） | **`n/a_self_reported`** | 它测的是"网关的 WAL 决策"，厂商侧**架构性缺席**（不是"能测但不可审计"，是**真的没有可读的东西**） |
| **C2 新建**的厂商 catch 指标（读 `vendor_labels`/`pr.decision`，§C2-2 已裁须新建） | **`measured` + `evidence_basis=self_reported`** | ⇒ **"厂商 catch X%（自报） vs 网关 catch Y%（WAL 审计）"这个比较成立，C2 不白做** |

**`needs_wal` × `moderation_api` = `n/a_self_reported`** 按原议保留 —— 且 `n/a_self_reported` 比 `n/a_needs_gateway` 更准：
它不是"缺网关"，是"厂商自报、本无此维"。

> **归属纪律**：C2 新指标的能力声明**随 C2 落地**（仍 gated 数据条款），**不在本增量**；本增量只把**枚举与派生规则**备好，
> 使 C2 到来时**改注入、不改指标**（同 `score_of` 提取器的做法）。

---

## 6. 件四：`collect` 的 CLI 形状（D3 已裁）

现状：`collect.py:181` 在缺 `--gateway` 时直接 `error: --gateway ... is required`。

**裁定（D3，架构师提议 + PM 三条加固，全部采纳）：新增 `--target-url` + 显式 `--target-kind`，不重载 `--gateway` 语义。**
重载 `--gateway` 会让**裸模型 URL 被误标成受治理网关** = 击穿 R1 诚实标注的初衷。

1. 🔴 **`--target-kind` 是封闭枚举**（`gateway|raw_model|moderation_api`）、**校验**，不收自由文本。
2. **`--gateway` 保留为 `gateway` 的语法糖** —— 内部归一成 `--target-url=<gw>` + `kind=gateway`，**单一代码路径**；与新参数**互斥**。
3. 🔴 **绝不推断 `target_kind`** —— 缺失即报错，**不 default**（URL 猜不出治理与否）。

`target_kind` 随之确定并写进 bundle（R1 已有字段）。**不改**任何指标计算。

---

## 7. 验收

1. **`OpenAITarget` 契约**：对一个 fake OpenAI 端点跑通，产出 `decision="" / evidence=None` 的 `ProbeResult`；token 从 `usage` 解析；`api_key` 不出现在任何输出/日志里。
2. 🔴 **护栏 1 守卫**：断言 `OpenAITarget` **不**引用规则/PII/WAL 写入路径（import 面或行为面的机械断言）。
3. **输出侧 4 指标逐字复用**：同一批 `ProbeResult`（evidence=None）跑出与网关模式**相同的实现**、非零 `sample_size`。
4. 🔴 **声明↔行为一致守卫**（§4.1）：所有声明 `output_only` 的指标在 `evidence=None` 下 `sample_size > 0`；
   所有 `needs_decision`/`needs_wal` 的在 `raw_model` 下 `availability != measured`。
5. **派生门**：`availability` 与 (`target_kind`×`evidence_requirement`) 的派生一致，不一致即 FAIL；
   `moderation_api` × `needs_wal` ⇒ `n/a_self_reported`（非 `n/a_needs_gateway`）。
6. 🔴 **N/A ≠ insufficient_data 守卫**（承 §2.1）：raw_model 下 `injection_catch_rate` 渲染为 **`n/a_needs_gateway`**，
   **不得**渲染成 `insufficient_data`（那会让人以为多跑几次就有）。**teeth：退回 P4-only 行为则测试变红。**
7. 🔴 **话术红线守卫**（护栏 4）：raw_model 报告中**不出现**"可验证审计 / WAL 锚定"式断言（同 R1 §7-3 的字段级守卫思路）。
8. **schema**：两处 schema 同批改 + 升版 + golden 同步；**单独提交**。
9. 门禁不回归（ruff/format/mypy/bandit/pytest/泄露门）。

---

## 8. 非目标

- 不做生产被动读（第三个 reader、租户隔离、PII 面）。
- 不做配对报告的渲染/对比视图（本增量只保证两跑**可比**：同语料 sha、同窗口、同 seed、同模型版本 —— 配对诚实性靠这条纪律，不靠新代码）。
- 不动 rubric 判级逻辑、不动指标计算、不动 WAL 读侧。
- 不把 spike/内容安全语料带进公开仓。

---

## 9. 裁定汇总（D1–D3 已闭合，2026-07-27 · PM review + 代码核对）

| # | 决策 | 裁定 |
|---|---|---|
| **D1** | `within_cost_budget` 归类（§4.2） | ✅ **`output_only`** —— 架构师原倾向（`needs_wal` + notes 降级）**被推翻**：无 WAL 实测仍出真数（40%/60%，n=10），且"标 n/a 但仍算"自相矛盾并破坏纯派生。可审计性交 `evidence_basis`。 |
| **D2** | `moderation_api` × `needs_decision`（§5.1） | ✅ **两条路分开**：**现有**（读 WAL 的）指标 = `n/a_self_reported`；**C2 新建**的厂商 catch 指标 = `measured` + `self_reported`。PM 的**原则对、映射错**，由代码纠正（判据收 WAL 记录、指标层零 `pr.decision`）；PM 已核并确认。 |
| **D3** | CLI 形状（§6） | ✅ **`--target-url` + 显式封闭枚举 `--target-kind`**；`--gateway` 降为语法糖、单一代码路径、互斥；**绝不推断 kind**。 |

**⇒ 三条已闭合，本规格可下发 Implementer。**

🔴 **执行提醒（PM 提出，采纳）：D1/D2 的结论改动了 §5 派生表 ⇒ schema 那次提交按本最终裁定落**
（`within_cost_budget` 走 `output_only`、moderation_api 两格均 `n/a_self_reported`），**不要按被推翻的中间方案落了再改**。
