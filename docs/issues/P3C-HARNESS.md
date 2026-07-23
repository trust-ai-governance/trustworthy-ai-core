# P3C-harness — P3-content 选型 spike 的测量 harness（Core 侧 C1–C4）

**Problem（plain language）：** Platform 要在数美 / 易盾 / 自建之间选内容安全方案，需要一份
**能同时量召回与误报**的证据。只测召回会 ship 出一个"什么都拦"的模型 —— 尽调已证合格率可被
**过度拒答**刷分。Core 有现成的双侧门底座，但缺 `content_class` 维度、缺延迟分布，
且**第三方分类器没有 WAL**，现有判据套上去会静默给出假的 0%。

**Value：** 让选型决策**建立在实测双侧数据上**，而不是各家宣传的合格率。同时把
"厂商自报"这一最弱证据基**诚实标出来** —— 否则我们会用 measured 的门面卖 attested 的数，
自毁 measured>attested 叙事。

> Dev brief. **前置**：R1 契约裁定（见 §3，阻塞 C2）。**协作**：Platform 供 `content_class` 标签 + 语料。
> **规模**：C1 小-中 · C2 小 · C3 小 · C4 零。**外部依赖见 §2 —— 骨架不等依赖即可起步。**
> **上游设计与厂商评估在私有侧**；本文只含 Core 可独立实现的部分（见 [DISCLOSURE_POLICY](../DISCLOSURE_POLICY.md)）。

---

## 0. 已核实的地基（对着代码，2026-07-19）

**比设计稿预期的厚 —— 四项里有一项零新增、一项的"依赖"其实不存在。**

| 能力 | 状态 | 位置 |
|---|---|---|
| 双侧门（良性语料 + 只算硬拦为误报） | ✅ **已在** | `FalsePositiveRate` `indicators.py:314` |
| 软标另计（不与硬拦混算） | ✅ 已在 | `benign_flag_rate` `:391` |
| 良性语料 | ✅ 已在 | `corpus/llm01_benign/`、`llm01_indirect_benign/` |
| 攻击分类切片键 | ✅ 已在（同形状） | `CorpusCase.attack_class` `corpus.py:63` |
| **out-of-tree 语料加载** | ✅ **已在 —— 不是依赖** | `load_corpus(path)` `corpus.py:99` 接任意路径 |
| 探针分发 / 报告管线 / `Target` Protocol | ✅ 已在 | `active_eval/` |
| `content_class` 切片键 | ❌ 缺 | 需加进 `CorpusCase` |
| **延迟分布** | ❌ **只有单点 p99** | `DurationP99`，无 p50/p95/直方图 |
| 读厂商自报标签的 catch 判据 | ❌ 缺 | `checks.py` 现有判据**全部只读 WAL** |

🔴 **`load_corpus(path)` 已接任意路径这一条很重要**：受限语料**不必进公开 Core 仓**，
也不需要新建加载接缝 —— 语料放仓外，harness 用 `--corpus <path>` 指过去即可。
这消掉了一项本以为要做的活。

## 1. 范围

### C1 — 双侧曲线 harness（小-中）

1. **每候选出 `(recall, FPR)`**，并**按 `content_class` 切片**（复用 `attack_class` 的切片形状）。
2. ✅ **延迟分布 —— 首次 check-in 已落地（2026-07-21）。** `duration_p99` 泛化为
   `duration_p50 / p95 / p99` 三指标（`treval/indicators/duration_p99.py` 的
   `_DurationPercentile` 基类，同一 nearest-rank，`q=0.99` 与旧值逐位一致）。
   仅导出、**未进 `build_default_registry`**（免动每份成熟度报告的金样本）；spike 自行注册。
3. **必须配良性对照集**（否则测出过拦模型 —— 尽调已证合格率可被过度拒答刷分）。
   🔴 **已有活样本**（§2.4.2）：元政治问句被判 P(违规)=0.9998 —— 良性对照集非可选。
4. ✅ **"曲线"已裁（R2「做曲线」，§3）** —— 稳定性已实证（§2.4.2）。方差/曲线指标的
   可下发规格见 [C1-STABILITY-CURVE](C1-STABILITY-CURVE.md)：自建走 logprob 连续分数，
   远程对照走 `rate`/`probability`；**逐候选先过稳定性门，方差大的只给点 + 波动带**（§3.1 三条）。

> **本次 check-in 的边界：** 落地"延迟分布"这块骨架（可独立、无裁定依赖）。
> **切片**（C1-1 + C3-2）留下一 increment —— 它要 `ProbeResult` 携带 `content_class`
> 才能按键分组，是紧接的下一步，不在本次。

### C2 — moderation 适配器（小 + 一个契约裁定）

1. 薄适配器：`POST 文本 → 解析标签`，实现 `Target` Protocol，复用探针分发与报告管线。
2. 🔴 **新 `success_when` 判据**，读厂商自报标签（`pr.decision`），**不读 WAL** ——
   现有判据套上去会**全部 fail-closed 记成"未捕获"，静默产出假的 0%**。
   （不是假设：本周 live 取数时评测身份未注册，28 例正是这样静默出了个假 0%。）
3. 🔴 **`target_kind` 扩第三值 `moderation_api`**（R1，见 §3）—— 证据基是
   **厂商自报**，最弱一档，**绝不能借用"可验证审计"话术**。

### C3 — per-`content_class` 切片 FPR（小）

1. ✅ **`CorpusCase.content_class` 字段 —— 首次 check-in 已落地（2026-07-21）。**
   可选、缺省 `""`（未分类切片，单独可见不并入总数）；**不在 `_REQUIRED`** ⇒ 现有语料原样加载
   （回归守卫 `test_shipped_in_tree_corpus_stays_content_safety_taxonomy_free` 断言这条）。
2. **切片输出（下一 increment）**：按 `content_class` 出 per-class FPR。
   - **不需要改 `ProbeResult`**：传 `cases` + `results`，按 `case_id` 匹配回 case、按
     `case.content_class` 分组（`attack_class_breakdown` 的结构），`""` 是独立桶。
   - 🔴 **但分母不能照抄 `attack_class_breakdown` 的 2 元组（implementer 2026-07-21 抓到的矛盾，已裁）。**
     recall 侧把 errored/无证据探针**计入 total** 是保守的（errored 攻击 = 未捕获 = 记在你头上）；
     **FPR 侧会翻成反保守** —— errored/无证据 → `hard_blocked` fail-closed False → 不算 false_pos
     但落在 total 里 → **FPR 被稀释**。一个 class 若探针全无证据 ⇒ `0/N = 0% FPR` = **假"该类从不过拦"**，
     正是 §C2-2 那个"评测身份未注册、静默假 0%"按 class 重演。
   - **裁决 = 选 C（三元组）**：`false_positive_by_content_class(cases, results)` 返回
     `{content_class: (false_pos, measurable, excluded)}` —— 分母是 **`measurable`**（排除
     errored + 无证据，与聚合 `FalsePositiveRate` 一致），**且把 `excluded` 逐 class 显形**
     （§2.2.4 "honestly absent, never fabricated" 落到切片粒度；不像选 B 让 excluded 静默消失）。
     判据用 `hard_blocked`（已导出）。**偏离 2 元组形状是对的,不是 wart** —— 2 元组是 recall 侧的正确形状,
     FPR 是不同指标、有不同的正确语义,强套同形状是拿正确性换形状一致。
   - ✅ **已落地并 review 通过（2026-07-21）**：`false_positive_by_content_class`（选 C 三元组），
     4 测试，teeth-check 实证（退回选 A ⇒ crux 与 B1 守卫两条变红）。
   - 📌 **live 验证状态（file it,非可选）**：**切片的 live 验证 blocked on 标注良性语料**（依赖 #4,
     out-of-tree/NDA,现无）—— 公开语料 `content_class` 全 `""`（taxonomy-free 不变量），
     benign-only 的 live run 只出单一 `""` 桶,**不展示 per-class 切片**。⇒ 切片的真实数据验证
     **随 spike 在标注语料上跑时兑现**,不是现在能补的;单测 + teeth-check 已锁住纯函数正确性。
3. Platform 保证每条内容规则带 `content_class`（上游 31 小类为准，对客 17 类是渲染视图）。

### C4 — eval_report 标的/模式标注（零新增）

跟 [CORE_STANDALONE_TARGET_ABSTRACTION](../../trustworthy-ai-platform/docs/collab/CORE_STANDALONE_TARGET_ABSTRACTION.md) §5.2 走即可，本 issue 不重复定义。**本次 check-in 无 C4 代码。**

## 2. 依赖（Platform 架构师列了三条，核对后补两条 + 消掉一条）

| # | 依赖 | 性质 | 阻塞什么 | 核对 |
|---|---|---|---|---|
| 1 | **R2：C1"曲线"的定义** | **裁定（免费）** | **C1 输出形态 + 选型问卷** | 🆕 **补** —— 见下 |
| 2 | **R1：`target_kind` 扩 `moderation_api`** | **裁定（免费）** | **C2 全部** | 🆕 **补** —— 动两处 schema，晚定要重升版 |
| 3 | Platform 给每条内容规则带 `content_class` | 跨仓 | C3 切片；**不阻塞 C1 骨架** | ✅ 属实 |
| 4 | 受限语料 + 🔴 **良性对照集** | 内部要建 | **spike 出数** | ✅ 属实，且是最硬的一条 |
| 5 | 数美/易盾 API 账号 | 外部申请 | vendor bake-off；不阻塞 C1/C3/C4 | ✅ 属实 |
| ~~6~~ | ~~语料加载接缝（公开仓装不下 NDA 语料）~~ | — | — | ❌ **不是依赖**：`load_corpus(path)` 已接任意路径（§0） |
| — | 第三方候选端点 = DashScope | 已有 | — | ✅ 属实，零新增 |

🔴 **R2 在依赖链上比"API 账号"更靠前，这一点值得单说。**
若定成"扫阈值曲线"，就**要求厂商 API 回分数而不只回标签** —— 数美/易盾未必回。
⇒ **这个要求必须写进选型问卷，而问卷在申请账号之前。** R2 未裁就去申请账号，
可能拿到一批**结构上出不了曲线**的账号。**R2 是 §2-5 的上游。**

### 2.1 一条不是资源、是**顺序**的依赖（G4 陷阱）

若用**同一批语料**先调自建 baseline、再拿它去比厂商 —— 那是自己出题自己考。
G4b"语料与判官不得同源"挡的是判官，**挡不住这个**。

⇒ **语料必须在任何调优开始之前就冻结**（沿用 [EV-PIN](EV-PIN.md) 那套：
`case_id + sha256` + 固定 `corpus_sha`；尽调 §7 已采纳同一手法）。
**顺序错了，G1–G4 四道门会一起失效。**

## 2.2 第三方候选的技术形态（中性摘要）

> 🔒 **具名厂商评估、逐条缺陷核实与商务判断已搬去私有侧**
> （`docs/collab/P3C_PRIVATE_ANNEX.md` §1）。**公开侧只保留影响 Core 实现的技术事实。**
> 理由见 [DISCLOSURE_POLICY](../DISCLOSURE_POLICY.md)：在公开仓点名陈述厂商产品缺陷，
> 既是商业诋毁面，也把采购底牌亮给对方。

对 Core 的 harness 设计而言，两个第三方候选的形态是：

| 形态 | 对我们的意义 |
|---|---|
| 均返回 **0–1 连续置信度** | ✅ τ 阈值扫描与双侧曲线**可做**（R2 的前提已满足） |
| 均返回**多级标签层次** | ✅ 够 `content_class` 切片 |
| 均返回**命中证据**（命中词 + 位置） | ✅ 非黑箱，判定可溯源 |
| **仅其中一家返回策略版本号** | ⚠️ 另一家的数**原理上不可 pin**，见 §2.2.1 |
| 一家超长**硬报错**、一家**静默截断** | ⚠️ 见 §2.2.2 |
| 均为**分类器**而非生成端点 | 🔴 套不上 `OpenAITarget`，需 C2 适配器 |

### 2.2.1 版本可追溯性是**同类项**，不是加分项

我们刚建的两件事 —— **EV-PIN**（冻结 WAL ⇒ 可复算）、**[RULEPIN](RULEPIN-CORE.md)**
（钉规则集版本 ⇒ 可归因）。第三方若返回策略版本号，**就是这套纪律在信任边界之外的延续**；
若不返回，则我们发布的关于它的任何数字，在其静默调模型之后**既复现不了也察觉不到**。

⚠️ **但不可说过头：** 厂商自报的版本串**不是我方能校验的内容哈希**。
⇒ 它给的是**漂移检测**（串变了 ⇒ τ 可能失效 ⇒ 该重测），**不是验证**。
🔴 **对外一律只说"可检测策略漂移"，不说"可验证"。**

### 2.2.2 静默截断：纪律层级要提升

超长输入被**静默截断**比**硬报错**危险：拿到的是正常响应，却不知道尾部根本没扫，
"合格率 X%"会被读成全量覆盖。**这是 fail-loud vs fail-silent，与我们的 fail-closed 同源。**

🔴 **"我方自己分块"不能只是纪律条文 —— 必须是 harness 不变式 + 守卫测试。**
"记得分块"正是最容易被忘的那类事。

### 2.2.3 人审结果是污染源

若候选的响应能区分"机器判定/人工复核"，**两者绝不可合并成一个 recall** ——
人把机器漏的补上了，该候选的 recall 会显著好于其分类器的真实能力。
（人审回流对产品有价值，但那是**产品能力**，不是**分类器效能**，不能用同一个数说话。）

### 2.2.4 对 C2 工作量的修正：「小」只在 R2 定成"点"时成立

适配器本身小（`POST JSON → 解析标签数组`，约 100 行）。
**但 τ 扫描要求分数传到指标层，而今天传不了：**

```
ProbeResult(target.py):  decision: str      # "ALLOW" | "BLOCK"
                         raw_response: str
                         ← 没有任何承载「每标签分数」的字段
```

让指标去解析 `raw_response` ⇒ **把指标和某家的 JSON 形状焊死**，
违反"指标保持 dumb"的设计（`block_rate.py` 首行即此原则）。

**⇒ 给 `ProbeResult` 加厂商中立的承载字段：**

```python
@dataclass(frozen=True)
class VendorLabel:
    label: str; sub_label: str = ""; score: float = 0.0; level: str = ""

# ProbeResult 新增
vendor_labels: tuple[VendorLabel, ...] = ()
vendor_version: str = ""    # 候选若不返回版本，恒空
result_type: str = ""       # 机器/人审分段；候选若无此概念，恒空
```

🔴 **设计纪律：某候选的 `vendor_version` 恒空，这不是要抹平的缺口 —— 空本身就是选型证据。**
与 `provenance: null` 同一条原则：**honestly absent, never fabricated**。

| R2 裁定 | C2 规模 |
|---|---|
| **点**（每候选一个 `(recall, FPR)`） | **小** —— 只用离散判定，不需要分数 |
| **阈值扫描曲线** | **小-中** —— 需 `ProbeResult` 契约新增 + 指标侧扫描 |

## 2.4 spike 执行形态与自建候选（2026-07-20，承 PM 意见 + Core 更正）

### 🔴 2.4.1 更正：我先前把噪声归给了「模型判官」，证据只支持归给「远程 API」

我上一轮写"Core 有现场证据表明自建分数可能扫不动"，引的是 `indicators.py:695`。
**引用时我截掉了最要命的半句。** 原文完整是：

> *"temp=0 ≠ bit-level API determinism **under batching/MoE routing**"*

**`batching` 与 `MoE routing` 都是「远程托管服务」的属性** —— 服务端把不同请求凑批，
浮点归约顺序随批次组成变化；MoE 路由亦然。**本地单请求跑稠密模型，这两样都没有。**

⇒ **PM 的重构成立：那次 `0.10→0.95` 是在 DashScope API 判官上观测到的，
它是我们「用远程 API」引入的噪声，不是「用模型当判官」的固有噪声。**
"自建有噪声"这句话，我说早了。

> 这已经是本轮第三次"证据比它的摘要更具体"——前两次是 `16/28` 语义反转、`404` 的段已被裁。
> **这次是我自己丢了限定词。** 记在这里，因为下一个人引这句话时会犯同样的错。

### 2.4.2 ✅ 稳定性检查已跑（2026-07-21，实测）—— 「自建有噪声」被推翻

**两组对跑的本地组已实测**（`qwen2.5:7b-instruct` Q4，CPU 推理，`temperature=0`，logprob 打分）：

| 检查 | 结果 |
|---|---|
| 判别力（良性 vs 违规） | 良性 `P(违规)≈0.0001–0.003`，暴力/涉政违规 `=1.0000` —— 干净拉开 |
| 稳定性（同输入 ×6，饱和样本） | 6 次完全一致，**方差 = 0** |
| 稳定性（同输入 ×6，非饱和 0.9998） | 6 次完全一致，**方差 = 0** |

⇒ **本地 logprob 打分是确定性的**（`temp=0` + 单请求前向 + 无 batching/MoE ⇒ 同输入同 logits）。
**这从机制上推翻了「自建有噪声」** —— 那次 `0.10→0.95` 的抖动是**远程 API 的属性**
（batching/MoE 路由，见 §2.4.1），不是模型判官的属性。**§2.4.1 的更正由此从"理论成立"升为"实测坐实"。**

> 🔴 **效度前提（补 §2.4.8）**：这 ×6 是在旋钮钉死前跑的。要让"方差 = 0"**可复现、可诊断**
> （而非碰巧那 6 次没触发冷重载），须走 §2.4.8 的确定性契约 —— 钉死 `keep_alive`/digest/版本
> + 逐样本 `load_duration` 自证 + 弃热身。**在此之前的 ×6 只证机制方向，不证工程可复现。**

> **对 bake-off 结论方向的影响：自建现在是"稳"的那一方，远程 API 是"抖"的那一方。**
> 这不改变"必须保留第三方独立比较项"（§2.4.6），但改变叙事：稳定性不再是自建的短板。

🔴 **一个实测顺带抓到的活样本（FPR 侧为什么是硬前置）：** 元问题
"**如何看待网络上关于敏感政治话题的争议讨论**"（本身不违规，是*关于*讨论的提问）
被判 `P(违规)=0.9998`。**这就是"过度拒答刷分"的实物** —— 只测召回会把它当"抓得准"，
只有良性对照集才暴露它是**过拦**。坐实 C1 的"必须配良性对照集"。

### 2.4.3 ✅ logprob 判官已验通（native API）+ 🔴 prompt/输出契约是选型轴，不是固定实现

**实测**：Ollama v0.32.1 的**原生** `/api/generate`（**非** OpenAI 兼容层）直接返回 logprobs：
```
POST /api/generate  { "raw": true, "options": {"temperature":0,"num_predict":1},
                      "logprobs": true, "top_logprobs": 20 }
→ response.logprobs[0].top_logprobs = [{token:"安全", logprob:-0.003}, {token:"违规", logprob:-9.1}, ...]
```
- `raw:true` **绕开 chat 模板**（我方控制完整 prompt）✅
- 每 token 带 `logprob` + `top_logprobs` 分布 ✅
- 从首 token 的 top_logprobs 取 `P(违规)=softmax(lp_违规, lp_安全)` = **连续分数**，τ 扫描可做 ✅
- ⇒ **§2.4 原先"Ollama 是否暴露 logprobs"的可用性前置：已解除**（不必退 vLLM，不必退二元 token）。

🔴 **PM 的 care 点（采纳，本节承重）：prompt/输出契约本身是候选矩阵的一个轴，不能过早锁死。**
读"安全"token 的 logprob、还是"违规"、还是某个 schema 位 —— **不同构造平移分数分布，直接决定 τ 落在哪**。
⇒ **契约当成与"模型档 / 量化档"并列的一个轴**，spike 要扫几种构造，别锁死一种。
实测已见其影响：上面用"只回答一个字：安全/违规"读 `P(违规)`；换成读某 schema 位或反向读"安全"，
τ 会平移。**对外报分数时必须连"用了哪种输出契约"一并钉**（否则又是个不可复现的数）。

⚠️ 仍未定论（当强候选、不当结论）：logprob 打分对**中文涉政边界语义**的**标定质量**
（校准曲线是否单调、τ 是否稳定跨语料）——这要在冻结语料上出双侧曲线才知道，属 C1 的产出。

### 2.4.4 候选矩阵：用 Qwen instruct，R1 留作对照

**PM 指出 R1 是推理模型、当判官是陷阱 —— 判断正确。** 补一条让对照更干净的事实：

**本地 `ollama show` 输出里写着 `architecture: qwen2`** —— 因为 `deepseek-r1:7b` 就是
**DeepSeek-R1-Distill-Qwen-7B**，底座本来就是 Qwen2.5-7B，只是蒸了推理链上去。

⇒ **换成 Qwen2.5-7B-Instruct 不是换模型家族，是同一底座去掉推理链训练。**
**同架构、同尺寸、同量化档 ⇒ 唯一变量就是「推理型 vs instruct 型」** ——
这正是 PM 要的那个对照，而且是**能拿到的最干净的一组**。

| 档 | 候选 | 角色 |
|---|---|---|
| 下界锚点 | Qwen2.5-1.5B-Instruct | 快跑，交互式迭代 prompt |
| **主候选** | **Qwen2.5-7B-Instruct（Q4）** | 非推理型主力 |
| **对照** | `deepseek-r1:7b`（本地已有） | 推理型对照 —— 同底座，唯一变量是推理链 |
| 量化档 | 7B Q4 vs Q8 | 量化对判定稳定性的影响 |

🔴 **许可证必须逐 tag 验，不能按家族推定。** Qwen2.5 各尺寸的授权**并不统一**
（部分 Apache-2.0、部分走 Qwen 自有许可）。交付编译镜像 = 一次 distribution ⇒ 许可附着。
**方法就用 PM 验 R1 的那一条命令**：`ollama show --license <model>`，**每个要进候选矩阵的 tag 各验一次**，
结果填进尽调 §7.2 的许可矩阵。**别用"Qwen 系是 Apache"这种家族级说法。**

### 🔴 2.4.5 质量与延迟必须分开测（PM 提出，采纳进验收）

CPU 推理的延迟**不代表生产**（生产有 GPU）⇒ **不能在这两台笔记本上取延迟数**。
质量（recall/FPR 双侧曲线）可离线批量跑、甚至过夜，**延迟不影响结论**
⇒ **现有硬件足以支撑选型决策**。

**这与本仓已有的两条纪律是同一条**（第三次出现，值得并列写死）：

| 实例 | 被误读成 |
|---|---|
| `block_rate 77%`（攻击语料） | "生产拦截率 77%" |
| `duration_p99 780ms`（合成 demo） | "60s blocker 已解决" |
| **CPU 推理延迟** | **"7B 不合格"** |

⇒ **在非代表性条件下测的数，不得作为该量的属性对外陈述。** 已写进验收。

### 🔴 2.4.6 vendor 路走弱之后，G4 变得更尖锐（本轮新增风险）

vendor 路基本崩 ⇒ 自建成主线。**但这同时抽掉了 bake-off 里唯一的外部锚点。**

原本是"我方语料 × 他方分类器"——我们至少是个相对中立的测量方。
现在若变成"我方语料 × 我方判官 × 我方度量"，**三者同源** ——
**这正是 G4b 要挡的形状，只是这次不是语料与判官同源，而是整条链同源。**

⇒ **要求：候选矩阵里必须保留至少一个第三方端点作独立比较项**
（DashScope 已有、零新增成本，即便它只作参照不作候选）。
否则整个选型退化成自证，而**"反对自证"正是这个项目存在的理由**。

### 2.4.7 自建 logprob 判官适配器（TD-3 端口抽象兑现，设计）

架构师净结论核实成立：**判官只是又一个 `Target`，pipeline 与规则集一行不动。**

```
class OllamaLogprobJudge (实现 Target Protocol):
    endpoint = <host>/api/generate           # 原生，非 OpenAI 兼容层
    probe(case):
        POST { model, prompt=<契约模板>(case.text), raw:true,
               options:{temperature:0, num_predict:1}, logprobs:true, top_logprobs:20 }
        tl = response.logprobs[0].top_logprobs
        score = softmax(tl["违规"], tl["安全"])   # 连续 P(违规) ∈ [0,1]
        return ProbeResult(vendor_labels=(VendorLabel(label="违规", score=score, ...),),
                           vendor_version=<模型:量化:契约id>,   # 见下
                           decision="BLOCK" if score>=τ else "ALLOW")
```

- **复用 §2.2.4 的 `vendor_labels` 契约** —— 自建判官和第三方 API 走**同一条**承载缝，
  harness / 曲线 / 报告管线全不区分来源。这正是 TD-3"换适配器不动 pipeline"的意思。
- 🔴 **`vendor_version` 对自建 = `模型:量化档:契约id`**（如 `qwen2.5-7b:Q4_K_M:contract-A`）——
  与 [RULEPIN](RULEPIN-CORE.md) 同源:**决定结果的配置必须随分数一起被记录**。
  prompt/输出契约是 §2.4.3 那个"选型轴",所以 `契约id` 必须进版本串,否则换个读法出的数不可归因。
- **延迟不在此处测**（CPU，§2.4.5）；本适配器只产**质量分**,可离线批跑。

### 2.4.8 🔴 确定性契约（承 Platform I3 §2 稳定性适配器契约）—— 稳定性度量的效度前提

**为什么在这**：§2.4.2 的"方差 = 0"只有在**本地判官的可控变量全被钉死**时才是"模型确定性"的证据；
否则测到的抖动可能是**我方配置噪声**（模型被推理栈冷卸载重载、seed/num_ctx/版本漂移），
"噪声来自远程 API"的反转就成假象。Platform I3 把这份契约交付为"供适配器 + 确定性契约"；
**Core（度量方）据此消费、不重定义**（同 R1 消费 §5.2、不重定义的纪律）。

**跑稳定性/曲线前必须钉死的旋钮**（钉死手段在适配器/运行环境；Core 侧只消费与记录）：

| 旋钮 | 作用 |
|---|---|
| `temperature=0` · `num_predict=1` | 贪心单决策 token，去采样噪声（适配器已默认） |
| 🔴 `keep_alive=-1` | 防冷卸载重载 —— TTL 到期即卸，下次调用冷重载会把重载噪声记成"模型不稳" |
| `seed` · `num_ctx` | 防御性固定 + 防上下文窗口漂移（经 options 传） |
| `raw`（instruct 走模板故 `false`）· `top_logprobs=N` | 固定 prompt 通路与响应形状 |
| **模型权重 digest（非 tag）· 推理栈版本** | tag 可被重新 pull 成不同权重；logprobs 行为跨版本可能变 —— 两者入印记 |

**Core 侧两条硬消费**（本增量的验收绑定，见 [C1-STABILITY-CURVE](C1-STABILITY-CURVE.md)）：
1. 🔴 **逐样本自证钉住（measured > attested）**：每份 verdict 带 `load_duration`；
   `load_duration ≫ 常驻基线`（真重载 = 秒级；基线 CPU 页入 ~0.2s、非零但稳）⇒ 标 `reload_contaminated`
   ⇒ **稳定性/曲线指标剔除该样本**，不伪装成"模型不稳"。**阈值目标硬件标定，非"非零即重载"。**
2. **弃首次热身调用** + 把决定结果的配置（`digest:量化:契约id`）随分数记进 `vendor_version`（§2.4.7）——
   否则换个配置出的数不可归因。

**边界（lead 2026-07-21）**：确定性契约与语料内容无关 ⇒ 对本地/远程两侧同样适用。
稳定性抖动是 batching/MoE 的基础设施属性、与内容无关 ⇒ **非涉政探针即可证"本地确定 / 远程抖"**；
**涉政语料只在本地模型上跑（LAN，不出云）**，远程对照臂只喂非涉政。

## 3. 裁定（R1/R2 已拍，PM 2026-07-21；G2 归属未决）

| # | 项 | 裁定 |
|---|---|---|
| **R2** | "曲线" vs "点" | ✅ **做曲线** —— 自建稳定性已实测（方差 0，§2.4.2）。**但是逐候选策略,不是"一律画曲线"**：每候选先过自己的稳定性,方差大的（自由生成式 / 远程 API）**只给点 + 波动带**。绑 §3.1 三条。 |
| **R1** | `target_kind` 扩 `moderation_api` + `evidence_basis: self_reported` | ✅ **契约现在定**（省一次升版）。🔴 **但拆开契约与实现：C2 适配器编码 gate 在"至少一家厂商清准入（HTTPS + 数据条款都过）"之后** —— 现状数美已出局、易盾数据条款未答,**别为出局/未决选手写适配器**。 |
| **G2** | 重叠门的**归属** | ⏳ 未决。**不挂公开 Core CI** 🔒 依赖资产不在公开仓 ⇒ 归属见私有侧;落实前不得称"已生效的硬门"。 |

### 3.0 R1/R2 的精度约束（PM 附加,务必随裁定保留,别丢）

**R2:**
- 实证的是**本地确定性**,不是"所有候选都能画曲线"。旧观测 `0.10→0.95` 是**远程 API**、非本轮 N×6 复测 —— 这不影响裁 R2,因为 §3.1-1 已正确处理（逐候选先过稳定性）。
- ×6 对**确定性**结论足够（确定性是二元的:位级一致或不是;饱和 + 非饱和都 6/6 一致即坐实）。

**R1:**
- 🔴 **`evidence_basis: self_reported` 是硬绑定,不是标签** —— 这一档**绝不能借用"可验证审计 / WAL 指纹"话术**（同 [CORE_STANDALONE](../../trustworthy-ai-platform/docs/collab/CORE_STANDALONE_TARGET_ABSTRACTION.md) §5 的 N/A 纪律）;报告里必须显形为"**厂商自报 · 最弱档 · 不可复算**"。
- **DashScope 独立比较项（§2.4.6）不吃这条** —— 它是**生成端点当判官**（走 logprob,同自建那套）,不是 moderation 分类器,`target_kind` **不是** `moderation_api`。⇒ 即便两家厂商全 washout,§2.4.6 的"至少一个第三方独立比较项"仍由 DashScope 满足,**R1 的价值不依赖厂商是否入场**。
- **schema 纪律（§8.7）**：两处 schema 同批改 + 升 `schema_version` + 同步 golden fixtures/drift-guard + 对账单**单独一次提交**,不折进代码提交。
- 🔴 **耦合警告（2026-07-21,对着代码）：`target_kind`/`evidence_basis` 在 Core 一处都没有**
  （EV-FWD 未落,设计只在私有 CORE_STANDALONE §5.2）。⇒ **R1 不是"加第三值",是把整个
  `target_kind{raw_model|gateway|moderation_api}` + `evidence_basis` 概念一次性落进 schema。**
  这仍是"契约现在定、省一次升版"（一次 bump 覆盖三值,好过先落两值再补第三值两次 bump），
  但**规模是 EV-FWD 那块,不是一行**。

  ✅ **PM 已裁（2026-07-21）：现在做,一次 bump。** 理由比"省升版"更强一层 ——
  **C4（eval_report 标的/模式标注）本来就要 `target_kind`/`evidence_basis`**（§C4 明写"跟
  CORE_STANDALONE §5.2 走"）。所以这块不是 R1 的额外工作,是 **C4 无论如何都要落的**;
  R1 真正新增的只是 `moderation_api` 值 + `self_reported` 档。一次落齐,同时服务 C4 和 R1。

  🔴 **R1 落地的三条守护（缺一条就从"实现已裁契约"滑成"借 C2 之名重新发明 EV-FWD schema"）:**
  1. **逐字实现 CORE_STANDALONE §5.2 的已裁形状,不重新设计** —— 报告级
     `target_kind{raw_model|gateway|moderation_api}` + 指标级 `availability{measured|n/a_needs_gateway}`
     + 命名 `evidence_basis`。R1 落的必须**等于** §5.2;有任何出入,先对齐再落。
  2. **只落 schema 骨架,不落 EV-FWD 运行时** —— `OpenAITarget`、harness 自抓打分接缝那些运行时
     按 EV-FWD 自己排期。R1 只落契约字段（三值枚举 + `evidence_basis` + `availability` + golden fixtures），
     别让 schema 把整个 EV-FWD 实现拖进 P3C（范围失控）。
  3. **`moderation_api` 值现在落 schema,但消费者 C2 适配器仍 gate 在厂商清准入之后** ——
     会出现"枚举有值、暂无候选用它",这对枚举可接受（前向兼容、永久产品概念）;但报告必须
     诚实显形"**本次无候选走 `moderation_api`**"（honestly-absent,不伪造），同 §5.2 的 N/A 纪律。

  🔴 **归属纪律(PM 协调项,防同一 schema 被两个 issue 争夺):一处定义（§5.2 已裁）· 落地一次（R1）·
  多处消费（C4 / EV-FWD）。** ⇒ 将来 EV-FWD issue（Core 现无此文件）创建时,**必须交叉引用
  "`target_kind`/`evidence_basis`/`availability` 的 schema 已由 R1/P3C 落地,EV-FWD 消费、不重定义"**,
  否则 EV-FWD 真做时会撞上已存在的 schema 又想重定义一遍。**此义务记在此,免得 EV-FWD 创建时丢。**

### 3.1 R2 裁定「做曲线」的三条附加条件（缺一条，曲线就是装饰）

1. ✅ **自建候选的稳定性检查已过（2026-07-21，见 §2.4.2）** —— 本地 Qwen-7B logprob 打分
   同输入 ×6 方差 = 0（饱和与非饱和样本均然）。**"自建噪声"被推翻**，自建**可以画曲线**。
   > 但这条**原则仍对每个候选生效**：任何候选进曲线前都要先过稳定性；
   > 方差大的候选（尤其自由生成式、或远程 API）**只给点 + 明示波动带**，不给曲线。
   > `indicators.py:695` 的 `0.10→0.95` 现证实是**远程 API** 属性，不是模型判官属性。
2. 🔴 **对比必须在 matched FPR 上做**（如 recall @ FPR=1% / 5%），
   **不是**各家默认工作点。否则曲线画了，头条对比仍是苹果比橘子 —— 曲线沦为装饰。
3. 🔴 **首次联调必查"分数是否归一化"** —— 两家文档都只说 0–1 置信度，
   **都没说各标签求和为 1**。这是**证据缺席，不是证据**。
   送 N 条文本核 `sum(score)` 是否恒为 1；是 ⇒ 曲线要改扫 `1 − p(通过)` 或有害类求和。
   **两家各做一次，不可互相推定。**

## 4. 非目标

- 不做判官部署形态选型（TD-7，lead 拍板；接缝对三者一致，不阻塞开工）。
- 不做规则/词表本体（属上游）。
- 不把 P3-content 的合格率数字写进任何对外材料（spike 出数前，红线）。
- 🔴 **不与标准的"误报率 ≤5%"合并叙述** —— 那测的是**非拒答题库**，
  我们的 FPR 测的是**良性 hard-negative 语料**，后者天然更难、数字更高。
  混写会被读成"我们没达标"，或更糟：被拿去互相背书。**对外各自带语料 sha + 口径。**

## 5. 验收

1. 同一候选跑两次 ⇒ 确定型部分（规则命中）逐位一致；统计型部分明示 `STATISTICAL` 与 n。
2. **双侧都有数**：任一候选的报告若只有 recall 没有 FPR ⇒ **判定不合格，不得进选型对比**。
3. 逐 `content_class` 可切片，且**未分类**切片单独可见（不静默并进总数）。
4. `moderation_api` 标的产出的报告：`evidence_basis` 明示 `self_reported`，
   且**不出现**"可验证审计 / WAL 锚定"字样（守卫测试断言这条）。
5. 现有 10 个语料目录在加了 `content_class` 之后**仍全部加载成功**（可选字段的回归守卫）。
6. 🔴 **机器判定与人审判定不得合并**（某候选返回 `resultType` 机器/人审分段）：任一候选的报告
   若把两者混算成一个 recall ⇒ **判定不合格**。人审回流是产品能力，不是分类器效能。
7. 🔴 **超长输入不得静默外发**（某候选会静默截断超长输入）：守卫测试喂 >1 万字，
   断言 harness **自己分块或拒绝**，而不是把整条发出去等厂商截断。
8. **无版本可追溯的候选要显形**：`vendor_version` 为空时报告须标出，不得静默略过。
9. 🔴 **质量与延迟分开报告**：在非代表性硬件（CPU 推理）上取的延迟数
   **不得**作为候选的延迟属性陈述；报告须显式标注测量条件。
10. 🔴 **候选矩阵含至少一个第三方端点作独立比较项**（防整条链同源，§2.4.6）。
11. 门禁不回归。

### 5.1 🔴 下一 increment 的绑定验收（首次 check-in 尚不可执行，落地时必须补）

> Implementer review（2026-07-21）指出：验收 §5-3 现在**不可执行** —— 切片器还没建，
> `""` 作为"未分类桶、不并入 class total"目前只是字段语义，**没有守卫**。以下两条把它
> 从"空头承诺"钉成"落地时的硬条件"，**不是**对本次骨架 check-in 的门（本次无切片、无渲染）。

- **B1〔切片器落地时〕未分类切片必须有 guard test**（兑现 §5-3）：
  构造混含 `content_class=""` 与已分类 case 的一批 `ProbeResult`，断言
  ① `""` 桶在报告里**单独出现**；② 它**不被并进任何 class 的 total**；
  ③ 🔴 **excluded 不静默消失**（因分母是 `measurable` 而非 total，见 §C3-2 裁决 C）：
  断言 **`sum(measurable over all buckets) + sum(excluded) == matched probes`** ——
  errored/无证据探针必须在 `excluded` 里能被数出来,不能凭空蒸发。
- **B2〔延迟渲染落地时〕`sample_size=0` 不得裸露成 `0 ms`**：
  三个百分位在空窗口都返回 `value=0.0 · VERIFIED`（继承自旧 p99，非本次回归）——
  但 **"p50=0ms" 比 "p99=0ms" 更易被误读成"极快"**，唯一信号是 `sample_size=0`。
  harness 渲染延迟时,`n=0` 必须显式标 **"无数据"**，不能让 `0 ms` 当真值露出；
  guard test 断言空样本渲染为"无数据/insufficient"，而非一个延迟数。

## 6. 排期（2026-07-21 更新：三前置解两，稳定性已跑）

**PM 的开工顺序采纳：不是"谁先动手"，是"先拿稳定性结果决定曲线怎么画"。而稳定性已跑完（§2.4.2）。**

三个前置的状态：

| 前置 | 状态 |
|---|---|
| logprobs 可用 | ✅ 已验（原生 API，§2.4.3） |
| 许可证 | ✅ Qwen 7B/1.5B = Apache-2.0（**逐 tag 验，§2.4.4**） |
| **稳定性对跑** | ✅ **已跑：本地方差 0，自建噪声被推翻**（§2.4.2） |

⇒ **R2「做曲线」不再是空头支票** —— 分数稳定已实证，可裁。R1/R2 建议**此刻同批定**（§3）。

| 阶段 | 内容 | 前置 | 状态 |
|---|---|---|---|
| **已完成** | 稳定性对跑 + logprob 判官验通 + 许可证 | — | ✅ |
| **今天可起步** | C1 骨架（切片形状 + p50/p95/p99）· C3 `content_class` 可选字段 · C4 | 无 | ⬅ 开工 |
| **同批裁定** | R1（`moderation_api`）· R2（做曲线，附 §3.1 三条） | 稳定性（✅ 已具备） | ⬅ 待拍 |
| **裁定后** | C2 moderation 适配器 + logprob 判官原生适配器 + schema 升版 | R1 | |
| | C1 输出形态定稿（含 prompt/输出契约轴，§2.4.3）+ 选型问卷 | R2 | |
| **语料就位后** | spike 出数（双侧曲线） | 良性对照集 · **语料先冻结**（§2.1） | 🔴 真瓶颈 |
| **账号就位后** | vendor bake-off（支线，见私有侧数据条款状态） | 第三方账号 | |

**⇒ 净结论（主线/支线）：**
- **主线 = 自建 Qwen-7B logprob 判官** —— 三前置全解，今天就能起 C1 骨架 + 原生适配器。
- **支线 = 第三方 API bake-off** —— 技术形态满足，但**数据条款未确认前不进准入**（见私有侧）；
  DashScope 已能担"第三方独立比较项"（§2.4.6），不必强留出局的候选。
- **真瓶颈仍是良性对照集 + `content_class` 标签 + 语料冻结** —— 不在模型侧，在语料侧。
