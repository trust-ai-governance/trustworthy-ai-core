# EV-R2 — active-eval 用例级结果契约

> **Problem（普通话）：** 报告能告诉你「注入拦截率 89%」，**但告诉不了你【哪几条没拦住】。**
> 主动评测那条流水线今天只出一份 markdown（`tools/eval_report.py` 的 docstring 逐字：
> *"writes ONE markdown"*），**没有任何机器可读的逐案契约** —— UI 做不出用例级详情，
> 外部工具接不上，运营者想知道"我该修哪条规则"只能人读 markdown。
>
> 而这**不是**扩 EV-R1 就能解决的：`case_id` **只活在主动评测进程的 `ProbeResult` 里，从没进过 WAL**
> （探针只发 `x-agent-id` + `{tool_id, params}`）。EV-R1 是**被动**流水线，样本是**真实请求**，
> 不是测试用例 —— **扩它的契约也变不出引擎从没观测过的字段。**
>
> **Value:** 让"89% 拦截"变成**可行动的**：哪 3 条漏了、属哪个手法、证据在 WAL 的哪条记录上。
> 🔴 **这也是唯一能让"聚合数字可被复算"的东西** —— 逐案结果在手，任何人都能自己把
> `injection_catch_rate` 加回来，而不是信我们那一个数。**这正是 measured>attested 落到用例粒度。**
>
> Dev brief. **归属：** 架构师出规格；Implementer 编码 + 测试。**规模：中。**
> **前置：** 无（与 [EV-R1](../REPORT_JSON_SCHEMA.md) / EV-W1 **正交**，已核）。
> **承：** [EVAL_ISSUES](../EVAL_ISSUES\(WIP\).md) EV-R2 登记 · [EV-ATTRIB](EV-ATTRIB.md)（判定语义的来源）。

---

## 0. 现状核对（对着代码，2026-08-02）

| 事实 | 出处 |
|---|---|
| 主动评测只出 **一份 markdown**，无机器可读契约 | `tools/eval_report.py` docstring |
| `case_id` / `request_id` / `decision` / `response_text` **都在** `ProbeResult` 上 | `active_eval/target.py` |
| 🔴 **逐案数据今天已经有** —— `format_attribution_report()` | `active_eval/reporting.py:159` |
| 🔴 **但它被明确标成内部产物**：*"INTERNAL Platform artifact — a live bypass map; write under the gitignored `reports/` dir"* | 同上 docstring |

🔴 **⇒ 本单不是"生成逐案数据"（已有），是"给它一份契约 + 一套披露纪律"。**
**而那套纪律才是本单的难点。**

---

## 1. 🔴 承重点：**一份逐案结果就是一张绕过地图**

每一条 `missed` 的用例都在说：**"这个攻击对这个网关有效。"**
一份完整的逐案结果 = **给攻击者一张现成的清单**，还附着"哪种手法能过"。

现有代码已经认识到这一点（把它写进 gitignored 目录、手工交给上游）。
🔴 **本单如果只做"加个 JSON 输出"，等于把那道人工纪律拆了。**

**⇒ 契约必须自带披露分层，而不是靠使用者记得别外发。**

> **与 EV-W1 撤销 `/evidence` 是同一族，但这里多一层**：
> 那次是 **PII 面**；这次除了 PII，还有 **攻击有效性情报** ——
> **即使一条内容都不带，"哪些手法没被拦"本身就是敏感的。**

---

## 2. 契约形状：两层，默认那层也不是公开物

### Tier 0 — 判定层（默认输出）

```jsonc
{
  "schema_version": 1,
  "disclosure_class": "operator_only",   // 🔴 见 §2.2，不是装饰
  "corpus_sha": "sha256:...",
  "target_kind": "gateway",
  "generated_at_ns": 1785...,
  "cases": [
    {
      "case_id": "llm01.direct.role_override_dan.003",
      "owasp": "LLM01",
      "attack_class": "direct_prompt_injection",
      "attack_technique": "role_override_dan",
      "verdict": "succeeded",              // §3，取值不新造
      "observable_via": "output_marker",   // 🔴 §3.2 分母选择器（null = 不可观测）
      "governance_reacted": true,          // 🔴 §3.2 逐案 blocked_or_flagged ≠ 拦住了
      "availability": "measured",          // 复用 EV-FWD 的轴
      "request_id": "req-...",             // 🔴 证据【指针】，不是内容
      "evidence_ref": { "segment": "...", "seq": 123 }
    }
  ]
}
```

🔴 **Tier 0 一个字节的响应内容都不带。** `request_id` / `evidence_ref` 是**指向 WAL 的指针** ——
读者要看内容，得自己有那份 WAL 的读取权限。**权限判定留在 WAL 侧，不在这份文件里。**

### Tier 1 — 内容层（显式 opt-in，永不进报告存储）

`response_text` · `raw_response` · 命中的 marker/canary 原文 · 判官输出。
**落盘规则与现有 `format_attribution_report` 同一条**：写 gitignored 目录，人工交接。
**默认关闭；开启需显式 flag，且 flag 名字要说清后果**（如 `--include-response-content`）。

### 2.2 🔴 `disclosure_class` 不是装饰，是本单的核心字段

| 值 | 含义 | 能进哪里 |
|---|---|---|
| `operator_only` | 逐案判定（Tier 0） | 运营者自己的界面 / 内部报告存储 | **❌ 不进对外报告、不进公开物** |
| `internal_handoff` | 含内容（Tier 1） | 🔴 **只落 gitignored 目录 + 人工交接** |

**为什么默认层也是 `operator_only`**：聚合报告已经公开了 `injection_catch_rate = 0.89`；
**逐案"哪几条漏了"严格更敏感**。
🔴 **一个不带披露级别的逐案契约，第一次被贴进工单就出去了。**

---

## 3. `verdict` 取值：🔴 **复用既有语义，一个新词都不造**

| verdict | 来源 | 说明 |
|---|---|---|
| `succeeded` / `hard_blocked` / `soft_flag_declined` / `declined_by_model` | **[EV-ATTRIB](EV-ATTRIB.md) 的四格** `checks.attribution_cell()` | 逐案判定就是四格本身 |
| `errored` | `pr.error is not None` | 基础设施故障，出分母 |
| `unmeasurable` | `gateway_undecided(pr)` 或该用例对该指标不可测（无 marker） | 🔴 **绝不写成"未拦截"** —— 那是假 0% 家族 |

🔴 **不得为逐案层新造判定词。** 新造一套就等于有了第二个真相源，
**两边迟早对不上，而对不上的时候没人知道该信哪个。**

### 3.1 🔴 本单最硬的一条验收：**逐案必须能把聚合复算回来**

> **从 `cases[]` 重算出的 `injection_catch_rate` / `injection_success_rate` / 四格，
> 必须与同一次跑的 aggregate measurement【逐位相等】。**

**这不是锦上添花，是这份契约存在的理由**：
它让"89%"从**我们说的一个数**变成**任何人都能自己加出来的数**。
**加不回来 = 契约与指标已经分叉 = 这份文件不可信。**（回归带牙，见 §7。）

### 3.2 🔴 裁定：光有 verdict **复算不回来** —— 补两个「可测性信号」（2026-08-02）

Implementer 在开工前指出：**单个 verdict 无法满足 §3.1**，成立，两处都对：

| 缺口 | 为什么 |
|---|---|
| **`injection_success_rate` 的分母取不回来** | 得逞率的分母是**带 marker 的子集**（n=8），拦截率是**全部已判用例**（n=28）。而 `declined_by_model` 这个 verdict，在「带 marker 但没照做」和「根本没有 marker」两种用例上**一模一样** ⇒ 分不出谁在 n=8 里 |
| **`injection_catch_rate` 取不精确** | catch = `blocked_or_flagged`；但四格把「**软标了、攻击还是得逞**」记在 `succeeded`（succeeded 优先）⇒ `hard_blocked + soft_flag_declined` **少算了那一条** |

#### 🔴 选项 (b)「假设 overlap=0」已被我们自己的实测数据证伪

用 2026-07-31 那份网关 bundle 实算：

```
catch@observable          = 8/8
四格                       succeeded=1  hard_blocked=6  soft_flag_declined=1  declined=0   (合计 8 ✅)
overlap = 8 − (6 + 1)     = 1          ← 那条 succeeded 的用例【同时被软标了】
```

⇒ **overlap 不是"今天恰好为 0、将来不保证"，而是【今天就等于 1】。** 选项 (b) 直接出局。

#### ✅ 裁定：走 (a) 两信号 —— **但两个名字都要改**

Implementer 的方向对：这两个**不是新 verdict**，而是
🔴 **verdict 这个单一分类【丢掉】的那两个谓词** —— 补它们不是打补丁，是把丢失的信息补回来。

| 字段 | Implementer 原名 | 🔴 定版 | 为什么改 |
|---|---|---|---|
| 分母选择器 | `observable: bool` | **`observable_via: "output_marker" \| "secret_canary" \| null`** | 一个 bool **分不出 marker 与 canary** —— llm02 的用例带 canary 不带 marker，若 `cases[]` 跨语料，bool 会把两个不同的分母混成一个。**而这个取值集就是 [EV-COVERAGE](EV-COVERAGE.md) 轴③ 的既有词汇 ⇒ 复用，不新造**，逐案契约与覆盖率报表**由构造保证一致** |
| 治理反应 | `caught: bool` | **`governance_reacted: bool`** | 🔴 我们整轮都在把**「有反应」和「真拦住」分开**（四格的全部意义）。字段叫 `caught` 会把那个区分又搅回去。它就是**逐案的 `blocked_or_flagged`**，注释里点明"这是 `injection_catch_rate` 数的那个谓词，**不等于**拦住了" |

**这两个字段合起来正好补上两处缺口，且不多不少**（已核三个聚合：catch 需 `governance_reacted` +
`errored`/`unmeasurable` 出分母；success 与四格需 `observable_via` + verdict —— **全部可复算**）。

> 🔴 **顺带记一句：这个缺口是 §3.1 那条验收在【开工前】逼出来的。**
> 一条"必须逐位复算"的验收，让一个单一 verdict 的设计在写代码之前就暴露了 ——
> **这正是带牙验收该起的作用。Implementer 拒绝先建再说，是对的。**

### 3.3 🔴 已知残留：**gateway-undecided 的 marker 用例无法用现有三字段表达**（2026-08-02 登记）

Implementer 在实现后诚实提出，我复核成立 —— **但要收窄一个词：不是 impossible，是"用现在这三个字段 impossible"。**

**根因（本轮第四次同形状）**：
🔴 **`verdict` 这一个字段在同时干两件事：承载【成员资格】（`unmeasurable`）和【结果】（四格）。**
而对一条 gateway-undecided 的 marker 用例，两个聚合需要**相反的答案** ——
`injection_catch_rate` 要它**出**分母（P4：网关没判 ≠ 没拦住），
`injection_success_rate` / 四格 要它**进**分母并带结果（输出看得见，与网关判没判无关）。

> **这与本轮拆过的三次是同一个形状**：`attack_class` 兼扛向量与手法 ·
> `canonical_source` 兼扛权威与可引 · `availability` vs `evidence_basis`。**每次的解都一样：拆字段。**

**解法（一个 bool，不必现在做）**：

```
gateway_decided: bool          # = not gateway_undecided —— 把【成员资格】从 verdict 里拆出来
```

- CATCH 分母 = `gateway_decided and verdict != "errored"`
- SUCCESS / 四格 分母 = `observable_via == "output_marker" and verdict != "errored"`（与 decided 无关）
- 四格结果 = `verdict` —— 🔴 **undecided 的行也能带真实结果，不必退化成 `unmeasurable`**

🔴 **触发条件（写死，免得再讨论一遍）：任何人需要从一次 gateway-undecided 的跑里拿逐案数据时。**
那时就加这个 bool，**不需要重新设计**。

**在此之前维持 fail-closed（拒发整份契约），理由已实核：**

1. **今天不咬** —— 规范 bundle 里零个这种用例（`catch@observable` 的 n == 四格 n == marker 数）；
2. 🔴 **拒发不连累排障** —— `eval_report` **先写 markdown、后写契约**（`tools/eval_report.py`），
   所以拒发只损失案级文件，**运营者仍拿得到报告与逐案归因去 debug**。
   **若顺序反过来（拒发把报告也毁掉），fail-closed 就不该批** —— 那等于在最需要排障时把材料一起扣了；
3. **另一条路更糟** —— "静默丢掉这些行"会让契约与聚合**无声分叉**，正是 §3.1 要禁的事。

**报错文案（定版，实现照此补半句）**：现有文案已点名 likely cause，**再加一句排障方向**：

> `…（Likely cause: a gateway-undecided marker-bearing probe — a healthy, all-decided run has none.`
> **`排查方向：网关是否就绪、评测身份是否已开通 —— 见 GATE-LASTMILE P4 / EV-PAIR 门 7。`**`）`

🔴 **理由**：现有文案把"契约拒发"翻译成了"你这次跑是坏的"，**很好**；
补这半句是让读者**直接走到修法**上，而不是停在现象上。

---

## 4. 与既有契约的关系（已核，不重复造）

| | 样本是什么 | 有没有 `case_id` |
|---|---|---|
| **EV-R1 / 成熟度报告**（被动） | **真实请求**（`request_id`） | ❌ **从来没有** —— WAL 里不存在这个字段 |
| **EV-R2**（本单，主动） | **测试用例**（`case_id`） | ✅ |

🔴 **两者不是一个契约的两个版本，是两条流水线的两份契约。**
`request_id` 是它们**唯一的交叉点** —— 本单把它带上，正是为了让逐案结果能**指回** WAL 证据。

---

## 5. 非目标

- **不改**任何指标计算（本单只是把已有判定写成契约）。
- **不扩** EV-R1（§4：它没有也不可能有 `case_id`）。
- **不做** UI（本单只交付契约；UI-3 / #5 消费它）。
- **不把** Tier 1 内容做成默认输出，**也不把 Tier 0 当公开物**。
- **不新造** verdict 词汇（§3）。

---

## 6. 开工前必裁

| # | 决策 | 建议 | 归属 |
|---|---|---|---|
| **P1** | Tier 0 带不带 `attack_technique`？ | **带。** 手法名本身在公开语料里（`corpus/` 是公开的）⇒ **无增量泄露**；而没有它，"该修哪条规则"就答不了 | 架构师定 |
| ✅ **P2** | Tier 0 的 `operator_only` 能不能进**只读报告服务**？ | ✅ **PM 已裁：允许，带五条机械条件（§6.1）** | **已定** |
| **P3** | 用什么 flag 开 Tier 1 | `--include-response-content`，且 help 文案写明"输出含完整响应正文与命中原文，属内部交接物" | 架构师定 |
| **P4** | 🔴 未来接入 #6（生产被动路径）后，`request_id` 会关联**真实用户请求** ⇒ PII 面变 | **本单不解**，**登记**：EV-R2 的 PII 评估只覆盖**评测语料**（合成用例）；生产侧接入须**重做威胁模型** | 登记 |
| **P5** | 🔴 **gateway-undecided 的 marker 用例无法用现有三字段表达**（§3.3） | **本单不解，登记**：根因是 `verdict` 兼扛成员资格与结果；解法 = 加 `gateway_decided: bool`；**触发条件 = 有人需要从 undecided 的跑里拿逐案数据**。在此之前 **fail-closed**（已实核不连累排障） | 登记 |

---

### 6.1 ✅ P2 裁定：允许 Tier 0 进只读报告服务 —— **五条机械条件**（PM，2026-08-02）

**裁定的张力就是本单存在的理由本身**：§3.1 的可复算价值（让审计员自己把 89% 加回来）
要求逐案面**可访问**；而 §1 的绕过地图风险要求它**不可外泄**。
🔴 **`(attack_technique, verdict=missed)` 这一对本身就是绕过地图 —— 零正文也一样。**

**⇒ 允许，但靠门不靠人，五条都是机械的：**

| # | 条件 | 防的是什么 |
|---|---|---|
| **1** | 🔴 **存储物理/逻辑隔离** —— 案级库与对外报告库分离，**结构上进不了外发材料** | 承重守卫：防"第一次贴进工单就出去" |
| **2** | 🔴 **租户作用域** —— 只对**拥有该网关的租户/操作员**服务；**绝不跨租户、绝不公开** | 看自己系统的绕过地图是正当的（那是他们修/验的依据）；看别人的不是。继承既有 `(tenant_id, agent_id)` 隔离 |
| **3** | 🔴 **`disclosure_class` 必填 + fail-closed** —— 缺级别 = **拒发**，不是默认公开；默认取**最严**，放宽须显式 | §2.2 |
| **4** | **Tier 1 内容永不进只读服务** —— 只读服务只出 Tier 0 指针；内容仍 opt-in + gitignored + WAL 读权限门控 | 权限判定留在 WAL 侧（§2） |
| **5** | 🔴 **存在理由锚在复算** —— Tier 0 进服务是**为了让 owning 租户/审计员复算聚合**，**不是"多给点数据看"** | 防止范围漂移：任何加进去的字段都要能回答"它服务于复算吗" |

### 6.2 🔴 这条裁定改变了 UI-3 的形状（也改变了它的规模）

**UI-3 不再是"给报告器加个案级 tab"**，而是：

> **独立存储的 Tier-0 子服务** + **租户作用域** + **`disclosure_class` 门** + **复算 affordance**
> （让审计员当场把 `cases[]` 加成聚合）；**内容层不碰**（WAL 门控）。

🔴 **复杂度与纪律都比"加个 JSON 视图"高一档 —— UI-3 须按【分离服务】设计，规模从「中」上调。**
（[EVAL_ISSUES](../EVAL_ISSUES\(WIP\).md) 的 backlog 相应更新。）

### 6.3 对外纪律（PM 定，记在这里免得走散）

**可验证性是卖点，绕过地图不是展示物。**
逐案数据 **tenant-internal，永不进对外材料**；
对外能讲的是**"客户可以在自己环境里从 `cases[]` 复算自己网关的数"** —— 那是能力，不是数据本身。

---

## 7. 验收

- Tier 0 输出**不含**任何响应内容字段（回归：断言 `response_text`/`raw_response` 的值不出现在输出里）；
- `disclosure_class` **必填**，缺失即 `SchemaError`（不是默认成 public）；
- 🔴 **复算带牙**：从 `cases[]` 重算 `injection_catch_rate` / `injection_success_rate` / 四格
  ⇒ **与 aggregate measurement 逐位相等**；构造一条分叉即让测试红；
- `unmeasurable` 的用例**不进任何率的分母**（回归：一条 `unmeasurable` 不会把 catch 拉低）；
- Tier 1 默认关闭；开启后输出**不进**报告存储（回归：存储写入路径拒绝 `internal_handoff`）；
- `verdict` 取值**只能**来自 §3 的集合（回归：新词即报错）。
- 🔴 **P2 五条的机械验收**：案级库与报告库分离（回归：报告导出路径**拿不到**案级记录）·
  跨租户读取被拒 · `disclosure_class` 缺失 ⇒ 拒发（**不是**默认公开）·
  `internal_handoff` 写入只读服务被拒。

---

## 8. Live Test

```bash
export PYTHONPATH=$PWD
# 一次已开通身份的主动评测，产出逐案契约
python -m tools.eval_report ... --cases-out /tmp/cases.json     # 具体 flag 名由实现定
```

**必须看到：**

1. `disclosure_class = "operator_only"`；输出里**搜不到**任何响应正文；
2. 🔴 **自己把 89% 加回来**：`grep verdict /tmp/cases.json | ...` 统计四格
   ⇒ 与同一跑的 `injection_catch_rate` / 四格 **逐位相等**；
3. 漏掉的那几条能被点名 —— **列出 `verdict != hard_blocked` 的 `attack_technique`**，
   这正是"该修哪条规则"的答案；
4. 加 `--include-response-content` ⇒ 内容出现，且**写入报告存储被拒**。

> 🔴 **第 2 项是这一跑的意义**：它第一次让"89%"变成**读者能自己验的数**，
> 而不是我们报的一个数。
