# PROV — 检测型数字 provenance 对账 + 冻结唯一规范 run（对外分发硬门）

**Problem（plain language）：** 同一检测型数字在多份文档取值不一、且都取自**移动窗口**，对外即不可复现：
- 注入 `injection_catch_rate`：≈4%（奠基）→ 57%/61%（P2-a 词法初版）→ 89%（调优后），散在三处、无桥接注；
- `chain_integrity 100%`：n=404 / 463 / 520 三处，其中 **463 取自 `__eval__` 0-0 移动窗口、已不可复现**，**520 是 demo 合成值**。

对一个卖"可验证审计"的产品，头条引一个自己都溯源不了的数，比薄样本注入 89% 更伤（89% 至少有 run/sha/可复现）。

**Value：** 把每个对外检测/基线数字钉成"**语料 sha + 口径 + 日期 + n（下界）+ pinned 窗口**"，并冻结**唯一规范 run**，
使白皮书 §5.2/§5.4 的数字可被第三方复算。这是 measured>attested 的诚实底座。

> Dev brief. **前置**：[EV-PIN](EV-PIN.md)（冻结 run 的能力 —— 没有它，规范 run 又是移动快照）。
> **协作**：Core 起头（度量侧 + 冻结规范 run）+ Platform 补齐（规则集/网关配置版本号 + 白皮书换字）。
> **对账 artifact**：[CORE_INJECTION_NUMBER_PROVENANCE](../../trustworthy-ai-platform/docs/collab/CORE_INJECTION_NUMBER_PROVENANCE.md)。
> **规模**：小（Core）/ 跨仓闭环。

---

## 0. 根因（两位架构师收敛 + 已代码核实）

🔴 **真正的根因 = 流程缺陷：对外数字取自 LIVE 移动窗口（`__eval__` 0-0 最新）而非冻结的 pinned run。**
移动窗口不可复现 ⇒ 任何引用即不可验证。通用教训：**对外数字必须来自 pinned run**（窗口 + WAL 段 + 日期 + sha），
不能是"最新"。—— 故 PROV 依赖 EV-PIN。

次因 = 归属错配（已更正）：`chain_integrity` 是 Core 自算（`indicators/chain_integrity.py` 读 `AuditEvidence.integrity`），
早前 provenance §6 让 Platform"钉 463"= 让它自证 chain_integrity，违反已 ratify 的分工。**更正后 Platform 只做换字。**

## 1. 裁决（已定，本 issue 执行）

1. **作废 n=463**（不可复现，窗口已前移，无法补 pin）。
2. **Core 冻结唯一规范 run**：用 EV-PIN 产出一次 **pinned** 的 chain_integrity 规范 run（窗口/WAL段/日期/sha 全钉）。
   🔴 **关键约束**：换上的规范值**必须是 pinned run**，**不能又是"404 最新"移动快照**（我手上的 404 bundle 窗口也是 `[0,0]`，
   直接引用等于把病从 463 搬到 404）。规范 n 是"那一冻结窗口内实际的 n"，不预设等于 404。
3. **Platform 对 chain_integrity 的唯一动作 = 文档换字**（白皮书 §5.4 line 249 + PM 的 HTML 决策块 line 216：
   463 → Core 冻结的规范值）—— 文档编辑，非计算，符合 ratify。
4. **Platform 的 §6 真正的活 = 注入两版规则集号**：57%（≈2026-06-30）/ 89%（≈2026-07-15）各对应哪版 Tier-1，
   确认同家族调优。（度量侧 Core 已钉：语料 git 证自 2026-06-28 未改、sha、日期、命中/分母。）
5. **硬门 9.2-B 不变**：PROV 闭环前，白皮书 §5.2（注入 89%）/§5.4（chain n）**不分发**。
6. 🔴 **仲裁：每个对外指标恰好一个规范来源**（2026-07-19 补，见 §5）。两次规范 run 都合法，但在 7 个指标上
   重叠取值不同 —— 不仲裁就等于把病从"移动窗口"换成"两个规范 run"。

## 2. 范围

- **Core：** ① 用 EV-PIN 冻结 chain_integrity 规范 run；② `injection_catch_rate` 89% 补钉 pinned 窗口
  （现 n=28 也取自移动窗口，同病）；③ 按 **9.2-A** 把 `block_rate` / `redaction_hit_ratio` / `duration_p99`
  也纳入"每个对外数带 sha + 口径 + 日期 + n + pinned 窗口"；④ demo 的 chain_integrity n=520 **标死"合成·非实测"**（Core 认领）。
- **Platform：** 见裁决 3、4。
- **共同：** 更新 provenance artifact §2 表的 ⏳ 格 → 全绿即闭环。

### 2.1 ✅ Core 侧已闭环（2026-07-19）

| 项 | 状态 |
|---|---|
| ① chain_integrity 规范 run 冻结 | ✅ `100% n=173`（`~/prov/canonical_wal`，段 sha `be827a1c…`） |
| ② 注入 89% 补 pinned 窗口 | ✅ `89.29% (25/28)`（`~/prov/injection_wal`，段 sha `a9c020da…`），且**可从冻结段重算**（replay 逐位一致） |
| ③ 9.2-A 各数带 sha + 口径 + 日期 + pinned 窗口 | ⚠️ **2/3** —— `redaction_hit_ratio`(2.52% n=119)与 `duration_p99`(59839 ms n=27)已测已 pin;**`block_rate` 从未跑过**（指标在 `treval/indicators/block_rate.py`，只是没进 collect） |
| ④ demo n=520 标"合成·非实测" | ✅ 报告级第三态 `示例数据`，UI 上肉眼可见（不只源码注释） |
| ⑤ 仲裁：每指标唯一规范来源 | ✅ §5，两份 artifact 带 `canonical_for` + 逐条 `canonical_source`，与 §5.0 表机器核对一致 |

**⇒ 不再是 Platform 的前置。** Platform 侧的两项（规则集号 / 换字）**已于 2026-07-19 完成**
（57% = `〔上游版本A〕` · 89% = `〔上游版本B〕`；§5.4 已换字并附完整印记）。

### 2.2 余下（本轮核查新掉出来的两条，Core 侧）

1. **`block_rate` 补测** —— 9.2-A 三项里唯一没测的。指标存在，只是从未进 collect。
2. 🔴 **`duration_p99` 需要一次代表性流量上的测量** —— 白皮书曾据 demo 的合成值
   `780 ms · n=240` 把「60s p99 blocker」标成**已解决**，而生成器源码逐字写着
   `# a HEALTHY latency baseline — 780 ms, not 60 s (good demo optics)`。
   唯一真实 pinned 值是 **59839 ms**（§5.1），但它取自 `__eval__` 探针批、**故意含 LLM10
   unbounded-consumption 用例**，被自家压力用例拉高是设计使然。
   **780 ms（合成）/ 23836 ms（acme 评测）/ 59839 ms（`__eval__` 评测）—— 76 倍跨度**，
   正是 §5 那条「9.2-A 是语料相关量，不是环境属性」的最好例证。
   ⇒ **诚实状态 = 未测定**，两个方向都没有代表性流量上的数。这两个数一起补测后，
   Platform 再填该次 run 的网关配置版本。

> **教训（与 ④ 同源，值得并排记）**：④ 是合成的**样本数**混进外部文档；这一条是合成的**数值**
> 被用来**关闭一个真实工程 blocker**，且 `verified`（本义 = 对着真实 WAL 验过哈希链）
> 一并被搬到了合成数上。**合成数据不能替真实测量作证** —— 这正是 demo 三态要在页面上自证的原因。

**④ 的做法值得记一条通用教训：** 生成器源码首行的 `SYNTHETIC` 声明是**给我们自己看的**，
拦不住有人把 demo 页面截图发出去 —— 而 n=520 混进外部文档走的正是这条路。
**合成数据必须在渲染出来的页面上自证**，否则它长得和实测报告一模一样。

## 3. 非目标

- 改数值本身（值是真的，病在窗口不冻结 / 多源无桥接）。
- 把 chain_integrity 计算搬去 Platform（它是 Core 自算，Platform 只引）。

## 4. 验收

1. 白皮书 §5.2/§5.4 引的每个数都能追到一份 **pinned run**（窗口 + WAL 段 sha + 日期 + n），第三方可复算。
2. 任何文档里作为"现值"的 ≈4% / 57% / n=463 / n=520 已清（标历史 / 标合成）。
3. provenance artifact 的三个 ⏳（注入两版规则集、chain 规范 run、9.2-A 露出项配置）全部补齐。
4. 注入进步叙事成立且可复现："同 28-case 语料（git 未动）+ 规则 ≈0→57→89"。
5. 🔴 **每个对外指标只有一个规范来源**（§5）：随机抽三个对外数字，各自只能追到**一处**规范值，
   不存在"两张表都写着可直接引用、取值不同"的情形。

## 5. 🔴 仲裁映射（每个对外数字恰好一个规范来源）

冻结后出现了**两次都合法的 pinned run**（`__eval__` chain 规范 run / `acme` 注入规范 run），
它们**在 7 个指标上重叠且取值不同**（`redaction_hit_ratio` 相差 10 倍：2.52% vs 24.53%；
`chain_integrity` n=173 vs n=73）。两张表若都标"可直接引用"，写手就能在两个官方值之间挑一个更好看的
—— **这正是 PROV 要治的病本身**，只是形态从"移动窗口"换成"两个规范 run"。

**规则（是规则，不是随手挑）：**
① 只有一次 run 测到 ⇒ 就是它；
② 两次都测到 ⇒ 取 **n 更大**、且 tenant 为**评测专用** `__eval__` 的那次；
③ 注入族只有 live 驱动的那次 run 有。
其余一律标 **"同 run 附带，不得对外引用"**。

**两个 gating 白皮书的规范值（其余见下方权威表）：**

| 对外指标 | 规范值 | n | tenant | 白皮书动作 |
|---|---|---|---|---|
| `chain_integrity` | 100% | **173** | `__eval__` | §5.4 line 249 + HTML 块 line 216：**463 → 173** |
| `injection_catch_rate` | **89.29%**(25/28) | 28 | `acme` | §5.2 保持 89%，补两版规则集号后解禁 |

> **完整 9 行映射表以对账 artifact
> [CORE_INJECTION_NUMBER_PROVENANCE §5.0](../../trustworthy-ai-platform/docs/collab/CORE_INJECTION_NUMBER_PROVENANCE.md) 为唯一权威，
> 本文不复制** —— 同一张表放两处必然漂移，那恰是本 issue 要消灭的失败模式。

**🔴 404 与 463 一并作废。** 404 从来不是"待 pin 的候选"，它和 463 同病（`window=[0,0]` 移动快照），
且**覆盖它的 WAL 段已被裁掉**（实测 `11442–11605` 半小时内整段消失），**已无法补 pin**。
把 463 换成 404 只是把病搬个家。规范 n 是冻结窗口里实际的 n = **173**。

**附带结论（对外措辞硬约束）：** 9.2-A 那几个数（`redaction_hit_ratio`/`duration_p99`/`boundary_breach_rate`…）
是**语料相关量，不是环境属性** —— 两次 run 差 2.5～10 倍，源于探针组合不同而非抖动。
故**永远不能写成"本系统的 PII 脱敏率是 X"**，只能写成"**在〈语料 + 口径〉上测得 X**"。

**交付完整性：** `injection_catch_rate` 的第三方复算依赖那 28 个 `request_id`
（窗口+租户单独只圈出 **53** 个）。冻结目录**必须连带 `evidence_refs` 的 bundle 一起交**。
