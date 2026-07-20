# EV-PIN — 冻结评测 run（pinned run：消除移动窗口，对外数字可复现）

**Problem（plain language）：** 今天 `collect` 产出的报告**窗口恒为 `[0,0]`**（`treval/cli/collect.py` 自述
"active-eval is not time-windowed"），且 collect **没有任何窗口/段参数**。于是任何从这份报告引到对外文档的
数字，都是对一个**移动窗口**（`__eval__` 的"0-0 最新"）的快照 —— WAL 尾部一前移，同一次引用就**不可复现**。
这已经现场咬人：白皮书 §5.4 的 `chain_integrity 100% n=463` 就是从移动窗口抓的快照，后来窗口前移读到 n=404，
**463 再也复现不出来**（见 [CORE_INJECTION_NUMBER_PROVENANCE](../../trustworthy-ai-platform/docs/collab/CORE_INJECTION_NUMBER_PROVENANCE.md)）。
更糟：我手上"替换用"的 n=404 bundle **窗口也是 `[0,0]`** —— 换过去只是把病从 463 搬到 404。

**Value：** 给 Core 一种**冻结一次 run** 的能力：run 绑定**明确窗口 + WAL 段范围 + 日期 + 语料/registry sha**，
落成一份可复现的 pinned artifact。对外数字从此**只能引 pinned run**，第三方拿同样的 WAL 段能算出同样的 n 和值 ——
这正是"可验证审计"产品该有的底座（一个卖可复现的产品，头条却引一个自己都溯源不了的数，是自我拆台）。

> Dev brief. **前置**：无（`WalEvidenceReader` 已支持窗口，见 §0）。**解锁**：PROV（冻结唯一规范 run）、
> 对外任何 live 数字。**规模**：小 —— reader 能力已在，主要是 producer 侧接线 + 印记落盘。

---

## 0. 已验证的地基（对着代码，2026-07-19）

1. **reader 已能窗口 + 按段读**：`treval/readers/wal_reader.py:87-89` 有 `time_from_ns` / `time_to_ns` 过滤，
   `list_segments()` 逐段读。**能 pin 的机制在，只是 collect 不驱动它。**
2. **collect 产出 `window=[0,0]`、无窗口参数**：`collect.py` 对 active+passive run 留窗口为 `(0,0)`。
   → 报告不带真实观测窗口，无法复现。
3. **`chain_integrity` 是 Core 自算**（`treval/indicators/chain_integrity.py`：读 `AuditEvidence.integrity`）。
   所以"冻结规范 run"是 Core 的活，Platform 只引不算。

## 1. 范围（做什么）

1. **collect 记录真实观测窗口**（下限，必做）：不再落 `(0,0)`，而是落本次读到的记录的
   **真实 `min/max received_at_ns`**（参考 scratchpad `passive_report.py` 已这么做）。这样每份报告至少**自带**它覆盖的窗口。
2. **collect 接受显式窗口边界**（pin，必做）：`--window-from-ns` / `--window-to-ns`（或 `--since` / `--until`），
   透传到 `WalEvidenceReader` 的 `time_from_ns/time_to_ns`。给定边界 ⇒ **run 可复现**（同 WAL 段 + 同窗口 = 同结果）。
3. **run 印记落盘**（pin artifact）：pinned run 的 bundle 额外带
   `{window:[from,to], wal_segments:[首段..末段], generated_at_ns, registry_fingerprint}`，
   并计算 **WAL 段内容 sha**（覆盖的 segment 文件字节哈希）—— 第三方据此核"跑的是这批 WAL"。
4. **"是否 pinned" 显式可判**：bundle 带 `pinned: true|false`。`false` = 移动窗口快照（如 `0-0 最新`），
   **对外文档禁止引用 `pinned:false` 的数**（这条进 PROV 的对账纪律 / 将来可做 CI 守卫）。

### 1.5 收尾补充（第一轮实现后的 live 复核发现，2026-07-19）

> 第一轮实现已合格并通过 live 验证（同窗口两跑 n/value 完全一致；半开窗口的洞察经实测坐实——写成闭区间会**恰好少读 1 条**）。
> 以下三条是**我在 §1.3 里写漏的一环 + 窗口变真后暴露的 UI 缺口**，合成一个小补丁收尾。

1. 🔴 **`provenance` 必须贯穿到交付 bundle（我 §1.3 只写了 collect 侧，漏了下游）。**
   实测：`GET /report.json` 顶层键只有 `['measurements','registry','registry_fingerprint','report','schema_version']`，
   **没有 `provenance`**，`report` 内也没有 `pinned`。⇒ `report --self-contained` 产出的 EV-R1 交付 bundle
   **丢掉了 pin 印记**，UI 因此**无法区分 pinned 与 unpinned 报告**。这直接架空 §1.4 的纪律：一份
   `window=0-0` 的旧报告在 UI 里和 pinned 报告长得一模一样，看不出它不可对外引用。
   - **做法**：`serialize_self_contained_bundle` 透传 `provenance`（连同 `pinned`）；`treval report --self-contained`
     从 measurement bundle 读到就带上，读不到则明确置 `provenance: null`（**不伪造**，旧 bundle 本就没有）。
   - **理由**：PROV 的规范 run 必须能在**交付物上自证 pinned**，否则第三方拿到 bundle 无从判断该不该引用。

2. **UI 标出 pinned / unpinned。** 报告页显式标注"未固定窗口 · 不可对外引用"（unpinned）
   vs "已固定窗口"（pinned）。措辞面向客户，别用内部术语；`provenance: null`（EV-PIN 之前的旧报告）
   按 unpinned 处理。

3. **窗口标签要人类可读。** 窗口变真之后，下拉里现在是裸纳秒：
   `1784461551481085225–1784462268427192905`——19 位数字，两个选项只在中间几位不同，**用户没法靠读分辨**
   （`0-0` 时代不暴露，窗口变真才显形）。改为可读时间（如 `2026-07-19 19:45 → 19:57 UTC`），
   EV-W2 已有 `ts()` 先例可复用；保留原始 ns 作 `title`/value 不变（value 是选择键，**不要动**）。

## 2. 非目标

- 不改任何指标的计算（值本身是对的；病在窗口不冻结）。
- ~~不做 UI 的窗口选择器改造（backlog #4）~~ → **#4 已由 EV-PIN 消解**：其根因是 active run 恒出
  `window=[0,0]` 导致所有窗口键相同（两个 option 同值且都带 `selected`，非法 HTML）。窗口变真后键自然唯一，
  实测「3 option / value 各不相同 / 恰好 1 个 selected / 恰好 1 个(最新)」。**不需要再改选择键**；
  §1.5-3 只改**标签渲染**，不动 value。
- 不做生产租户被动读（那是 #6；EV-PIN 只解决"窗口能冻结"，不碰租户隔离/PII）。

## 3. 验收

1. `collect --window-from-ns A --window-to-ns B` 产出的 bundle：`window==[A,B]`、带 `wal_segments` 段范围、
   带 WAL 段 sha、`pinned:true`。
2. **可复现**：同 WAL 目录 + 同 `[A,B]` 跑两次 → **同 n、同 value、同段 sha**（byte-identical 的度量部分）。
3. 不给边界时：`window` == 本次真实 `min/max received_at_ns`（不再是 `[0,0]`），`pinned:false`。
4. `chain_integrity` 在 pinned run 上：n 恒定（不随 WAL 尾部前移变化）。
5. 门禁不回归；`import treval` 不拉 web/PG。

### 3.6 收尾补充的验收（对应 §1.5）

1. **贯穿**：`treval report --self-contained` 产出的 bundle **顶层含 `provenance`**（含 `pinned`）；
   `GET /report.json` 返回的字节里同样能读到 —— 即 pin 印记从 collect 一路到交付物不丢。
2. **不伪造**：用一份 EV-PIN 之前的旧 measurement bundle（无 provenance）跑 `--self-contained`，
   交付 bundle 里 `provenance` 为 **null**，**不是**编造出来的窗口/sha。
3. **UI 可判**：pinned 报告与 unpinned 报告在页面上**肉眼可区分**；`provenance:null` 的旧报告按 unpinned 呈现。
4. **标签可读**：窗口下拉的 label 是可读时间，**value 仍是 `<from>-<to>` 原始 ns**（选择键不变，
   切换/深链不回归）。回归守卫加一条：label 不得是裸 19 位数字。
5. 现有 528 项门禁不回归；渲染守卫（EV-W2）继续通过。

## 4. 与 PROV 的关系

PROV 的"冻结唯一规范 run"**依赖本 issue**：先有 pin 能力，才能把规范 chain_integrity 冻成可复现的一次 run
（而不是又一个"最新"快照）。§1.5-1 是这条依赖的**关键环**——交付物不带 pin 印记，PROV 就无法自证。

🔴 **且 pin 窗口本身还不够（live 复核实证）**：`/home/olvan/wal` 的段在**分钟级被裁**
（实测 `11439`/`11441` 十分钟内消失；半小时后 `11442–11605` 整段区间全没）。所以规范 run 必须
**连段字节一起冻结**。已冻：`/home/olvan/prov/canonical_wal`（11 段、185 记录全 VERIFIED、
sha `be827a1c…`），候选规范值 **`chain_integrity n=173 value=100%`**（`__eval__`，
窗口 `[1784461551593936504, 1784462278375026879)`，两跑一致）。详见该目录的 `canonical_wal.README.md`。
