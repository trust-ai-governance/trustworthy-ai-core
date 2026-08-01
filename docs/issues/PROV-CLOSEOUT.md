# PROV-CLOSEOUT — 9.2-A 收口：(c)「标注未测定」的可下发施工单

> **Problem（普通话）：** PROV 的 Core 侧只差 9.2-A 的 `block_rate` / `duration_p99`。
> 但**核对冻结产物后发现，缺口比 PROV §2.2 写的小、也更具体**：
> `block_rate` **早已测过并已带诚实口径注**；真正的缺口是 **`duration_p99` 的口径注是空的** ——
> 而它恰恰是**最需要口径**的那个数（59839 ms 取自故意含 LLM10 压力用例的探针批）。
> 更要紧的是：合成的 `780 ms` 曾被用来把「60s p99 blocker」标成**已解决** ——
> 🔴 **那个"已解决"建在自证的合成数上，无效，必须撤。**
>
> **Value:** 用**零测量成本**把这两个数从"有值但口径不明"变成**明确的「未测定 —— 无代表性流量」**，
> 并撤掉一个建在合成数上的工程结论。(c) 档立即可做、完全诚实；(b)/(a) 是后续，不阻塞本单。
>
> **归属：** Implementer 编码 + 测试。**规模：小（无新测量、无新指标）。**
> **裁定来源：** PM 已拍 **(c) 立即执行 + 撤 780ms 的无效"已解决"**；(b) 下一步、(a) 等 POC。
> **承：** [PROV](PROV.md) §2.2 · [EV-PIN](EV-PIN.md)（pin 机制已就绪）。
>
> **本轮下发范围（2026-07-30 更新）：件一 · 件二 · 件三 · 件五。**
> **件四已随披露收口落地**（政策落点 = [DISCLOSURE_POLICY](../DISCLOSURE_POLICY.md) §6），不再下发。
> **件五是本轮新增**：配对 delta 缺「可引性」判词（§5）—— 同属 provenance 收口，故并入本单。
> **Live Test：只有件五需要，且用现成 bundle 即可，不需重跑网关（§7）。**

---

## 0. 现状核对（对着冻结产物与代码，2026-07-28）

| PROV §2.2 的说法 | 实际 | 结论 |
|---|---|---|
| 「`block_rate` 从未跑过」 | 🔴 **过时** —— 冻结 artifact 里有 `block_rate = 0.7731 · n=119 · canonical_source=true`，**且 notes 已写明**：*「语料相关量：本 run 的探针以攻击用例为主，故此值是「对该攻击语料的拦截比例」，不是生产流量的拦截率。对外引用前必须先有代表性流量上的测量」* | ✅ **已达 (c) 标准，本单只需复核措辞** |
| 「`duration_p99` 需代表性流量测量」 | ✅ 属实，**且更糟：`duration_p99 = 59839 · n=27` 的 notes 是空的** | 🔴 **本单的主要活** |
| demo 三态（④） | ✅ 已闭环：`data_source: "synthetic_demo"` + 渲染层「示例数据」标 | 无需再做 |

🔴 **⇒ 本单的真实范围不是"补两个数"，是：给 `duration_p99` 补口径注 + 撤那个无效的"已解决"。**

---

## 1. 件一 🔴 `duration_p99` 补口径注（冻结 artifact）

**问题**：`59839 ms · n=27` 是 canonical 值，却**没有任何 notes** —— 读者无从知道它取自
**故意含 LLM10 unbounded-consumption 压力用例**的探针批（被自家压力用例拉高是**设计使然**）。

**范围**：给该 measurement 补 notes，措辞**与 `block_rate` 已有的那条对齐**（同一纪律、同一句式），至少覆盖：
1. **它是流量相关量**，不是环境属性；
2. **本 run 的流量构成**：`__eval__` 探针批，**含 LLM10 压力用例**（值被拉高是设计使然）；
3. 🔴 **对外引用前必须先有代表性流量上的测量**；
4. **并列已知值及各自口径**：`780 ms`（合成 demo）/ `12156 ms`（`acme` 评测，2026-07-31 实跑）/
   `23836 ms`（`acme` 评测，另一次）/ `59839 ms`（本值，含 LLM10 压力用例），
   **说明四者跨度约 77 倍、无一可代表生产**。
   🔴 **注意 `12156` 与 `23836` 是同一租户、同一类批次的两次跑，差 ~2 倍** ——
   **这比"合成 vs 真实"那个跨度更能说明问题：连口径相同的两跑都差一倍，单点 p99 不构成结论。**

**验收**：`duration_p99` 的 notes 非空，且含上述四点；与 `block_rate` 的口径注句式一致（复核可读性，不要求逐字相同）。

---

## 2. 件二 🔴 撤销建在合成数上的「blocker 已解决」

**事实**：`tools/make_demo_report.py` 里 `duration_p99 = 780.0 ms · n=240`，源码注释逐字写着
*「a HEALTHY latency baseline — 780 ms, not 60 s (good demo optics)」* —— **它是为了 demo 好看而选的合成值**。
该值曾被用来把「60s p99 blocker」标成**已解决**。

🔴 **裁定（PM）：那个"已解决"无效，必须撤。** 合成数据不能替真实测量作证。

**范围（Core 侧）**：
- 在 Core 文档中凡出现「60s p99 blocker 已解决」或等价表述之处，改为**诚实重述**：
  > **p99 在代表性流量上未测定**；`__eval__` 压力批下约 60 s（含 LLM10 压力用例，设计使然）；
  > **「blocker 已解决」不能靠合成的 780 ms 立着。**
- 🔴 **保留 780 ms 本身**（demo 需要它），但**它已被 `synthetic_demo` + 渲染层「示例数据」标住**（④ 已闭环）——
  本件不改 demo，只**撤掉基于它的工程结论**。
- **Platform 侧的对外材料由 PM 处置**（白皮书两格保持「未测定/待代表性流量」）—— 不在 Core 范围。

**验收**：Core 文档中不再存在「基于 780 ms 的 blocker 已解决」表述；替换后的措辞含"未测定"与"压力批下约 60s"两层。

---

## 3. 件三：`block_rate` 口径注复核（很小）

已达标，本单**只复核**：其 notes 是否同时含①语料相关量 ②本 run 流量构成 ③对外引用前需代表性测量。
**缺哪条补哪条，不重写。**

---

## 4. 件四：把「流量口径政策」写进公开纪律面 —— ✅ **已落地（2026-07-29）**

PROV/EV-PAIR 共用同一政策（PM 已裁为常设纪律），**Core 公开侧需要一处可引的落点**，
否则每个 issue 各写一遍、迟早分叉。

✅ **落点：[DISCLOSURE_POLICY](../DISCLOSURE_POLICY.md) §6**（随披露收口一并提交）。已含三档 (a)/(b)/(c)、
76 倍跨度证据、以及两条硬纪律（①数字自带流量口径 ②`block_rate` 排除裁定不得翻）。
**本件不再需要下发；后续 issue 引 §6，不重述。**

---

## 5. 件五 🔴 配对 delta 不自带「可引性」判词（本轮新增，随件一~三 一同下发）

**问题**：`pair` 出的每条 delta 已带 `corpus_sha` / 两侧 n / 两侧 `evidence_basis` / `traffic_tier`
——**但没有任何一句话说"这个数能不能对外引"**。而 delta 恰恰是最会被拿去做胶片的那个数。
实测：手上那份 75%→25% 的产物，**任何人拿 `/tmp/pair.json` 直接做片都不会被挡一下**。

🔴 **这是 [DISCLOSURE_POLICY](../DISCLOSURE_POLICY.md) §6 硬纪律①的同族缺口**：流量口径已同框，**可引性判词没有**。

### 5.1 🔴 先钉死：`pinned` **不是**这里的钥匙（否则会挂错锚）

直觉上"未 pin ⇒ 不可引"（[EV-PIN](EV-PIN.md) §1.4），**但对配对产物不成立**，理由是机制层面的：

| | 由谁产出 | `pair` 读不读 |
|---|---|---|
| `CURATION` 的 6 个指标（含门 7 的 `injection_catch_rate`） | **本跑的主动探针**（决策侧读探针自己的 `evidence`；输出侧读 `response_text`/`canary`/`marker`） | ✅ **全读** |
| `PASSIVE` 的一组指标（`chain_integrity`/`duration_p99`/…） | **被动 WAL 窗口扫描** | ❌ **一个都不读** |

而 **`pinned` 钉的是那个被动窗口** —— 一组 `pair` 从不触及的指标。
⇒ 🔴 **把 `citable` 建在 `pinned` 上，等于用一个和 delta 里每个数都无关的标去证明 delta 可引。**

**佐证（两份真 bundle）**：`raw_model` 侧 `window: null` / `wal_dir: null` / `record_count: 0`
—— 根本没有窗口可钉；而 `collect` 里 `pinned = window_from is not None and window_to is not None`
**不看 `target_kind`**，所以给裸模型跑传上窗口参数会盖一个**毫无所指的 `pinned: true`**。
（这条 `collect` 语义缺陷本单**不改**，登记进 §8。）

**裸模型侧真正的可复算锚是 `corpus_sha` + `model` + `temperature`** —— 已被门 3 / 门 4 检着。

> **写下这一节是因为下一个人一定会去加 `pinned`。** 这里记着为什么不加。

### 5.2 真正的两条阻塞

| 阻塞 | 判据 | 今天的实况 |
|---|---|---|
| **流量口径** | `traffic_tier != a_real_traffic` ⇒ 只 NDA/下界口径，不进对外 headline（§6 (b) 档） | `b_assumed_mix`（默认）⇒ **命中** |
| 🔴 **统计功效** | delta **必须大于自己的区间宽度**：`delta <= ci_hw(raw) + ci_hw(gw)` ⇒ 该 delta **不构成结论** | 见 5.3 —— **旗舰那条命中，另一条不命中** |
| 🔴 **良性对照臂缺失** | 该 delta 没有同框的 `benign_compliance_rate`（未测 / `insufficient_data` / 不在 bundle 里）⇒ **对外不可引**（内部迭代仍可用） | ⏳ 今天**全部命中** —— 良性臂尚未建（[EV-CAPCTRL](EV-CAPCTRL.md) §5.1.1；PM 2026-07-31 签） |

### 5.3 🔴 用 Wilson 区间，不用 Wald（否则 0%/100% 会被伪造成"确定"）

以手上的真数算（95%）：

| delta | 两侧 n | 半宽之和 | delta | 判词 |
|---|---|---|---|---|
| `injection_success_rate` 75% → 25% | **8 / 8** | **0.52** | 0.50 | 🔴 **不构成结论** —— n=8 就是 6 例 vs 2 例；**且只差 0.02** |
| `sensitive_disclosure_rate` 93% → 0% | 14 / 14 | **0.24** | 0.93 | ✅ 功效足够 |

⚠️ **订正（实现后实跑复核）**：早先手算的 0.60 是 Wald 式估计；**Wilson 实测是 0.52**。
结论不变（0.50 ≤ 0.52 仍判欠功效），🔴 **但余量只有 0.02** —— 这条 delta 距「勉强成立」只差一两个样本。
**这更说明扩 n 的必要，也说明不要拿这 0.02 去争「其实差不多够了」。**

🔴 **必须用 Wilson**：Wald 在 `p=0` / `p=1` 处宽度为 **0**，会把"14 例里 0 次"当成**零误差的确定值**
—— 那正是"边界处伪造确定性"，和假 0% 同一族。**本仓已有区间口径的先例**（`recall_at_fpr` 返回
`(low, point, high)`），沿用同一约定，不要新造。

### 5.4 落成方式：**披露字段，不是门**

🔴 **`pair` 不因不可引而拒绝出数** —— 内部迭代正是靠读这些 delta。它只需**不许这个数冒充可引数**：

- 每条 delta 加 **`citable: bool`** + **`citable_blockers: list[str]`**（人可读、**指出可操作方向**）；
- 每条 delta 加 **`raw_ci` / `gateway_ci`**（Wilson，`[low, high]`），与值**同框**；
- `pairing` 顶层给一条汇总 `citable`（全部 delta 皆可引才为 true）。

**blocker 文案（示意，实现可调，但必须可操作）**：
- `"traffic_tier=b_assumed_mix — NDA/下界口径 only, not an external headline (DISCLOSURE_POLICY §6); needs (a) real traffic"`
- `"underpowered: delta 0.50 <= combined 95% CI half-width 0.60 (n=8 vs 8) — grow the corpus or raise n"`

**验收**：
- 手上两份 bundle ⇒ `injection_success_rate` 的 delta **仍被产出**，但 `citable:false` 且
  blockers **同时**含流量口径与功效两条；`sensitive_disclosure_rate` 只含流量口径一条；
- `traffic_tier=a_real_traffic` + 功效足够 ⇒ `citable:true`、blockers 空；
- 🔴 **回归带牙**：断言 `citable:false` 的 delta **在 `deltas[]` 里**（不是被移进 `rejected[]`）——
  它是披露，不是门；
- 🔴 **Wilson 回归**：`0/14` 与 `14/14` 的区间宽度 **> 0**（Wald 实现会让这条测试红）；
- **`pinned` 不参与 `citable` 计算**（测试：raw 侧 `pinned:true`、网关侧 `false` ⇒ 判词不变）。

---

## 6. 非目标

- **不做**新测量（(b) 代表性语料、(a) 真实流量都不在本单）。
- **不改**任何指标计算（`BlockRate`/`DurationP99` 实现不动）。
- **不改** demo 生成器的 780 ms（它已被三态标住；本单只撤基于它的结论）。
- **不推翻** `block_rate` 在评测流量上的排除裁定。
- **不动** Platform 侧对外材料（PM 处置）。
- 🔴 **不给 delta 加 `pinned`**（§5.1：挂错锚）；**不改** `collect` 的 `pinned` 语义（登记进 §8）。
- **不把 `citable` 做成门** —— 它是披露字段，`pair` 照常出数（§5.4）。

---

## 7. Live Test 效果（明确回答：这些小改动要不要 live 跑）

| 件 | 要不要 Live Test | 怎么验 |
|---|---|---|
| 件一 `duration_p99` 口径注 | ❌ **不需要** | 改的是**冻结 artifact 的 notes**，无新测量。验法：冻结产物回归 + 渲染守卫 + 披露门 |
| 件二 撤 780 ms 结论 | ❌ **不需要** | 纯文档措辞。验法：全仓 grep 无「blocker 已解决」等价表述 |
| 件三 `block_rate` 口径注复核 | ❌ **不需要** | 同件一 |
| **件五 `citable` 同框** | ✅ **需要，且零成本** | 见 §7.1 —— **不需要重跑网关**，用手上两份 bundle 就能验完 |

> 🔴 **说实话：本单四件里只有件五有 live 价值，而它连新跑都不需要。**
> 不要为了"跑一下"去重跑网关 —— 那只会产出新的一批 WAL 与新的 108 次调用，验不到任何本单的东西。

### 7.1 件五的 Live Test（用现成 bundle，纯本地）

```bash
PYTHONPATH=$PWD python -m treval.cli pair /tmp/raw.json /tmp/gw.json --out /tmp/pair.json
```

**必须看到（否则件五没做对）：**

1. `injection_success_rate` 的 delta **仍在 `deltas[]` 里**，带 `citable: false` 与**两条** blocker
   （流量口径 · 功效不足 n=8）；
2. `sensitive_disclosure_rate` 的 delta `citable: false`，但**只有流量口径一条** blocker
   —— 🔴 **这是判别实现对不对的关键一跑**：如果它也报"功效不足"，说明用了 Wald（0/14 处宽度为 0
   会算出 delta 远大于半宽… 或反之实现错向），**回去看 §5.3**；
3. 两条 delta 都带 `raw_ci` / `gateway_ci`，且 `0/14` 那侧的区间 **宽度 > 0**。

**这一跑的产出价值**：手上那张 75%→25% 的旗舰图**从此自带"不可引 + 为什么"** ——
而且它会第一次把「**n=8 撑不起 50 点 delta**」这句话写进产物本身，
不再依赖有人记得去问一句"样本多少"。

---

## 8. 后续（不在本单，登记）

| 档 | 内容 | 触发条件 |
|---|---|---|
| **(b)** | 代表性混合语料（良性为主 + 声明比例的攻击）+ 一次 pinned run，两个数**同一次测** | lead/售前定"是否发布 assumed-mix 图"后 |
| **(a)** | 真实 POC 流量上复测 | 有真实流量（今日 `acme` 仅 49 条，n 不足） |
| 🆕 **语料功效** | 🔴 §5.3 的直接推论：**`output_marker` 用例只有 8 条**（全在 `llm01_prompt_injection`）⇒ 旗舰 delta 结构性欠功效。要让它成为结论，**先把 marker 用例扩到 n≥30** | 与 [EV-CAPCTRL](EV-CAPCTRL.md) 的良性孪生语料**同一批工作**，建议并做 |
| 🆕 **`collect` 的 `pinned` 语义** | `pinned` 不看 `target_kind`，裸模型跑可盖一个无所指的 `pinned:true`（§5.1）⇒ 应在 `raw_model` 下拒绝窗口参数或不盖 `pinned` | 小；独立收 |

🔴 **(b) 的用法已由 PM 钉死**：它产的是「在**假定流量口径**下的数」，**不是生产数** ——
标签写死「assumed-mix vX · 攻击占比 Y% · 非生产实测」，**只在 NDA/下界口径下给，不进对外 headline**。
