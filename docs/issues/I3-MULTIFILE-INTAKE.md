# I3-MULTIFILE-INTAKE — 文件分组多输入（`i3_run`/loader 真语料 intake 规格）

> **Problem:** `i3_run` / `load_verdict_runs` 现在吃**单 verdict 文件 + 行号切分**（`--benign 1,2 --violating 3`）——
> 那是 3 探针 smoke 的形态。真语料运行产**多个独立 verdict 文件**（violating / benign / benign-meta 各一），
> 良性/违规由**文件归属**承载（C1 §3 Flag 1），每文件是 per-`(line, repeat)` 行。单文件+行号形态不适用。
>
> **Value:** 把 loader + CLI 泛化为**文件分组多输入**：case_id 按组命名空间（防行号跨文件相撞）·
> **保留 `repeat` 转置**（warmup-drop 照旧生效）· 加 `--dry-run` 预检。**内容无感**；真语料是本地、仓外的消费者。
>
> **归属：** Implementer 编码 + 测试；架构师出本规格。🔴 **语料/verdict 在仓外、本地私有路径、永不进公开仓**（红线）——
> 本文只描述**接口**，零语料正文、零测量数字、零私有路径。
>
> **承：** [C1-STABILITY-CURVE](C1-STABILITY-CURVE.md)（承载缝 + `score_stability`/`roc_curve` + warmup-drop）。

---

## 1. 四缝 ratify（已闭合，2026-07-25）

| 缝 / Q | 定案 |
|---|---|
| **A 文件级多输入** | 🔴 **Core 需改**（§2）：`load_verdict_groups`，case_id `{group}:{line}` 命名空间;向后兼容旧单文件形态 |
| **B score 极性随 contract** | ✅ **ACK**（§3）：Core 读 `score` 为 P(bad)，极性生成侧处理，Core 不推 |
| **C 暖机丢弃** | ✅ **Core 丢 `runs[0]` 零改**（§4）+ 生成侧 `warmup=1` **双丢无害**;🔴 硬要求 = loader **保留 `repeat` 转置**（§4.1 有样本预算注记） |
| **D 门口径 + 诚实边界** | ✅ **ACK**（§5） |
| **Q1 dry-run 靶** | ✅ **`i3_run --dry-run` = verdict 级**;**语料级预检归生成侧**（其已有校验工具）—— 两级分开，Core 不建 corpus-preflight |
| **Q2 meta 双 contract** | ✅ 生成侧补产 meta@violate（随重跑一并）;D3 分叉用。🔴 **但两 contract 必须分开加载 —— 见 §2.1，混装会掐掉整轮** |
| **Q3 safe 极性** | ✅ 实测确认 = P(unsafe) = P(bad)，`score>=τ` 两 contract 通用 |

---

## 2. 缝 A — 文件分组多输入（代码改动）

**CLI（`i3_run`）：**
```
python -m treval.active_eval.i3_run \
  --violating   <verdicts-file> \
  --benign      <verdicts-file> \
  --benign-meta <verdicts-file>     # 可选
  [--dry-run]
```
保留旧 `--verdicts <file> --benign/--violating <行号>` 单文件形态（smoke 向后兼容）。

**Loader（新增，不改现有 `load_verdict_runs`）：**
```python
def load_verdict_groups(
    files_by_group: Mapping[str, str],   # {"violating": path, "benign": path, "benign_meta": path}
) -> tuple[list[list[ProbeResult]], dict[str, list[str]], dict[str, str]]:
    # → (runs, side_case_ids, content_class_by_case_id)
```
- 🔴 **case_id 按组命名空间**：`f"{group}:{line}"`（防 `violating` 的 line 1 与 `benign` 的 line 1 相撞）。
- **`runs` = 跨所有组、按 `repeat` 转置**（`runs[k]` = 全部 case 在 `repeat==k`）—— 喂 `score_stability` 全量，**保留 §4 的 rep0-drop 语义**。
- **`side_case_ids`**：`{"benign": [...], "violating": [...]}`，`benign = benign ∪ benign_meta` 组的 case、`violating = violating` 组 —— 喂 `roc_curve` 两侧切分。
- **`content_class`** 逐 case 从行内读（per-class 切片）。**复用现有 `verdict_to_probe`**（字段映射不变）。

**`--dry-run`（Q1 定案 = verdict 级）：** 只装载 + 报**每组条数 · 每 line 的 repeat 数 · content_class 覆盖 · 解析错**，
不跑指标、不打分。**语料级预检（`{text, content_class}` 那层）归生成侧的既有校验工具，Core 不建** —— 两级分开，别混一个入口。

### 2.1 🔴 一次加载 = 一个 contract（Q2 引出的硬约束，已实证）

**同一 `case_id` 下混装两个 contract 的观测 ⇒ 该 case 的分数在"重复"维度上横跨两个分布 ⇒ `span>0` ⇒ 判为非确定。**
实证（对着产品代码跑）：把 meta@violate 与 meta@safe 混进同一 case_id ⇒
`deterministic_fraction=0.0 · curve_eligible=False` —— **整轮曲线被静默掐掉**;分开加载则 `1.0 / True`。

⇒ **规则：`load_verdict_groups` 一次只吃一个 contract 的 verdict 集**（主跑 = violate 的三组;D3 分叉 = 另一次加载 safe 的 meta）。
- **D3 分叉 = 两次独立加载 + 分析步比对**（各自 `recall_at_fpr` / per-class FPR 并列），**不是**把两 contract 喂进同一 `score_stability`。
- 若将来确需单次混装，**命名空间必须含 contract**（`{contract}:{group}:{line}`）—— 但那样 per-case 确定性就变成"每 contract 各自确定"，
  语义已不同，**首跑不走这条**。
- **守卫**：loader 见到同一 `case_id` 下出现**多于一个 `contract` 值** ⇒ **报错**（fail loud），不静默产出假非确定。

---

## 3. 缝 B — score 极性随 contract（ACK）

- Core 把 `score` 读作 **P(bad)**（越高越该拦）。生成侧对**两种 contract 都产 P(bad)**（`violate`: P(是=violating)；`safe`: P(unsafe)）
  ⇒ `roc_curve` 的 `blocked(τ)=score>=τ` **两 contract 一致适用**，Core **不再自行推极性**；contract 已进 `vendor_version`。
- 🔴 **小订正**：`verdict_to_probe` 现硬编 `label="违规"`；`safe` contract 下 label 不准。但 `score_of` 读 `[0].score`、不读 label 串
  ⇒ **指标不受影响**。建议 label 随 contract 派生（cosmetic，可选）。
- **要生成侧确认**（§8-Q3）：`safe` contract 的 `score` 确为 **P(unsafe)**（bad 方向），使 `score>=τ` 对两 contract 都成立。

---

## 4. 缝 C — 暖机丢弃：Core 丢 rep0，零代码改动

🔴 **Core 的 `score_stability` 已经丢 rep0。** loader 按 `repeat` 转置 ⇒ `runs[0]` = **每条 case 的 rep0**
（不是某一文件的"全局第一遍"）；`score_stability` 丢 `runs[0]` ⇒ **每条 case 的冷 rep0 都被丢**。
⇒ **采纳 option 2（Core 丢 rep0），`score_stability` 零改**（与 C1 hermetic 的 `warmup_dropped` 承重同源、已有回归证过）。
- **唯一要求**：§2 的文件分组 loader **必须保留这个转置**（`runs[k]` = 跨所有组、第 k 个 repeat 的全部 case）。
- 生成侧 `--warmup 1`（源头已丢冷跑）+ Core 丢 `runs[0]` = **双丢，无害**（多丢一个**暖**遍，不影响确定性判定）。

### 4.1 🔴 双丢的样本预算（重跑前请确认，避免 n 不够）

Core 的 drop 是**按位置**而非按 `repeat` 值：`runs` 按文件中出现的 repeat 值**排序**，`runs[0]` = 最小的那个 repeat。
⇒ **无论 `repeat` 从 0 还是 1 编号，Core 都会丢掉最靠前的一遍。**

> **不变量：`n_used = (每 line 在文件里的 repeat 遍数) − 1`。**

⇒ 生成侧 `--warmup 1` 后，若文件里每 line 仍是 **7 遍** ⇒ Core 用 **6** 遍（与 smoke 一致，✅）;
若只剩 **6 遍** ⇒ Core 用 **5** 遍（仍有效，只是样本少一）。**重跑时按目标 `n_used` 反推遍数即可**;
`score_stability` 输出的 `warmup_dropped` 会如实显形丢了多少（= 一遍的条数）。

---

## 5. 缝 D — 诚实边界（报告层 ACK）

Core 的 `eval_report` 引用语料规模/质量时，**守语料侧钉死的 claim_wording**：分立溯源计数不合并成一个大数、门 `NA` 不称"通过"、
单人隔日盲复不称"双人背靠背"。**属诚实红线**（同报告层"不得暴露数字↔配置映射"的纪律）。无指标代码影响，是报告层前向约束。

---

## 6. 首跑非结论（反坍缩）—— Core 引用纪律

- **`roc_curve` 是 recall@FPR 的权威源**；该判官**绝对分极小** ⇒ 🔴 **必须 matched-FPR（`recall_at_fpr`），不是 `score>=0.5` 硬阈值**
  （0.5 读法是误读，会严重低估召回）。
- 首跑 = 多轴对照表**首行**，**非"选了 7B"**；**数字不进对外材料**（红线，C1 §7）。
- 未过双侧门 ⇒ 迭代轴 = contract / prompt / few-shot（**示例进 prompt ≠ 权重训练**，属契约轴），不是换模型、更不是训练。

---

## 7. 验收（可下发）

1. **文件分组 loader**：多 verdict 文件 → 命名空间 case_id、每组条数、`content_class` per case;`benign` 侧 = benign ∪ meta。
2. 🔴 **转置保留**：`runs[0]` = 每条 case 的 rep0;cold-rep0 fixture 上**丢 runs[0] ⇒ `curve_eligible=True`**、**不丢 ⇒ `deterministic_fraction<1.0`**（承 warmup-drop 承重）。
3. **`roc_curve` 切分**：benign = benign ∪ meta 组，violating = violating 组;单侧类不进 `by_class`（无假 0% FPR）。
4. **`--dry-run`**：每组条数 + 每 line 的 repeat 遍数 + content_class + 解析错，不跑指标。
5. 🔴 **单-contract 守卫（§2.1）**：同一 `case_id` 下出现多于一个 `contract` 值 ⇒ **报错**;
   teeth-check：混装两 contract 若不报错则会得 `curve_eligible=False`（已实证 `deterministic_fraction=0.0`）—— 断言报错而非静默假非确定。
6. **样本预算不变量（§4.1）**：`n_used == 每 line 遍数 − 1`;fixture 覆盖 `repeat` 从 **1** 起编号的情形（生成侧 `--warmup 1` 后），断言仍正确丢最靠前一遍。
7. **hermetic 回归**：新增**文件分组 fixture**（匿名化 content_class、真判官实录、保留冷 rep0），字节复现稳定性靶。
8. 门禁不回归 + **taxonomy-free 守卫覆盖新 fixture**（匿名占位，不烤真类目码）。

---

## 8. 开工状态

**四缝 + Q1–Q3 已闭合（§1）。本规格可下发 Implementer。**

- **Core 代码改动 = 仅缝 A**（§2 文件分组 loader + CLI 多输入 + `--dry-run` + §2.1 单-contract 守卫 + §7 fixture/回归）。
- **缝 B/C/D 零代码改动**（C 已由现有 `runs[0]`-drop 覆盖）。
- **不依赖真语料就位**：本 increment 用**匿名化文件分组 fixture** 做 hermetic 回归即可完工;真语料到位后直接跑。
- **与 C1（提交 A/B/C）互相独立** —— C1 那笔可先提。

**跑前对生成侧的两条提醒**（非阻塞，重跑时顺带确认）：① §4.1 样本预算（`n_used = 遍数 − 1`，按目标 n 反推 `--repeat`）;
② §2.1 主跑与 D3 分叉是**两次独立加载**，meta@violate 与 meta@safe 别混进同一次。
