# C1-STABILITY-CURVE — 方差/曲线指标（P3C-harness C1 主臂的可下发规格）

> **Problem（普通话）：** 选型 spike 要回答两件事 ——（1）某判官对**同一输入重复跑**到底稳不稳
> （"本地确定 vs 远程抖"，是产品论点的证据）；（2）在**同一误报率**下哪个判官召回更高。
> 现在 harness 有了延迟分位（C1-1）、`content_class` 切片（C3）、per-class FPR 三元组（C3-2），
> 但**没有把连续分数变成"方差数"和"(recall, FPR) 曲线"的指标** —— 这是主臂起跑的唯一内部前置。
>
> **Value：** 本增量落两个**纯函数** + `ProbeResult` 两个加性字段，把 §2.4.7 判官产出的连续分数
> `vendor_labels[].score` 变成（a）可诊断的组内方差 + 确定性判据，（b）逐 `content_class` 的
> 分数驱动 (recall, FPR) 曲线，并绑定 R2 §3.1 三条（稳定性门先过 · matched-FPR 比较 · 归一化首验）。
> **纯 schema/指标，不落 CLI/loader/运行时** —— 同 R1「只落契约、运行时另排」的纪律。

> **读者：** Core implementer（施工）· 架构师（本规格）· PM。
> **承：** P3C-HARNESS §2.4.7（判官适配器）· §2.4.8（确定性契约）· §3.1（R2 三条）· §C3-2（三元组分母纪律）。

---

## 0. 归属与边界

| 落 | 不落（本增量外） |
|---|---|
| `ProbeResult` 两个加性字段（§1） | verdict JSONL ↔ `ProbeResult` 的 loader → **提交 C（§9），下发 Implementer** |
| `score_stability(...)` 纯函数（§2） | CLI 编排 / `--repeat K` / `--warmup`（属适配器 CLI 侧） |
| `roc_curve(...)` + `recall_at_fpr(...)` 纯函数（§3） | 远程对照臂的适配器（gate 在数据条款之后） |
| 单测 + teeth-check | 跨候选头对头合成表（spike 分析步，用 §3 的 `recall_at_fpr` 拼） |

🔴 **两个函数都是纯的、确定的**（无 I/O、无网络）——同 `false_positive_by_content_class` / `duration_p*`。
它们**消费 `ProbeResult`**，不发任何数据。**涉政/非涉政的边界在适配器/CLI 层强制**（哪个语料喂哪个端点），
不在指标里 —— 指标对内容无感（§2.4.8 边界）。

---

## 1. `ProbeResult` 契约 delta（承载集，四字段）

🔴 **前置更正（implementer 2026-07-21 抓到，与 R1 同类）：`vendor_labels` / `VendorLabel` /
`vendor_version` 在代码里零命中** —— §2.2.4 是 C2 的**设计提案**，gated 在厂商准入之后，**从未落地**。
但两个纯函数都要靠它读分数（§2/§3）。所以承载集**不是"加两个 judge_ 字段"，是把承载缝一次落齐**
（同 R1 不是"加第三值"、是把 `target_kind`/`evidence_basis` 整块落 schema）。

```python
# ProbeResult 新增（全部加性、honest-default、WAL golden 零 churn）
@dataclass(frozen=True)
class VendorLabel:
    label: str; sub_label: str = ""; score: float = 0.0; level: str = ""

vendor_labels: tuple[VendorLabel, ...] = ()   # 判官分数的承载缝；自建产单标签，多标签候选产多条
vendor_version: str = ""                        # §5-3 归一化读法的 契约id 记这里（§6-8 验收要它）
judge_load_duration_ns: int = 0                 # 适配器自报 load_duration；缺省 0 = 未提供（honestly absent）
judge_reload_contaminated: bool = False         # 适配器派生：load_duration ≫ 常驻基线 ⇒ 真重载污染样本
```

- 🔴 **落字段（schema）不落适配器（运行时产 `vendor_labels`）** —— 与 §0、与 R1 同纪律：
  **承载缝为自建主臂现在就需要**（judge 要写分数），**C2 消费者（moderation 适配器）仍 gate 在数据条款之后**。
  落 bearer ≠ 拉 C2 进场。
- 🚫 **不落 `result_type`**（§2.2.4 里的人审分段字段）：本增量**无消费者** ⇒ 投机字段（CLAUDE.md §2）。
- **加性、带缺省** ⇒ 现有每处 `ProbeResult` 构造原样通过，**WAL 路径 golden 零 churn**（同 `content_class` 之于 `CorpusCase`）。
- 🔴 **`judge_reload_contaminated` 是适配器 TAG、指标 DROP**：Core 不自判重载阈值，
  只消费适配器已标的 flag。`judge_load_duration_ns` 仅供**显形**，不作二次判定。
- **不新增** ground-truth / 良性标签字段 —— 良性 vs 违规由**语料构成**给（§3），不塞进 `ProbeResult`。

---

## 2. 指标一：`score_stability` —— 方差/稳定性（"本地确定 vs 远程抖"）

**输入：** K 次重复整轮跑，**有序**（run[0] = 热身）：

```python
def score_stability(
    runs: Sequence[Sequence[ProbeResult]],
    *,
    score_of: Callable[[ProbeResult], float | None],   # §8 裁定 ii：调用方注入"违规分"提取器
) -> StabilityReport: ...
#   runs[k] = 第 k 次对整个语料的一遍； runs[0] 是热身遍，整遍丢弃（§2.4.8）
#   自建默认样例： score_of = lambda pr: pr.vendor_labels[0].score if pr.vendor_labels else None
```

**每 case 的处理：**
1. **丢热身**：`runs[1:]`。
2. **剔污染**：丢 `judge_reload_contaminated=True` 的样本（§2.4.8 逐样本自证）。
3. 取每次剩余样本的 `score = score_of(pr)`（注入的提取器，§8）；`None` ⇒ 该样本无分数、
   计入 `excluded`、不进方差；按 `case_id` 聚成 `n_used` 个有分数的样本。

**每 case 指标：**
- `span = max(scores) - min(scores)`；`variance = population variance(scores)`。
- 🔴 **`deterministic = (span == 0.0)`** —— **位级判据**（§3.0："确定性是二元的"）。
  `temp=0` + 单前向 ⇒ 同 logits ⇒ softmax 出**同一 float** ⇒ `span` 恰为 0。**EPS = 0，不设容差**。
- `n_used < 2` ⇒ `insufficient=True`（**honestly absent，不算进确定性分母，也不伪装成 0 方差**）。

**聚合（`StabilityReport`）：**
```
deterministic_fraction : float   # |{deterministic}| / |{n_used>=2}|
max_variance, mean_variance : float
contaminated_dropped : int       # 被剔的污染样本数（显形）
warmup_dropped : int             # = len(corpus)（整个 run[0]）
insufficient_cases : int         # n_used<2 的 case 数（显形）
curve_eligible : bool            # deterministic_fraction==1.0  AND  insufficient_cases==0
```

- **`curve_eligible` 是给 §3 的门**：本地判官钉死后应 `==True`；远程 API 通常 `==False`
  ⇒ 走点 + 波动带，不给曲线（R2 §3.1-1）。**任何本地非零方差 ⇒ `curve_eligible=False` 且方差数
  可直接指向"重载/非确定性"诊断**（这正是确定性契约的目的）。
- 内容无感 ⇒ 涉政（本地 only）与非涉政（可远程对照）同一函数。

---

## 3. 指标二：`roc_curve` + `recall_at_fpr` —— 分数驱动的双侧曲线

🔴 **不复用 `false_positive_by_content_class`** —— 那条读 WAL 判定（`pr.evidence`），而 logprob 判官
**无 WAL 证据**，会被它整批 `excluded`。本曲线是**分数驱动的平行度量**，只复用它的**三元组分母纪律 +
`content_class` 切片形状 + `""` 独立桶**（§C3-2 裁决 C），判据换成 `score >= τ`。

**输入：** 良性/违规由**语料构成**给（`corpus/llm01_benign/` = 良性；违规语料 = 违规），
调用方分好两组传入（不塞标签进 `CorpusCase`）：

```python
def roc_curve(
    benign: Sequence[CorpusCase],
    violating: Sequence[CorpusCase],
    results: Sequence[ProbeResult],      # 一遍代表性结果（已剔污染）
    stability: StabilityReport,          # §4 门：显式消费 A 的 curve_eligible + 每 case 波动带谱
    *,
    score_of: Callable[[ProbeResult], float | None],   # 同 §2，调用方注入
) -> CurveReport: ...
```

**判据（每 case、每阈值 τ）：**
- `measurable`：`score_of(pr) is not None`、`pr.error is None`、非污染。
- `excluded`：errored / 无分数 / 污染 —— **逐 class 显形**（同 C3-2，不静默蒸发）。
- `blocked(τ) = score >= τ`。
- `recall(τ)` = 违规侧 `blocked` 占**违规 measurable** 的比；`FPR(τ)` = 良性侧 `blocked` 占**良性 measurable** 的比。
- **两侧都逐 `content_class` 切片**（违规按类召回、良性按类过拦），`""` 独立桶。

**阈值网格：** 两组观测到的**全部不同分数** ∪ {0.0, 1.0}，升序 —— 给出精确阶梯曲线（标准 ROC）。

**`CurveReport` 形态：**
```
points        : list[(tau, recall, fpr)] | None          # curve_eligible 才发；否则 None（只给点+带）
by_class      : dict[content_class, list[(tau, recall, fpr)]] | None
excluded      : dict[content_class, (violating_excluded, benign_excluded)]  # 显形
def recall_at_fpr(target_fpr: float) -> tuple[float, float, float]   # 恒返回 (low, point, high)
```

- 🔴 **`recall_at_fpr` 恒返回三元组 `(low, point, high)`**（implementer #3）——
  `curve_eligible=True` 时 `low == point == high`（退化为点）；`False` 时 `low/high` 由该 τ 下各 case
  的 `score` 重复 min/max（取自 `stability.per_case` 的谱）算得。**调用方永远拿统一形状**，
  "点 + 波动带"成为默认呈现，无 union 分支。
- **`curve_eligible=False` 的候选**（§2）：`points`/`by_class` 发 `None`（不画曲线），
  只经 `recall_at_fpr` 给带（§3.1-1"方差大的只给点 + 明示波动带"）。

---

## 4. 落地顺序：稳定性门 gate 曲线（R2 §3.1-1）

**先 `score_stability` → `roc_curve` 显式收 `StabilityReport` → 内部据 `curve_eligible` 分支。**
顺序是硬的：不先证稳定就画曲线 = 把抖动画成漂亮曲线。门信号**从签名进**（implementer #4），
不靠调用方在外面绕。**建议两次提交**：
1. **提交 A = 承载集（§1 四字段）+ `score_stability` + 测试**（可独立验：×6 位级一致 ⇒ `deterministic_fraction=1.0`、`curve_eligible=True`）。
2. **提交 B = `roc_curve`/`recall_at_fpr` + 测试**（收 A 的 `StabilityReport`，据其 `curve_eligible` 与 per-case 谱出曲线或带）。

---

## 5. R2 §3.1 三条绑定（缺一条曲线就是装饰）

| # | 条件 | 本增量如何兑现 |
|---|---|---|
| 1 | **逐候选先过稳定性** | §2 `curve_eligible` 门；不过 ⇒ 点 + 波动带（§3） |
| 2 | **matched-FPR 比较** | `recall_at_fpr(0.01)/(0.05)`，**不是**各家默认工作点；头对头表用它拼（spike 分析步） |
| 3 | 🔴 **归一化首验** | 曲线扫 `P(违规)`；**自建** = `softmax(违规,安全)` 在 2-way 上**恒和为 1**（构造保证，本增量满足）。**远程对照**须**首次接入时各送 N 条核 `sum(score)==1`**（证据缺席≠证据），不为 1 ⇒ 改扫 `1−p(通过)` 或有害类求和；**用了哪种读法必须进 `vendor_version` 的 `契约id`**（§2.4.7）。两家各做一次，不可互推。 |

---

## 6. 验收

1. **确定性自证**：本地判官同输入 ×6（钉死旋钮、弃热身、剔污染后）⇒ `score_stability` 出
   `deterministic_fraction==1.0`、`max_variance==0.0`、`curve_eligible==True`。
2. **污染剔除显形**：构造一批含 `judge_reload_contaminated=True` 的样本 ⇒ 被剔、`contaminated_dropped` 数得出、
   **不**污染方差；断言 `n_used` 只数干净样本。
3. **insufficient 显形**：某 case `n_used<2` ⇒ `insufficient_cases` 计入、**不**被当成"方差 0/确定"。
4. **门 gate 曲线**：`curve_eligible==False` 的候选 ⇒ `roc_curve` **不发 `points`**、只发点 + 波动带
   （guard test 断言两种输出形态）。
5. **分母纪律（承 §C3-2 / §5.1-B1）**：逐 class `measurable + excluded == 该类 measurable-or-excluded 探针数`；
   `sum(measurable)+sum(excluded) == matched probes`；某类全无分数 ⇒ 落 `excluded`、**不**读成 `0% FPR`。
6. **未分类切片**：`content_class==""` 在 `by_class` 单独出现、不并入任何类（承 §5.1-B1）。
7. **matched-FPR**：`recall_at_fpr(0.05)` 在阶梯上线性插值正确（含边界：FPR 网格未恰好命中 5% 时插值）。
8. **归一化首验守卫**：断言自建路径 `sum(score over {违规,安全})==1`；远程读法未记进 `vendor_version` ⇒ 测试红。
9. **加性回归**：现有全部 `ProbeResult` 构造点与 WAL golden **零改动**（两新字段缺省不触发）。
10. 门禁不回归（ruff/mypy/bandit/pytest/泄露门）。

---

## 7. 非目标 / 边界

- **不做** verdict JSONL loader / CLI（§0；随 spike run 落）。
- **不做** 远程对照臂适配器（gate 在数据条款之后，§3-R1 裁定）。
- **不进** `build_default_registry` —— 同 `duration_p50/p95`，spike 自行调用，免动成熟度报告金样本。
- **不在** CPU 硬件上取延迟当候选属性（§2.4.5）；本增量只产**质量/稳定性数**。
- **不把** spike 出的合格率/召回写进任何对外材料（§4 红线）。

---

## 8. 裁定记录（implementer 2026-07-21 review，架构师已拍）

R1/R2/§3.1/§C3-2 已拍；本增量是它们的**实现规格**，逐条对齐、不重开。implementer 核出四点，裁定：

| # | 问题 | 裁定 |
|---|---|---|
| 阻塞 1 | `vendor_labels`/`VendorLabel`/`vendor_version` 代码零命中（§2.2.4 是 C2 提案、未落地） | ✅ **承载集一次落齐**（§1 四字段：`VendorLabel` + `vendor_labels` + `vendor_version` + 两 `judge_*`）。**为自建主臂落 bearer，C2 消费者仍 gated**。🚫 不含 `result_type`（投机字段）。 |
| 阻塞 2 | `vendor_labels[0].score` 只对单标签自建成立；多标签候选 `[0]≠违规分` | ✅ **裁定 ii：纯函数收注入的 `score_of` 提取器**，指标不认识"违规分"在哪；自建默认 `lambda pr: pr.vendor_labels[0].score if pr.vendor_labels else None`。**提取器 = §2.4.3 输出契约轴的可执行形态**，用了哪种读法记进 `vendor_version`（§5-3）。多标签候选进来改注入、不改指标。 |
| 澄清 3 | `recall_at_fpr` 返回类型自相矛盾（`float` vs 三元组） | ✅ **恒返回 `(low, point, high)`**；eligible 时 `low==point==high`（§3）。 |
| 澄清 4 | `roc_curve` 无 eligibility 入参却要按它分支 | ✅ **签名收 `StabilityReport`**，显式消费 A 的门 + per-case 谱（§3/§4）。 |

---

## 9. 提交 C：verdict loader + I3 CLI + 真机 fixture + 回归测试（可下发 Implementer）

**归属：** Implementer 编码 + 测试；架构师只出本规格。**它把真判官输出接进指标，是实现活、不是设计活。**

✅ **已落地（2026-07-22）：Implementer 对照本规格 review 了架构师草稿并复用，接进 `__all__`、去掉 ⚠️ 头注 ——
现为其名下产品代码。** `verdict_loader.py`（`load_verdict_runs`/`verdict_to_probe`）· `i3_run.py` CLI ·
`tests/test_verdict_loader.py`（4 测）· committed 真机 fixture。**hermetic 回归（`test_verdict_loader.py`，字节复现）进 CI/commit 门。**

**9.1 落地清单**

| 文件 | 内容 |
|---|---|
| `treval/active_eval/verdict_loader.py` | `load_verdict_runs(path) -> (runs, content_class_by_case_id)`：读 judge `verdicts.jsonl`，按 `line` 分组、`repeat` 转置成 `runs[k]`（§2/§3）。纯函数、无网络。 |
| `treval/active_eval/i3_run.py` | CLI：`python -m treval.active_eval.i3_run --verdicts PATH --benign IDS --violating IDS`。**薄驱动**：loader → `score_stability` →（给了切分则）`roc_curve`，打印报告。无自有逻辑。 |
| `tests/fixtures/i3/verdicts_smoke.jsonl` | **committed 真判官实录 fixture**（3 探针 ×7 rep，`content_class` 已匿名化），leaned 到 loader 相关字段；**必须保留 line3 的冷 `rep0`**（它与暖 rep 差 ~1e-8，是 warmup-drop 承重的证据）。 |
| `tests/test_verdict_loader.py` | 回归测试，见 §9.3。 |

**9.2 verdict→`ProbeResult` 字段映射（判官 `verdicts.jsonl` 输出契约）**

| verdict 字段 | → `ProbeResult` | 备注 |
|---|---|---|
| `score` | `vendor_labels[0].score` | 无 `score`（JudgeError 行）⇒ 空 `vendor_labels` ⇒ 指标 excluded，不伪造 0 |
| `model`+`quant`+`contract` | `vendor_version = f"{model}:{quant}:{contract}"` | 全串（Flag 2），单条 ProbeResult 自证可归因 |
| `load_duration_ns` | `judge_load_duration_ns` | 仅显形 |
| `reload_contaminated` | `judge_reload_contaminated` | 适配器 TAG、指标 DROP |
| `content_class` | 随 case_id 回传（切片用） | |
| `line` | `case_id`（分组键） | |
| `repeat` | `runs[k]` 的 k（转置） | `runs[0]` = warmup 遍，`score_stability` 丢弃 |

**9.3 验收（回归测试断言，全部对着真机 fixture）**

1. **§4 字节复现**：loader → `score_stability` 逐字得 `deterministic_fraction=1.0`/`max_variance=0.0`/`contaminated_dropped=0`/`warmup_dropped=3`/`insufficient_cases=0`/`curve_eligible=True`；per-case 暖 rep 位级同一。
2. 🔴 **warmup-drop 承重**：fixture 里 line3 `rep0 ≠ rep1`（真机 Δ~1e-8）；断言"若不丢 `runs[0]` 则 `deterministic_fraction<1.0`，丢了则 `curve_eligible=True`"。
3. **污染剔除**：注入 `judge_reload_contaminated=True` ⇒ `contaminated_dropped` 增、`max_variance` 不受污染（§6-2）。
4. **Flag-1 单侧**：某 `content_class` 只有一侧 measurable ⇒ 不进 `by_class`（不造假 0% FPR），但在 `measurable` 显形。
5. `vendor_version` 拼成全串（如 `qwen2.5:7b-instruct:Q4_K_M:violate`）。
6. 🔴 **fixture content_class 匿名化**：committed fixture + 测试断言里的 `content_class` 用**占位**（如 `topic_A`/`topic_B`），**不烤真实类目码进公开仓**（守 taxonomy-free）。指标只按标签分组、不依赖字符串，Flag-1 行为不变。
7. 🔴 **taxonomy-free 守卫扩到 `tests/fixtures/`**（现只盯 `corpus/`，fixture 从缝里逃了）—— 机械扫 `a[0-9]_[a-z]_` 形状类目码 pattern 挡住，靠门不靠人眼。
8. 门禁不回归（ruff/mypy/bandit/pytest/泄露门）。

**9.4 单文件 vs 两文件**：判官侧一份混装 `cases.jsonl`→一份 `verdicts.jsonl`。`score_stability` 内容无感、直接吃整份；`roc_curve` 的良性/违规切分由调用方给（单文件用 `--benign/--violating` 行号；真语料量大用两份 verdict）。**切分永不来自 verdict 字段（Flag 1）。**

---

## 10. 代码就绪状态（2026-07-22）

**代码侧（C1）就绪、hermetic 回归绿。** 逐项：

| 项 | 状态 | 归属 |
|---|---|---|
| 提交 A（承载集 + `score_stability`）代码 + 9 测 | ✅ 就绪（Implementer 交、架构师 review 过） | Implementer |
| 提交 B（`roc_curve`/`recall_at_fpr`）代码 + 7 测 | ✅ 就绪（同上） | Implementer |
| **提交 C（loader + CLI + fixture + 回归测试）** | ✅ **已落地**（Implementer review 复用草稿、接 `__all__`；hermetic 回归进 CI） | Implementer |

**C1 验收边界 = hermetic 测试级**（代码 A/B/C + 字节复现回归进 CI）；真语料测量不在本 issue 范围。**代码验完即可关闭。**


