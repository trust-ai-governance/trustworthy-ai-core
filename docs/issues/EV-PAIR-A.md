# EV-PAIR-A — 让 `collect` 在裸模型上产出真数字（输出侧生产者进 CURATION）

> **Problem（普通话）：** EV-FWD 之后，`collect --target-kind raw_model` 能跑、标注也正确，
> **但产不出任何数字** —— 它的生产者清单 `CURATION` 里只有两条，且**两条都是决策侧**
> （`injection_catch_rate` / `tool_scope_violation_rate`），在裸模型上按设计恒为 `n/a_needs_gateway`。
> 结果：裸模型评测**跑得通、出不了数**。（架构师用产品 API 手工拼跑才拿到 `injection_success_rate=83%`，
> 说明能力在、产品路径不在。）
>
> **Value:** 往 `CURATION` 补**输出侧**生产者 —— 它们对 `raw_model` 与 `gateway` **都是 `measured`**，
> 于是 `collect` 一条命令就能产出裸模型的真实数字，也顺带让两种标的的 bundle **在同一批指标上可比**
> （配对 delta 的前置，但 delta 本身不在本 patch）。
>
> **归属：** Implementer 编码 + 测试。**规模：很小 —— 表驱动，无新逻辑。**
> **承：** [EV-FWD](EV-FWD.md)（`OpenAITarget` + `availability`，已 merged）· [EV-PAIR](EV-PAIR.md) §1（本 patch = 其件①）。

---

## 1. 现状（已核实，2026-07-27）

- 🟢 `collect` **已经会建 `OpenAITarget`**（`collect.py:234`），也已用 `run_corpus`（它负责把 `output_marker`/`secret_canary` 附到 `ProbeResult` 上 —— 输出侧指标依赖这一步）。
- 🟢 五份 canonical 语料**都在**：`llm01_prompt_injection`(28) · `llm02_sensitive_disclosure`(14) · `llm05_improper_output`(12) · `llm07_system_prompt_leak`(14) · `llm10_unbounded_consumption`(12)。
- 🔴 缺的只是 `CURATION` 表里没有输出侧那几条。

⇒ **本 patch 不写新逻辑，只补表 + 一处构造形式的小调整（§3）。**

---

## 2. 范围：补四条输出侧生产者

| 生产者 | canonical 语料 | 与 `eval_report` 的映射一致? |
|---|---|---|
| `injection_success_rate` | `llm01_prompt_injection` | ✅ 一致 |
| `sensitive_disclosure_rate` | `llm02_sensitive_disclosure` | ✅ 一致 |
| `unsafe_output_passthrough_rate` | `llm05_improper_output` | ✅ 一致 |
| `system_prompt_leak_rate` | `llm07_system_prompt_leak` | ✅ 一致 |

- **决策侧两条保持不变** —— raw_model 下继续 `n/a_needs_gateway`（EV-FWD 已验，本 patch 不得改变它）。
- 🔴 **不改任何指标实现**：输出侧指标本就只读 `response_text`/`secret_canary`/`output_marker`，EV-FWD §7.3 已证它们在 `evidence=None` 上可测。
- **语料映射照抄 `eval_report` 的既有绑定**，不另起一套（避免两处口径分叉）。

---

## 3. 🔴 一处必须先解的构造形式问题：`within_cost_budget` 本 patch **不收**

`Producer.factory` 被调用成 **`prod.factory()`（无参）**，而实测：

```
InjectionSuccessRate / SensitiveDisclosureRate /
SystemPromptLeakRate / UnsafeOutputPassthroughRate   ✅ 无参可构造
WithinCostBudget                                     🔴 需要 budget 参数
```

⇒ 收 `within_cost_budget` 就得把 `Producer.factory` 从 `type[CorpusIndicator]` 改成 **可调用工厂**（如 `Callable[[], CorpusIndicator]`），
那是**结构改动**，不属于"很小"。

**裁定：本 patch 只收上表四条；`within_cost_budget` 连同 `Producer.factory` 的形式调整，留给 EV-PAIR 主体（或单独小 patch）。**
（它是 `output_only`（D1），迟早要进，但**不值得为它把这个 patch 变成结构改动**。）

---

## 4. 验收

1. 🔴 **裸模型出真数**：`collect --target-url <OpenAI 兼容端点> --target-kind raw_model` 产出的 bundle 里，
   上表四条 **`availability=measured`** 且 **`sample_size > 0`**（不再全是 `n/a`）。
2. **网关侧同样可测**：同一批生产者在 `--target-kind gateway` 下也 `measured` —— 这是两种标的可比的前提。
3. 🔴 **决策侧无回归**：`injection_catch_rate` / `tool_scope_violation_rate` 在 raw_model 下**仍是 `n/a_needs_gateway`**
   （不得因为新增生产者而被改成 `measured`）。
4. **不改指标实现**的机械证据：指标模块的 diff 为空（本 patch 只动 `collect.py` 的表 + 其导入）。
5. **语料映射一致**：四条的 `corpus_subdir` 与 `eval_report` 的既有绑定逐条相同（守卫或 review 断言）。
6. **端点不可用时诚实**：端点 404/401 ⇒ 探针记 `error`（EV-FWD 已修），输出侧指标呈现 `insufficient_data`，
   🔴 **不得是一个"很干净"的 0%**（这条是既有行为，本 patch 加一条回归断言即可）。
7. 门禁不回归（ruff/format/mypy/bandit/pytest/泄露门）。

---

## 5. Live Test（本 patch 落地后可立即跑）

```bash
cd ~/ai/trustworthy-ai-core
export TREVAL_TARGET_URL=http://$(ip route | awk '/default/{print $3}'):11434/v1

PYTHONPATH=$PWD python -m treval.cli collect \
  --target-url "$TREVAL_TARGET_URL" \
  --target-kind raw_model \
  --model qwen2.5:1.5b-instruct \
  --out /tmp/raw.json

python3 -c "
import json; b=json.load(open('/tmp/raw.json'))
for m in b['measurements']:
    print(f\"{m['indicator_id']:32} {m.get('availability'):20} n={m['sample_size']:3}  value={m['value']:.0%}\")
"
```

🔴 **两条粘贴纪律（本轮各踩一次）：**
- **`--model` 必须显式传** —— CLI 的 `--model` 读 `TREVAL_EVAL_MODEL`，**不读 `TREVAL_TARGET_MODEL`**；
  不传即默认 `deepseek-v4-flash`（网关时代的部署 id），在任意 OpenAI 兼容端点上几乎必然 404 ⇒ 全部探针 error ⇒ 一份 `n=0` 的空报告。
- **续行 `\` 之后不得有 `#` 注释** —— `\` 会转义注释前的空格，整条命令粘贴即碎。旗标说明写在命令块外。
**期望**：四条输出侧 `measured` 且 `n>0`（有真实百分比）；两条决策侧仍 `n/a_needs_gateway` 且 `n=0`。

🔴 **口径提醒**：这些是**统计型**指标（模型非确定），且本跑 `pinned:false`（移动窗口）——
**不得对外引用**；它证明的是"裸模型这条路能出数了"，不是一个可发布的数字。

---

## 6. 非目标

- **不做** delta / 配对（EV-PAIR 主体：配对门、`corpus_sha`、`pair` 子命令）。
- **不收** `within_cost_budget`（§3）。
- **不动**指标实现、`availability` 派生规则、`eval_report`。
- **不用**非公开语料。
