# EV-8 — 评测 driver / CLI:Measurement bundle → MaturityReport → {json, human, csv}

**Problem (plain language):** EV-7 的 rubric 引擎已能把 Measurement 打成一份可信度授级报告——但**没有任何东西把实时数据喂进去**:活体指标(注入拦截、越权)产出 Measurement,却没有一个 driver 把「registry + 实测 Measurement + posture」串起来跑出报告。引擎是纯函数,躺在那儿没接线。

**Value:** EV-8 是**让 EV-7 活起来**的那根线,也是运营/客户能真正拿到的**第一份可交付成果**:一条命令 → 一份「已验证 L_n vs 自声明 L_m + 过度声明 gap」的报告(JSON / 终端 / CSV)。它同时把 D3 歧义收敛到一张明确的**策展映射表**(引擎的 fail-loud 是网),并诚实呈现「现在能实测什么、什么还只是声明」——这份诚实本身就是产品可信度的最强证明。

> Dev brief。Self-contained:实现读本文件 + `treval.rubric`(EV-7,已 merged)+ `treval.active_eval`
> (harness)+ `treval.posture`(EV-3 `PostureFileReader`)+ `docs/REPORT_JSON_SCHEMA.md`。
> **Prereq:EV-7 ✅、EV-3 ✅、EV-1/EV-4 ✅、active-eval harness ✅ 均已合入。** 决策见 §0。
> 纯 grade/render 路径**确定性、无 gateway 依赖、可 CI 单测**;活体 collect 是操作员路径。

---

## 0. RATIFIED(运营视角复核后拍板)

| # | 决策 | 结论 |
|---|---|---|
| ① | **先做 EV-8,不等指标补全** | 立即打通全链、让 NotMeasured 生动可见;后续 EV-5/EV-9 指标**零 EV-8 改动**逐行点亮 |
| ② | **拆分 grade vs collect** | `report`(纯逻辑,可测,无 gateway)/ `collect`(产 bundle,可能环境失败)——故障隔离 + 部署灵活 |
| ③ | **D3 = 策展映射表(非命名空间)** | registry 保持裸 id;driver 一张 `bound_id → (indicator, canonical corpus)` 表只喂规范语料那一条;引擎 `DuplicateIndicatorError` 是网 |
| ④ | **首版只主动指标** | 活体探测=检测效能(客户最关心「拦得住吗」);被动/生产流量另一维度,后置,**绝不与活体探测混算** |
| ⑤ | **黄金语料场景后置** | 先跑通真实报告,报告形态稳定后再固化 conformance 用例(EV-8.2) |

**4 项运营补充(已纳入):** report_schema_version 显性化(§4);错误聚合不崩溃(§5);`--measurement-bundle` 离线渲染(§2);首页网格图(§4)。

---

## 1. 覆盖现实(诚实边界,必须写进报告)

registry 的 **measured** 行绑 11 个 indicator,**现存代码仅 3 个**:

| 现可产出 | 缺(挂后续 issue) |
|---|---|
| `injection_catch_rate`(active)✅<br>`tool_scope_violation_rate`(active)✅<br>`block_rate`(passive)✅ | `chain_integrity`/`unclosed_loop_rate`/`duration_p99`/`terminal_error_ratio` → **EV-5a/5b**<br>`boundary_breach_rate`/`drift_alert_count`/`redaction_hit_ratio`/`pii_exposure_surface` → **EV-9** |

**⇒ 首版报告实测 3 行、覆盖 2/5 维度(robustness、security)。** privacy / transparency /
efficient_reliability **零可产出 measured 行 → `measured_ceiling=None` = NotMeasured**,且(EV-7 引擎)
**声明抬不动它**。这不是缺陷,是 measured>attested 的最强演示:报告直白说「robustness/security 可*验证*,
其余三维只是*声明*」。指标随 EV-5/EV-9 落地逐行点亮,EV-8 不改。

## 2. CLI 契约

```
treval collect  --gateway <url> --wal <dir> --corpus <dir> --out bundle.json   # 产 Measurement bundle
treval report   --measurement-bundle bundle.json --posture posture.yaml \
                [--format json|human|csv] [--out report.*]                     # grade + render(纯)
```

- **`report` 是纯的**:`bundle(§3) + posture + registry → evaluate()(EV-7) → serialize`。无 gateway、无时钟、
  确定性、可 CI 单测。`--measurement-bundle` = 离线复现路径(支持团队不碰客户环境即可调报告——运营补充③)。
- **`collect` 是操作员路径**:按 §3 策展映射跑活体 producer → 写 bundle。环境/网络失败**聚合不崩**(§5)。
- 便利:`treval run`(= collect ∘ report)一条龙;但**权威纯路径是 `report --measurement-bundle`**。
- 对齐 `wal_verify` 的退出码习惯;`--format` 默认 `human`。

## 3. Measurement bundle + D3 策展映射(③ 的落地)

bundle = `docs/REPORT_JSON_SCHEMA.md` 的 `{schema_version, report?, measurements[]}`——但 `collect` 只写
`measurements[]`(+ 元数据);`report` 负责 grade 出 `report`。**D3 收敛**在 `collect` 的一张显式表:

| bound `indicator_id` | producer | canonical 语料 / 源 | 相 |
|---|---|---|---|
| `injection_catch_rate` | `InjectionCatchRate` | `corpus/llm01_prompt_injection` | active(`__eval__`) |
| `tool_scope_violation_rate` | `ToolScopeViolationRate` | `corpus/llm06_tool_scope` | active |
| `block_rate` | `BlockRate` | **生产 WAL / 生产 tenant+窗口** | passive(**后置**,§6) |

- 每个 bound id **只产一条 aggregate Measurement**(规范语料那一条)→ bundle 内**无重复 aggregate id**
  → 引擎 fail-loud 永不触发;万一策展漏了,`DuplicateIndicatorError` 立即抓(不静默错绑)。
- eval_report 里 LLM02/05/07 那几个 `InjectionCatchRate` 复用**是诊断,不进映射表、不进 bundle**。
- **`Measurement.integrity`**:active producer 读链验证 WAL → `VERIFIED`(EV-7 D1 默认正确);passive/PG
  的 min-integrity retrofit 是 **EV-2 硬门**(见 EV-2 §6),与本 issue 无关。

## 4. 渲染器 + 首页结构(④ 网格优先)

报告结构(高层先看全貌,审计再看深度):

1. **首页:5×5 网格**(维度 × 级,颜色区分 **awarded / measured-only / attested-only / NotMeasured**)。
   CTO/安全负责人 5 秒获全局:「哪几维有信心,哪几维只是承诺」。
2. **gap 表**:每条「过度声明」(attested-met 高于 measured_ceiling)量化列出——审计发现。
3. **逐维明细**:支撑授级的每个 objective(met/unmet/insufficient_data/unverified_evidence)+ 其 Measurement。
4. **附录**:方法论、`verification_basis`(wal/index/hybrid)、`integrity_summary`、数据源完整性声明。

- **json** = `bundle_to_json`(EV-7 已实现,字节确定)。**human** = 上述 4 段(终端;网格用 ANSI 色,非 TTY
  降级为符号)。**csv** = 逐 objective 扁平行(维度/级/kind/status/indicator/value/integrity),供表格。
- **`report_schema_version`**(运营补充①):bundle 已带 `schema_version`;human/csv 头部**显性打印**,
  UI/解析器可平滑升级、不破坏历史报告兼容。

## 5. 面向运营的错误处理(补充②)——尽力收集,聚合展示,绝不首错即崩

- `collect`:某 producer 失败(gateway 不可达 / 未 provision / 超时)→ **记一条 warning,继续跑其余**;
  该指标在 bundle 里缺席 → `report` 判 `insufficient_data`(诚实缺数,非崩溃)。
- `report`:即使 bundle 空/过时也产出**诚实报告**(标注缺数);**报告顶部**一个聚合的
  **warnings/errors 区**,一次性列出所有问题——运营一次看全,不必反复跑反复错。
- 退出码:渲染成功即 0(即便有 warning);仅致命(坏 bundle / 坏 registry)非 0。

## 6. 主动 vs 被动(④ 的架构,首版只做主动)

两类 Measurement,**不同 tenant/窗口,严禁混算**:
- **active** = `__eval__` 合成攻击探测 → **检测效能**(`injection_catch_rate` / `tool_scope_violation_rate`)。**首版做这个。**
- **passive** = **生产** WAL/tenant 某时间窗 → **观测治理行为**(`block_rate` / 后续 `chain_integrity`…)。
  设计好接口但**后置**(需生产作用域 + EV-5/EV-9 指标作伴)。`block_rate` 现虽可产,但语义上要生产流量,随 passive 期。

## 7. 验收

- `report --measurement-bundle fixture.json --posture p.yaml --format json` → 符合 REPORT_JSON_SCHEMA;
  同输入字节一致(确定性)。
- `--format human` → 网格首页 + gap 表 + 逐维明细 + 附录;网格领先。`--format csv` → 逐 objective 扁平行。
- **部分 bundle**(缺指标)→ NotMeasured / insufficient_data 如实渲染,**不崩**;顶部聚合 warning。
- `collect` 活体一轮 → bundle 每个 bound id 恰一条 aggregate(策展表)→ 喂 `report` **无 `DuplicateIndicatorError`**。
- 活体 smoke(issue 就绪时):3 measured 行授级(2 active + posture),3 维度 NotMeasured——即预期诚实画面。
- 覆盖 ≥60%(纯 `report` 路径)/ mypy / ruff 干净。

## 8. 非目标

- **passive/生产作用域读取的接线**(设计在 §6,实现后置到 EV-8.2 / EV-5·EV-9 落地时)。
- **黄金 conformance 语料**(⑤,EV-8.2)。
- **Web UI**(EV-W1/W2 渲染本 JSON;EV-8 只出 json/human/csv)。
- **新指标**(EV-5/EV-9);**PG 路径**(EV-2)。
- 仅凭遥测自动定级——设计明令禁止。

## 9. 待定 / 问 reviewer

1. 终端网格配色:awarded=绿 / measured-only=蓝 / attested-only=黄 / NotMeasured=灰?非 TTY 降级符号集确认。
2. 是否本期附一份 `posture.sample.yaml`(让 attested 侧可跑)——倾向**是**(否则报告全 NotMeasured 看不到 min 门)。
3. `collect` 的 active producer 是否直接复用 `tools/eval_report.py` 的机器(抽出共享 runner),还是 EV-8 内薄封装?倾向**抽共享**,避免两处漂移。
