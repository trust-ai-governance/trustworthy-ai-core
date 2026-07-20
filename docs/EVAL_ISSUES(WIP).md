# Trustworthy-AI Core — 测评引擎 Issues（第 1 轮分解）

对 `docs/EVAL_ARCHITECTURE.md` 的可执行 issue 分解。每个 issue 含：从（仓库/路径）/
维度 / 前置 / 范围 / 验收（可验证，开发写单测、测试写系统/E2E）/ 非目标。
沿用 `PHASE1_ISSUES.md` 的体例。

> 这是**第 1 轮**。第 2 轮调整点集中列在文末「待定决策」。issue 落库到 GitHub
> core repo 的 Project 后，随实现推进增删。
>
> 架构师默认决策（可在第 2 轮推翻）：前缀 `EV-`（避免与 ir-spec/platform 的既有
> issue `E1` 冲突）；切片顺序＝先用单个参考实现打通契约，再铺开集合。

### 项目级决策（已拍板，第 1 轮）

| # | 决策 | 影响 |
|---|---|---|
| 包名 | **`treval`**（`import treval`，区别于脚本式 `tools/`） | 全部路径；EV-0 |
| Measurement/Indicator 形状 | `Indicator.measure() -> tuple[Measurement,...]`；`Measurement` 加 `subject: str=""`（`""`＝聚合，非空＝per-entity 如 agent_id）。空输入 → 单条 `sample_size=0` 聚合。rubric 只匹配聚合（`subject==""`） | EV-0 冻结契约；EV-4/5/7 |
| YAML 依赖 | **PyYAML**（MIT，过 copyleft 扫描）；posture/registry/corpus 共用 | EV-3/6/8；requirements + CI |
| EV-5 拆分 | 按 **A↔B-join 轴**拆 EV-5a（单记录率指标）/ EV-5b（A↔B-join 指标，含共享关联 helper，EV-9 复用） | EV-5；EV-9 前置 |
| **Postgres 读取**（第 2 轮新增） | **EV-2 复活**为 `PostgresEvidenceReader`：SQL 过滤 + 解码原始 payload（同 WAL 解码器）→ `UNVERIFIED`。WAL 仍是完整性/Transparency 唯一源 | EV-2；EV-6/7 `requires_integrity` |
| **完整性门细化** | 控制目标加 `requires_integrity`：`UNVERIFIED` 可满足聚合目标，但不满足完整性目标（Transparency 仍须 WAL）。report 加 `verification_basis` | EV-0（冻结字段）/EV-6/EV-7 |
| **PG 驱动许可** | **`pg8000`(BSD) 或 `asyncpg`(Apache-2.0)**；**禁 `psycopg`/`psycopg2`（LGPL，宪法 §1.2）** | EV-2；CI license |
| **Web UI** | core 出**只读 Python 服务 + SSR**（后端渲染，client 下载 HTML）+ report JSON API；`treval[web]` extra，引擎不依赖 web | EV-R1/EV-W1/EV-W2 |

**架构默认（未单独拍板，可异议）**：① 依赖方向 `treval → tools/`（复用
`_wal_format`），`tools/` 保持零依赖客户面参考；共享 RCtx 解码器从 `wal_dump.py`
**外科式抽取**到 `tools/` 级 helper，两者共用（现有 wal_dump/wal_verify 测试作回归
护栏）。② `treval` 可硬依赖开源 ir-spec(proto) + PyYAML，**绝不依赖闭源 platform**；
license CI 扩展到 `treval`。③ `satisfied_when` 是**锁定迷你文法**
`<field> <op> <number>`，field∈{value,sample_size}，op∈{>=,>,<=,<,==}，
无 eval/名字/调用（宪法 §4）。④ A↔B 关联是**唯一共享 helper**（稀疏 B 按
**`request_id`** 关联 A——A/B 共享 request_id，全局唯一且实例安全；`decision_seq`
仅作实例内校验。A4 多实例下 `seq` 非全局唯一，故不可用 seq 关联），EV-5b 建、EV-9
复用。⑤ **确定性**为全员守则：无时钟/随机、
键序稳定、输出不依赖 set 迭代 → JSON 字节一致。⑥ Registry 本期落 `core`，加载器吃
路径以便后续迁 ir-spec。⑦ 分支 per-issue，EV-0 先并入 main，PR 必过 CI（宪法 §13.1）。

---

## 第 3 轮转向：成熟度可信度（active-eval / 框架吸收 / 行审计）

**背景**：成熟度模型 **82% 声明（attested）/18% 测量**，大量沿袭 CSA AISMM 的厂商/流程
条款，可信度存疑。三份新文档定调：`MATURITY_ROW_AUDIT.md`（逐行审计）、
`FRAMEWORK_ALIGNMENT.md`（CSA 核对 + OWASP/ISO42001/CAICT 吸收）、
`ACTIVE_EVAL_CORPUS_DESIGN.md`（主动评估语料库）。

| 决策（已拍板） | 影响 |
|---|---|
| **效用为基准**（Q-R1）：`sample_size>=1` 等"存在阈值"是缺陷，每个测量行须测**效用** | 全维度 registry 内容；新指标 |
| **主动评估语料库**（OWASP 种子，**有界**：内置参考语料 + BYO target/corpus 接口） | 新 workstream **EV-AE**；是 82%→可信的关键杠杆 |
| **框架吸收不加第 6 维**：OWASP→测量内容；ISO42001→声明侧锚点（regulation 列）；CAICT→国内认可 + SafetyAI Bench 测试集 | registry 内容；regulation 列 |
| **Affordable 升华**＝"无厂商锁定即可评估"——挡掉 CSA 厂商天花板条款 | 行审计的纳入/剔除门 |
| **定位**：非认证机构，只报 **"已验证 L_n"**（Core 实测满足的最高级）vs 客户自声明级，不报"已认证" | EV-7 report；EV-W* 展示 |

**重排序**（关键路径不变，新增 active-eval 支线）：
- **EV-4（SDK + block_rate）仍是下一个**——主动评估指标也是 `Indicator`，复用 SDK，EV-4 是地基。
- **EV-AE（主动评估）= EV-4 之后的新优先支线**：先做 **LLM01 注入 → `injection_catch_rate`**
  纵切（设计见 `ACTIVE_EVAL_CORPUS_DESIGN.md` §3），再按 OWASP 路线图逐类薄 issue。
  依赖运行中的 gateway+model，CI integration-gated（同 PG 套件）。
- **EV-9（网关 tag 被动维度指标）降级**：active-eval 是 Robustness/Security 更强的测量源；
  EV-9 仍有效但次于 EV-AE。
- **行审计是内容轨**（非编码 issue）：驱动 registry YAML 的剔除/改写 + 决定要建哪些指标；
  与引擎/UI 并行推进，`detection_to_siem` 已剔（Q-R2）。

**EV-AE0 — 已实现 + 实测验证（done）**：语料格式 + `Target`/`GatewayTarget` + runner +
`InjectionCatchRate`（网关拦截，确定性）+ `InjectionSuccessRate`（输出成功，statistical，
startswith canary 保守下界）；28 例 LLM01 语料（8 例带 marker）；brief 见 `docs/issues/EV-AE0.md`。
**实测**（live gateway，详见 `MATURITY_ROW_AUDIT.md` §3 + `PLATFORM_ASK_INJECTION_DETECTION.md`）：
网关注入拦截 ≈ 0（4% 是 pii-block 误命中邮箱，非注入检测）；DeepSeek 输出成功 0/8。
顺带修复 `_wal_format.list_segments` 支持归档段命名 `START-END-TS.wal`（S3 archive 直读）。

**EV-AE1 — LLM02 敏感信息泄露纵切（已 brief，待实现）**：`sensitive_disclosure_rate`
（隐私维度，**首个输出型/统计型**指标）。brief 见 `docs/issues/EV-AE1.md`，决策已拍板：
**in-band canary**（秘密置于 prompt，零平台改动；out-of-band 留作 `…_rate_full` 后续）、
新增 `secret_canary` 语料字段（与 LLM01 的 `output_marker` 攻击哨兵区分）、子串完整命中=泄露
（near-upper-bound，与注入成功率的 lower-bound 反向）、`temperature=0` 固定可重现、纯函数
`is_sensitive_disclosed(output, canary)`。维度标 `privacy_data_protection`，目标绑定
（`prv.l2.redaction` 升级或新 `prv.l3.extraction_resistance`）留给 EV-7/行审计。

**EV-AE2 — LLM07 系统提示词泄露纵切（已 brief，待实现，决策已拍板）**：`system_prompt_leak_rate`
（security_alignment）。brief 见 `docs/issues/EV-AE2.md`。**首个 system-prompt 纵切，零平台改动**
（D1）：harness 在 `params.messages` 里直接发一条真实 `role:"system"`（含 canary）消息，forwarder
原样透传上游——非部署种植、非注册表配置、可完全复现。**切勿**用 in-band 替身（把 `[SYSTEM]` 文本塞进
user 消息——那只测指令遵从，是 LLM02 不是 LLM07）。复用 EV-AE1 的 `sensitive_disclosed` 原样不变；
`checks.py` 不动，新增一个薄指标 + `system_prompt` 语料字段 + GatewayTarget 发送系统消息。指标方向为
**下界**（攻击者看不到 canary→无过计数；转述泄露漏计），与 LLM02 近上界互补，勿直接比较。

**EV-AE3 — LLM06 越权工具调用纵切（已 brief + 语料，待实现）**：`tool_scope_violation_rate`
（security_alignment）。brief 见 `docs/issues/EV-AE3.md`，语料 `corpus/llm06_tool_scope/`
（12 例越权工具：admin/shell/filesystem/db/http(SSRF)/email/secrets/payments/user_mgmt/
code_exec/infra/model_admin）。**非 canary 泄露形**——**确定性、基于 WAL authorization**
（`injection_catch_rate` 的形，非输出统计）：eval agent 仅有 `tool:chat:*`，探测越权
`tool_id`，量网关是否拒绝（`final_decision==BLOCK` 或 `authorization.allowed==false`）。
**最重处**：新增 target 能力（调用 chat 以外的 tool）+ `tool_id` 语料字段 + `scope_enforced`
判定 token。**关键决策 D2（须先确认，勿猜）**：越权 `tool_id` 是否触发 authz 拒绝（可测）还是
tool-not-found（不可测，需注册一个未授权工具）；越权-性由语料保证，不靠网关的 `missing_scopes`。
锚点 `sec.l3.oauth_scope`（其 `scope_deny_rate` 的 Q-R1 效用升级）。确定性、可比特复现，无 temperature。

**EV-AE4 — LLM05 输出处理不当纵切 + CanaryLeakRate 合并 — 已合并**：
`unsafe_output_passthrough_rate`（security_alignment）。brief 见 `docs/issues/EV-AE4.md`。
**实测：100% 原样透传 / 0% 网关中和**（无输出净化；P2-dlp 缺口）。
**经分析 LLM05 就是第 3 个同形泄露纵切**：把 marker 设为**完整原始危险载荷**（含 `<>'; {` 等特殊字符 +
高熵 token），则**逐字子串**检查天然区分"转义=安全"vs"原样透传=不安全"——复用 EV-AE1 的
`sensitive_disclosed`/`not_leaked`/`secret_canary` 原样不变，无新 check/token/field/target 改动。
**触发 EV-AE1 D6 合并**：把 LLM02/07/05 三个同形指标折叠为 `CanaryLeakRate` 基类 + 三个薄子类
（行为不变，LLM02/07 既有测试须原样通过）。诚实边界：测的是**网关输出中和**（纵深防御），非下游
sink 的处理（真正的 LLM05 面，属调用方）；**下界**；很可能高（与无 output-DLP 一致）。
**决策已拍板**：D1 现在合（base 内部抽象 + 三薄子类，LLM02/07 测试须原样通过=硬验收门）；
D2 复用 `secret_canary`（仅改 docstring，不改名不破坏）。未来若需不同判定逻辑（语义级，非字面子串）
另抽象，勿塞进 `CanaryLeakRate`。

**EV-AE5 — LLM10 无界消耗 — 已 brief，待实现**。brief `docs/issues/EV-AE5.md`。新形：
`cost_runaway_caught`（确定性 WAL-decision，复用 `blocked_or_flagged`，类 LLM06）+ `within_cost_budget`
（读 `token_usage.total_tokens` ≤ budget，统计）。dimension `efficient_reliability`（首个）。
小改 target（解析 usage→ProbeResult.total_tokens）+ token_usage WAL 交叉校验。**待拍板**：D2 budget 阈值
（策略量，env 可配，默认~2000）、D3 token_usage 来源（响应体+WAL校验 vs 纯 WAL）、D4 语料 success_when
（复用 blocked_or_flagged）。速率/配额限制不在此（per-probe 难建模 burst）。Corpus 适配器为后续。

**检测器质量轨（Platform P2-a 注入规则触发，cross-repo）**——见 `PLATFORM_ASK_INJECTION_DETECTION.md` §7：
- **EV-AE6（双向验收：召回 + 误报）— 已合并**：benign 语料（20 例，含硬负例）+ `allowed` token +
  `false_positive_rate` 指标（确定性），集成测试两侧都断言（召回 ≥τ_recall 且 FPR ≤τ_fpr，已确认
  τ_recall≥0.80/τ_fpr≤0.05）。**实测验证 P2-a Tier-1：召回 4%→43%（39% 纯注入），FPR 0%——精确不过宽。**
  附带 `attack_class_breakdown`/`format_attribution_report` 助手（每类技术捕获率，EV-AE7 喂料）；
  **逐例 caught/missed 报告是部署网关的实时绕过图，内部交 Platform，gitignore `reports/`，不入公共库。**
- **EV-AE7（对抗变体生成器）— 已实现 + 实测验证（merging）**。brief `docs/issues/EV-AE7.md`。
  确定性轻扰动（大小写/零宽/标点/同形字，渲染等价/可规范化击穿）量 Tier-1 规则鲁棒性；绕过变体=Tier-2 种子（JSONL，内部）。
  **实测 = P2-norm 验收测试：鲁棒性 51%→100%**（P2-norm NFKC+零宽/同形字剥离后，所有逃逸变体恢复被捕）——
  **故 61% 捕获率是实测鲁棒、非过拟合**（D1/D2/D3 已拍板：JSONL 种子；鲁棒性为诊断非 rubric 指标；级联扰动延后）。

**前瞻**：OWASP 现另有 **Agentic AI Top 10**（面向 agent/工具调用的攻击面）——本期不做，
待 LLM Top 10 纵切铺开后再评估纳入（与 LLM06 工具越权一脉相承）。

---

## 依赖图

```
EV-0 契约/模型 ──┬─► EV-1 WalReader（+抽共享解码器）─┬─► EV-4 SDK+block_rate ─┬─► EV-5a 单记录率 ┐
                 │                                   └─► EV-2 PostgresReader   └─► EV-5b A↔B+helper ┤
                 ├─► EV-3 PostureProvider+File ──────────────────────────────────────────────────┤► EV-7 ─► EV-8
                 ├─► EV-6 Registry（+requires_integrity）────────────────────────────────────────►│      └─► EV-9
                 └─► EV-R1 Report JSON 契约 ──►（UI 用 fixtures 起 EV-W2）──► EV-7 ─► EV-W1 ─► EV-W2（UI 上线）

ir-spec E1（已落）+ EV-5b（关联 helper）──────────────────────────────────► EV-9 维度归因指标 ──────────┘
```

无依赖根、可并行起步：**EV-0**（必须最先并入 main），随后 **EV-1 / EV-3 / EV-6 / EV-R1** 并行。
- 引擎关键路径：EV-0→EV-1→EV-4→EV-5(a/b)→EV-7→EV-8；EV-9 挂 EV-5b 后、与 EV-8 并行。
- **EV-2（Postgres）** 挂 EV-1 抽出的共享解码器之后，与 EV-1 尾并行，**不在关键路径**。
- **UI 分支**在 EV-0 经 EV-R1 分出：UI 工程师用 fixtures 并行起 EV-W2，EV-W1 后接真数据。

---

## EV-0 — 测评包骨架 + Evidence/Measurement 模型 + 核心 Protocol

- **从**：core，新建包 `treval/`（+ `tests/`）
- **维度**：框架（接口先于实现 / 宪法 §10）
- **前置**：无

**范围**
- 包骨架 `treval/`：`__init__.py`、`py.typed`，可 `import treval`。
- frozen dataclass（字段严格对齐 EVAL_ARCHITECTURE §2.1/§2.2/§2.4）：
  `IntegrityStatus(enum)`、`EvidenceRef`、`AuditEvidence`、`PostureEvidence`、
  `Measurement`（**含 `subject: str=""`**）、`ObjectiveResult`、`DimensionReport`、
  `MaturityReport`。
- Protocol：`AuditEvidenceReader`、`PostureProvider`、`Indicator`（`typing.Protocol`）；
  **`Indicator.measure() -> tuple[Measurement,...]`**（已拍板，见顶部决策表）。
- CI：扩展 `ci.yml` 对 `treval` 跑 ruff/format/mypy/pytest-cov（license 扫描已覆盖）。
- **不含任何逻辑、I/O**。

**验收**
- `import treval` 成功；`mypy treval` 干净；ruff/format 干净。
- 全部 dataclass 为 frozen；按文档字段构造并读回一致（单测）。
- Protocol 可被一个测试内的 dummy 实现满足并通过类型检查；dummy `measure` 返回
  `tuple[Measurement,...]`（含空输入→单条 `sample_size=0` 聚合的形状示例）。
- 新增路径 CI 绿。

**非目标**：任何 reader/indicator/engine 逻辑；report 的 JSON 序列化格式（归 EV-7）。

---

## EV-1 — WalEvidenceReader（规范的零信任审计源）

- **从**：core `treval/readers/wal_reader.py`
- **维度**：Transparency（可独立验证的证据入口）
- **前置**：EV-0

**范围**
- 在只读 WAL 目录上实现 `AuditEvidenceReader`：复用 `tools/_wal_format.iter_records`
  与 `tools/wal_dump.py` 里的惰性 RequestContext 解码器——**把共享解码器从
  wal_dump.py 抽到可复用 helper（外科式抽取，不改行为）**。
- 跑 `wal_verify` 的链/CRC/seq 校验，逐条设 `IntegrityStatus`：完好链上的记录
  `VERIFIED`；链断点及其之后、或 CRC 失败的记录 `BROKEN`。
- 从解码的 `Envelope` 填 `EvidenceRef(source="wal:<path>", seq, request_id)`、
  `tenant_id`、`received_at_ns`。
- 支持 tenant 过滤 + 时间区间过滤。
- 解码不可用时**直接报错**（测评强依赖解码器，与 wal_dump 可回退预览不同）。

**验收**
- 喂已知多记录 WAL fixture（用 `tests/walgen.py` 构造）：产出 N 条
  `AuditEvidence`，seq/request_id/tenant_id 正确，全部 `VERIFIED`。
- 写后篡改某记录 payload：该记录及其后续 `BROKEN`，之前 `VERIFIED`。
- tenant + 时间过滤选出预期子集。
- **跑 ir-spec 的 WAL v2 golden 向量**（EVAL_ARCHITECTURE §4.1-D）：已知字节 →
  期望 `(seq, payload, record_hash)` + 段头解码逐一相符；任一不符即 fail。
  （`walgen.py` 仅作便利 fixture 生成器，**不是** conformance oracle——它从
  `_wal_format` 自身常量派生，无法自证与 platform `wal.py` 不漂移。）
- 单测覆盖 ≥ 60%；mypy/ruff 干净。
- （E2E，测试负责）指向平台真实跑出的只读 WAL mount：记录数 + 完整性与
  `wal_verify` CLI 在同一 mount 上的输出一致。

**非目标**：export/sqlite reader（EV-2）；归档段对象存储读取；repair。

---

## EV-2 — PostgresEvidenceReader（规模/速度路径，**第 2 轮复活**）

> 第 2 轮变更：WAL 全量扫描在大体量下慢，Platform 正建 Postgres 审计索引+查询。
> 故复活本 issue 为 **`PostgresEvidenceReader`**（替代原 sqlite/export 设想）。WAL
> 仍是完整性唯一源、保持 canonical；Postgres 是**规模/速度路径**。详见
> EVAL_ARCHITECTURE §4a 与跨仓契约 `docs/POSTGRES_READ_CONTRACT.md`。

- **从**：core `treval/readers/postgres_reader.py`（`treval[postgres]` extra）
- **维度**：框架（规模路径）/ Efficient Reliability
- **前置**：EV-0；**EV-1（复用其抽出的共享 RCtx 解码器）**；跨仓 Platform 暴露索引

**范围**
- 在 `AuditEvidenceReader` 同一接口下读 Platform 的 Postgres 索引：按索引列
  （`tenant_id`/`received_at_ns`/`agent_id`/`final_decision`/`record_type`）做
  **SQL 下推过滤**，`SELECT` **原始 RequestContext payload 字节**，用与 WAL reader
  **同一个解码器**解码 → `AuditEvidence(integrity=UNVERIFIED)`。reader-agnostic，
  所有指标无改动即可跑（速度收益在 `WHERE`，不是另一种数据形状）。
- 驱动：**`pg8000`(BSD) 或 `asyncpg`(Apache-2.0)**；**禁 `psycopg`/`psycopg2`
  （LGPL，宪法 §1.2）**。连接配置走 env/CLI，需 **只读 `SELECT`** 角色（`A4` 写角色
  是 INSERT/UPDATE/DELETE，core 另需只读 grant）。读 schema 限定表
  `<schema_name>.audit_events`（A4 默认 `trustworthy_audit`）。
- **多实例身份（A4 落地）**：共享库由多实例（多 WAL）写入，**`seq` 仅 WAL 内唯一**
  （PK `(gateway_instance, seq)`）。core **以 `request_id` 为记录身份与 A↔B 关联键**，
  **不以 `seq` 作全局键**；`gateway_instance` 仅编入 `EvidenceRef.source` 供 drill-down。
  core 跨实例读（同 A4 Search 模式，不加实例过滤）。**EvidenceRef/AuditEvidence 无需改**。
- 不连接 / 不导入闭源 platform；只读 Platform 暴露的库表/视图。

**验收**
- 给定样例 PG（或 pg8000 可接的 fixture）：对同一批记录产出的 `AuditEvidence` 与
  WAL reader **逐字段一致，除 `integrity=UNVERIFIED`**；过滤确实下推到 SQL；无
  platform import。
- 同一指标（如 `block_rate`/`scope_deny_rate`）在 WAL 输入与 PG 输入上给出一致聚合
  （除完整性维度）。
- 覆盖/mypy/ruff；`treval[postgres]` extra 安装后才需要驱动，引擎核心不依赖。
- （E2E，测试负责）指向 Platform 真实 Postgres：记录数/过滤与 WAL 路径一致。

**非目标**：链校验（索引本就不可能，恒 `UNVERIFIED`）；写入/迁移；hybrid 抽样回
WAL 校验（后续增强）；sqlite/CSV 适配器（若仍需可后补，同接口）。

---

## EV-3 — PostureProvider 扩展位 + PostureFileReader

- **从**：core `treval/posture/`
- **维度**：框架（企业可扩展的声明证据源 / 宪法 §10）
- **前置**：EV-0

**范围**
- 实现 `PostureProvider` 与 `PostureFileReader`：从 YAML/JSON 读声明姿态 →
  `PostureEvidence(key, value, attested_by, attested_at_ns, ref source="attest:<path>")`。
- 定义并文档化 posture 文件 schema：`[{key, value, attested_by, attested_at_ns?}]`，
  带 tenant 作用域。
- MVP 接受未签名，`attested_by` 记为明文声明；**签名校验＝非目标（后续）**。
- 在 `tools/README` 或 docs 写一节「如何编写自己的 PostureProvider」，暴露扩展位。

**验收**
- 读样例 `posture.yaml` → `PostureEvidence` 列表且 `attested_by` 已填；缺必填字段
  →**清晰报错（fail-closed，不静默跳过）**。
- 测试内第二个 dummy Provider 实现同 Protocol，能接同样的下游（证明扩展位）。
- 不变量测试：`PostureEvidence` 无任何可标记为 "measured" 的字段（类型层面保证
  posture 不能抬高 measured ceiling）。

**非目标**：签名方案；IaC/IAM/SIEM Provider（企业自写 / 未来）；registry 内容。

---

## EV-4 — Indicator SDK（runner/registry）+ 首个参考指标端到端

- **从**：core `treval/indicators/`
- **维度**：框架 + Security（首个指标 `block_rate`）
- **前置**：EV-0、EV-1

**范围**
- Indicator runner：给定已注册 indicators + `AuditEvidence` 迭代器 → `Measurement[]`
  （每个 indicator 对其 evidence 纯函数；runner 负责分发；空输入→`sample_size=0`）。
- Indicator registry（id → indicator）+ 按 dimension 检索。
- **完整实现首个参考指标 `block_rate`**（Security；`final_decision`）：
  打通「evidence → measure → Measurement（含 evidence_refs、sample_size）」。

**验收**
- SDK 在 fixture 上跑通注册指标，返回 `Measurement[]`，`evidence_refs` 已填、
  `sample_size` 正确。
- 空 evidence → `sample_size=0`（与 `value=0` 区分）。
- `block_rate`：3×ALLOW + 1×BLOCK → 返回 1-tuple，单条
  `value=0.25, sample_size=4, subject="", len(evidence_refs)=4`。
- 纯度测试：同一 evidence 跑两次 → 完全相同 Measurement。
- 覆盖/mypy/ruff。

**非目标**：完整指标集（EV-5）；维度归因指标（EV-9，E1 已落，独立 issue）；rubric 打分。

---

## EV-5a — 单记录率指标（✓，无需 A↔B 关联）

- **从**：core `treval/indicators/`
- **维度**：Security / Reliability / Transparency
- **前置**：EV-4

**范围**（EVAL_ARCHITECTURE §5 标 ✓ 且只读单条记录的指标）
- `scope_deny_rate`（Security；`authorization.allowed`/`missing_scopes`）
- `error_rate` / `terminal_error_ratio`（Reliability；`audit.errors[]`/`response.final_terminal`）
- `duration_p99`（Reliability；`response.duration_ms`）
- `chain_integrity`（Transparency；来自 reader 的 `IntegrityStatus` 汇总）
- `hint_emission_rate`（Transparency；`audit.hint_emitted`）

**验收**
- 每个指标有**手算预期**的 fixture 测试；`chain_integrity` 注入 BROKEN 时正确反映；
  所有 `evidence_refs` 已填；标量指标返回 1-tuple（`subject==""`）。
- 覆盖/mypy/ruff。

**非目标**：A↔B-join 指标（EV-5b）；⚠ 维度归因（EV-9）；阈值/打分（rubric）。

---

## EV-5b — A↔B-join 指标 + 共享关联 helper

- **从**：core `treval/indicators/` + `treval/`（关联 helper）
- **维度**：Affordable / Transparency
- **前置**：EV-4

**范围**
- **共享 A↔B 关联 helper**（唯一实现，EV-9 复用）：在 `AuditEvidence` 流上把稀疏的
  record B 按 **`request_id`** 关联回 record A（A/B 共享 request_id；B 无 `agent_id`，
  须从 A 取）。**不按 `seq` 关联**——A4 多实例下 `seq` 仅 WAL 内唯一（PK 是
  `(gateway_instance, seq)`），`request_id` 才全局唯一且实例安全；`decision_seq` 仅作
  实例内校验。
- `token_cost_per_agent`（Affordable；`response.token_usage` × A 的 `agent_id`）——
  **per-entity**：每 agent 一条 `Measurement`（`subject=agent_id`），另出一条聚合
  （`subject==""`）。
- `unclosed_loop_rate`（Transparency；A=ALLOW 而无配对 B）。

**验收**
- 配对记录 fixture：`token_cost_per_agent` 按 agent 正确归集（手算预期），既出 per-agent
  也出聚合；`unclosed_loop_rate` 对「A=ALLOW 无 B」正确计数。
- 关联 helper 单测：B→A 关联正确；孤儿 B / 孤儿 A（无配对）按定义处理且不抛。
- 覆盖/mypy/ruff。

**非目标**：⚠ 维度归因（EV-9，复用本 issue 的关联 helper）；阈值/打分（rubric）。

---

## EV-6 — DimensionRegistry 加载器 + 5 维 rubric YAML

- **从**：core `treval/registry/` + `registry/dimensions/*.yaml`
- **维度**：框架（数据驱动的标准载体 / 宪法 §14.3、§14.5）
- **前置**：EV-0

**范围**
- 按 EVAL_ARCHITECTURE §2.3 的 YAML 形状实现 `DimensionRegistry` 加载器
  （dimension、L1–L5、control_objectives：`kind=measured|attested`、
  `indicator_id|posture_key`、`satisfied_when` 表达式、**`requires_integrity: bool`
  （默认 false）**）。
- **`requires_integrity: true`** 的目标只能由 `VERIFIED`（WAL）证据满足——给
  Transparency 维的链/seq/防篡改类目标标 `true`（保证 Postgres `UNVERIFIED` 数据
  抬不动 Transparency 这条护城河）。规则消费在 EV-7。
- 依 5×5 成熟度表（CSA 对齐）撰写 5 份维度 YAML。Affordable 作横切（成本指标在
  其他维内被引用，**不单列文件**）。
- 校验：每个 `indicator_id` 能解析到已注册指标；`posture_key` 合规；
  `satisfied_when` 可解析。
- `satisfied_when` 迷你求值器**必须安全**：禁用 `eval()`，仅白名单比较，作用于
  `Measurement` 字段（`value`/`sample_size`）（宪法 §4 精神：不执行任意代码）。

**验收**
- 5 份 YAML 往返加载成功；mypy/ruff。
- 校验能抓出：未知 `indicator_id`、畸形 `posture_key`、坏 `satisfied_when` → 清晰报错。
- `satisfied_when` 求值器：拒绝任意表达式；样例比较结果正确。
- 完整性测试：5 维 × 5 级均有内容（空格须显式标 N/A，不得隐式留空）。

**非目标**：rubric 打分引擎（EV-7）；registry 落 core vs ir-spec（待定 fork，本期落
core）；编辑 UI。

---

## EV-7 — MaturityRubricEngine + report + 确定性 JSON 序列化

- **从**：core `treval/rubric/`
- **维度**：Transparency/Accountability（measured ∪ attested、gap 报告）
- **前置**：EV-4（Measurement）、EV-3（PostureEvidence）、EV-6（Registry）

**范围**
- `RubricEngine.evaluate(registry, measurements, posture) -> MaturityReport`。
- 逐 objective：measured/attested 归并；status = `met/unmet/insufficient_data/unverified_evidence`。
- `measured_ceiling`、`attested_ceiling`、`awarded_level = min(...)`。
- **完整性门（第 2 轮细化，替代旧规则）**：`BROKEN` 证据**永不**满足任何 objective；
  `UNVERIFIED` 证据**可**满足 `requires_integrity=false` 的目标，但对
  `requires_integrity=true` 的目标解析为 `unverified_evidence`（不满足）。
  → 让 Postgres（`UNVERIFIED`）规模路径可用，同时 Transparency 完整性目标仍须 WAL。
- **`verification_basis`**：据 evidence 的 `IntegrityStatus` 构成填
  `"wal"|"index"|"hybrid"`，写入 `MaturityReport`（字段已在 EV-0 冻结）。
- `gaps` = 已 attested-met 但缺 measured 支撑的 objective（过度声明标记）。
- `integrity_summary` 计数。
- `MaturityReport` 确定性 JSON 序列化（键序稳定，便于复现/diff）；契约见
  `docs/REPORT_JSON_SCHEMA.md`（EV-R1）。
- 引擎对输入纯函数。

**验收**
- measured L3 + attested L2 → 授 L2（min 门）。
- attested L4 + measured L2 → 列出过度声明 gap；授 L2。
- 某 objective 仅有 BROKEN 证据 → `unverified_evidence`，该级不满足。
- **完整性门**：全 `UNVERIFIED`（Postgres-only）输入 → 聚合目标可满足，但
  Transparency 的 `requires_integrity=true` 目标 → `unverified_evidence`；同数据走
  WAL（`VERIFIED`）则满足。`verification_basis` 相应为 `index`/`wal`。
- `insufficient_data`（`sample_size=0`）与 `unmet` 区分。
- 同输入 → 字节一致 JSON（确定性测试）。
- 覆盖/mypy/ruff。

**非目标**：human/CSV 渲染（EV-8）；仅凭遥测自动定级（设计明令禁止）。

---

## EV-8 — 测评 CLI + 语料格式 + 首批场景（conformance 的对应物）

- **从**：core `treval/cli.py`、`corpus/*.yaml`
- **维度**：框架 + 护城河（开源事实标准语料 / 宪法 §14.5）
- **前置**：EV-7

**范围**
- CLI：`python -m treval <wal_dir> --posture posture.yaml [--export db] [--json|--human|--csv]`
  → reader → indicators → registry → rubric → 渲染 `MaturityReport`；对齐
  `wal_verify` 的 CLI 习惯与退出码。
- human + CSV 渲染器。
- 语料格式：自描述 YAML 用例 = `{description, audit_records（RCtx 映射或生成的 WAL）,
  posture, expected: MaturityReport 子集}`；pytest 驱动的语料 runner（仿 conformance）。
- 首批场景取自成熟度表（**先取 ✓ 指标可建的**）：如 Character.AI 漂移
  （Robustness 低）、AWS Bedrock 全链路（Transparency L3）、OpenAI/Mixpanel 泄露
  （Privacy 反面）。

**验收**
- CLI 在 fixture WAL + posture 上端到端 → 三种格式报告；退出码合理。
- 每个语料用例跑通并复现其 `expected` 子集（语料 runner 绿）。
- 语料平台无关（fixture 本地构造，仿 `walgen.py`）。
- 覆盖/mypy/ruff。
- （E2E，测试负责）真实 WAL mount + posture → CLI 产报告；与开发 fixture 行为一致。

**非目标**：现在就 100+ 场景（持续扩，§14.5）；PDF；**Web UI（已移出，见 EV-W1/
EV-W2）**；需 ir-spec E1 维度 tag 的场景（随 EV-9）。

---

## EV-9 — 维度归因指标 + Robustness/Privacy 可测信号（**E1 已落，解除阻塞**）

- **从**：core `treval/indicators/`；消费 ir-spec E1 契约 + platform emit
- **维度**：Robustness、Privacy（需 dimension 归因）
- **前置**：~~ir-spec E1~~ **已落**（proto A1–A4 + platform emit + WAL golden 全合入，
  CI 绿）；EV-5b（复用其 A↔B 关联 helper 读响应侧规则）；EV-4（指标框架）

**E1 契约（已落，详见 EVAL_ARCHITECTURE §4.1）**——core 直接消费下列字段：

| ID | message.field (#) | 类型 | core 用途 |
|---|---|---|---|
| A1 | `RuleEvaluation.tags` (6) | `map<string,string>` | `tags["dimension"]` 维度归因（可能缺）；其余 tags 元数据 |
| A2 | `RuleEvaluation.score_deltas` (7) | `map<string,double>` | 本规则**命名**增量（一规则可多名） |
| A3 | `DecisionTrace.scores` (7) | `map<string,double>` | 聚合记分板，`scores[n] == Σ score_deltas[n]` |
| A4 | `RequestContext.audit_schema_version` (9) | `optional uint32` | 代别判别；**=1** 起为 E1，**缺省 ⇒ pre-E1 历史** |

要点（消费侧必须遵守的语义）：

- **逐字、不解释**：tags/score_deltas 字节等同；维度分类法只在 core。
- **覆盖**：每条**已评估**规则都带 tags（命中与否都有）；仅触发 score 的规则带非空
  score_deltas。
- **双记录**：record A（decision.made）带请求侧规则 + 聚合 `decision.scores`；
  record B（response.observed）**稀疏**——带响应侧 per-rule（`on_tool_response_rules`）
  但**无 DecisionTrace、无聚合板**。core 从 A 读板、从 B 读响应规则（按 `request_id` 关联）。
- **Σ 不变式 = 免费完整性校验**：`decision.scores[n] == Σ score_deltas[n]`（conformance
  011），EV-9 应断言之并标记违反记录。
- **A4 用 presence 判别**（`HasField`）：缺省即 pre-E1，按「无维度数据」处理（排除出维度
  覆盖率分母），**不是错误**。

**WAL golden（原 D，已落）**：ir-spec
`gen/python/trustworthy_ai_conformance/wal_v2_golden/`，5 例（001–005，含
**005 hash_field_corrupt**：读存储 hash 而非重算 + `chain_verify: reject`）。
两解析器（platform `wal.py` / core `_wal_format`+`wal_verify`）同跑。
core 侧本分支已落 `tests/conformance/test_wal_golden.py`。

> **EV-9 开工前先核**：本仓 venv 里安装的 ir-spec 上次检查仍是 **pre-E1** proto。
> 先 `pip install -U -r requirements.txt` 重新拉取，确认编译出的 descriptor 上
> `RuleEvaluation.tags` / `DecisionTrace.scores` / `RequestContext.audit_schema_version`
> 存在；`tools/wal_dump.py --decode` 能解出 tags 即就绪。
> （admin API 看不到 tags 是正常的：它是派生 SQLite 索引的投影摘要，不含
> `rule_evaluations[*].tags`；core 一律读 WAL 字节，不读 admin。）

**范围**
- 实现 ⚠ 指标：`injection_rule_hit_ratio`、`boundary_breach_rate`、
  `drift_alert_count`（读 `rules_evaluated[].tags["dimension"]`、`score`）；
  `redaction_hit_ratio`、`pii_exposure_surface`（`params_indexed` 的 `pii_*/phi_*`）。
- 补对应语料场景（如 EigenShield L4 攻防量化）。

**验收**
- 用 post-E1 proto 的 fixture：指标按 dimension 正确归因；EigenShield 式量化场景
  复现；覆盖/mypy/ruff。

**非目标**：ir-spec E1 契约合入前的任何动作；V1.1 PII 标签器（privacy 指标可先
stub 至标签器落地）。

---

## EV-R1 — Report JSON 契约（提前落，解锁 UI 工程师）

> **设计定稿见 [`docs/issues/EV-R1.md`](issues/EV-R1.md)（2026-07-15）** —— 以下为要点摘录。

- **从**：core `docs/REPORT_JSON_SCHEMA.md` + `docs/report.schema.json` + `tests/fixtures/report/{valid,invalid}/*.json`
- **维度**：框架（UI 的稳定消费契约）
- **前置**：EV-0（`MaturityReport` 已冻结）+ EV-7（`bundle_to_json` 序列化器，已在）

**范围（设计定稿）**
- **自包含交付包（核心决策）**：交付/fixture 形态是**一份自包含 bundle**，内联
  `report` + `registry` + `measurements`：`{schema_version, registry_fingerprint, report,
  registry, measurements}`。UI 加载**一个文件**即可渲染（含 value 列 + 5×5 结构），不会漏配/错配。
  引擎内部仍**解耦**（三个数据类不变），内联只是序列化时的组装步骤。**核心层（解耦，机器/API）
  vs 交付层（自包含，人/UI）** —— 见设计文档 §1a。
- **关联规则**：objective 只有 `objective_id`+`status`，值/等级/文案须经 registry 关联
  （`objective → registry.spec.evidence.indicator_id → measurement`）—— 故 registry 必须内联。
- **fixtures = 真序列化器生成的 golden 快照 + CI 防漂移测试**（`UPDATE_FIXTURES=1` 一键更新）；
  覆盖六态（rich / all-not-measured / over-claim gaps / insufficient_data / verification_basis / per-subject）。
- **正式 JSON Schema（draft-07，非 2020-12 —— 生态工具链更广，UI 无额外依赖负担）**；`invalid/` 集
  测 UI 拒绝路径（不进 golden，防污染防漂移测试）。

**验收**
- 每个 `valid/` fixture 过 schema 校验；drift-guard 重生成比对通过；`invalid/` 全部被 schema 拒。
- UI 工程师仅凭一份自包含 bundle 起 EV-W2，无需后端就绪。

**将来改进（证据触发，非既定任务 —— 触发条件见设计文档 §8）**：二者都**无法现在拍板**，触发条件
须待 EV-R1 落地、生成真实 bundle / UI 实际消费（即 live test）后才可观测 —— 触发前无事可做、无 issue
可建，EV-R1 **不因此不 ready**。① 规模化时改**解耦下发**（registry 只发一次，reports 按
`registry_fingerprint` 配对）；② measurement 详情外移（可选 `detail_url`）。均为 `schema_version`
加值式演进，不破契约。（**已既定且已跟踪**的 `registry_fingerprint` 失配处置在 **EV-W1**，非此处 prose。）

**非目标**：序列化**实现**内部改动（EV-7 数据类不动）；渲染与服务（EV-W1/W2）；serve 时对
`registry_fingerprint` 失配的处置（EV-W1）。

---

## EV-W1 — 只读报告服务（报告存储 + 索引 + SSR 端点）

> **设计定稿见 [`docs/issues/EV-W1.md`](issues/EV-W1.md)（2026-07-17）** —— 以下为要点摘录。
> 原第 2 轮 stub 的三处已被原型 + 代码核对推翻，见下「与原 stub 的差异」。

- **从**：core `treval/web/`（`treval[web]` extra，宿主是已并入的 EV-W0）
- **维度**：框架 / Transparency（结果可视）
- **前置**：EV-7（report）、EV-R1（契约，已并）、EV-W0（服务骨架，已并）

**范围**
- **报告存储（新增）**：`treval report --self-contained --out-dir DIR` 落 EV-R1 交付 bundle；
  内容寻址 `bundles/<sha256>.json` + `index.json`（原子替换）。**服务只读该目录，绝不在请求里跑引擎**
  —— 这是「切租户秒级」的前提。
- 端点：`GET /reports`（索引，喂顶栏两个下拉，默认最新）、`GET /`（Dashboard SSR）、
  `GET /detail`（报告详情 SSR）、`GET /report.json`（**原样返回存储字节**）、`GET /api/registry`（EV-W0 不变）。
- **无任何写路由**；**无 `/evidence`** ⇒ 服务不读、不渲染任何请求体，宪法 §12 由构造保证而非靠约束。
- 鉴权：loopback + token，**operator/审计视图**，非多租户门户（逐人租户 ACL 属 Platform）。
- 依赖隔离：`treval.web` import 引擎；**引擎绝不 import web**（`tests/test_web.py` 两条守卫已在）。

**与原 stub 的差异（均经代码/真数据核对）**
1. **`/evidence` 撤销** —— 定稿 UI 不下钻到请求级，无消费方；撤掉后服务不暴露任何 PII。
2. **regenerate 管理员 + 异步 撤销** —— 重新评测改为**外链跳转**到评测执行页 ⇒ 只读性由构造保证。
3. **新增报告存储** —— 今天**没有任何组件存储生成好的报告**；且 CLI 的 `--format json` 走的是
   core 层 `bundle_to_json`，**产不出 EV-R1 交付 bundle**（须 `self_contained_bundle_to_json`）。

**待裁定**：**O1** —— 重新评测跳去哪？评测执行页**不存在**（今天只有 CLI）。
建议先落「显示可复制的 CLI 命令」（诚实、零新面），见设计文档 §8。

**非目标**：dashboard 模板/UX（EV-W2）；写操作；`/evidence`；逐人租户 ACL；留存/GC。

---

## EV-W2 — Dashboard 模板 / UX（UI 工程师）

> **设计定稿见 [`docs/issues/EV-W2.md`](issues/EV-W2.md)（2026-07-17）** —— 以下为要点摘录。
> 呈现已用**六份真实 fixture 的原型**评审定稿：本 issue 是**誊写，不是探索**。

- **从**：core `treval/web/templates/`（+ 静态资源）
- **维度**：框架（可视化）
- **前置**：EV-R1（fixtures 起步，已并）→ EV-W1（端点集成）

**范围**
- 两个视图：**Dashboard = 结论**（结论横幅 · 风险卡 · **雷达图** ǀ **成熟度总表**）；
  **报告详情 = 依据**（**判定规则与本次结果合并为一张表**，71 行，可按类型/维度/只看过度声明筛选 + 搜索）。
- 租户/窗口下拉**常驻顶栏**，跨视图不变（全局作用域 vs 视图）。
- **`null` 不是 0** —— 无实测信号的维度画灰虚轴 + 标注，**绝不画成 0 分**（否则等于给没测过的维度捏造一个不及格）。
- 雷达图纯 SVG，点由 EV-W1 服务端算（`radar_points()`），**不引图表库**。
- 判定规则 **WAF Signature 式**：全可查、**零编辑入口**；讲明为何不可改（`registry_fingerprint` 绑定）
  以及与 WAF 的差别（**语料原文不公开，只公开清单 ID+类别+sha256**）。
- 设计 token **沿用 EV-W0**（`--measured` teal / `--attested` amber / logo / banner），仅新增 `--risk`。

**验收**（详见设计文档 §8）
- 六份 fixture 全部正确渲染，尤其 `all_not_measured`（5 根无信号轴，不捏造 0）与 `verification_basis`（破损 → 结论①）。
- **无头渲染守卫为硬验收**：断言**零 JS 错误** + 关键元素存在。
  *理由（本 issue 自己的历史）*：原型三轮上线即坏 —— 一次引号错配吞掉表格单元格导致整列错位，
  一次 `title="…"` 嵌在双引号 JS 字符串里抛 `SyntaxError` 整页白屏。**两次源码审阅都看着是对的。**
- 决不臆造总分（`MaturityReport` 没有总体等级）；界面不出现内部措辞（待裁定/issue 号）。

**非目标**：SPA/JS 构建链；图表库；导出/打印报告（**当前目标是在线视图**）；请求级下钻；语料清单浏览（依赖语料库）。

---

## EV-R2 — active-eval 用例级结果契约（**新增，第 3 轮**）

- **从**：core `tools/eval_report.py`(active) + 新契约
- **前置**：无（与 EV-W1/W2 正交）
- **触发**：原型评审时提出「详情页要能看失败/成功的用例名字」。

**为什么它不在 EV-R1/EV-W1 里（经代码核对）**
`case_id` 只活在 active eval 进程的 `ProbeResult`（`treval/active_eval/target.py:49`）；探针只发
`x-agent-id` + `{tool_id, params}` ⇒ **case 名字从没进过 WAL**。EV-R1 是 **passive** 流水线，读 WAL 生产流量 ——
样本是**真实请求（request_id），不是测试用例**。**扩 EV-R1 契约也变不出引擎从没观测过的字段。**
用例级结果属于 **active** 那条流水线（OWASP LLM Top-10），今天只出 markdown/csv，**无机器可读契约**。

**范围（待设计）**：给 active eval 一份 JSON 契约（case_id ↔ request_id ↔ 判定 ↔ 证据指针），
使 UI 能呈现用例级结果。**注意**：它承载请求内容 ⇒ PII 面与 EV-W1 完全不同，须独立威胁模型。

**非目标**：把用例名单塞进 EV-R1 bundle（数据不存在，且会把 PII 塞进交付物）。

---

## 排期 Backlog（第 3 轮后 · 2026-07-19 定稿 · PM/售前/架构师三方过）

> 三方 review 后的近期次序。三个协调判断:①**PROV(+ 其前置 EV-PIN)排在 EV-FWD 之前** —— 同时卡着待审稿白皮书与 roadmap 对外数字,杠杆最高、size 最小;**EV-PIN 是 PROV 的根因修复**(对外数字必须来自 pinned run,不能是 `__eval__` 0-0 移动窗口);②**P3C-harness 是外部依赖**,spike 点火时可能抢占 EV-FWD,Core 须预留,别让 OSS 增长盖过 Platform 主线 P3-content;③EV-FWD vs #6 的 tiebreaker 仍是"有没有活的生产报告 POC"。

| 序 | 项 | 为什么这个位置 | 规模 |
|---|---|---|---|
| 1 | **CI-1** 渲染守卫 CI 里 fail 非 skip | 原 P0,护旗舰守卫,且是 v0.2.0 门 | 小 |
| 2 | 🔴 **EV-PIN** 冻结评测 run(消除移动窗口) | PROV 的前置:对外数字须来自 pinned run,今天 collect 恒 `window=[0,0]`、无窗口参数 | 小 |
| 3 | 🔴 **PROV** 数字 provenance 对账(**协作:Core 起头 + Platform 补齐**) | **唯一同时解锁待审稿白皮书 §5.2/§5.4 与 roadmap 对外数字**(9.2-B 硬门);依赖 EV-PIN | 小(Core)/ 跨仓 |
| 4 | **EV-FWD** standalone 标的抽象 | OSS 推广总开关,便宜、无生产 PII | 中 |
| 5 | **#4** 窗口键 → `generated_at_ns` | 潜伏 bug,顺手 | 小 |
| 6 | 🆕 **P3C-harness** P3-content spike 测量 harness | Platform 即将开 P3-content 跨仓依赖,spike 起跑时 Core 须能供 harness | 中 |
| 7 | **#6** 生产被动路径 | 大头(reader+租户隔离+PII 面);按有无活 POC 定序 | 中 |
| 8 | **P2 束** UI-3 证据下钻(网关)/#5 执行页/EV-R2/DX 一条命令/UI-6 趋势 | 产品完整性 | 中/大 |

---

### CI-1 — 渲染守卫在 CI 里 fail 而非 skip（P0）

- **从**:`.github/workflows/ci.yml` + `package.json`(jsdom 已声明)
- **问题**:EV-W2 无头渲染守卫**正因原型三轮上线即坏才存在**,但 CI 无 `npm ci`/node → `pytest.skip` → 在唯一重要处形同虚设。
- **范围**:CI 加 `setup-node` + `npm ci`;`CI=true` 时守卫**缺 node/jsdom 即 fail,不 skip**。
- **验收**:CI 日志显示守卫实跑(非 skip);故意破坏一个模板 → CI 红。

### EV-PIN — 冻结评测 run（pinned run，消除移动窗口）🔴 PROV 前置

- **设计定稿**:[docs/issues/EV-PIN.md](issues/EV-PIN.md)
- **根因**:`collect` 产出 `window=[0,0]`、无窗口参数 → 任何对外引的数都是移动窗口(`__eval__` 0-0 最新)快照,不可复现。`WalEvidenceReader` **已支持 `time_from_ns/time_to_ns` + 按段读**(`wal_reader.py:87-89`)—— **reader 能 pin,producer 不给驱动**。
- **范围**:① collect 落**真实观测窗口**(min/max received_at_ns,不再 `[0,0]`);② collect 接受 `--window-from-ns/--window-to-ns` 透传 reader → **run 可复现**;③ bundle 带 `{window, wal_segments, WAL 段 sha, pinned:bool}`;④ `pinned:false` 的数**禁止对外引用**。
- **验收**:同 WAL + 同窗口跑两次 → 同 n/同 value/同段 sha;`chain_integrity` 的 n 不随 WAL 尾部前移变化。
- **非目标**:改指标计算;UI 窗口选择键(#4,正交);生产租户被动读(#6)。

### PROV — 检测型数字 provenance 对账（🔴 排 EV-FWD 前 · **协作:Core 起头 + Platform 补齐** · 依赖 EV-PIN）

- **设计定稿**:[docs/issues/PROV.md](issues/PROV.md) · **对账 artifact**:[CORE_INJECTION_NUMBER_PROVENANCE.md](../../trustworthy-ai-platform/docs/collab/CORE_INJECTION_NUMBER_PROVENANCE.md)(附可转发的 Platform 待补清单 §6)
- **根因(两位架构师收敛)**:🔴 对外数字取自 LIVE 移动窗口而非 pinned run → 不可复现。**463 与 404 同病**(我手上的 404 bundle 窗口也是 `[0,0]`)。故依赖 EV-PIN。
- **裁决**:① 作废 n=463(不可复现,pin 不了);② **Core 用 EV-PIN 冻结唯一规范 run**(关键约束:不能又是"404 最新"移动快照);③ **Platform 对 chain_integrity 只做白皮书 463→规范值换字**(文档编辑,非计算 —— 原让 Platform"钉 463"是派错了活,已更正);④ Platform 真正的活 = 注入两版规则集号;⑤ demo 520 标合成(Core)。
- **硬门(9.2-B)**:白皮书 §5.2/§5.4 在本对账落定前**不分发**。
- **非目标**:改数值本身(值是真的,病在窗口不冻结/多源无桥接)。
- **✅ Core 侧已闭环(2026-07-19)**:两个规范 run 已冻结并可复算(`chain_integrity 100% n=173` /
  `injection_catch_rate 89.29% n=28`)· §5.0 仲裁表消除双值 · 两份 artifact 带 `canonical_for` +
  逐条 `canonical_source`(与 §5.0 表机器核对一致,无重叠无缺口)· demo 三态落地。
  **余下两项全在 Platform**:注入两版 Tier-1 规则集号 + 白皮书 `463 → 173` 换字。
- 🔴 **换字目标值是 173,不是 404** —— 404 与 463 同病且**覆盖段已被裁掉,无法补 pin**。

### F4 — `collect` 支持离线复算(无 `--gateway`)〔backlog,不阻塞 PROV〕

- **现象**:`collect` 无条件要求 `--gateway`(实测 `error: --gateway ... is required for collect`),
  即使只想在冻结副本上重算被动指标。
- **为什么重要**:第三方拿到冻结目录**用不了我们自己的 CLI**,得自己写 Python 才能复算。
  对一个卖"第三方可复算"的产品,这是真摩擦 —— 复现路径应当是"跑我们的命令",不是"读我们的源码"。
- **不阻塞 PROV**:现有复现路径(冻结目录 + artifact 的 `evidence_refs`)已成立并实测通过。
- **建议**:加 `--no-active` / 离线模式,跳过探针驱动,只跑 reader + 被动指标。**规模:小。**

### EV-FWD — standalone 标的抽象（OpenAITarget + 能力声明 + 报告契约）

- **从**:core `treval/active_eval/`(新 `OpenAITarget`)+ `treval/rubric`(能力声明→N/A 叠加)
- **设计定稿**:[CORE_STANDALONE_TARGET_ABSTRACTION.md §1–6](../../trustworthy-ai-platform/docs/collab/CORE_STANDALONE_TARGET_ABSTRACTION.md)
- **范围**:
  1. `OpenAITarget` 实现已有 `Target` Protocol(`target.py:93`):裸 OpenAI 信封 `/v1/chat/completions` + 解析响应 + 抽输出;覆盖私有端点(自建 base_url / 自定义 auth / 自签 TLS / DashScope·千帆)。**不是换 base_url**。
  2. **指标能力声明** `evidence_requirement: output_only | needs_decision | needs_wal` —— 🔴 **正确性闸门**:决策/WAL 指标在**跑之前**按 (mode×能力) 排除(`checks.py:41` "无决策→判未拦截→0%",不排除会造出诬告性 0%),报告标 `n/a_needs_gateway`。
  3. **报告契约**:报告级 `target_kind: raw_model | gateway` + 指标级 `availability` + 命名 `evidence_basis` —— 动 **EV-R1 bundle + eval_report 两处 schema**,`schema_version` 升版 + 同步 golden fixtures/drift-guard,**单独一提交**落对账单。
  4. **配对报告(paired,一等公民)**:裸 vs 网关同模型·**同一批语料对象(case ID + sha256)**·同窗口/seed;delta 建在**输出侧得逞率**上(非拦截率)。9.2-D:两侧必须同一上游模型。
- **复用面(已代码核实)**:输出侧 4 个指标逐字复用;决策/WAL 走 N/A。
- **护栏**:forwarder 永为最小测试客户端(不带规则/PII/审计 WAL);输出侧指标 ≠ 我方做内容安全(9.2-E,守能力边界)。
- **非目标**:把 forwarder 做成治理路径;standalone 借用"可验证审计/WAL 指纹"话术。

### #4 — 窗口选择键改 `generated_at_ns`（小,潜伏 bug）

- active 跑出的 `window=(0,0)` 使同租户多份报告窗口键相同,选择器两个 option 同值。D2 契约小改;详见 EV-W1 review 发现 #4。

### P3C-harness — P3-content 选型 spike 的测量 harness（🆕 外部依赖,可能抢占 EV-FWD）

- **从**:core active-eval(复用 harness/指标)+ P3-content 语料(受限,NDA)
- **触发**:Platform 即将开 P3-content 跨仓依赖;spike 点火时 Core 必须能供 harness。
- **范围(Core 承接四条)**:①**双侧**检测(recall ∧ FPR,守双向门);②**延迟预算**(治理不能把延迟吃穿);③**G4 样本隔离**(train/test + 近重复 + 来源分离);④**失败自解释**(每个判定可回溯到证据,非黑箱)。
- **红线**:P3-content 语料**不进开源仓**(护栏 3 / 受限语料计划);harness 代码开源,语料 NDA。
- **协调**:这是 Platform 主线,spike 起跑时优先级**可能高于 EV-FWD** —— Core 预留产能。

### #6 — 生产被动路径（大头,按有无活 POC 定序）

- **从**:core `treval/collect`(去 `--gateway` 硬依赖的被动读)+ 生产 WAL reader
- **设计**:见 CORE_STANDALONE §3 —— 挂**被动侧接缝** `AuditEvidenceReader`(第三个 reader),**非** EV-FWD 的 `ProbeResult` 缝。
- **范围**:生产 WAL 被动读 + **租户隔离** + **PII 面独立评估**(比 EV-W1 只读服务的 PII 面大得多)。
- **今天的缺**:`collect` 强制 `--gateway`(`collect.py:13` "Production-scoped passive reads land later");要给真实租户出报告须绕过 CLI 直接调库。
- **tiebreaker**:EV-FWD vs #6 谁先 = 有没有活的生产报告 POC;无则 EV-FWD 先。

### P2 束（产品完整性,数据/裁定到位后）

- **UI-3** 证据下钻(`verified` 可点进 WAL/sha256 清单)= 重开 EV-W1 D3 撤销的 `/evidence`,**须重评 PII 面**(仅网关模式)。
- **#5** 评测执行页(重新评测跳转目标;O1 现落地为显示 CLI 命令)—— 真写面,独立威胁模型。
- **EV-R2** active-eval 用例级契约(见上)。
- **DX 一条命令**(9.2-C):v0.2.0 加"一条命令跑起来"开发者体验门。
- **UI-6** 跨窗口趋势(依赖 #4 + #6 的多窗口真实数据)。

### 已 gate / 外部依赖(观望)

C0-c M1a(等 lead K1 命名空间)· C0-e indirect-benign 扩样 n≥100 · C0-f conformance fixtures · EV-AE14(等语料库 repo + G1–G4)· drift_alert_count(等 P3-drift)· EV-2 Postgres reader。

---

## 待定决策（第 2 轮 / 随实现调整）

1. ~~**包名 `treval`**~~ → **已定：`treval`**（见顶部决策表）。
2. ~~**EV-2 ExportReader 本期不做**~~ → **第 2 轮翻转：复活为 `PostgresEvidenceReader`**
   （WAL 规模慢 + Platform 建 PG 索引；`UNVERIFIED` 规模路径，详见 EV-2 + 顶部决策表）。
   待办：① Platform 落 `POSTGRES_READ_CONTRACT.md` 的索引列；② 选 `pg8000` vs `asyncpg`。
3. **Registry 落 core vs ir-spec**：两者皆开源；落 ir-spec 会使 rubric 成为像
   conformance suite 一样的发布契约。本期先落 core，第 2 轮定。
4. ~~**EV-5 是否再拆**~~ → **已定：拆 EV-5a（单记录率）/ EV-5b（A↔B-join+helper）**
   （见顶部决策表；关联 helper 归 EV-5b，EV-9 复用）。
5. **语料与 conformance suite 是否共用 loader**：暂分离，勿投机统一。
6. **PostureProvider 参考桩**：是否本期附 IAM/IaC 的「空但带类型」参考桩（仿平台
   `NOT_PROVIDED`）以示范扩展位，还是只留 `PostureFileReader` + Protocol。
7. **PG 驱动 `pg8000`(同步,纯 Python) vs `asyncpg`(异步,Apache-2.0)**：引擎/CLI 同步，
   倾向 `pg8000`（更简单、无 async 管线）；若 web 层走 async 再评估。**禁 psycopg(LGPL)**。
8. **Web 栈 `FastAPI`+Jinja2+HTMX（推荐）vs Flask+Jinja2**：FastAPI 类型友好、与 mypy
   严格度合；待 EV-W1 起步时与 UI 工程师/我敲定。`treval.web` 与引擎隔离（extra）。
