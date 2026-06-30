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

- **从**：core `docs/REPORT_JSON_SCHEMA.md` + `tests/fixtures/report/*.json`
- **维度**：框架（UI 的稳定消费契约）
- **前置**：EV-0（`MaturityReport` 已冻结，含 `verification_basis`）

**范围**
- 据**已冻结**的 `MaturityReport` 写 JSON 契约：字段名、嵌套、枚举/`subject` 渲染、
  键序（确定性）。EV-0 后即可写，**不等** EV-7 的序列化实现。
- 提交若干**示例 report JSON fixtures**（覆盖：授级、过度声明 gap、`index`
  vs `wal` 的 `verification_basis`、per-agent `subject` 行）。
- 提供 JSON Schema（draft 2020-12）供 UI/测试校验。

**验收**
- fixtures 与 schema 互校通过；EV-7 的序列化输出（落地后）符合本 schema。
- UI 工程师可仅凭本契约 + fixtures 起 EV-W2，无需后端就绪。

**非目标**：序列化**实现**（EV-7）；渲染（EV-W1/W2）。

---

## EV-W1 — `treval[web]` 只读服务（API + SSR 骨架）

- **从**：core `treval/web/`（`treval[web]` extra）
- **维度**：框架 / Transparency（结果可视）
- **前置**：EV-7（report）、EV-R1（契约）、EV-1 和/或 EV-2（drill-down reader）

**范围**
- **FastAPI + Jinja2（+ HTMX）**，只读。端点：`GET /`、`GET /report`（缓存报告的
  SSR HTML）、`GET /report.json`（EV-R1 JSON）、`GET /evidence/{request_id}`
  （实时 drill-down，走 reader 点查）。
- **服务缓存报告，不每请求重算**（引擎跑得慢）；带 `generated_at_ns`；regenerate
  仅管理员/异步。
- **鉴权 + 租户作用域为硬验收**（暴露审计证据，含潜在 PII）：默认 loopback 绑定 +
  可选 token（仿平台 admin）；每查询带 `tenant_id`（宪法 §7）；**绝不渲染完整响应体**
  （宪法 §12）。
- 依赖隔离：`treval.web` import 引擎；**引擎绝不 import web**。web 依赖
  （FastAPI MIT / Starlette·Jinja2·uvicorn BSD / HTMX BSD-2）走 license CI。

**验收**
- 指向一个 fixture 报告：`GET /report.json` 符合 EV-R1 schema；`GET /` 返回渲染好
  的 SSR HTML（含 5×5 网格 + `verification_basis` 提示条）；`GET /evidence/{id}`
  能 drill-down。
- 未鉴权 / 跨租户请求被拒；任何端点都不外泄完整响应体。
- 覆盖/mypy/ruff；`pip install treval`（不带 extra）时引擎/CLI 不拉 web 依赖。
- （E2E，测试负责）真实启服务 + 真实/样例报告。

**非目标**：dashboard 模板/UX（EV-W2）；写操作；多报告/历史（后续）。

---

## EV-W2 — Dashboard 模板 / UX（UI 工程师）

- **从**：core `treval/web/templates/`（+ 静态资源）
- **维度**：框架（可视化）
- **前置**：EV-R1（fixtures 起步）→ EV-W1（端点集成）

**范围**
- Jinja2 模板 + HTMX 交互：5×5 成熟度网格、逐维 measured-vs-attested + gap 视图、
  evidence drill-down、完整性/`verification_basis` 提示条。SSR——client 下载渲染好
  的 HTML（不引入前端构建链）。
- 先用 EV-R1 fixtures 离线开发，EV-W1 就绪后接真数据。

**验收**
- 用 fixtures 渲染出三类页面（总览/维度/证据）；无后端亦可静态预览。
- 接 EV-W1 后端到端走通；可访问性/空数据/`insufficient_data` 态有合理呈现。
- 与 EV-W1 共同的 E2E（测试负责）。

**非目标**：SPA/JS 构建链；图表库重依赖（先 SSR + 轻量）；PDF 导出（后续）。

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
