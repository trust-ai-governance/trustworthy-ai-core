# Trustworthy-AI Core — 测评引擎 Issues（第 1 轮分解）

对 `docs/EVAL_ARCHITECTURE.md` 的可执行 issue 分解。每个 issue 含：从（仓库/路径）/
维度 / 前置 / 范围 / 验收（可验证，开发写单测、测试写系统/E2E）/ 非目标。
沿用 `PHASE1_ISSUES.md` 的体例。

> 这是**第 1 轮**。第 2 轮调整点集中列在文末「待定决策」。issue 落库到 GitHub
> core repo 的 Project 后，随实现推进增删。
>
> 架构师默认决策（可在第 2 轮推翻）：包名 `treval/`（根目录可 import 库，区别于脚本
> 式 `tools/`）；前缀 `EV-`（避免与 ir-spec/platform 的既有 issue `E1` 冲突）；
> 切片顺序＝先用单个参考实现打通契约，再铺开集合。

---

## 依赖图

```
EV-0 契约/模型 ──┬─► EV-1 WalEvidenceReader ──┐
                 │                              ├─► EV-4 Indicator SDK+参考指标 ─► EV-5 ✓指标集 ┐
                 ├─► EV-3 PostureProvider+File ─┤                                                ├─► EV-7 RubricEngine ─► EV-8 CLI+语料
                 ├─► EV-6 DimensionRegistry ────┘                                                │
                 └─► EV-2 ExportReader（可延后）                                                  │
                                                                                                 │
ir-spec E1（审计 schema 增 tags/score，跨仓）+ EV-5 ──────────────────────► EV-9 维度归因指标 ───┘
```

无依赖根、可并行起步：**EV-0**（必须最先），随后 **EV-1 / EV-3 / EV-6** 可并行。

---

## EV-0 — 测评包骨架 + Evidence/Measurement 模型 + 核心 Protocol

- **从**：core，新建包 `treval/`（+ `tests/`）
- **维度**：框架（接口先于实现 / 宪法 §10）
- **前置**：无

**范围**
- 包骨架 `treval/`：`__init__.py`、`py.typed`，可 `import treval`。
- frozen dataclass（字段严格对齐 EVAL_ARCHITECTURE §2.1/§2.2/§2.4）：
  `IntegrityStatus(enum)`、`EvidenceRef`、`AuditEvidence`、`PostureEvidence`、
  `Measurement`、`ObjectiveResult`、`DimensionReport`、`MaturityReport`。
- Protocol：`AuditEvidenceReader`、`PostureProvider`、`Indicator`（`typing.Protocol`）。
- CI：扩展 `ci.yml` 对 `treval` 跑 ruff/format/mypy/pytest-cov（license 扫描已覆盖）。
- **不含任何逻辑、I/O**。

**验收**
- `import treval` 成功；`mypy treval` 干净；ruff/format 干净。
- 全部 dataclass 为 frozen；按文档字段构造并读回一致（单测）。
- Protocol 可被一个测试内的 dummy 实现满足并通过类型检查。
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

## EV-2 — ExportEvidenceReader（便利适配器，**本期不做 / 已降级**）

> 部署结论（详见 EVAL_ARCHITECTURE §4a）：真实 Docker 环境下 core 以**只读**挂载
> 网关 WAL 卷（`wal-data:/wal:ro`）直读段文件即可，**不需要 DB**——D1 规定 WAL 是
> 唯一权威源，sqlite `audit.db` 是派生可弃索引；读它只能标 `UNVERIFIED`，对需要链
> 完整性的 maturity 评估收益小。故本 issue **本期不做**，待 WAL 重解析成为瓶颈再
> 作为「便利、UNVERIFIED」适配器加入。postgres 同理（更远）。

- **从**：core `treval/readers/export_reader.py`
- **维度**：框架（便利路径，可选）
- **前置**：EV-0；（平台导出格式确定）

**范围**
- 在 `AuditEvidenceReader` 同一接口下读平台审计导出（SqliteAuditSink 产出的
  SQLite，或 CSV）；每条 `IntegrityStatus.UNVERIFIED`（无法逐字节重校链）。
- Evidence 形状与 WAL reader 一致。

**验收**
- 给定样例导出 DB/CSV：产出 `AuditEvidence` 与 WAL reader 同记录一致（除
  integrity）；每条 `UNVERIFIED`；过滤生效。

**非目标**：链校验（导出本就不可能）；写入/迁移。
> 架构注：耦合平台导出格式，且削弱独立验证叙事。建议第 2 轮再定是否本期做。

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
- `block_rate`：3×ALLOW + 1×BLOCK → `value=0.25, sample_size=4, len(evidence_refs)=4`。
- 纯度测试：同一 evidence 跑两次 → 完全相同 Measurement。
- 覆盖/mypy/ruff。

**非目标**：完整指标集（EV-5）；维度归因指标（EV-9，需 ir-spec E1）；rubric 打分。

---

## EV-5 — 当前 proto 可建（✓）指标集

- **从**：core `treval/indicators/`
- **维度**：多维（Security/Reliability/Transparency/Affordable）
- **前置**：EV-4

**范围**（实现 EVAL_ARCHITECTURE §5 中标 ✓ 的指标，每个注明 dimension + 源字段）
- `scope_deny_rate`（Security；`authorization.allowed`/`missing_scopes`）
- `token_cost_per_agent`（Affordable；`response.token_usage` × `agent_id`，A↔B join）
- `error_rate` / `terminal_error_ratio`（Reliability；`audit.errors[]`/`response.final_terminal`）
- `duration_p99`（Reliability；`response.duration_ms`）
- `unclosed_loop_rate`（Transparency；A=ALLOW 而无配对 B）
- `chain_integrity`（Transparency；来自 reader 的 `IntegrityStatus` 汇总）
- `hint_emission_rate`（Transparency；`audit.hint_emitted`）

**验收**
- 每个指标有**手算预期**的 fixture 测试；A↔B join 类用配对记录测；
  `chain_integrity` 在注入 BROKEN 时正确反映；所有 `evidence_refs` 已填。
- 覆盖/mypy/ruff。

**非目标**：⚠ 维度归因指标（需 ir-spec E1）；阈值/打分（归 rubric）。

---

## EV-6 — DimensionRegistry 加载器 + 5 维 rubric YAML

- **从**：core `treval/registry/` + `registry/dimensions/*.yaml`
- **维度**：框架（数据驱动的标准载体 / 宪法 §14.3、§14.5）
- **前置**：EV-0

**范围**
- 按 EVAL_ARCHITECTURE §2.3 的 YAML 形状实现 `DimensionRegistry` 加载器
  （dimension、L1–L5、control_objectives：`kind=measured|attested`、
  `indicator_id|posture_key`、`satisfied_when` 表达式）。
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
- `BROKEN/UNVERIFIED` 证据 → `unverified_evidence` → **不能满足**任何 objective。
- `gaps` = 已 attested-met 但缺 measured 支撑的 objective（过度声明标记）。
- `integrity_summary` 计数。
- `MaturityReport` 确定性 JSON 序列化（键序稳定，便于复现/diff）。
- 引擎对输入纯函数。

**验收**
- measured L3 + attested L2 → 授 L2（min 门）。
- attested L4 + measured L2 → 列出过度声明 gap；授 L2。
- 某 objective 仅有 BROKEN 证据 → `unverified_evidence`，该级不满足。
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

**非目标**：现在就 100+ 场景（持续扩，§14.5）；PDF；Web UI；需 ir-spec E1 维度
tag 的场景（随 EV-9）。

---

## EV-9 —（阻塞于 ir-spec E1）维度归因指标 + Robustness/Privacy 可测信号

- **从**：core `treval/indicators/`；依赖 ir-spec E1 + platform emit
- **维度**：Robustness、Privacy（需 dimension 归因）
- **前置**：ir-spec E1（下列 A 项）合入 → 可建；platform emit（B 项）落 → 可在真实数据上验收；EV-5

**ir-spec E1 具体依赖**（详见 EVAL_ARCHITECTURE §4.1；当前 proto 的
`RuleEvaluation` 仅 `rule_id/rule_version/matched/actions_fired/eval_duration_ns`，
无 tags/score；`DecisionTrace` 无 scores）：

> **已核实（descriptor 内省）**：A/B 两侧 `rules_evaluated` 与
> `on_tool_response_rules` **同一个** `RuleEvaluation` 消息 → 改一处覆盖两侧。
> RuleEvaluation 现用 1–5，空号 6/7；DecisionTrace 现用 1–6 + 20，空号 7–19。
> **无任何 audit schema 版本字段**（B2 只加了 `record_type`=#7 枚举，不是版本）。

- **A. proto 变更（ir-spec，编译期依赖）**
  - A1 `RuleEvaluation.tags: map<string,string>`（新增 optional，**#6**）——透传
    含 `dimension` 的规则 tags。**硬阻塞**：无此则零维度归因，EV-9 全废。
  - A2 `RuleEvaluation.score_deltas: map<string,double>`（新增 optional，**#7**）
    ——per-rule **命名**增量。**（由 `score: double` 修正）** ScoreStmt=
    `(score_name, delta)` 且一条规则可含多个不同名 ScoreStmt，单标量丢名字且无法
    表达多分；map 同时与 A3 同形，core 可顺带交叉校验「Σ per-rule == 聚合」。
  - A3（推荐）`DecisionTrace.scores: map<string,double>`（**#7**）——请求级聚合
    记分板（对应 conformance 011）。落盘它不算「解释」（本就是执行期请求级状态）。
    无则 score 指标退化为 per-rule sum。
  - A4（推荐，**非阻塞**）`RequestContext.audit_schema_version: uint32`（新顶层，
    如 **#9**）——**修正「与 B2 合并」**：B2 只加 record_type 非版本。proto3 map
    无 presence，空 tags 分不清 pre-E1/未打 tag；此字段让 core 把 legacy 排除出
    「维度覆盖率」分母。无它 core 仍能出「X% 记录带维度」，故非 gate。
  - A5 字段规则：additive/optional/字段号永不复用，1–6 号不动（宪法 §3.2/3.3/3.5）。
- **B. platform emit（闭源网关，运行期数据依赖）**
  - B1 对**每条已评估规则**（命中与否都）填 tags（一处消息、两侧自然覆盖），
    否则比率类指标缺分母。
  - B2 严格只 emit 不解读（PLAN §1），网关不得算 dimension。
- **C. spec conformance（可选）**：增 1 用例断言 tags+score_deltas 透传进审计事件。
- **D. WAL v2 golden 向量（ir-spec，本期交付，非可选）**：两个解析器
  （core `_wal_format` / platform `wal.py`）须跑同一组「已知字节→期望解码」golden，
  否则帧漂移在客户侧（部署 C）才爆。详见 EVAL_ARCHITECTURE §4.1-D；core 在
  **EV-1 验收**消费。D 独立于 A/B，应尽早落（降全部署风险，不止 EV-9）。

> A/B/C/D 均非 core 仓**编写**任务，core 只消费契约（并跑 golden）。A 先于 B；
> D 独立可先行。

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

## 待定决策（第 2 轮 / 随实现调整）

1. **包名 `treval`**：确认或改名（如 `eval_core`）。影响全部路径。
2. ~~**EV-2 ExportReader 本期做否**~~ → **已定：本期不做**（部署上 WAL 只读直读已
   足够，不需要 DB；详见 EV-2 头注 + EVAL_ARCHITECTURE §4a）。
3. **Registry 落 core vs ir-spec**：两者皆开源；落 ir-spec 会使 rubric 成为像
   conformance suite 一样的发布契约。本期先落 core，第 2 轮定。
4. **EV-5 是否再拆**：7 个指标可拆成 2 个 issue（Security/Reliability 一组、
   Transparency/Affordable 一组）若单 issue 过大。
5. **语料与 conformance suite 是否共用 loader**：暂分离，勿投机统一。
6. **PostureProvider 参考桩**：是否本期附 IAM/IaC 的「空但带类型」参考桩（仿平台
   `NOT_PROVIDED`）以示范扩展位，还是只留 `PostureFileReader` + Protocol。
