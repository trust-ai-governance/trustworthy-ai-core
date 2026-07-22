# R1 — 报告契约落 `target_kind` / `availability` / `evidence_basis`（schema，非运行时）

**Problem（plain language）：** 一份报告现在不声明**它测的是什么标的**（裸模型 / 受治理网关 /
第三方审核 API），也不声明**每个指标的证据强度**。于是一个"裸模型基线"报告和一个"受治理"报告
长得一样，读者无从分辨 `injection_catch_rate 0%` 是"治理崩了"还是"这本就是无治理的基线"。

**Value：** 把"标的 + 证据强度"做成报告契约的一等字段，让每份报告**自证它属于哪一档证据**。
最弱一档（第三方自报）必须显形为"**不可复算**"，不能借用"可验证审计"话术 —— 这是 measured>attested
叙事在证据分层上的落地。

> Dev brief. **这是实现单,不是设计** —— 设计已在上游 §5.2 ratify（[CORE_STANDALONE_TARGET_ABSTRACTION](../../trustworthy-ai-platform/docs/collab/CORE_STANDALONE_TARGET_ABSTRACTION.md) §5.2，私有）。
> **只落 schema，不落运行时**（`OpenAITarget` / harness 自抓打分归 EV-FWD 排期）。
> **规模**：小 —— 序列化字段 + schema + fixtures + 一次升版。**§8.7 单独提交。**

---

## 0. 边界（先划清，防范围膨胀 —— §1.5 review 后收窄）

- ✅ **做**：两个 bundle 顶层 envelope 加 **`target_kind` + 派生 `evidence_basis`** 两字段
  + JSON schema（.json + .md）+ golden fixtures + `SCHEMA_VERSION` 升版。
- ❌ **不做（推 EV-FWD）**：`availability` 真值表 + `evidence_requirement` 指标声明（§1.5-A）·
  `OpenAITarget` · harness 自抓打分接缝 · 任何 target 运行时。R1 只落**报告级契约字段**。
- ❌ **不动** rubric 引擎判级逻辑（序列化叠加，判级照旧）· 共享的 `serialize_measurement`（§1.5-C）。

## 1. 已裁形状（逐字对齐 §5.2，不重新设计）

| 字段 | 层级 | 取值 | R1 范围（2026-07-21 implementer review 后裁定，见 §1.5-A） |
|---|---|---|---|
| `target_kind` | 报告级（顶层 envelope） | `raw_model \| gateway \| moderation_api` | ✅ **R1 落**；`moderation_api` = R1 增量；**默认 `gateway`** |
| `evidence_basis` | 报告级（顶层 envelope） | **派生自 `target_kind`**（见 §2）；`wal_anchored \| harness_observed \| self_reported` | ✅ **R1 落**（派生，非独立存储） |
| `availability` | 指标级（每 measurement） | `measured \| n/a_needs_gateway` | 🔴 **推 EV-FWD**（见 §1.5-A）—— 在默认 `gateway` 下恒 `measured`、inert 且测不到 |
| `evidence_requirement` | 指标能力声明（~25 指标） | `output_only \| needs_decision \| needs_wal` | 🔴 **推 EV-FWD** —— 它是 `availability` 的派生输入,落它 = 动全体指标 = 运行时,违守护 #2 |

对客中文标签（`target_kind`）：`raw_model` = 裸模型基线评测 · `gateway` = 治理后评测（WAL 锚定）·
`moderation_api` = 第三方审核 API。

## 1.5 implementer review 裁定（2026-07-21，对着代码逐条）

> 四个字段代码里**零存在**（净新增，无对齐现状包袱）。以下把"往哪落"定死。

**🔴 A（主 gate）：`availability` + `evidence_requirement` 推 EV-FWD —— 这才让 R1"真的小"。** 理由（implementer 抓到、我认）：
- 序列化层拿不到 `evidence_requirement`（`Measurement` 无此字段）；落它要给 ~25 个指标类逐个加能力声明 = **动全体指标**,正是 §0 警惕的范围膨胀。
- **默认 `target_kind=gateway` 下 `availability` 恒 `measured`、`evidence_requirement` 不参与计算** —— 整条派生 inert；真正触发 `n/a_needs_gateway` 的 `raw_model`/`moderation_api` 报告是 **EV-FWD 运行时**才产出的,Core 现在产不出、也就测不到。
- 那条"正确性闸门"（`raw_model` 上不排除 `needs_wal` 指标会造诬告 0%）是**判级前排除的运行时行为**,而 §0/§7 明确 R1 不动判级 ⇒ 闸门归 EV-FWD。
- ⇒ **R1 = `target_kind` + 派生 `evidence_basis`；`availability`（槽位 + 真值表）+ `evidence_requirement`（指标声明）整体推 EV-FWD**（它拥有产非 gateway 报告的运行时、也才测得动）。这是守护 #2 应用到 availability。
- 📌 **需 PM/§5.2 点头**：§5.2 把 `availability` 列进契约,本裁定是"R1 vs EV-FWD 的范围切分",不改 §5.2 的形状,只改**谁落**。PM 确认即锁。

**B〔默认值〕：`target_kind` 默认 = `gateway`。** ✅ 裁定。现有报告都是 gateway 报告,默认 gateway ⇒ 现有 golden fixtures 只新增 `target_kind=gateway`/`evidence_basis=wal_anchored`,值正确；判级逻辑逐位不变（§7-5 指判级,不指序列化字节）。

**C〔两处 schema〕：认 (i) —— 两个 bundle 的顶层 envelope 都加 `target_kind`/`evidence_basis`,两个 `SCHEMA_VERSION` 一起升,一个 commit。** 这就是 P3C"EV-R1 bundle + eval_report 两处"的两处：`rubric/serialize.py`（交付 bundle）+ `cli/bundle.py`（collect bundle,记"探的是哪个标的"）。**因 A 推掉了 `availability`,共享的 `serialize_measurement` 不动 ⇒ 无 per-measurement churn**（implementer 担心的那半消解）。

**D〔放哪〕：顶层 envelope**,与 `schema_version`/`provenance` 并列（`serialize.py` 现有 provenance 就在顶层）。JSON 路径钉死：`bundle.target_kind` / `bundle.evidence_basis`。`serialize_bundle`（非 self-contained）与 `serialize_self_contained_bundle` **同放**。

**E〔两份 schema 文档 + 升哪个版本〕：** `docs/report.schema.json` **和** `docs/REPORT_JSON_SCHEMA.md` **两份同步**（.md 是真值源,施工单 §3 漏了它）。升版：`rubric/serialize.py` 的 `SCHEMA_VERSION`（必升）+ `cli/bundle.py` 的（按 C 也升）；`registry/serialize.py` 的**不动**（无关）。

**F〔`n/a_needs_gateway` 词不达意〕：因 A 推掉 `availability`,R1 不落真值表 ⇒ F 对 R1 消解。** 但 implementer 点出一个 §5.2 待补:`moderation_api` **也没有 WAL**,`n/a_needs_gateway` 对它词不达意（它缺的不是 gateway,是可验证性）—— **EV-FWD 落 availability 时,§5.2 需补第二个 n/a 原因值**（如 `n/a_self_reported`）。记此,给 EV-FWD。

## 2. `evidence_basis` 是派生，不是独立字段（裁定 A —— 这是 R1 的关键约束）

🔴 **单一真值源 = `target_kind`。`evidence_basis` 永不独立设置**，序列化时按固定映射**计算写入**：

```
gateway        → wal_anchored     （WAL 锚定 · 可复算 · 最强）
raw_model      → harness_observed （harness 自观测 · 中）
moderation_api → self_reported    （厂商自报 · 最弱 · 不可复算）
```

- **校验器机械门（不靠自觉）**：序列化后断言 `evidence_basis == derive(target_kind)`，
  不一致即 **FAIL**。把"单一真值源"做成门，同本项目一贯的"靠门不靠人"。
- 🔴 **红线**：`self_reported` 档**绝不借用"可验证审计 / WAL 指纹 / 可复算"话术**；
  无候选走 `moderation_api` 时报告**诚实显 absent，不伪造**（honestly-absent 纪律）。
- **⇒ "R1 增量只是 `moderation_api` + `self_reported`" 精确成立**：`target_kind` 加一个存储枚举值
  `moderation_api`；`self_reported` 只是那条派生映射的一个值，**不是独立枚举、不用发明
  `gateway`/`raw_model` 的 evidence_basis 值** —— 那正是裁定 A 绕开的坑。

## 3. 范围（改哪些文件 —— §1.5 review 后精确化）

1. **`treval/rubric/serialize.py`**：顶层 envelope 写 `target_kind`（默认 `gateway`）+ 派生 `evidence_basis`；
   `serialize_bundle` 与 `serialize_self_contained_bundle` 同放（§1.5-D）。**升其 `SCHEMA_VERSION`。**
   🔴 **不碰 `serialize_measurement`**（availability 推 EV-FWD，§1.5-A/C）。
2. **`treval/cli/bundle.py`**：collect bundle 顶层同加 `target_kind`/`evidence_basis`；**升其 `SCHEMA_VERSION`** +
   loader 接受（§1.5-C 的第二处 schema）。
3. **`docs/report.schema.json` + `docs/REPORT_JSON_SCHEMA.md`**：**两份同步**加字段 + 枚举（.md 是真值源，§1.5-E）。
4. **golden fixtures / drift-guard**：两个 bundle 的 fixtures 同步（`test_cli_bundle`/`test_report_store`/
   `test_web_report` 等，随 collect bundle 升版一起动）。
5. **入口穿参**：`target_kind` 需穿过 `bundle_to_json` / `self_contained_bundle_to_json` + 调用点
   （`cli/main.py`、`tools/make_demo_report.py`），或落进 `MaturityReport`；默认 `gateway`（§1.5-B）。
6. ❌ **不改 ~25 个指标类**（evidence_requirement 推 EV-FWD）· 不改 `registry/serialize.py` 的版本（无关）。

## 4. 守护三条（已在 [P3C-HARNESS §3.0](P3C-HARNESS.md)，此处复述锁范围）

1. **逐字实现 §5.2，不重新设计** —— §1/§2 就是 §5.2 的转写；有出入先对齐 §5.2 再落。
2. **只落 schema 骨架，不落 EV-FWD 运行时** —— 见 §0。别让 schema 把 `OpenAITarget` 拖进来。
3. **`moderation_api` 值现在落，消费者（C2 适配器）仍 gate 在厂商清准入之后** —— 会出现
   "枚举有值、暂无候选用它"，可接受（前向兼容）；但报告须诚实显 absent（§2 红线）。

## 5. §8.7 schema 纪律

- schema 改动**单独一个 commit** + 升**两个** `SCHEMA_VERSION`（`rubric/serialize.py` + `cli/bundle.py`，§1.5-C/E）
  + 同步两个 bundle 的 golden fixtures/drift-guard；对账单**单独一次提交**，不折进代码提交。
- 🔴 **对账单条目措辞**：`evidence_basis` 记成 **"派生自 `target_kind`、非独立存储"** ——
  别让它在账本里长成一个独立枚举，否则将来有人会去给它单独升版（真值源就裂成两个了）。

## 6. 归属纪律（一处定义 · 落地一次 · 多处消费）

- **一处定义** = 上游 §5.2（现已完整）。**落地一次** = R1 落 `target_kind`+`evidence_basis`；
  `availability`+`evidence_requirement` 由 **EV-FWD 落**（§1.5-A）。**多处消费** = C4 / EV-FWD。
- 🔴 **将来 EV-FWD issue 创建时必须交叉引用**："`target_kind`/`evidence_basis` 的 schema 已由 R1 落地，
  EV-FWD **消费、不重定义**，并在其上补 `availability`/`evidence_requirement` + `n/a` 第二原因值（§1.5-F）。"
  否则同一 schema 被两个 issue 争夺归属。**此义务记在此 + P3C-HARNESS §3.0。**

## 7. 验收（只测 R1 所落，不测推给 EV-FWD 的）

1. **两个** bundle 顶层均含 `target_kind`（三值枚举，默认 `gateway`）+ `evidence_basis`。
2. 🔴 **派生门**：构造 `target_kind` 三值各一，断言 `evidence_basis` 分别 == `wal_anchored` /
   `harness_observed` / `self_reported`；**篡改 `evidence_basis` 使其 ≠ derive(target_kind) ⇒ 校验 FAIL**
   （守卫测试，退回"独立设置"必须变红）。
3. **`self_reported` 报告不出现**"可验证审计 / WAL 锚定 / 可复算"字样（守卫断言）。
4. **无候选走 `moderation_api`** 时报告显 absent，非伪造一个空 target。
5. **现有 golden fixtures** 只新增 `target_kind=gateway`/`evidence_basis=wal_anchored`（默认 gateway 的正确值），
   **rubric 判级逐位不变**（字段是叠加，不进判级）。
6. 两个 `SCHEMA_VERSION` 已升；两个 bundle 的 fixtures 同步；`.json` + `.md` 两份 schema 一致；
   门禁不回归；`import treval` 不拉 web/PG。
7. **不测** `availability` 非 gateway 真值表（推 EV-FWD）—— 验收面与所落内容一致（§1.5-A）。
