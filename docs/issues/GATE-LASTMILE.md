# GATE-LASTMILE — 三条"已建好但没接上"的保护（CI-1 · RUFF-SELECT · C4）

> **Problem（普通话）：** 仓里有三处保护，**东西都造好了，但最后一厘米没接上**，于是它们看起来在保护、实际不保护：
> ① **无头渲染守卫**（EV-W2）在**本地跑、CI 跳** —— 它存在的理由正是"原型三轮上线即坏"，可它恰好在唯一重要的地方（CI）失效；
> ② **lint 门**刚 pin 住版本，但**规则集从未声明**，仍是"装上那个 ruff 碰巧的默认集" —— 下次主动升级同样会被规则漂移咬；
> ③ **R1 的 `target_kind`/`evidence_basis` schema 已 merged，却没有任何消费者** —— `tools/eval_report.py` 里两个字段命中 **0**，报告不标注标的与证据基。
>
> **Value:** 一个**静默不跑的保护比没有保护更糟** —— 它产生虚假信心（"守卫在的"/"lint 管着的"/"报告标了的"）。本增量把这三条各自的最后一厘米接上：守卫在 CI 里**缺依赖即 fail 而非 skip**、规则集**显式冻结**、报告**标注标的/模式**。三条独立可发，建议三次提交。
>
> **归属：** Implementer 编码 + 测试；架构师出本规格。
> **承：** backlog §CI-1 · [R1-TARGET-KIND-SCHEMA](R1-TARGET-KIND-SCHEMA.md)（schema 已落，本文只做消费）· P3C-HARNESS §C4。

---

## 0. 为什么合成一份（而不是三个 issue）

三条的**失效模式是同一个**：保护存在 → 但在真正需要它的路径上**静默退化**（skip / 继承默认 / 无人消费），且**退化不会让任何门变红**。合成一份是为了让这条纪律被写一次、验一次：

> 🔴 **凡"缺依赖就跳过"的守卫，在 CI 上必须改成"缺依赖就失败"。静默跳过等于没有守卫，还多一份虚假信心。**

**但三条彼此无耦合 ⇒ 建议三次提交**（P1/P2/P3），任一条可单独回滚。

---

## 1. P1 — CI-1：渲染守卫在 CI 里 fail 而非 skip

**现状（对着代码核实，2026-07-27）：**
- 守卫 = `tests/test_web_report.py::test_headless_render_guard`，用 `node tests/web/check_render.js` 对渲染出的页面做无头检查。
- 它有 **三层静默跳过**：① `shutil.which("node") is None` → skip；② `node -e "require('jsdom')"` 失败 → skip；③ 整个 web 测试族的 `pytest.importorskip("fastapi")` → skip。
- `package.json` 已声明 `jsdom`；**但 `.github/workflows/ci.yml` 无 `setup-node`、无 `npm ci`** ⇒ **CI 上 node 缺失 ⇒ 守卫恒 skip**。
- 本地开发机 node+jsdom+fastapi 齐全 ⇒ **守卫只在本地跑**。**保护装在了最不需要的地方。**

**范围：**
1. CI 加 `actions/setup-node` + `npm ci`（`package.json` 已就绪）。
2. 🔴 **三层 skip 在 CI 上一律改 fail**：当环境变量 `CI` 为真时，`node` 缺失 / `jsdom` 缺失 / **`treval[web]` 未装**都必须 **fail 并说明缺什么**，不得 skip。
   - **第 ③ 层是 backlog 原文没写、但必须一起补的**：只加 node 而 web extra 没装，守卫照样静默消失（`importorskip` 连 skip 记录都不显）。CI 已装 `requirements-web.txt`，所以这层平时不触发 —— 但**正因如此，它坏了也没人知道**，必须由门本身兜住。
3. 本地保持"缺依赖 → skip 且说明原因"（不逼开发机装 node）。**差异只由 `CI` 环境变量驱动。**

**验收：**
- CI 日志显示守卫**实跑**（非 skip）。
- 🔴 **teeth**：故意破坏一个模板（或在 CI 环境下模拟移除 node/jsdom/web extra）⇒ **CI 红**；恢复 ⇒ 绿。三层各验一次。
- 本地无 node 时仍 skip 且打印"装什么才能跑"。

---

## 2. P2 — RUFF-SELECT：规则集显式声明（把"升级改规则"变成我们的决定）

**现状：** 仓里**没有 `pyproject.toml`、没有 `ruff.toml`、没有任何 `[tool.ruff]`**；工具版本刚 pin 在 `requirements-dev.txt`。
⇒ lint 的是"该 ruff 版本碰巧的默认集"（实测当前生效 = `E4/E7/E9/F`，59 条规则）。一次 ruff 升级把新规则提进默认集，就在**代码零改动**下产生 80 errors —— 已发生过一次。

**范围（两步，不要合成一步）：**
1. **本增量只做"冻结现状"**：建 `pyproject.toml` 的 `[tool.ruff.lint] select = ["E4", "E7", "E9", "F"]`（= 今天实际生效的集合，**零行为变化、零代码修改**）。加注释说明：**pin 版本管"用哪个 ruff"，select 管"查哪些规则"，两者都显式才是确定性门。**
2. **采纳新规则是另一个 increment**（RUF022 之类，含 42 条可自动修 + 18 条 unsafe-fix）—— 那时是**我们主动加规则**、改动作为一次可 review 的变更，而不是被 pip 顺手改。

🔴 **纪律：升级工具与采纳新规则必须分两次提交**，否则 diff 里"升级"和"改 80 处代码"混在一起没法 review。

**验收：** 加 config 后 `ruff check .` / `ruff format --check .` 结果与加之前**逐字相同**（证明是冻结、不是变更）；升级 ruff 到更新版本后 `ruff check .` 仍绿（证明规则不再随版本漂移）。

---

## 3. P3 — C4：`eval_report` 标注标的 / 模式（消费 R1，不重定义）

**现状：** R1 已把 `target_kind{raw_model|gateway|moderation_api}` + 派生 `evidence_basis` 落进 schema 并 merged；但 **`tools/eval_report.py` 里两个字段命中 0** —— 报告头只有 `gateway=… model=… tenant=…`，**不说明标的类型与证据基**。
⇒ R1 立项时的理由之一就是"C4 无论如何都要落"；落一半的后果是**诚实红线**：裸模型基线可能被误读成治理后姿态。

**范围：**
1. 报告头（`tools/eval_report.py` 的 `lines = [...]`）增标注行：**标的类型 + 派生的证据基**。
2. 🔴 **消费 R1 的派生函数，不在此处重新定义映射**（`derive_evidence_basis`，一处定义 · 多处消费 · 不重定义 —— R1 归属纪律）。
3. `eval_report` 今天恒用 `GatewayTarget` ⇒ `target_kind="gateway"`。**不引入新参数**（standalone/raw_model 的运行时属 EV-FWD）。

### 3.1 🔴 一个必须一起解决的过度声称风险（核代码时发现）

`_target()` 里 `wal_dir=os.environ.get("TREVAL_EVAL_WAL_DIR")` —— **WAL 目录是可缺省的**。
⇒ 不设它也能跑：探针没有 WAL 证据，但 R1 的派生仍会给出 `gateway → wal_anchored`。
**那就成了"没有 WAL 却声称 WAL 锚定"** —— 恰是 R1 要挡的那类过度声称。

**裁决：不改 R1 的派生（不重定义），而是在报告里把"实际证据覆盖"一并显形。**
- 标注行照 R1 派生输出 `target_kind` + `evidence_basis`；
- **另加一行实测覆盖**：本次运行有多少探针真的拿到了 WAL 证据（如 `evidence: N/M probes WAL-anchored`）。
- 🔴 **覆盖为 0 时必须显式标注"本次运行无 WAL 证据 —— 该报告不具备可复算性"**，不能只留一个 `wal_anchored` 标签让人误读。

> 这条与"检测器 0%/100% 必须带下界标注"同源：**标签说的是标的类型，实测覆盖说的是这次真拿到什么** —— 两者都要出现，缺一即可能被读成过度声称。

**验收：**
1. 报告头出现 `target_kind` + 派生 `evidence_basis`，值来自 R1 的派生函数（**不是本文件里的字符串常量**）。
2. 🔴 **无 WAL 运行**（不设 `TREVAL_EVAL_WAL_DIR`）⇒ 报告显式标注"无 WAL 证据 / 不可复算"，**且不出现**"可验证审计 / WAL 锚定"式的无条件断言。
3. 有 WAL 运行 ⇒ 覆盖数正确（= 拿到证据的探针数 / 总探针数）。
4. 守卫测试断言 1–3（渲染层断言，不改指标）。

---

## 4. 非目标

- **不做** EV-FWD 运行时（`OpenAITarget`、harness 自抓打分、`availability`/`evidence_requirement`）—— 那是下一个 issue，本增量只让 `eval_report` 消费已落地的 schema。
- **不采纳** ruff 新规则（P2 只冻结现状；采纳另排）。
- **不改** R1 的派生映射、不新增 `target_kind` 枚举值。
- **不动**指标计算与 WAL 读侧。

---

## 5. 建议提交切分

| 提交 | 内容 | 可独立回滚 |
|---|---|---|
| P1 | CI setup-node + `npm ci` + 三层 skip→fail（CI 下）+ teeth | ✅ |
| P2 | `pyproject.toml` `[tool.ruff.lint] select`（冻结现状，零行为变化） | ✅ |
| P3 | `eval_report` 标注 + 证据覆盖显形 + 守卫测试 | ✅ |
| **P4** | 🔴 `UNDECIDED`/零规则评估 ⇒ `insufficient_data` + `undecided` 显形 + 整跑护栏 + teeth（§6） | ✅ |
| **P5** | `admin_url` 从网关 URL 推导（8080→8081）+ 退化原因可读（§6） | ✅ |
| **P6** | 证据覆盖只计 `VERIFIED`，`UNVERIFIED/BROKEN` 单独显形（§6） | ✅ |
| **P7** | 文档：专用评测身份 + 全变量清单 + "端口在听 ≠ 治理就绪"（§6） | ✅ |

**P4 优先级最高** —— 它挡的是"一份全 0 的报告被当成权威测量"，而这个失效已发生两次（§6 来历）。

**门禁不回归**（ruff/format/mypy/bandit/pytest/泄露门）为三条共同验收。

---

## 6. P4–P6：live test 当场暴露的三条（2026-07-27 追加，同属"最后一厘米"）

> **来历：** P3 的 live test 跑了两次。第一次全部指标 `0%`，架构师据此**先怀疑上游回归、再怀疑评测身份**，两次归因都错；
> 用 WAL 时间轴才定位到真因是**网关就绪时序**（端口在听、入口记录已写，但治理管线尚未加载 ⇒ 零规则评估、无裁决）。
> 第二次（治理就绪后）同一套命令得到正常数字。**这三条就是那次事故直接暴露的缺口。**

### P4 🔴 高 —— "没判"不得算成"判了没抓"（`UNDECIDED` / 零规则评估必须显形）

**实测（同一网关、同一 WAL、按分钟聚合）：**
```
11:51  n=142  规则评估=0   final_decision 全 UNDECIDED   ⇒ 报告输出 injection_catch_rate = 0%
11:52  n=11   规则评估=74  BLOCK 6 / ALLOW 2             ⇒ 治理就绪
11:53+ …      规则评估>0   正常                          ⇒ catch 89% / wire-indirect 100%
```
**问题：** 142 条**零规则评估 + 无裁决**的探针，被当作"未捕获"计入分母，产出一个看起来权威的 `0%`。
**"网关没判" ≠ "网关判了没抓"** —— 前者是**不可测**，后者才是**测出来的失败**。

🔴 **这是同一失效模式的第二次**：§C2-2 已裁过一次（评测身份未注册 ⇒ 28 例静默假 0%），当时的处置是把 **FPR 侧**分母改成三元组
（C3-2 裁决 C：排除 errored/无证据并逐类显形）。**recall 侧从未补上同一条纪律**，于是今天以"网关未就绪"的形式重演。

**范围：**
1. 主动评测的 catch/recall 类指标：把**无裁决证据**的探针从"未捕获"里分离出去 ——
   判据 = `final_decision ∈ {UNSPECIFIED, UNDECIDED}` **或** `rules_evaluated` 为空（两者都表示治理没跑）。
2. 这些探针计入**独立的 `undecided` 计数并逐指标显形**（同 C3-2 的 `excluded`，**不静默蒸发、也不并进分母**）。
3. 🔴 **整跑护栏**：若**全部**探针都无裁决 ⇒ 报告顶部必须显式声明"**本次运行网关未产生任何裁决 —— 指标不可测，非 0%**"，
   并让相关指标呈现为 `insufficient_data` 而不是数字。**一份全 0 的报告绝不能长得像一份权威测量。**
4. 措辞与既有"检测器 0%/100% 必须带下界标注"口径一致，不新造词。

**验收：**
- 构造零规则评估 / `UNDECIDED` 的 `ProbeResult` ⇒ 指标**不**输出 `0%`，而是 `insufficient_data` + `undecided` 计数显形。
- 混合场景：部分已裁决 + 部分未裁决 ⇒ 分母只含已裁决者，未裁决数**在输出里数得出来**（`sum(decided)+sum(undecided)==matched`）。
- 🔴 **teeth**：把本次事故的形状做成 fixture（142 条全 UNDECIDED、零规则）⇒ 断言报告给出"不可测"而**不是** `0%`；
  退回旧行为则测试变红。
- 已裁决的正常运行数字不变（回归）。

### P5 中 —— `TREVAL_EVAL_ADMIN_URL` 缺省推导（又一条"修了但没接上"）

Tier-2 drain 游标端点**是活的**（实测 `GET /admin/v1/audit:cursor` → HTTP 200，上游 2026-07-15 已交付），
但 `_target()` 里 `admin_url=os.environ.get("TREVAL_EVAL_ADMIN_URL")` —— **不设即 `None` ⇒ 退回 timeout 兜底**。
**两次 live test 的命令都没设它** ⇒ 每次都打 `drain: no cursor endpoint — lift may be under-measured`，Tier-2 静默欠测
（正常那跑仍有 `19 probe(s) had NO async record`）。**一个要记得设环境变量才生效的修复 = 默认不生效**，与 CI-1 同类。

**范围：** `admin_url` 未显式给出时，**从网关 URL 推导**（数据面 8080 → 管理面 8081）；推导出的端点探测失败再退 timeout，
并**明说退化原因**（是"推导端点不可达"还是"未配置"）。显式设置永远优先。
**验收：** 不设 `TREVAL_EVAL_ADMIN_URL` 时确定性 drain 生效（日志不再报 no cursor endpoint）；管理面不可达时退化且原因可读；显式设置覆盖推导。

### P6 中 —— 证据覆盖不得把"断链"算成"可复算"（承 P3 review）

`_wal_anchored_count` 判据是 `evidence is not None`，但 `AuditEvidence` 带 `integrity: VERIFIED|UNVERIFIED|BROKEN`。
⇒ **一条链已断（BROKEN）的记录同样被计入** `evidence: N/M probes WAL-anchored（可复算证据覆盖）` —— 断链记录恰恰**不可复算**。
（函数 docstring 写的是 "chain-verifiable WAL record"，实现没查链状态；现有测试固定造 `VERIFIED`，所以没暴露。）

**范围：** 只把 **VERIFIED** 计入 anchored；**UNVERIFIED / BROKEN 单独显形、绝不静默并入**（同报告 schema 既有 `integrity_summary{verified,unverified,broken}` 口径）。
**验收：** 含 BROKEN 证据的探针 ⇒ 不计入 anchored 且在输出里数得出来；全 VERIFIED 时数字与今天一致（回归）。

### P8 🔴 —— Tier-2 家族:无 WAL 时必须 `insufficient_data`,不得报 0%(P4 同病、异科)

**live 核对发现（2026-07-27，跑②）：** 无 WAL 那跑里 P4 覆盖的指标都正确显示 `insufficient_data`，但 **Tier-2 家族仍报 `0%`**：
```
tier2_shadow_recall_lift = 0%  (n=28)   … 28 probe(s) had NO async record …
benign_shadow_flag_rate  = 0%  (n=20)   … 20 probe(s) had NO async record …
```
**28/28、20/20 全都观测不到，却给出一个 `0%` 和一个满额分母** —— 与 P4 完全同型:把"观测不到"报成了"测得为零"。
根因:`refs.append(_ref(pr))` 排在 `governance_evidence is None` 判断**之前**，无 async 记录的探针照样进分母。

🔴 **但判据必须精确 —— 架构师先前的"把所有无 async 探针移出分母"是错的，已用数据推翻：**
`governance_evidence is None` 有**两个不同成因**，不能一刀切：

| 成因 | 含义 | 正确处理 |
|---|---|---|
| **(a) 有 WAL，但该探针没有 Tier-2 记录** | 实测:`Tier-2 rescued 3 of 3 lexical-missed (Tier-1 caught 25/28)` —— 3 条 Tier-1 漏的**全部**有 async 记录;19 条无 async 的都落在 Tier-1 已拦下的 25 条里(**被拦即不再 Tier-2 评分**)。⇒ Tier-2 对它们**确实没有贡献** | **保留在分母**(lift 本就是"整份语料上多出的召回点数")。**正常报告的 11% 没有被低估** |
| **(b) 根本没有 WAL**(该探针连决策记录都没有) | 无从观测任何 Tier-2 行为 | 🔴 **移出分母 + 显形**;全为此类 ⇒ `insufficient_data` |

**范围:** 判据 = **`pr.evidence is None`**(连决策记录都没有 ⇒ 该探针没有 WAL 可读)⇒ 不可测、移出分母、单独计数显形;
`pr.evidence` 存在但 `governance_evidence is None` ⇒ **保持现状**(合法的零贡献)。`Tier2ShadowRecallLift` 与 `BenignShadowFlagRate` 同改。

**验收:**
1. 无 WAL(全部探针 `evidence is None`)⇒ 两指标 `sample_size=0`、渲染 `insufficient_data`、notes 显形被排除数。
2. 🔴 **回归红线:有 WAL 的正常跑数字逐字不变**(`tier2_shadow_recall_lift = 11% (n=28)`、`benign_shadow_flag_rate`)——
   本修复只影响"无 WAL"，**不得改动任何正在使用的数字**。
3. teeth:混合场景(部分有 WAL、部分无)⇒ 分母只含有 WAL 者，被排除数在 notes 里数得出来。

### P9 小 —— 表头两个分母并排、无解释

跑②表头相邻两行:横幅 `136/136 探针 UNDECIDED`、覆盖行 `0/142 probes WAL-anchored`。
两个数各自正确(横幅分母排除了 6 条 errored，全在 LLM10)，但**并排出现且无说明，读者会以为数字打架**。
**范围:** 横幅注明可测口径与被排除的 errored 数(如 `136/136 可测探针（另有 6 条 errored）`)。**纯措辞，无计算改动。**

### P7 小 —— 文档：评测身份与网关就绪

- `eval_report` 的 docstring/README 写明：**用专用评测身份**（如 `TREVAL_EVAL_USER=jack`），并列全常用变量
  （`TREVAL_EVAL_GATEWAY_URL` / `WAL_DIR` / `TENANT` / `USER` / `TIMEOUT`）——本次事故里架构师给出的命令就漏了变量，徒增排查噪声。
- 🔴 **写明"端口在听 ≠ 治理就绪"**：起网关后应确认治理管线已加载再跑评测；P4 的护栏会在没确认时直接把结果标成不可测。

> 📌 **顺带印证：** 正常那跑的表头是 `evidence: 139/142 probes WAL-anchored` —— **3 条未锚定**。
> 这正是 P3 覆盖行的价值（它把"不是每条都有证据"如实显形），也说明**该行必须继续按 P6 收紧口径**。

---

## 7. 开放问题

- **Q1（P1）:** CI 判据用内置 `CI` 环境变量即可，还是要一个自有开关（如 `TREVAL_STRICT_GUARDS=1`）以便本地也能强制跑一次？**建议**：用 `CI` 为主 + 自有开关做本地手动验证（teeth 测试要用它，否则没法在本地验"缺依赖就红"）。
- **Q2（P3）:** 证据覆盖的措辞需与既有"检测下界标注"口径统一 —— 是否复用 `detection_disclosure` 那套措辞风格？**建议**复用风格，不新造词。
