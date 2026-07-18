# EV-W2 — Dashboard templates / UX (the report someone actually reads)

**Problem (plain language):** EV-R1 froze the bundle and EV-W1 will serve it, but a JSON
bundle answers nothing on its own. The question a customer opens this to ask is *"what level
are we, and where are we exposed?"* — and the honest answer (we measure two dimensions out of
five, and the claims run higher than the measurements) is precisely the one that a careless
UI turns into a lie: plot "not measured" at zero and you have reported a failing score for
something that was never tested.

**Value:** EV-W2 renders the thesis — **measured > attested** — so it reads at a glance. The
radar shows the claimed shape against the measured shape and the gap between them *is* the
product. The design is already settled against real data: the prototype rendered all six
EV-R1 fixtures and was reviewed to sign-off, so this issue is **transcription, not
exploration**.

> Dev brief. **Prereq:** EV-R1 (fixtures — merged), EV-W1 (endpoints + store).
> **Owner:** UI engineer. Scaffolds against `tests/fixtures/report/valid/*.json` immediately;
> integrates on EV-W1. **Status:** design ratified — ready to implement.
> **Reference implementation:** the reviewed prototype (see §7).

---

## 0. Verified ground truth (checked against real fixtures + live bundles, 2026-07-17)

1. **The registry is identical across all six fixtures** (one `registry_fingerprint`), and
   every bundle embeds it. The UI needs no second source for rubric text.
2. **All 71 objectives carry a rule** — `satisfied_when` (measured, e.g. `value >= 0.80`) or
   `posture_key` (attested). Both ship in the bundle's `registry`.
3. **The report carries all 71 objectives with a status**, so rules and outcomes can be joined
   into one table (D3).
4. **Sparse is the normal case, not an error state.** In `rich` — the richest fixture — only
   2 of 5 dimensions have a `measured_ceiling`; in `all_not_measured`, zero do. The UI must
   read correctly in this shape, because this shape *is the finding*.

## 1. D1 — Two views: Dashboard = the conclusion, 详情 = the basis

| View | Answers | Contents |
|---|---|---|
| **Dashboard** (`/`) | "what level are we, where are we exposed?" | 报告标识条 · **结论横幅** · **风险卡** · **雷达图 ǀ 成熟度总表** · 图例 |
| **报告详情** (`/detail`) | "on what basis?" | 行动区 · **判定规则与本次结果**(一张表) |

**Shell:** an EV-W0 banner (brand + global scope) over a **left navigation rail** + content.

- **Tenant/window live in the banner** and persist across views — they are a *global scope*,
  while the views are lenses on the same scoped report. They must not reset on a view switch.
- **Navigation is a vertical rail, not top tabs.** The view list grows (配置运行 …); a sidebar
  absorbs new entries without re-flowing the banner.
- **The banner is EV-W0's, reused verbatim** — logo mark, navy gradient, yellow rule,
  `Core UI · 在线只读视图`. The mark lives in **one** partial (`templates/_logo.html`) included
  by every page: the first implementation inlined it in `registry.html` and re-invented it as a
  placeholder `◆` in `base.html`, and the two drifted immediately.

## 2. D2 — The radar: `null` is not zero

Half of this issue's value is in one rule. A dimension with `measured_ceiling = None` has **no
measurement**; drawing it at radius 0 reports "scored zero" for something never tested — a
fabricated failing grade. Required treatment:

- **No-signal axes:** grey **dashed** spoke, greyed axis label, an explicit `无实测信号`
  sub-label. Legend states **无信号 ≠ 0 分**.
- **Measured** (`--measured`, teal): filled polygon — what evidence supports.
- **Attested** (`--attested`, amber): **dashed outline** — what is claimed.
- **Over-claim** (`--risk`): a radial segment + dot from measured out to attested, on each
  axis where the claim exceeds the measurement. This is the money shot: the gap made visible.
- Radius = L1→L5; ring labels on the vertical axis. Points come from EV-W1's
  `radar_points()` (server-side, D6 there) — **no chart library**.

## 3. D3 — Rules and outcomes are **one** table, not two lists

An earlier prototype pass rendered a rule catalog *and* per-dimension objective cards — the
same 71 objectives listed twice on one page. They are not redundant in content (rules come
from the registry and are report-independent; outcomes come from the report), but listing
them twice is. **Merge:** one table, one row per objective, carrying both.

Columns: `规则 ID / 目标` · `维度` · `等级` · `类型` · `判定规则` · `数据源` · `本次结果`.
Filters: kind (全部/measured/attested) · **只看过度声明** · 维度 · free-text search.
Over-claimed rows are tinted and tagged. Switching report state must change the outcome column
while the rules stay put — that difference is itself the explanation.

## 4. D4 — WAF-Signature posture: fully inspectable, categorically not editable

The ratified reference is a WAF signature UI — you can read every signature, you cannot change
one. Requirements:

- Every rule visible in full (`satisfied_when` / `posture_key`), searchable and filterable.
- **Zero editing affordances.** Not disabled buttons — *absent* ones. A `只读 READ-ONLY` badge.
- The page states *why*: rules are pinned by `registry_fingerprint` and delivered with the
  report — **change the rule and the fingerprint changes, which invalidates the report. A
  grading system whose subject can edit the grading rules is not a grading system.**
- **Where the WAF analogy breaks, say so plainly.** A WAF shows you the signature's payload;
  we cannot show attack corpus text (not public, and not in the bundle). What is publishable
  is the **corpus manifest**: case ID + category + `sha256` — enough for a third party to
  verify we ran the corpus we claim, without disclosing it. Same hash-binding idea as
  `wal_verify`, applied to the corpus. *(Manifest rendering is gated on the corpus repo —
  §8. EV-W2 ships the explanation, not the manifest view.)*

## 5. D5 — The verdict headline is derived, never authored

One banner, resolved by strict precedence — the worse fact always wins:

1. `integrity_summary.broken > 0` → **完整性破损 —— 本报告不可信** (risk). Nothing below is
   worth reporting if the chain is broken.
2. any `gaps` → **声明高于实测 —— N 项目标** (risk)
3. no dimension has `measured_ceiling` → **无实测信号 —— 不能支撑任何实测授级** (warn)
4. `unverified > 0` → **含未验证证据 —— N 条** (warn)
5. else → **实测与声明一致 —— 已授级 N/5 维** (ok)

Risk cards: 过度声明目标 · 完整性破损记录 · 未验证证据 · 维度有实测信号 N/5 · 实测指标条数.
Maturity table per dimension: 实测 · 声明 · **授级 = min(实测, 声明)** · 结论 pill.

**Never invent an aggregate score.** There is no overall level in `MaturityReport`; computing
one here would be the UI asserting a grade the engine refused to give.

## 6. D6 — Design tokens: EV-W0's system, not a new one

`treval/web/static/style.css` already defines the language — **reuse it, do not re-pick**:
`--logo #ffc62b` · banner `#0f1a30 → #1d2c49` + yellow rule · `--headbg #1f2937` ·
**`--measured #0e7490` (teal)** · **`--attested #b45309` (amber)** · radius 8px · logo top-left.
Exactly one token is new: **`--risk #b3261e`** (EV-W0 has no report state, hence no alarm
colour). Dark-theme variants required for all of them.

**Do not re-declare an existing selector.** `.topbar` is EV-W0's banner; a second `.topbar`
rule added for the scope bar won the cascade and flattened the banner — on EV-W0's own page
too. Style the new thing, never the shared bar.

Copy rule: **internal vocabulary never reaches the customer.** No 待裁定/裁定/issue IDs, and
no invented concepts — an early pass shipped a column called 运行 that corresponded to nothing
in the data. Every label must trace to a real field.

## 7. Reference implementation

The reviewed prototype renders all six fixtures with the above and is the visual spec:
`report_prototype.html` + `check_proto.js` + `gen_proto_data.py` (session scratchpad — copy
into the repo alongside this issue if it is to be kept). It is a throwaway: SSR replaces its
client-side rendering. What transfers is the **layout, tokens, radar geometry, verdict
precedence, and the merged table**.

## 8. Acceptance

1. Jinja2 SSR templates for both views, rendering from EV-W1's context. No chart library, no
   React/Vue toolchain (`frontend-stack-decision`).
2. **Renders all six EV-R1 fixtures correctly** — in particular `all_not_measured` (5 no-signal
   axes, no fabricated zeros) and `verification_basis` (basis `hybrid`, broken → verdict ①).
3. **A headless render guard, and it is not optional.** Load the served page in a DOM, assert
   **zero JS errors** and that key elements exist (radar rings/spokes/labels, 71 rows, verdict,
   risk cards). *Rationale, from this issue's own history:* three separate prototype rounds
   shipped visually broken — once a mismatched quote silently swallowed a table cell and
   shifted every column; once a stray `title="…"` inside a double-quoted JS string threw a
   `SyntaxError` that blanked the entire page. **Both looked correct in source review.** SSR
   removes most of this class, but any client-side filter/search JS reintroduces it.
   `check_proto.js` is the working template for this guard.
   **The guard must cover the chrome, not just the report body.** Its first version asserted
   radar/verdict/rows/filters and passed green while the banner rendered as an unstyled `◆` on
   white — the logo loss reached review precisely because nothing looked at it. Assert: the
   real logo mark (17 rects), `.topbar` present and no invented `.banner`, the subtitle, no
   placeholder glyph, scope inside the banner, the nav rail, exactly one `aria-current`.
4. Over-claim rows tinted; 只看过度声明 filter returns exactly `len(gaps)` rows.
5. `null` ceilings never plotted as 0 — asserted, not eyeballed.
6. No mutating control anywhere in the templates; 重新评测 is a link (EV-W1 D5/O1).
7. Responsive: no horizontal body scroll; wide tables scroll in their own container.
8. Accessible: keyboard focus visible, radar has a text alternative (the maturity table is it).

## 9. Non-goals

- Export/print report (deferred; explicitly *not* the current target — this is an online view).
- Request-level drill-down (no `/evidence` — EV-W1 D3).
- Corpus manifest browser (gated on the corpus repo).
- Trend/history charts (needs >1 window per tenant to exist first).
- Per-objective status colouring beyond gap/over-claim (`ev-w1-status-colors` — deferred).
