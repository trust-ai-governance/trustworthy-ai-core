/* EV-W2 §8.3 — the headless render guard. NOT optional.
 *
 * Rationale, from this issue's own history: three prototype rounds shipped VISUALLY BROKEN
 * and all three passed source review — once a mismatched quote swallowed a table cell and
 * shifted every column; once a stray title="…" inside a double-quoted JS string threw a
 * SyntaxError that blanked the entire page. Source review cannot catch that class; a DOM
 * that actually executes the page can.
 *
 * Adapted from the reviewed prototype's check_proto.js. The prototype toggled views and
 * switched fixtures client-side; under SSR each (fixture × view) is a real page, so the
 * Python side renders them to files and this script asserts each one.
 *
 * Usage: node check_render.js <dir>   # dir holds <fixture>.dash.html / <fixture>.detail.html
 */
"use strict";
const fs = require("fs");
const path = require("path");
const { JSDOM, VirtualConsole } = require("jsdom");

const dir = process.argv[2];
if (!dir) { console.error("usage: node check_render.js <dir>"); process.exit(2); }

const fails = [], ok = [];
const check = (name, cond, extra) =>
  (cond ? ok : fails).push(name + (extra ? " — " + extra : ""));

function load(file) {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push("jsdomError: " + (e.stack || e.message)));
  vc.on("error", (...a) => errors.push("console.error: " + a.join(" ")));
  const html = fs.readFileSync(file, "utf8");
  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    resources: undefined,
    virtualConsole: vc,
    // jsdom has no layout: scrollTo/alert are unimplemented stubs that raise jsdomError.
    // Real browsers implement both — stub before parse so they don't pollute the signal.
    beforeParse(w) { w.scrollTo = () => {}; w.alert = () => {}; },
  });
  return { dom, doc: dom.window.document, errors };
}

// The SSR page links /static/report.js; jsdom won't fetch it, so inline it before parse.
const reportJs = fs.readFileSync(
  path.join(__dirname, "..", "..", "treval", "web", "static", "report.js"), "utf8");

// The dashboard links /static/help.js (click popovers); inline it so click actually toggles.
const helpJs = fs.readFileSync(
  path.join(__dirname, "..", "..", "treval", "web", "static", "help.js"), "utf8");

function loadDash(file) {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push("jsdomError: " + (e.stack || e.message)));
  vc.on("error", (...a) => errors.push("console.error: " + a.join(" ")));
  let html = fs.readFileSync(file, "utf8");
  html = html.replace(
    /<script src="\/static\/help\.js[^"]*"[^>]*><\/script>/,
    "<script>" + helpJs + "</script>");
  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    virtualConsole: vc,
    beforeParse(w) { w.scrollTo = () => {}; w.alert = () => {}; },
  });
  return { dom, doc: dom.window.document, errors };
}

function loadWithScript(file) {
  const errors = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push("jsdomError: " + (e.stack || e.message)));
  vc.on("error", (...a) => errors.push("console.error: " + a.join(" ")));
  let html = fs.readFileSync(file, "utf8");
  html = html.replace(
    /<script src="\/static\/report\.js[^"]*"[^>]*><\/script>/,
    "<script>" + reportJs + "</script>");
  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    virtualConsole: vc,
    beforeParse(w) { w.scrollTo = () => {}; w.alert = () => {}; },
  });
  return { dom, doc: dom.window.document, errors };
}

const fixtures = fs.readdirSync(dir).filter((f) => f.endsWith(".dash.html"))
  .map((f) => f.replace(/\.dash\.html$/, ""));
check("fixtures rendered", fixtures.length === 6, "found=" + fixtures.length);

// Expected no-signal axis counts per fixture (null ≠ 0 — asserted, not eyeballed).
const NOSIG = { rich: 3, all_not_measured: 5, over_claim_gaps: 4,
                insufficient_data: 5, verification_basis: 4, per_subject: 4 };

for (const fx of fixtures) {
  const { doc, errors } = load(path.join(dir, fx + ".dash.html"));
  const $ = (s) => doc.querySelector(s);
  const $$ = (s) => [...doc.querySelectorAll(s)];
  const txt = (s) => ($(s) ? $(s).textContent.replace(/\s+/g, " ").trim() : "«MISSING:" + s + "»");
  const P = fx + " dash: ";

  check(P + "no js errors", errors.length === 0, errors.join(" | "));

  // --- Brand + shell (EV-W2 D6). The guard shipped WITHOUT these and a broken banner went
  // straight to review: base.html had used a placeholder "◆" and a `.banner` class with no
  // CSS behind it, while a SECOND `.topbar` rule silently overrode EV-W0's navy banner. The
  // render guard passed the whole time, because it only looked at the report body. ---
  check(P + "EV-W0 banner (.topbar), not an invented .banner",
        $("header.topbar") !== null && $(".banner") === null);
  check(P + "real logo mark — 5 chevron + 12 ring = 17 rects",
        $$("header.topbar .logo svg rect").length === 17,
        "rects=" + $$("header.topbar .logo svg rect").length);
  check(P + "no placeholder glyph", !doc.body.textContent.includes("◆"));
  check(P + "subtitle present", txt("header.topbar .subtitle").includes("Core UI"));
  check(P + "scope lives IN the banner", $("header.topbar .scope") !== null);
  check(P + "scope is NOT inside a view", $(".shell .scope") === null);
  check(P + "left nav rail with both views",
        $("aside.sidenav") !== null && $$("aside.sidenav .navitem").length === 2);
  check(P + "exactly one nav item is current", $$('[aria-current="page"]').length === 1);
  check(P + "verdict present", $("#verdict") !== null && txt("#verdict").length > 8, txt("#verdict"));
  check(P + "5 risk cards", $$("#risks .rk").length === 5);
  check(P + "risk cards have sub-labels", $$("#risks .rk .s").length === 5);
  check(P + "radar 5 rings", $$("#radar polygon.web").length === 5);
  check(P + "radar 5 spokes", $$("#radar line.spoke").length === 5);
  check(P + "radar 5 axis labels", $$("#radar text.axl").length === 5);
  check(P + "maturity table 5 rows", $$("#mat tbody tr").length === 5);
  check(P + "maturity table 5 cols", $$("#mat thead th").length === 5);
  check(P + "every row has a 结论 pill", $$("#mat tbody tr .pill").length === 5);

  // null ≠ 0 — the core rule of this issue.
  check(P + "no-signal axes marked 无实测信号", $$("#radar text.axsub").length === NOSIG[fx],
        "axsub=" + $$("#radar text.axsub").length + " want=" + NOSIG[fx]);
  check(P + "no-signal spokes dashed", $$("#radar line.spoke.nosig").length === NOSIG[fx]);
  for (const cls of ["p-meas", "p-att", "p-awarded"]) {
    const poly = $("#radar polygon." + cls);
    check(P + cls + " points finite (no NaN/undefined)",
          !poly || !/NaN|undefined/.test(poly.getAttribute("points")),
          poly ? poly.getAttribute("points") : "");
  }
  // 授级 is the third line and the hero. Where it exists it must equal min(measured,attested)
  // geometrically — i.e. its polygon coincides with the LOWER input, never floats on its own.
  const awP = $("#radar polygon.p-awarded");
  if (awP) {
    const pts = (poly) => (poly ? poly.getAttribute("points").trim().split(/\s+/) : []);
    const aw = pts(awP), me = pts($("#radar polygon.p-meas")), at = pts($("#radar polygon.p-att"));
    // awarded == min(measured, attested): every awarded vertex must equal the measured OR the
    // attested vertex on that spoke — it never floats to a position of its own.
    const independent = aw.some((v, i) => v !== me[i] && v !== at[i]);
    check(P + "授级 coincides with measured or attested at every vertex (min, not independent)",
          !independent, "awarded vertex with no matching input");
  }
  // legend names all three lines + keeps the null≠0 rule
  check(P + "legend names 授级 / 实测 / 声明", txt(".legend").includes("授级") &&
        txt(".legend").includes("measured_ceiling") && txt(".legend").includes("attested_ceiling"));
  check(P + "legend states 无信号 ≠ 0 分", txt(".legend").includes("无信号 ≠ 0 分"));

  // scope lives in the persistent topbar, not the report body
  check(P + "被测租户 in topbar scope, not the report body",
        txt("header.topbar .scope").includes("被测租户") && !txt("#idbar").includes("被测租户"));
  check(P + "fingerprint labelled as a rubric fingerprint, not 报告指纹",
        txt("#idbar").includes("评级标准指纹") && !txt("#idbar").includes("报告指纹"), txt("#idbar"));
  check(P + "tenant + window selects are in the topbar",
        $("header.topbar #sel-tenant") !== null && $("header.topbar #sel-window") !== null);

  // no invented vocabulary / no internal wording
  check(P + "no invented 运行 concept", !$("main").textContent.includes("运行"));
  check(P + "no internal wording",
        !/待裁定|已裁定|另开 issue|EV-W1|EV-R1|遗留:/.test(doc.body.textContent),
        (doc.body.textContent.match(/.{0,20}(待裁定|已裁定|另开 issue|EV-W1|EV-R1).{0,20}/) || [""])[0]);
  // no mutating control anywhere
  check(P + "no mutating controls", $$("main form[method=post], main button[type=submit]").length === 0);
}

// verdict precedence spot-checks (the two fixtures whose whole point is a distinct verdict)
{
  const d = load(path.join(dir, "all_not_measured.dash.html")).doc;
  const t = d.querySelector("#verdict").textContent;
  check("all_not_measured → 无实测信号 verdict", t.includes("无实测信号"), t.trim().slice(0, 60));
  check("all_not_measured → no measured/awarded polygon (no fabricated zeros)",
        d.querySelector("#radar polygon.p-meas") === null &&
        d.querySelector("#radar polygon.p-awarded") === null);
  const rd = loadDash(path.join(dir, "rich.dash.html"));
  const r = rd.doc;
  check("rich → 声明高于实测 verdict", r.querySelector("#verdict").textContent.includes("声明高于实测"));
  check("rich → verdict styled as risk", r.querySelector("#verdict").classList.contains("risk"));
  // PM feedback, dashboard chrome:
  check("thesis (不给总分 + 规则被指纹锁定) promoted out of the footer",
        r.querySelector(".thesis") !== null &&
        r.querySelector(".thesis").textContent.includes("不给总分") &&
        r.querySelector(".thesis").textContent.includes("指纹"));
  check("过度声明 explained as methodology output, not a system failure",
        r.querySelector("#verdict .vnote") !== null &&
        r.querySelector("#verdict .vnote").textContent.includes("不是系统故障"));
  {
    // 结论 ? must OPEN on click (a native title= tooltip read as "nothing happens").
    const wrap = r.querySelector("#mat thead th .helpwrap");
    const btn = wrap && wrap.querySelector("button.help");
    const pop = wrap && wrap.querySelector(".pop");
    check("结论 ? is a clickable button with a popover", !!btn && !!pop &&
          /一致|过度声明/.test(pop ? pop.textContent : ""));
    check("结论 ? popover is closed until clicked", wrap && !wrap.classList.contains("open"));
    if (btn) btn.dispatchEvent(new rd.dom.window.MouseEvent("click", { bubbles: true }));
    check("结论 ? opens on click", wrap && wrap.classList.contains("open") &&
          btn.getAttribute("aria-expanded") === "true");
  }
  {
    // the sha256 fingerprint confused a reader — it needs a plain-language ? explainer.
    const fpWrap = r.querySelector("#idbar .helpwrap");
    const pop = fpWrap && fpWrap.querySelector(".pop");
    check("评级标准指纹 has a ? explaining what the hash is",
          !!pop && pop.textContent.includes("SHA-256") && pop.textContent.includes("身份证"));
  }
  check("怎么读 no longer lectures about colour-blind/solid-dashed",
        !r.querySelector(".howto").textContent.includes("只靠颜色"));
  check("radar has a 怎么读 (how-to-read) line, not colour-only",
        r.querySelector(".howto") !== null &&
        r.querySelector(".howto").textContent.includes("虚线"));
  const v = load(path.join(dir, "verification_basis.dash.html")).doc;
  check("verification_basis → basis hybrid shown", v.querySelector("#idbar").textContent.includes("hybrid"));
}

// ---- detail view: the merged table + its filters (the only client JS) ----
for (const fx of fixtures) {
  const { dom, doc, errors } = loadWithScript(path.join(dir, fx + ".detail.html"));
  const $ = (s) => doc.querySelector(s);
  const $$ = (s) => [...doc.querySelectorAll(s)];
  const txt = (s) => ($(s) ? $(s).textContent.replace(/\s+/g, " ").trim() : "«MISSING:" + s + "»");
  const shown = () => $$("#sigt tbody tr[data-kind]").filter((r) => !r.hidden).length;
  const P = fx + " detail: ";

  check(P + "no js errors", errors.length === 0, errors.join(" | "));
  check(P + "71 objectives listed once each", $$("#sigt tbody tr[data-kind]").length === 71 &&
        new Set($$("#sigt .sid").map((e) => e.textContent)).size === 71,
        "rows=" + $$("#sigt tbody tr[data-kind]").length);
  check(P + "table carries 本次结果 column",
        $$("#sigt thead th").map((t) => t.textContent.trim()).includes("本次结果"));
  check(P + "every objective shows its rule", $$("#sigt tbody tr[data-kind] .rule").length === 71);
  check(P + "read-only badge", txt(".sighead .ro").includes("只读"));
  check(P + "explains why rules are not editable", txt(".signote").includes("registry_fingerprint"));
  check(P + "states the WAF difference (corpus text) + sha256",
        txt(".signote").includes("攻击语料原文我们不能给") && txt(".signote").includes("sha256"));
  const VIEW_CONTROLS = ["#sigchips", "#sigpager"];   // filter chips + pager: navigate, never mutate
  const suspicious = $$(".sig input, .sig textarea, .sig button, .sig select").filter(
    (el) =>
      !VIEW_CONTROLS.some((sel) => el.closest(sel)) &&
      el.id !== "sigdim" &&      // dimension filter
      el.type !== "search"       // search box
  );
  check(P + "no editing affordances in the rule table", suspicious.length === 0,
        suspicious.map((e) => e.tagName + "#" + e.id).join(","));
  check(P + "重新评测 is a command/link, not an action",
        $("#rerun") !== null && txt("#actlead").includes("评测执行页") && txt("#actlead").includes("只读"));
}

// filters on the fixture with known gaps (rich has exactly 2)
{
  const { dom, doc, errors } = loadWithScript(path.join(dir, "rich.detail.html"));
  const $ = (s) => doc.querySelector(s);
  const $$ = (s) => [...doc.querySelectorAll(s)];
  const shown = () => $$("#sigt tbody tr[data-kind]").filter((r) => !r.hidden).length;
  // The counter reads "<range> / <matched>[ (共 N)]" — the number after the slash is the
  // match count. `shown()` is the page window (≤ PER_PAGE), a different thing entirely.
  const matched = () => +$("#sigcnt").textContent.match(/\/\s*(\d+)/)[1];
  const PER_PAGE = 15;

  check("rich: over-claim rows tinted", $$("#sigt tr.gaprow").length === 2,
        "gaprow=" + $$("#sigt tr.gaprow").length);
  check("rich: all 71 matched, first page shown", matched() === 71 && shown() === PER_PAGE,
        "matched=" + matched() + " shown=" + shown());
  check("rich: pager visible when paging is needed", !$("#sigpager").hidden);
  check("rich: prev disabled on page 1", $("#sigprev").disabled && !$("#signext").disabled);

  $('#sigchips button[data-k="gap"]').click();
  check("只看过度声明 returns exactly len(gaps)", matched() === 2, "matched=" + matched());

  $('#sigchips button[data-k="measured"]').click();
  const nMeas = matched();
  $('#sigchips button[data-k="attested"]').click();
  const nAtt = matched();
  check("measured + attested = 71", nMeas + nAtt === 71, nMeas + "+" + nAtt);

  $('#sigchips button[data-k="all"]').click();
  const sel = $("#sigdim");
  sel.value = "robustness";
  sel.dispatchEvent(new dom.window.Event("change"));
  const nRob = matched();
  check("dimension filter works", nRob > 0 && nRob < 71, "robustness=" + nRob);
  sel.value = "all";
  sel.dispatchEvent(new dom.window.Event("change"));
  check("dimension filter resets", matched() === 71);

  const q = $("#sigq");
  q.value = "injection";
  q.dispatchEvent(new dom.window.Event("input"));
  check("search works", matched() > 0 && matched() < 71, "injection=" + matched());
  check("count reflects the filter", $("#sigcnt").textContent.includes("共 71"),
        $("#sigcnt").textContent);

  q.value = "zzzz-no-such-rule";
  q.dispatchEvent(new dom.window.Event("input"));
  check("empty result renders the empty state, not a phantom row",
        matched() === 0 && shown() === 0 && !$("#sigt tbody tr.empty").hidden);
  check("pager hides when there is nothing to page", $("#sigpager").hidden);

  q.value = "";
  q.dispatchEvent(new dom.window.Event("input"));
  check("clearing search restores all 71 matches", matched() === 71 && shown() === PER_PAGE,
        "matched=" + matched() + " shown=" + shown());
  // Paging must not leak across a filter change. NOTE: filtering to a SMALL set proves
  // nothing — apply() clamps `page` to the last page, so the reset is invisible there. Use a
  // filter whose result is still multi-page, so staying on page 2 would actually be possible.
  $("#signext").click();
  check("next advances the page window", shown() === PER_PAGE && !$("#sigprev").disabled);
  $('#sigchips button[data-k="attested"]').click();
  check("the multi-page filter is still multi-page (else this proves nothing)",
        matched() > PER_PAGE, "attested=" + matched());
  check("a new filter resets to page 1", $("#sigprev").disabled, $("#sigpage").textContent);
  $('#sigchips button[data-k="all"]').click();
  q.value = "";
  q.dispatchEvent(new dom.window.Event("input"));
  check("no js errors after filtering", errors.length === 0, errors.join(" | "));
}

// the rules stay put while the outcome column changes with report state
{
  const a = loadWithScript(path.join(dir, "all_not_measured.detail.html")).doc;
  check("all_not_measured: rules still all listed (rules are report-independent)",
        a.querySelectorAll("#sigt tbody tr[data-kind]").length === 71);
  // A numeric value (.n:not(.dash)) means an actual measurement; the "—" placeholder (.n.dash)
  // shown for insufficient_data is NOT a value and must not count.
  check("all_not_measured: no measured values in the outcome column",
        a.querySelectorAll("#sigt .out .n:not(.dash)").length === 0);
  check("insufficient_data shows a — placeholder, never a value + verified",
        [...a.querySelectorAll("#sigt tbody tr[data-kind]")].every((tr) => {
          const rst = tr.querySelector(".rst.insufficient_data");
          if (!rst) return true;
          // the row must NOT carry a numeric value, and must NOT claim verified on an n=0 meta
          const hasValue = tr.querySelector(".out .n:not(.dash)");
          const meta = (tr.querySelector(".meta") || {}).textContent || "";
          const falseVerified = /n=0\b/.test(meta) && /verified/.test(meta);
          return !hasValue && !falseVerified;
        }), "an insufficient_data row still shows a value or a false verified");
  check("all_not_measured: no over-claim rows", a.querySelectorAll("#sigt tr.gaprow").length === 0);
  const r = loadWithScript(path.join(dir, "rich.detail.html")).doc;
  check("rich: measured values present in the outcome column",
        r.querySelectorAll("#sigt .out .n").length > 0);

  // 60s-p99 blocker: a sample-size-gated objective ("met" = enough samples, not a good value)
  // must NOT look like a judged pass. rich has ≥2 such rows.
  const baselineVals = r.querySelectorAll("#sigt .out .n.baseline");
  const baselineRst = r.querySelectorAll("#sigt .out .rst.baseline");
  check("rich: baseline (sample-gated) readings are marked distinct from judged values",
        baselineVals.length >= 2 && baselineRst.length >= 2,
        "n.baseline=" + baselineVals.length + " rst.baseline=" + baselineRst.length);
  check("rich: baseline rows say 基线达成, never a bare green 达标",
        [...baselineRst].every((e) => e.textContent.trim() === "基线达成"));
  check("rich: baseline reading carries a 基线 marker + explanation",
        [...baselineRst].every((e) => /样本量达标|建立基线/.test(e.getAttribute("title") || "")));
}

console.log("PASS " + ok.length);
if (fails.length) {
  console.log("\nFAIL " + fails.length);
  fails.forEach((s) => console.log("  FAIL " + s));
  process.exit(1);
}
console.log("ALL CHECKS PASSED");
