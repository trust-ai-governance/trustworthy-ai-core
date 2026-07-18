/* EV-W2 — the ONLY client-side script: filter/search/paginate over rows the server already
   rendered. It reads the DOM and toggles `hidden`; it never constructs HTML from strings.
   That is deliberate: three prototype rounds shipped visually broken because HTML was
   built inside JS string literals (a stray title="…" closed the string → SyntaxError →
   blank page; a mismatched quote swallowed a cell and shifted every column). Both passed
   source review. With SSR + visibility-toggling, that entire class is structurally gone.

   Pagination is a VIEW over the filtered set, never a filter of its own: filter first, then
   page the survivors. Any filter/search change resets to page 1 — otherwise you can land on
   page 5 of a 2-page result and stare at an empty table that is not the empty state. */
(function () {
  "use strict";
  var table = document.getElementById("sigt");
  if (!table) return;

  var rows = Array.prototype.slice.call(table.querySelectorAll("tbody tr[data-kind]"));
  var empty = table.querySelector("tbody tr.empty");
  var chips = document.getElementById("sigchips");
  var dimSel = document.getElementById("sigdim");
  var query = document.getElementById("sigq");
  var count = document.getElementById("sigcnt");
  var pager = document.getElementById("sigpager");
  var prev = document.getElementById("sigprev");
  var next = document.getElementById("signext");
  var pageInfo = document.getElementById("sigpage");
  var total = rows.length;
  var kind = "all";
  var page = 1;
  var PER_PAGE = 15;

  function matches(tr) {
    var dim = dimSel ? dimSel.value : "all";
    var q = query ? query.value.trim().toLowerCase() : "";
    var okKind =
      kind === "all" ||
      (kind === "gap" ? tr.dataset.gap === "1" : tr.dataset.kind === kind);
    var okDim = dim === "all" || tr.dataset.dim === dim;
    var okQ = !q || tr.textContent.toLowerCase().indexOf(q) !== -1;
    return okKind && okDim && okQ;
  }

  function apply() {
    var hits = rows.filter(matches);
    var pages = Math.max(1, Math.ceil(hits.length / PER_PAGE));
    if (page > pages) page = pages;
    var start = (page - 1) * PER_PAGE;
    var end = start + PER_PAGE;

    rows.forEach(function (tr) {
      tr.hidden = true;
    });
    hits.slice(start, end).forEach(function (tr) {
      tr.hidden = false;
    });

    // A filter with no matches must render the empty state, not a phantom data row.
    if (empty) empty.hidden = hits.length !== 0;
    // Always "<visible range> / <matched>", plus "(共 N)" whenever a filter is narrowing the
    // set — so the number after the slash is unambiguously the match count, never the total.
    if (count) {
      var range = hits.length ? Math.min(start + 1, hits.length) + "–" + Math.min(end, hits.length) : "0";
      count.textContent =
        range + " / " + hits.length + (hits.length === total ? "" : " (共 " + total + ")");
    }
    if (pager) pager.hidden = hits.length <= PER_PAGE;
    if (pageInfo) pageInfo.textContent = "第 " + page + " / " + pages + " 页";
    if (prev) prev.disabled = page <= 1;
    if (next) next.disabled = page >= pages;
  }

  function refilter() {
    page = 1; // a changed filter invalidates the current page number
    apply();
  }

  if (chips) {
    chips.addEventListener("click", function (e) {
      var b = e.target.closest("button");
      if (!b) return;
      kind = b.dataset.k;
      chips.querySelectorAll("button").forEach(function (x) {
        x.classList.toggle("on", x === b);
        x.setAttribute("aria-pressed", String(x === b));
      });
      refilter();
    });
  }
  if (dimSel) dimSel.addEventListener("change", refilter);
  if (query) query.addEventListener("input", refilter);
  if (prev)
    prev.addEventListener("click", function () {
      if (page > 1) {
        page--;
        apply();
      }
    });
  if (next)
    next.addEventListener("click", function () {
      page++;
      apply();
    });
  apply();
})();
