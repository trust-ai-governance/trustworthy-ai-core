/* Click-to-open help popovers. The Dashboard's ? markers need a CLICK affordance — a native
   `title=` tooltip is unreliable (slow, sometimes never shows) and gives no click feedback,
   which read as "nothing happens". This toggles a sibling `.pop` on click, closes on outside
   click or Esc, and is keyboard-operable. No HTML is ever built from strings (see report.js). */
(function () {
  "use strict";
  var wraps = Array.prototype.slice.call(document.querySelectorAll(".helpwrap"));
  if (!wraps.length) return;

  function closeAll(except) {
    wraps.forEach(function (w) {
      if (w !== except) {
        w.classList.remove("open");
        var b = w.querySelector(".help");
        if (b) b.setAttribute("aria-expanded", "false");
      }
    });
  }

  wraps.forEach(function (w) {
    var btn = w.querySelector(".help");
    if (!btn) return;
    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      var open = w.classList.toggle("open");
      btn.setAttribute("aria-expanded", String(open));
      closeAll(w);
    });
  });

  document.addEventListener("click", function () {
    closeAll(null);
  });
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") closeAll(null);
  });
})();
