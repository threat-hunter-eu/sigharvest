// sigharvest UI behaviour. No framework, no build step, no inline handlers (CSP script-src 'self'); every page works
// without it. Rule text is only ever set with textContent, never innerHTML.
// Keys: "/" search, "?" shortcuts, g+o/s/c/e go to a page, j/k move, Enter open, x select, e export, y copy YAML,
// 1-7 query tab, t theme, Esc.
// Shared with suriharvest (docs/conventions.md, "Web UI"): the theme, toast + copy and focus + selection sections and
// the keydown guards (shortcuts work on a focused checkbox or radio, are ignored while a dialog is open, the
// select-all box shows an indeterminate state, list filters stay inside their own list). Port fixes to both tools.
(function () {
  "use strict";
  var root = document.documentElement;
  root.classList.add("js");

  function $(sel, ctx) { return (ctx || document).querySelector(sel); }
  function $$(sel, ctx) { return Array.prototype.slice.call((ctx || document).querySelectorAll(sel)); }

  // ---------------------------------------------------------------- theme
  function themeLabel() {
    var t = root.getAttribute("data-theme") || "auto";
    $$("[data-theme-label]").forEach(function (el) { el.textContent = "Theme: " + t; });
  }
  function cycleTheme() {
    var order = ["auto", "light", "dark"], cur = root.getAttribute("data-theme") || "auto";
    var next = order[(order.indexOf(cur) + 1) % 3];
    if (next === "auto") root.removeAttribute("data-theme"); else root.setAttribute("data-theme", next);
    try { if (next === "auto") localStorage.removeItem("sigharvest-theme"); else localStorage.setItem("sigharvest-theme", next); } catch (e) { /* storage blocked */ }
    themeLabel();
  }

  // ---------------------------------------------------------------- toast + copy
  function toast(msg) {
    var t = $("#toast"); if (!t) return;
    t.textContent = msg; t.hidden = false; clearTimeout(t._h); t._h = setTimeout(function () { t.hidden = true; }, 1800);
  }
  function copyText(text, what, btn) {
    if (!navigator.clipboard) { toast("Copy is blocked by the browser: select the text and copy it"); return; }
    navigator.clipboard.writeText(text).then(function () { toast(what || "Copied"); if (btn) copied(btn); }, function () { toast("Copy is blocked by the browser"); });
  }
  // The button itself confirms (check mark, "Copied") for a moment; the toast stays for screen readers.
  function copied(btn) {
    var use = btn.querySelector("use"), label = btn.lastChild;
    if (btn._t) clearTimeout(btn._t); else btn._orig = [use && use.getAttribute("href"), label && label.nodeType === 3 ? label.nodeValue : null];
    btn.classList.add("is-copied");
    if (use) use.setAttribute("href", btn._orig[0].replace(/#.*$/, "#check"));
    if (btn._orig[1] !== null) label.nodeValue = "Copied";
    btn._t = setTimeout(function () { btn.classList.remove("is-copied"); if (use) use.setAttribute("href", btn._orig[0]); if (btn._orig[1] !== null) label.nodeValue = btn._orig[1]; btn._t = null; }, 1600);
  }

  // ---------------------------------------------------------------- results: focus and selection
  function items() { return $$("#results .result, #results tbody tr[data-key]"); }
  var cur = -1;
  function move(i) {
    var rows = items(); if (!rows.length) return;
    if (cur >= 0 && rows[cur]) rows[cur].classList.remove("is-focused", "cur");
    cur = Math.max(0, Math.min(rows.length - 1, i));
    var r = rows[cur];
    r.classList.add(r.tagName === "TR" ? "cur" : "is-focused");
    r.scrollIntoView({ block: "nearest" });
  }
  function boxes() { return $$("#results input[type=checkbox][name=h]"); }
  function selected() { return boxes().filter(function (c) { return c.checked; }); }
  function updateSelection() {
    var n = 0;
    boxes().forEach(function (c) {
      var item = c.closest(".result, tr");
      if (item) item.classList.toggle("is-selected", c.checked);
      if (c.checked) n++;
    });
    $$("[data-selected-count]").forEach(function (el) { el.textContent = n; });
    var bar = $("[data-selection-bar]"); if (bar) bar.classList.toggle("is-empty", n === 0);
    var all = $("#check-all"); if (all) { var b = boxes(); all.checked = n > 0 && n === b.length; all.indeterminate = n > 0 && n < b.length; }
  }
  function exportSelection() {
    var form = $("#selection");
    if (!form || !selected().length) return false;
    form.submit();
    return true;
  }

  // ---------------------------------------------------------------- rule page: query tabs converted on demand
  function convertPanel(panel) {
    if (!panel || panel.getAttribute("data-loaded")) return;
    var box = $("#convert"), target = panel.getAttribute("data-convert");
    if (!box || !target) return;
    panel.setAttribute("data-loaded", "1");
    var pre = $("pre", panel), meta = $(".tab-meta span", panel);
    fetch("/api/convert/" + encodeURIComponent(box.getAttribute("data-logic")) + "?target=" + encodeURIComponent(target))
      .then(function (r) { return r.json().then(function (d) { return { ok: r.ok, d: d }; }); })
      .then(function (res) {
        var d = res.d || {};
        if (!res.ok) {
          // Busy or over the per-rule limit: say why and let the next tab switch try again.
          panel.removeAttribute("data-loaded");
          pre.textContent = d.detail || "Conversion is unavailable right now.";
          return;
        }
        var qs = (d.queries || []).join("\n\n");
        pre.textContent = qs || ((d.status === "error" ? "Cannot convert: " : "") + (d.reason || d.error || d.status));
        if (meta) meta.textContent = "Converted with pySigma just now · " + (d.pipeline_line || d.status) + " · check field names against your data";
      })
      .catch(function () { panel.removeAttribute("data-loaded"); pre.textContent = "Conversion failed. Try `sigharvest convert` in a terminal."; });
  }
  function convertChecked() {
    var r = $(".tabs > input[type=radio]:checked"); if (!r) return;
    convertPanel($(".tab-panel.p-" + r.id.slice(2) + "[data-convert]"));
  }

  document.addEventListener("DOMContentLoaded", function () {
    // a box that scrolls sideways (code, wide tables, tab rows) can be reached and scrolled with the keyboard
    var focusScrollers = function () {
      Array.prototype.forEach.call(document.querySelectorAll("pre, .table-wrap, .table-scroll, .tab-list, .file-tree, .cmd code"), function (el) {
        if (el.scrollWidth > el.clientWidth && !el.hasAttribute("tabindex")) { el.setAttribute("tabindex", "0"); }
      });
    };
    focusScrollers();
    window.addEventListener("load", focusScrollers); // web fonts can widen code after DOMContentLoaded
    // phones: the filters sit above the results, so their groups start closed (a group with an active filter stays
    // open); the results are then on the first screen instead of two screens down
    if (window.matchMedia && window.matchMedia("(max-width: 900px)").matches) {
      Array.prototype.forEach.call(document.querySelectorAll(".facets > details.facet[open]"), function (d) {
        if (!d.querySelector("[aria-current=true]")) d.removeAttribute("open");
      });
    }
    // phones: the page links are one scrollable row; keep the current page in view
    // `here`, not `cur`: a `var cur` in this function shadowed the j/k cursor the keydown handler below uses
    var here = document.querySelector(".side .nav [aria-current=page]");
    if (here && here.parentNode.parentNode.scrollWidth > here.parentNode.parentNode.clientWidth) {
      var row = here.parentNode.parentNode;
      var a = here.getBoundingClientRect(), r = row.getBoundingClientRect();
      row.scrollLeft += a.left - r.left - (r.width - a.width) / 2;
    }
    themeLabel();
    updateSelection();
    convertChecked();

    document.addEventListener("click", function (ev) {
      var a = ev.target.closest("[data-action]"); if (!a) return;
      var act = a.getAttribute("data-action");
      if (act === "theme") cycleTheme();
      else if (act === "shortcuts") { var d = $("#shortcuts"); if (d && d.showModal) d.showModal(); }
      else if (act === "close-dialog") a.closest("dialog").close();
      else if (act === "copy") { var src = $(a.getAttribute("data-target")); if (src) copyText(src.textContent.replace(/\s+$/, "") + "\n", null, a); }
      else if (act === "select-page") { boxes().forEach(function (c) { c.checked = true; }); updateSelection(); }
      else if (act === "clear-selection") { boxes().forEach(function (c) { c.checked = false; }); updateSelection(); }
      else if (act === "export-dialog") { var x = $("#export-dialog"); if (x && x.showModal) { ev.preventDefault(); x.showModal(); } }
    });
    document.addEventListener("change", function (ev) {
      var t = ev.target;
      if (t.matches("#results input[type=checkbox][name=h]")) updateSelection();
      if (t.id === "check-all") { boxes().forEach(function (c) { c.checked = t.checked; }); updateSelection(); }
      if (t.matches("select[data-autosubmit]") && t.form) t.form.submit();
      if (t.matches(".tabs > input[type=radio]")) convertChecked();
    });
    document.addEventListener("input", function (ev) {
      var t = ev.target, sel = t.getAttribute && t.getAttribute("data-filter");
      if (!sel) return;
      var q = t.value.toLowerCase(), list = $(sel);
      if (!list) return;
      $$("li", list.parentNode).forEach(function (li) { li.hidden = !!q && li.textContent.toLowerCase().indexOf(q) < 0; });
      var more = $("details.more-values", list.parentNode); if (more && q) more.open = true;
    });

    var pending = null;
    document.addEventListener("keydown", function (e) {
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      var t = e.target, typing = t && /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) && !(t.type === "checkbox" || t.type === "radio");
      if (typing) { if (e.key === "Escape") t.blur(); return; }
      if ($("dialog[open]") && e.key !== "Escape") return;
      if (pending) {
        var go = { o: "/", s: "/search", c: "/coverage", e: "/export" }[e.key];
        pending = null;
        if (go) { e.preventDefault(); window.location = go; }
        return;
      }
      var rows = items(), row = rows[cur];
      switch (e.key) {
        case "/": var q = $("#q") || $("#global-search"); if (q) { q.focus(); q.select(); } break;
        case "?": var d = $("#shortcuts"); if (d && d.showModal) d.showModal(); break;
        case "g": pending = true; setTimeout(function () { pending = null; }, 1200); break;
        case "j": if (!rows.length) return; move(cur + 1); break;
        case "k": if (!rows.length) return; move(cur - 1); break;
        case "Enter": if (!row) return; var o = $("a.open", row); if (o) window.location = o.href; break;
        case "x": if (!row) return; var c = $("input[type=checkbox]", row); if (c) { c.checked = !c.checked; updateSelection(); } break;
        case "X": boxes().forEach(function (b) { b.checked = true; }); updateSelection(); break;
        case "e":
          if (exportSelection()) break;
          var ex = $(".rule-head [data-action=export-dialog]"), dlg = $("#export-dialog");
          if (ex && dlg && dlg.showModal) dlg.showModal(); else return;
          break;
        case "y": var y = $("#yaml"); if (!y) return; copyText(y.textContent.replace(/\s+$/, "") + "\n", "Rule YAML copied"); break;
        case "t": cycleTheme(); break;
        case "Escape": if (selected().length) { boxes().forEach(function (b) { b.checked = false; }); updateSelection(); } else return; break;
        default:
          if (/^[1-7]$/.test(e.key)) {
            var tabs = $$(".tabs > input[type=radio]"), tab = tabs[parseInt(e.key, 10) - 1];
            if (!tab) return;
            tab.checked = true; convertChecked();
            break;
          }
          return;
      }
      e.preventDefault();
    });
  });
})();
