/* Rule cards for blog articles. Paste where the card should appear:
     <div class="sigharvest-rule" data-rule="0123456789ab"><a href="/rules/rule.html?l=0123456789ab">Sigma rule 0123456789ab</a></div>
     <script src="/rules/static/embed.js" defer></script>
   The script replaces each .sigharvest-rule[data-rule] with a card (title, level, ATT&CK, YAML when its licence
   allows, licence line, link to the full page). Self-contained; rule data is written with textContent only. */
(function () {
  "use strict";
  var me = document.currentScript;
  var base;
  try { base = new URL("../", me && me.src ? me.src : location.href + "rules/static/").href; } catch (e) { return; }
  var HEX = /^[0-9a-f]{6,64}$/, TECH = /^attack\.(t\d{4})(?:\.(\d{3}))?$/, LEVELS = ["informational", "low", "medium", "high", "critical"];
  var cache = {};
  function json(path) {
    if (!cache[path]) cache[path] = fetch(base + path, { credentials: "omit" }).then(function (r) { if (!r.ok) throw new Error(path); return r.json(); });
    return cache[path];
  }
  function safe(u) { return typeof u === "string" && /^https:\/\/[^\s"'<>\\]+$/.test(u) ? u : null; }
  function el(tag, cls, content, attrs) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (attrs) Object.keys(attrs).forEach(function (k) { if (attrs[k] !== null && attrs[k] !== undefined) e.setAttribute(k, attrs[k]); });
    (Array.isArray(content) ? content : [content]).forEach(function (c) {
      if (c === null || c === undefined || c === false) return;
      e.appendChild(typeof c === "object" ? c : document.createTextNode(String(c)));
    });
    return e;
  }
  function page(d) {
    return d.page && /^r\/[0-9a-f]+\.html$/.test(d.page) ? base + d.page : base + "rule.html?l=" + d.lid;
  }
  function card(d, attack) {
    var head = [];
    if (LEVELS.indexOf(d.level) >= 0) head.push(el("span", "sgc-badge sgc-" + d.level, d.level));
    if (d.validation === "ok") head.push(el("span", "sgc-badge", "validates"));
    head.push(el("span", "sgc-badge", "score " + Math.round(Number(d.score) || 0)));
    var ls = d.logsource || {};
    var techs = (d.tags || []).map(function (t) {
      var identity = ((attack || {}).interpretations || {})[String(t).toLowerCase()];
      if (identity) {
        var current = identity.current_id;
        if (current && /^T\d{4}(?:\.\d{3})?$/.test(current)) return el("li", null, el("a", null, identity.label, { href: "https://attack.mitre.org/techniques/" + current.replace(".", "/") + "/", rel: "noopener" }));
        return el("li", null, identity.label);
      }
      var m = TECH.exec(String(t).toLowerCase());
      if (!m) return null;
      var id = m[1].toUpperCase() + (m[2] ? "." + m[2] : ""), name = ((attack || {}).techniques || {})[id];
      return el("li", null, el("a", null, name ? id + " " + name : id, { href: "https://attack.mitre.org/techniques/" + m[1].toUpperCase() + (m[2] ? "/" + m[2] : "") + "/", rel: "noopener" }));
    }).filter(Boolean);
    var src = safe((d.canonical || {}).url);
    var body;
    if (d.yaml) body = el("details", "sgc-yaml", [el("summary", null, "Sigma rule (YAML)"), el("pre", null, el("code", null, d.yaml))]);
    else body = el("p", "sgc-note", [d.yaml_note === "size" ? "Rule text too large to show. " : "Text not redistributed (licence). ",
      src ? el("a", null, "View at source →", { href: src, rel: "noopener nofollow" }) : null]);
    return el("article", "sgc", [
      el("div", "sgc-head", head),
      el("h3", "sgc-title", el("a", null, d.title || "Untitled rule", { href: page(d) })),
      el("p", "sgc-meta", (ls.product || "-") + (ls.category ? " / " + ls.category : "") + (ls.service ? " / " + ls.service : "")),
      techs.length ? el("ul", "sgc-attack", techs, { "aria-label": "MITRE ATT&CK techniques" }) : null,
      body,
      el("p", "sgc-foot", ["Licence: " + (d.licence || "not stated") + (d.author ? " · by " + d.author : "") + " · ",
        src ? el("a", null, "source", { href: src, rel: "noopener nofollow" }) : null, src ? " · " : null,
        el("a", null, "full rule page", { href: page(d) })]),
    ]);
  }
  function render() {
    var nodes = document.querySelectorAll(".sigharvest-rule[data-rule]");
    if (!nodes.length) return;
    if (!document.querySelector("link[data-sigharvest-embed]")) {
      var link = document.createElement("link");
      link.rel = "stylesheet";
      link.href = base + "static/embed.css";
      link.setAttribute("data-sigharvest-embed", "");
      document.head.appendChild(link);
    }
    Promise.all([json("data/meta.json"), json("data/attack.json").catch(function () { return {}; })]).then(function (res) {
      var meta = res[0], attack = res[1];
      Array.prototype.forEach.call(nodes, function (node) {
        var want = String(node.getAttribute("data-rule") || "").trim().toLowerCase();
        if (!HEX.test(want) || node.getAttribute("data-sigharvest-done")) return;
        node.setAttribute("data-sigharvest-done", "1");
        json("data/d/" + want.slice(0, meta.detail_prefix) + ".json").then(function (shard) {
          var lid = want.slice(0, meta.lid);
          var d = Object.prototype.hasOwnProperty.call(shard, lid) ? shard[lid] : null;
          if (!d) return; /* keep the fallback link */
          node.textContent = "";
          node.appendChild(card(d, attack));
        }).catch(function () { /* keep the fallback link */ });
      });
    }).catch(function () {});
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", render);
  else render();
})();
