/* Client-side search over the prebuilt index (see sigharvest/site/build.py).
   data/meta.json is loaded once; a query loads the token shards of its words (data/t/<first 2 chars>.json), the
   facet postings of active filters (data/f/*.json) and only the result rows it shows (data/m/<n>.json).
   Ranks are in score order, so the matches come out sorted without a sort. */
(function (g) {
  "use strict";
  var TOKEN = /[a-z0-9]+(?:\.[a-z0-9]+)*/g;
  var LEVEL_SETS = { critical: ["critical"], high: ["high", "critical"], medium: ["medium", "high", "critical"], low: ["low", "medium", "high", "critical"] };

  function tokenize(q, meta) {
    var stop = {}, out = [], max = (meta && meta.token_max) || 40;
    ((meta && meta.stop) || []).forEach(function (w) { stop[w] = 1; });
    (String(q || "").toLowerCase().match(TOKEN) || []).forEach(function (t) {
      if (t.length >= 2 && !stop[t] && out.indexOf(t) < 0) out.push(t.slice(0, max));
    });
    return out;
  }

  function decode(deltas, bits) {
    var prev = -1;
    for (var i = 0; i < deltas.length; i++) { prev += deltas[i] + 1; bits[prev] = 1; }
  }

  function Engine(base, fetchJson) {
    this.base = base;
    this.fetch = fetchJson;
    this.meta = null;
  }
  Engine.prototype.init = function () {
    var self = this;
    return this.fetch(this.base + "data/meta.json").then(function (m) { self.meta = m; return m; });
  };
  Engine.prototype.posting = function (path, bits) {
    return this.fetch(this.base + path).then(function (deltas) { decode(deltas, bits); });
  };
  /* -> Promise<{ids: Int32Array (ranks, best first), terms: [...]}>; filters: {level, product, score, text, valid} */
  Engine.prototype.search = function (q, f) {
    var self = this, meta = this.meta, n = meta.indexed, terms = tokenize(q, meta), jobs = [], sets = [];
    f = f || {};
    terms.forEach(function (t) {
      var bits = new Uint8Array(n);
      sets.push(bits);
      meta.token_shards.forEach(function (key) {
        if (t.lastIndexOf(key, 0) !== 0 && key.lastIndexOf(t, 0) !== 0) return;
        jobs.push(self.fetch(self.base + "data/t/" + key + ".json").then(function (shard) {
          for (var k in shard) if (k.lastIndexOf(t, 0) === 0) decode(shard[k], bits);
        }));
      });
    });
    function facet(names) {
      var bits = new Uint8Array(n);
      sets.push(bits);
      names.forEach(function (name) { if (meta.facets[name]) jobs.push(self.posting("data/f/" + name + ".json", bits)); });
    }
    if (f.level && LEVEL_SETS[f.level]) facet(LEVEL_SETS[f.level].map(function (l) { return "level-" + l; }));
    if (f.product && /^[a-z0-9-]+$/.test(f.product)) facet(["product-" + f.product]);
    if (f.text) facet(["text"]);
    if (f.valid) facet(["val-ok"]);
    var limit = n, s = parseInt(f.score, 10);
    if (s >= 0 && s <= 100) limit = meta.score_cut[s];
    return Promise.all(jobs).then(function () {
      var out = new Int32Array(limit), k = 0;
      outer: for (var i = 0; i < limit; i++) {
        for (var j = 0; j < sets.length; j++) if (!sets[j][i]) continue outer;
        out[k++] = i;
      }
      return { ids: out.subarray(0, k), terms: terms };
    });
  };
  /* rows for ranks: [lid, title, level, score, product, category, techniques, n_independent, page, validation, text, family size] */
  Engine.prototype.rows = function (ids) {
    var self = this, chunk = this.meta.chunk, need = {};
    for (var i = 0; i < ids.length; i++) need[Math.floor(ids[i] / chunk)] = 1;
    var keys = Object.keys(need);
    return Promise.all(keys.map(function (c) { return self.fetch(self.base + "data/m/" + c + ".json"); })).then(function (chunks) {
      var by = {};
      keys.forEach(function (c, i) { by[c] = chunks[i]; });
      return Array.prototype.map.call(ids, function (id) { return by[Math.floor(id / chunk)][id % chunk]; });
    });
  };

  g.SigharvestSearch = { Engine: Engine, tokenize: tokenize };
  if (typeof module !== "undefined" && module.exports) module.exports = g.SigharvestSearch;
  if (typeof document === "undefined" || !document.getElementById("search")) return;

  // ------------------------------------------------------------ UI
  var S = g.Sigharvest, base = S.base(), el = S.el;
  var form = document.getElementById("search"), qEl = document.getElementById("q");
  var status = document.getElementById("status"), list = document.getElementById("results"), more = document.getElementById("more");
  var top = document.getElementById("top");
  var fields = { level: "f-level", product: "f-product", score: "f-score", text: "f-text", valid: "f-valid" };
  var engine = new Engine(base, S.json), ready = null, seq = 0, current = null, shown = 0, PAGE = 25;

  function filters() {
    var f = {};
    Object.keys(fields).forEach(function (k) {
      var e = document.getElementById(fields[k]);
      f[k] = e.type === "checkbox" ? e.checked : e.value;
    });
    return f;
  }
  function fromUrl() {
    var p = new URLSearchParams(location.search), any = false;
    if (p.get("q")) { qEl.value = p.get("q"); any = true; }
    Object.keys(fields).forEach(function (k) {
      var e = document.getElementById(fields[k]), v = p.get(k);
      if (v === null) return;
      any = true;
      if (e.type === "checkbox") e.checked = v === "1";
      else if (Array.prototype.some.call(e.options, function (o) { return o.value === v; })) e.value = v;
    });
    return any;
  }
  function toUrl(q, f) {
    var p = new URLSearchParams();
    if (q) p.set("q", q);
    Object.keys(f).forEach(function (k) { if (f[k]) p.set(k, f[k] === true ? "1" : f[k]); });
    var s = p.toString();
    history.replaceState(null, "", location.pathname + (s ? "?" + s : ""));
  }
  function row(r, meta) {
    var lid = r[0], level = meta.levels[r[2]] || "", cat = meta.categories[r[5]] || "", prod = meta.products[r[4]] || "";
    var m = [];
    if (level) m.push(el("span", { class: "badge " + S.levelClass(level) }, level));
    m.push(el("span", null, "score " + r[3]));
    if (prod || cat) m.push(el("span", null, prod + (cat ? " / " + cat : "")));
    if (r[6]) m.push(el("span", null, r[6].split(" ").slice(0, 3).join(" ")));
    if (r[11] > 1) m.push(el("span", null, "+" + (r[11] - 1) + " variant" + (r[11] === 2 ? "" : "s")));
    if (!r[10]) m.push(el("span", { class: "badge" }, "link only"));
    return el("li", null, [el("a", { class: "t", href: S.ruleHref(base, lid, r[8] ? "r/" + lid + ".html" : null) }, r[1] || "Untitled rule"), el("div", { class: "m" }, m)]);
  }
  function showMore() {
    if (!current) return Promise.resolve();
    var ids = current.ids.subarray(shown, shown + PAGE), mine = seq;
    return engine.rows(ids).then(function (rows) {
      if (mine !== seq) return;
      rows.forEach(function (r) { list.appendChild(row(r, engine.meta)); });
      shown += rows.length;
      more.classList.toggle("hidden", shown >= current.ids.length);
    });
  }
  function run() {
    var mine = ++seq, q = qEl.value.trim(), f = filters(), t0 = performance.now();
    toUrl(q, f);
    var active = q || Object.keys(f).some(function (k) { return f[k]; });
    if (top) top.classList.toggle("hidden", !!active);
    if (!active) { list.textContent = ""; more.classList.add("hidden"); status.textContent = ""; current = null; return; }
    status.textContent = "searching…";
    ready = ready || engine.init();
    ready.then(function () { return engine.search(q, f); }).then(function (res) {
      if (mine !== seq) return;
      current = res; shown = 0; list.textContent = "";
      return showMore().then(function () {
        if (mine !== seq) return;
        var n = res.ids.length, ms = Math.round(performance.now() - t0);
        status.textContent = n.toLocaleString("en") + " rule" + (n === 1 ? "" : "s") + " match (" + ms + " ms)" +
          (engine.meta.scope === "families" ? ", one per family" : "");
      });
    }).catch(function () { if (mine === seq) status.textContent = "Search failed to load its index; reload the page."; });
  }
  var timer = null;
  qEl.addEventListener("input", function () { clearTimeout(timer); timer = setTimeout(run, 140); });
  form.addEventListener("change", run);
  form.addEventListener("submit", function (e) { e.preventDefault(); run(); });
  more.addEventListener("click", function () { showMore(); });
  qEl.addEventListener("focus", function () { ready = ready || engine.init(); }, { once: true });
  if (fromUrl()) run();
})(typeof window !== "undefined" ? window : globalThis);
