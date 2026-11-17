/* sigharvest static site: shared helpers. Rule data is untrusted: it is only ever written with textContent, links only
   for https URLs (or site-relative ones built here from validated ids). No HTML parsing of data, ever. */
(function (g) {
  "use strict";
  var S = (g.Sigharvest = g.Sigharvest || {});
  var HEX = /^[0-9a-f]{6,64}$/;
  var TECH = /^attack\.(t\d{4})(?:\.(\d{3}))?$/;
  var GROUP = /^attack\.([gs])(\d{4})$/;
  var CVE = /^cve\.(\d{4})[.-](\d{4,7})$/;
  var LEVELS = ["informational", "low", "medium", "high", "critical"];

  S.base = function () {
    var m = document.querySelector('meta[name="sigharvest-base"]');
    var b = (m && m.getAttribute("content")) || "/";
    return /^\/(?:[A-Za-z0-9._-]+\/)*$/.test(b) ? b : "/";
  };
  S.isLid = function (s) { return typeof s === "string" && HEX.test(s); };
  S.safeUrl = function (u) {
    return typeof u === "string" && /^https:\/\/[^\s"'<>\\]+$/.test(u) ? u : null;
  };
  S.levelClass = function (lv) { return LEVELS.indexOf(lv) >= 0 ? "lv-" + lv : ""; };

  var cache = {};
  S.json = function (url) {
    if (!cache[url]) {
      cache[url] = fetch(url, { credentials: "same-origin" }).then(function (r) {
        if (!r.ok) throw new Error(r.status + " " + url);
        return r.json();
      });
      cache[url].catch(function () { delete cache[url]; });
    }
    return cache[url];
  };

  /* el("a", {class: "x", href: "..."}, "text" | [nodes]) - attributes are set one by one, text with textContent. */
  S.el = function (tag, attrs, content) {
    var e = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) return;
        if (k === "href" && !(S.safeUrl(v) || /^\/[A-Za-z0-9._\/?=&#-]*$/.test(v))) return;
        e.setAttribute(k, v === true ? "" : String(v));
      });
    }
    if (content !== undefined && content !== null) {
      (Array.isArray(content) ? content : [content]).forEach(function (c) {
        if (c === null || c === undefined || c === false) return;
        e.appendChild(typeof c === "object" ? c : document.createTextNode(String(c)));
      });
    }
    return e;
  };

  S.ruleHref = function (base, lid, page) {
    if (page && /^r\/[0-9a-f]+\.html$/.test(page)) return base + page;
    return base + "rule.html?l=" + (S.isLid(lid) ? lid : "");
  };

  /* Same as build.tag_info in Python: [label, url or null, kind]. */
  S.tagInfo = function (tag, attack) {
    var t = String(tag).trim().toLowerCase(), m;
    attack = attack || {};
    var identity = (attack.interpretations || {})[t];
    if (identity) {
      var current = identity.current_id;
      var link = current && /^T\d{4}(?:\.\d{3})?$/.test(current) ? "https://attack.mitre.org/techniques/" + current.replace(".", "/") + "/" : null;
      return [identity.label, link, identity.domain === "enterprise" ? "technique" : "tag"];
    }
    if ((m = TECH.exec(t))) {
      var tid = m[1].toUpperCase() + (m[2] ? "." + m[2] : "");
      var name = (attack.techniques || {})[tid];
      return [name ? tid + " " + name : tid, "https://attack.mitre.org/techniques/" + m[1].toUpperCase() + (m[2] ? "/" + m[2] : "") + "/", "technique"];
    }
    if ((m = GROUP.exec(t))) {
      var id = m[1].toUpperCase() + m[2];
      return [id, "https://attack.mitre.org/" + (m[1] === "g" ? "groups" : "software") + "/" + id + "/", m[1] === "g" ? "group" : "software"];
    }
    if ((m = CVE.exec(t))) {
      var cve = "CVE-" + m[1] + "-" + m[2];
      return [cve, "https://nvd.nist.gov/vuln/detail/" + cve, "cve"];
    }
    if (t.indexOf("attack.") === 0) {
      var tac = (attack.tactics || {})[t.slice(7)];
      return tac ? [tac[1], "https://attack.mitre.org/tactics/" + tac[0] + "/", "tactic"] : [t.slice(7), null, "tactic"];
    }
    return [String(tag), null, "tag"];
  };

  S.badges = function (d) {
    var el = S.el, items = [];
    if (d.level) items.push(el("li", { class: "badge " + S.levelClass(d.level) }, "level: " + d.level));
    if (d.status) items.push(el("li", { class: "badge" }, "status: " + d.status));
    if (d.validation === "ok") items.push(el("li", { class: "badge ok" }, "validates"));
    else if (d.validation === "warning") items.push(el("li", { class: "badge warn" }, "validates with warnings"));
    else if (d.validation === "error") items.push(el("li", { class: "badge bad" }, "validation errors"));
    var n = Number(d.n_independent) || 1;
    items.push(el("li", { class: "badge" }, n + " independent source" + (n === 1 ? "" : "s")));
    items.push(el("li", { class: "badge" }, "score " + Math.round(Number(d.score) || 0)));
    (d.quality_flags || []).forEach(function (f) { items.push(el("li", { class: "badge flag" }, String(f).replace(/_/g, " "))); });
    return el("ul", { class: "badges", "aria-label": "Rule summary" }, items);
  };

  S.tagChips = function (tags, attack) {
    return S.el("ul", { class: "chips" }, (tags || []).map(function (t) {
      var info = S.tagInfo(t, attack);
      var url = S.safeUrl(info[1]);
      return S.el("li", null, url ? S.el("a", { class: info[2], href: url, rel: "noopener" }, info[0]) : S.el("span", null, info[0]));
    }));
  };

  S.yamlBlock = function (d) {
    var el = S.el;
    var src = S.safeUrl((d.canonical || {}).url);
    if (d.yaml) {
      var id = "yaml-" + d.lid;
      return el("details", { open: true }, [
        el("summary", null, "Sigma rule (YAML)"),
        el("pre", { class: "yaml", id: id }, el("code", null, d.yaml)),
        el("p", null, el("button", { class: "btn", type: "button", "data-copy": id }, "copy YAML")),
      ]);
    }
    var why = d.yaml_note === "size" ? "The rule text is too large to show here."
      : d.licence_class === "none" ? "Text not redistributed: this rule has no stated licence, so only its metadata is published here."
      : "Text not redistributed: the licence of this rule (" + (d.licence || "?") + ") does not allow it to be republished here.";
    return el("div", { class: "notice" }, [el("p", null, why), src ? el("p", null, el("a", { href: src, rel: "noopener nofollow" }, "View the rule at its source →")) : null]);
  };

  // Each licence id linked to its text (the licence URI travels with the rule: DRL item 3, CC-BY 3(a)(1)(C)).
  S.licenceLinks = function (d) {
    var el = S.el, links = d.licence_links || [];
    if (!links.length) return d.licence || "not stated";
    var out = [];
    links.forEach(function (l, i) {
      if (i) out.push(" / ");
      var url = S.safeUrl(l.url);
      out.push(url ? el("a", { href: url, rel: "noopener" }, l.id) : l.id);
    });
    return el("span", null, out);
  };

  S.licenceBlock = function (d) {
    var el = S.el, c = d.canonical || {}, src = S.safeUrl(c.url);
    return el("div", { class: "notice licence" }, [
      el("p", null, [el("strong", null, "Licence: "), S.licenceLinks(d), d.licence_from ? el("span", { class: "muted" }, " (" + d.licence_from + ")") : null,
        d.licence_class ? el("span", { class: "muted" }, " - class " + d.licence_class) : null]),
      d.drl_origin ? el("p", null, ["This rule is a copy of a SigmaHQ rule under the ",
        el("a", { href: "https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md", rel: "noopener" }, "Detection Rule License 1.1"),
        ": keep its author when you share it."]) : null,
      el("p", null, [el("strong", null, "Author: "), (d.author || "not stated") + ". Copyright stays with the rule's authors."]),
      el("p", null, [el("strong", null, "Canonical copy: "), c.source || "?", c.path ? " / " : null, c.path ? el("code", null, c.path) : null,
        c.commit ? " @ " : null, c.commit ? el("code", null, String(c.commit).slice(0, 12)) : null,
        src ? " - " : null, src ? el("a", { href: src, rel: "noopener nofollow" }, "open at source") : null]),
    ]);
  };

  S.renderRule = function (box, d, attack, base) {
    var el = S.el, ls = d.logsource || {};
    var lsText = (ls.product || "-") + (ls.category ? " / " + ls.category : "") + (ls.service ? " / " + ls.service : "");
    var conv = d.conversion || {};
    var convNode = conv.tested
      ? el("span", null, Object.keys(conv.counts || {}).sort().map(function (k) { return conv.counts[k] + " " + k; }).join(", "))
      : el("span", { class: "muted" }, "not tested in this release");
    var kv = [el("dt", null, "log source"), el("dd", null, el("code", null, lsText))];
    if ((d.attack || []).length) kv.push(el("dt", null, "ATT&CK interpretation"), el("dd", null, d.attack.map(function (tag) { return el("div", null, tag.label); })));
    if ((d.tags || []).length) kv.push(el("dt", null, "tags"), el("dd", null, S.tagChips(d.tags, attack)));
    if (d.modified) kv.push(el("dt", null, "modified"), el("dd", null, d.modified));
    kv.push(el("dt", null, "rule id"), el("dd", null, el("code", null, d.rule_id || "")));
    kv.push(el("dt", null, "logic hash"), el("dd", null, el("code", null, String(d.logic_hash || "").slice(0, 16))));
    kv.push(el("dt", null, "conversion"), el("dd", null, convNode));
    var aside = [el("h2", null, "Details"), el("dl", { class: "kv" }, kv)];
    if ((d.variants || []).length) {
      var others = (Number(d.family_size) || 1) - 1;
      aside.push(el("h2", null, "Family variants"),
        el("p", { class: "muted" }, others + " other version" + (others === 1 ? "" : "s") + " of this rule (same id, logic or meaning) from other repositories."),
        el("ul", null, d.variants.map(function (v) {
          return el("li", null, [el("a", { href: S.ruleHref(base, v[0], v[4]) }, v[1] || "Untitled"), " ", el("span", { class: "muted mono" }, "score " + v[2] + (v[3] ? ", " + v[3] : ""))]);
        })));
    }
    var snippetId = "embed-" + d.lid;
    aside.push(el("h2", null, "Embed"), el("details", null, [
      el("summary", null, "rule card for an article"),
      el("pre", { class: "yaml snippet", id: snippetId }, el("code", null, S.embedSnippet(base, d.lid))),
      el("p", null, el("button", { class: "btn", type: "button", "data-copy": snippetId }, "copy snippet")),
    ]));
    var main = [el("h2", null, "Rule"), S.yamlBlock(d), el("h2", null, "Licence and source"), S.licenceBlock(d)];
    if ((d.sources || []).length > 1) main.push(el("p", { class: "muted" }, "Also carried by: " + d.sources.slice(0, 12).join(", ") + (d.sources.length > 12 ? " and " + (d.sources.length - 12) + " more" : "") + "."));
    var parts = [el("h1", null, d.title || "Untitled rule"), S.badges(d)];
    if (d.page) parts.push(el("p", { class: "muted" }, ["Static page: ", el("a", { href: S.ruleHref(base, d.lid, d.page) }, "permalink")]));
    if (d.description) parts.push(el("p", { class: "desc" }, d.description));
    parts.push(el("div", { class: "grid2" }, [el("div", null, main), el("aside", null, aside)]));
    box.textContent = "";
    box.appendChild(el("article", null, parts));
  };

  S.embedSnippet = function (base, lid) {
    lid = S.isLid(lid) ? lid : "";
    return '<div class="sigharvest-rule" data-rule="' + lid + '"><a href="' + base + "rule.html?l=" + lid + '">Sigma rule ' + lid + "</a></div>\n" +
      '<script src="' + base + 'static/embed.js" defer></' + "script>";
  };

  /* copy buttons: <button data-copy="element-id"> */
  if (typeof document !== "undefined") {
    document.addEventListener("click", function (ev) {
      var b = ev.target && ev.target.closest ? ev.target.closest("[data-copy]") : null;
      if (!b) return;
      var src = document.getElementById(b.getAttribute("data-copy"));
      if (!src || !navigator.clipboard) return;
      navigator.clipboard.writeText(src.textContent).then(function () {
        var old = b.textContent;
        b.textContent = "copied";
        setTimeout(function () { b.textContent = old; }, 1500);
      });
    });
  }
})(window);
