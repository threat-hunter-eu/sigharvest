/* rule.html?l=<lid>: renders one rule from its detail shard (data/d/<prefix>.json). */
(function () {
  "use strict";
  var S = window.Sigharvest, base = S.base(), box = document.getElementById("rule");
  function say(text) { box.textContent = ""; box.appendChild(S.el("p", { class: "notice" }, text)); }
  var want = (new URLSearchParams(location.search).get("l") || "").trim().toLowerCase();
  if (!S.isLid(want)) { say("No rule given: open a rule from the search page."); return; }
  Promise.all([S.json(base + "data/meta.json"), S.json(base + "data/attack.json")]).then(function (res) {
    var meta = res[0], attack = res[1];
    var lid = want.slice(0, meta.lid);
    return S.json(base + "data/d/" + want.slice(0, meta.detail_prefix) + ".json").then(function (shard) {
      var d = Object.prototype.hasOwnProperty.call(shard, lid) ? shard[lid] : null;
      if (!d && lid.length < meta.lid) {
        var keys = Object.keys(shard).filter(function (k) { return k.indexOf(lid) === 0; });
        if (keys.length === 1) d = shard[keys[0]];
      }
      if (!d) { say("No rule " + want + " in this release (it may have changed upstream: search for it by title)."); return; }
      document.title = (d.title || "Untitled rule") + " | sigharvest";
      S.renderRule(box, d, attack, base);
    });
  }).catch(function () { say("No rule " + want + " in this release."); });
})();
