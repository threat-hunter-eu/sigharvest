// Test helper for tests/test_site.py: a tiny DOM for node, enough for common.js / embed.js / search.js.
// Usage: node site_dom.js SITE_ROOT (embed|render|search) ARG
const fs = require("fs"), path = require("path"), vm = require("vm");
const [root, mode, arg] = process.argv.slice(2);
class Node { constructor(tag) { this.tagName = tag; this.attrs = {}; this.children = []; this.className = ""; this.classList = { toggle() {}, add() {} }; }
  setAttribute(k, v) { this.attrs[k] = String(v); } getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
  appendChild(c) { this.children.push(c); return c; }
  set textContent(v) { this.children = v ? [{ text: String(v) }] : []; }
  get textContent() { return this.children.map(c => c.text !== undefined ? c.text : c.textContent).join(""); } }
const card = new Node("div"); card.setAttribute("data-rule", arg || ""); card.appendChild({ text: "fallback" });
const head = new Node("head");
const document = { readyState: "complete", head, currentScript: { src: "https://blog.example/rules/static/embed.js" },
  createElement: t => new Node(t), createTextNode: t => ({ text: String(t) }), addEventListener() {},
  querySelector: s => s.startsWith("meta") ? { getAttribute: () => "/rules/" } : null,
  querySelectorAll: () => [card], getElementById: () => null };
const fetch = url => { const p = new URL(url, "https://blog.example/").pathname.replace(/^\/rules\//, "");
  try { const b = fs.readFileSync(path.join(root, p)); return Promise.resolve({ ok: true, json: () => Promise.resolve(JSON.parse(b)) }); }
  catch (e) { return Promise.resolve({ ok: false }); } };
const ctx = { document, fetch, URL, URLSearchParams, console, setTimeout, Promise, location: { href: "https://blog.example/post", search: "" } };
ctx.window = ctx; vm.createContext(ctx);
const dump = n => n.text !== undefined ? { text: n.text } : { tag: n.tagName, attrs: n.attrs, cls: n.className, children: n.children.map(dump) };
const load = f => vm.runInContext(fs.readFileSync(path.join(root, "static", f), "utf8"), ctx);
(async () => {
  if (mode === "embed") { load("embed.js"); }
  else if (mode === "render") { load("common.js"); const shard = JSON.parse(fs.readFileSync(path.join(root, "data/d", arg.slice(0, JSON.parse(fs.readFileSync(path.join(root, "data/meta.json"))).detail_prefix) + ".json")));
    ctx.Sigharvest.renderRule(card, shard[arg], {}, "/rules/"); }
  else if (mode === "search") { load("search.js"); const e = new ctx.SigharvestSearch.Engine("", u => fetch("https://blog.example/rules/" + u).then(r => r.json()));
    await e.init(); const res = await e.search(arg, {}); const rows = await e.rows(res.ids); console.log(JSON.stringify(rows.map(r => r[1]))); return; }
  await new Promise(r => setTimeout(r, 200));
  console.log(JSON.stringify(dump(card)));
})();
