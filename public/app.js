// All dynamic content uses textContent (never innerHTML): log data is attacker-controlled.
const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; };
const fmt = (ms) => new Date(ms).toISOString().slice(0, 19).replace("T", " ");

function bars(root, items, max) {
  root.replaceChildren();
  for (const [label, n] of items) {
    const row = el("div", undefined, "bar");
    const f = el("div", undefined, "fill"); f.style.width = `${Math.max(2, (n / max) * 100)}%`;
    row.append(el("span", label), f, el("span", String(n)));
    root.append(row);
  }
}

async function load() {
  const q = new URLSearchParams();
  if ($("sev").value) q.set("severity", $("sev").value);
  if ($("ip").value.trim()) q.set("ip", $("ip").value.trim());
  const [stats, alerts] = await Promise.all([
    fetch("/api/stats").then((r) => r.json()),
    fetch(`/api/alerts?${q}`).then((r) => (r.ok ? r.json() : [])),
  ]);
  $("meta").textContent = `${stats.events} events analyzed`;
  const cards = $("cards"); cards.replaceChildren();
  for (const s of ["critical", "high", "medium", "low"]) {
    const c = el("div", undefined, "card"); const n = el("div", String(stats.bySeverity[s]), `n sev ${s}`);
    c.append(n, el("div", s, "l")); cards.append(c);
  }
  const tmax = Math.max(1, ...stats.byTechnique.map((t) => t.count));
  bars($("tech"), stats.byTechnique.map((t) => [`${t.id} ${t.name}`, t.count]), tmax);
  bars($("ips"), stats.topIps.map((i) => [i.ip, i.maxScore]), 100);

  const rows = $("rows"); rows.replaceChildren();
  for (const a of alerts) {
    const tr = el("tr");
    const ruleCell = el("td"); const d = el("details");
    d.append(el("summary", a.title)); d.append(el("p", a.response)); d.append(el("pre", a.evidence.join("\n")));
    ruleCell.append(d);
    const tags = el("td"); for (const t of a.tags) tags.append(el("span", t, t === "known-bad-ip" ? "tag bad" : "tag"));
    tr.append(el("td", String(a.score)), el("td", a.severity, `sev ${a.severity}`), ruleCell,
      el("td", a.user ? `${a.ip} (${a.user})` : a.ip), el("td", String(a.count)), el("td", fmt(a.firstSeen)), tags);
    rows.append(tr);
  }
}
$("sev").addEventListener("change", load);
$("ip").addEventListener("input", load);
load();
