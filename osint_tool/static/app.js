"use strict";

/* ================= helpers ================= */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
function safeUrl(url) {
  try {
    const u = new URL(url, location.href);
    return ["http:", "https:"].includes(u.protocol) ? u.href : "#";
  } catch { return "#"; }
}
const link = (url, text) => `<a href="${esc(safeUrl(url))}" target="_blank" rel="noopener noreferrer">${esc(text ?? url)}</a>`;
const pivot = (q, text, type = "") => `<button class="tag pivot" data-q="${esc(q)}" data-type="${esc(type)}" title="Scan ${esc(q)}">${esc(text ?? q)}</button>`;
const tag = (text, cls = "") => `<span class="tag ${cls}">${esc(text)}</span>`;
const pill = (text, cls = "neutral") => `<span class="pill ${cls}">${esc(text)}</span>`;
const yesNo = (v, goodWhen = true) => v === null || v === undefined
  ? pill("unknown")
  : pill(v ? "yes" : "no", v === goodWhen ? "good" : "bad");
const section = (title) => `<div class="section-title">${esc(title)}</div>`;
const empty = (text = "Nothing found") => `<p class="empty">${esc(text)}</p>`;

function kv(rows) {
  const items = rows.filter(([, v]) => v !== null && v !== undefined && v !== "" && !(Array.isArray(v) && !v.length));
  if (!items.length) return "";
  return `<dl class="kv">${items.map(([k, v, raw]) => `<dt>${esc(k)}</dt><dd>${raw ? v : esc(v)}</dd>`).join("")}</dl>`;
}
function fmtDate(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return isNaN(d) ? iso : d.toISOString().slice(0, 10);
}
function ago(days) {
  if (days === null || days === undefined) return "";
  const years = days / 365.25;
  return years >= 1 ? `${years.toFixed(1)} years` : `${days} days`;
}
function timeAgo(ts) {
  const s = (Date.now() - ts) / 1000;
  if (s < 60) return "now";
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}
function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove("show"), 1800);
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); toast("Copied to clipboard"); }
  catch { toast("Copy failed"); }
}
const store = {
  get(key, fallback) { try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; } },
  set(key, value) { try { localStorage.setItem(key, JSON.stringify(value)); } catch {} },
};

const ICON = {
  copy: '<svg viewBox="0 0 24 24"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/></svg>',
  chevron: '<svg viewBox="0 0 24 24"><path d="m6 9 6 6 6-6"/></svg>',
  retry: '<svg viewBox="0 0 24 24"><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/></svg>',
};

/* ================= renderers ================= */
const R = {};

R.dns = (d) => {
  const rows = [];
  for (const type of ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"]) {
    for (const v of d.records[type] || []) {
      let val;
      if (type === "MX") val = `<span class="mono">${esc(v.priority)}</span> ${pivot(v.host, v.host, "domain")}`;
      else if (type === "A" || type === "AAAA") val = pivot(v, v, "ip");
      else if (type === "NS" || type === "CNAME") val = pivot(v, v, "domain");
      else val = `<code>${esc(v)}</code>`;
      rows.push(`<tr><td><span class="rtype">${type}</span></td><td>${val}</td></tr>`);
    }
  }
  return `<table class="data"><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>${rows.join("")}</tbody></table>`;
};

R.whois = (d) => {
  if (d.kind === "ip") {
    return kv([
      ["Network", d.name], ["Handle", d.handle], ["Range", d.range], ["CIDR", d.cidr?.join(", ")],
      ["Country", d.country], ["Type", d.type], ["Registered", fmtDate(d.created)], ["Updated", fmtDate(d.updated)],
    ]) + contacts(d.contacts);
  }
  const exp = d.expires_in_days;
  const expCls = exp === null ? "" : exp < 30 ? "bad" : exp < 90 ? "warn" : "good";
  return kv([
    ["Registrar", d.registrar],
    ["Created", d.created ? `${fmtDate(d.created)} <span class="note">(${ago(d.age_days)} ago)</span>` : null, true],
    ["Expires", d.expires ? `${fmtDate(d.expires)} ${exp !== null ? pill(exp < 0 ? "expired" : `in ${exp} days`, expCls) : ""}` : null, true],
    ["Updated", fmtDate(d.updated)],
    ["DNSSEC", d.dnssec === undefined || d.dnssec === null ? null : yesNo(d.dnssec), true],
  ]) +
  (d.nameservers?.length ? section("Nameservers") + `<div class="tags">${d.nameservers.map((n) => pivot(n, n, "domain")).join("")}</div>` : "") +
  (d.status?.length ? section("Status") + `<div class="tags">${d.status.map((s) => tag(s)).join("")}</div>` : "") +
  contacts(d.contacts);
};

function contacts(list) {
  const useful = (list || []).filter((c) => c.name || c.email || c.phone);
  if (!useful.length) return "";
  return section("Contacts") + `<table class="data"><tbody>${useful.map((c) => `
    <tr><td>${(c.roles || []).map((r) => tag(r, "blue")).join(" ")}</td>
    <td>${esc(c.name || "")}${c.email ? `<br>${pivot(c.email, c.email, "email")}` : ""}${c.phone ? `<br><span class="mono">${esc(c.phone)}</span>` : ""}${c.address ? `<br><span class="note">${esc(c.address)}</span>` : ""}</td></tr>`).join("")}</tbody></table>`;
}

R.email_security = (d) => {
  const risk = { low: "good", medium: "warn", high: "bad" }[d.spoofing_risk];
  const row = (label, x) => `<tr><td><b>${label}</b></td><td>${pill(x.present ? (x.policy || "present") : "missing", x.grade)} <span class="note">${esc(x.note)}</span>${x.record ? `<br><code>${esc(x.record)}</code>` : ""}</td></tr>`;
  return `<div class="big-stat"><div class="grade ${risk}">${esc(d.spoofing_risk[0].toUpperCase())}</div>
    <div><b>Spoofing risk: ${esc(d.spoofing_risk)}</b><span>How easily someone could send email pretending to be this domain.</span></div></div>
    <table class="data"><tbody>${row("SPF", d.spf)}${row("DMARC", d.dmarc)}
    <tr><td><b>MTA-STS</b></td><td>${d.mta_sts ? pill("enabled", "good") : pill("not set", "neutral")}</td></tr></tbody></table>` +
    (d.mail_services.length ? section("Email services in use") + `<div class="tags">${d.mail_services.map((s) => tag(s, "blue")).join("")}</div>` : "") +
    (d.verified_services.length ? section("Verified with (TXT records)") + `<div class="tags">${d.verified_services.map((s) => tag(s)).join("")}</div>` : "");
};

R.web = (d) => {
  const sh = d.security_headers;
  const gcls = { A: "good", B: "good", C: "warn", D: "bad", F: "bad" }[sh.grade];
  const c = d.contacts;
  const social = Object.entries(c.social || {}).flatMap(([net, links]) => links.map((l) => `<a class="tag" href="${esc(safeUrl(l))}" target="_blank" rel="noopener noreferrer">${esc(net)}: ${esc(l.replace(/^https?:\/\/(www\.)?/, ""))}</a>`));
  return kv([
    ["Title", d.title], ["Description", d.description],
    ["Final URL", link(d.url), true],
    ["Status", pill(d.status, d.status < 400 ? "good" : "bad"), true],
    ["Server", d.server],
  ]) +
  (d.redirects.length > 1 ? section("Redirect chain") + `<div class="tags">${d.redirects.map((r) => tag(`${r.status} ${r.url}`, r.status >= 300 && r.status < 400 ? "warn" : "")).join('<span class="note">→</span>')}</div>` : "") +
  section("Technologies") + (d.technologies.length ? `<div class="tags">${d.technologies.map((t) => tag(t, "blue")).join("")}</div>` : empty("No fingerprints matched")) +
  section("Security headers") + `<div class="big-stat"><div class="grade ${gcls}">${esc(sh.grade)}</div><div><b>${sh.present.length} of 6 recommended headers</b><span>${sh.missing.length ? "Missing: " + esc(sh.missing.map((m) => m.header).join(", ")) : "All recommended headers present"}</span></div></div>` +
  (c.emails.length || c.phones.length || social.length ? section("Contacts found on page") +
    `<div class="tags">${c.emails.map((e) => pivot(e, e, "email")).join("")}${c.phones.map((p) => pivot(p, p, "phone")).join("")}${social.join("")}</div>` : "") +
  (d.robots_disallow.length ? section("robots.txt disallowed paths") + `<div class="tags scroll">${d.robots_disallow.map((p) => tag(p)).join("")}</div>` : "") +
  (d.security_txt ? section("security.txt") + `<pre class="json">${esc(d.security_txt)}</pre>` : "") +
  `<details class="raw"><summary>Response headers (${Object.keys(d.headers).length})</summary><table class="data">${Object.entries(d.headers).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td><code>${esc(v)}</code></td></tr>`).join("")}</table></details>`;
};

R.subdomains = (d, card) => {
  if (!d.subdomains.length) return empty("No subdomains in certificate transparency logs");
  setTimeout(() => {
    const input = $(".filter-input", card);
    input?.addEventListener("input", () => {
      const q = input.value.toLowerCase();
      $$(".tags .pivot", card).forEach((el) => { el.hidden = !el.dataset.q.includes(q); });
    });
  });
  return `<p class="note"><b>${d.count}</b> unique hostnames from ${esc(d.sources.join(", "))}${d.truncated ? " (showing first 500)" : ""}.</p>
    <input class="filter-input" placeholder="Filter subdomains…" aria-label="Filter subdomains">
    <div class="tags scroll">${d.subdomains.map((s) => pivot(s, s, "domain")).join("")}</div>`;
};

R.tls = (d) => {
  const total = (new Date(d.valid_to) - new Date(d.valid_from)) / 86400000;
  const pct = Math.max(0, Math.min(100, (d.days_left / total) * 100));
  const cls = d.expired || d.days_left < 14 ? "bad" : d.days_left < 30 ? "warn" : "good";
  return (d.verified ? "" : `<div class="error-box">Certificate NOT trusted: ${esc(d.verify_error)}</div><br>`) +
    `<div class="big-stat"><div class="grade ${cls}">${d.expired ? "✗" : "✓"}</div><div style="flex:1"><b>${d.expired ? "Expired" : `${d.days_left} days remaining`}</b>
    <div class="meter"><i style="width:${pct}%;background:var(--${cls})"></i></div><span>${fmtDate(d.valid_from)} → ${fmtDate(d.valid_to)}</span></div></div>` +
    kv([["Subject", d.subject], ["Organization", d.organization], ["Issuer", d.issuer], ["Issuer CN", d.issuer_cn],
      ["Protocol", d.tls_version], ["Cipher", d.cipher], ["Serial", d.serial]]) +
    (d.san.length ? section(`Subject alternative names (${d.san.length})`) + `<div class="tags scroll">${d.san.map((s) => s.startsWith("*.") ? tag(s) : pivot(s, s, "domain")).join("")}</div>` : "");
};

R.wayback = (d) => {
  const entries = Object.entries(d.per_year);
  const max = Math.max(...entries.map(([, n]) => n), 1);
  return kv([
    ["First capture", `${link(d.first.url, d.first.date)}`, true],
    ["Latest capture", `${link(d.last.url, d.last.date)}`, true],
    ["Months archived", d.months_with_captures],
    ["All captures", link(d.calendar, "Open calendar"), true],
  ]) + section("Months with captures, per year") +
    `<div class="bars">${entries.map(([y, n]) => `<div class="bar" style="height:${(n / max) * 100}%" title="${y}: ${n} months"></div>`).join("")}</div>
     <div class="bars-axis"><span>${esc(entries[0]?.[0])}</span><span>${esc(entries.at(-1)?.[0])}</span></div>`;
};

R.geoip = (d, card) => {
  const hasCoords = typeof d.lat === "number" && typeof d.lon === "number";
  if (hasCoords) setTimeout(() => drawMap($(".map", card), d));
  const flags = [d.proxy && tag("proxy/VPN", "warn"), d.hosting && tag("hosting/datacenter", "blue"), d.mobile && tag("mobile", "blue")].filter(Boolean);
  return (hasCoords ? `<div class="map" role="img" aria-label="Map of approximate location"></div>` : "") +
    kv([
      ["Location", [d.city, d.region, d.country].filter(Boolean).join(", ")],
      ["Coordinates", hasCoords ? `${d.lat}, ${d.lon}` : null],
      ["Postal", d.postal], ["Time zone", d.timezone],
      ["ASN", d.asn ? link(`https://bgp.he.net/${d.asn}`, d.asn) : null, true],
      ["Organization", d.org], ["ISP", d.isp],
      ["Flags", flags.join(" "), true],
    ]) + `<p class="note">Source: ${esc(d.source)} · IP geolocation is approximate.</p>`;
};

function drawMap(el, d) {
  if (!el || !window.L) { if (el) el.outerHTML = `<p class="note">Map unavailable (Leaflet failed to load).</p>`; return; }
  const map = L.map(el, { scrollWheelZoom: false, attributionControl: true }).setView([d.lat, d.lon], 9);
  L.tileLayer("https://{s}.basemaps.cartocdn.com/{style}/{z}/{x}/{y}{r}.png", {
    style: document.documentElement.dataset.theme === "light" ? "light_all" : "dark_all",
    attribution: "&copy; OpenStreetMap &copy; CARTO", subdomains: "abcd", maxZoom: 19,
  }).addTo(map);
  L.circle([d.lat, d.lon], { radius: 6000, color: "#3ee6b0", weight: 1.5, fillOpacity: 0.15 }).addTo(map);
  L.circleMarker([d.lat, d.lon], { radius: 6, color: "#3ee6b0", fillColor: "#3ee6b0", fillOpacity: 1 }).addTo(map);
  setTimeout(() => map.invalidateSize(), 200);
}

R.rdns = (d) => d.ptr.length
  ? `<table class="data"><thead><tr><th>Hostname</th><th>Forward-confirmed</th></tr></thead><tbody>${d.ptr.map((h) => `<tr><td>${pivot(h, h, "domain")}</td><td>${yesNo(d.forward_confirmed[h])}</td></tr>`).join("")}</tbody></table>`
  : empty("No PTR record");

R.exposure = (d) => {
  if (!d.ports.length && !d.vulns.length) return empty(d.note || "No exposed services observed");
  return section("Open ports") + `<div class="tags">${d.ports.map((p) => tag(p, [21, 23, 445, 3389, 5900, 6379, 9200, 27017].includes(p) ? "warn" : "blue")).join("")}</div>` +
    (d.vulns.length ? section(`Known vulnerabilities (${d.vulns.length})`) + `<div class="tags scroll">${d.vulns.map((v) => `<a class="tag bad" href="https://nvd.nist.gov/vuln/detail/${esc(v)}" target="_blank" rel="noopener noreferrer">${esc(v)}</a>`).join("")}</div>` : "") +
    (d.cpes.length ? section("Software (CPE)") + `<div class="tags">${d.cpes.map((c) => tag(c.replace("cpe:/", ""))).join("")}</div>` : "") +
    (d.hostnames.length ? section("Hostnames") + `<div class="tags">${d.hostnames.map((h) => pivot(h, h, "domain")).join("")}</div>` : "") +
    (d.tags.length ? section("Tags") + `<div class="tags">${d.tags.map((t) => tag(t, "warn")).join("")}</div>` : "");
};

R.username = (d, card) => {
  const labels = { found: "Found", manual: "Check manually", error: "Unknown", not_found: "Not found" };
  setTimeout(() => {
    $$(".seg button", card).forEach((b) => b.addEventListener("click", () => {
      $$(".seg button", card).forEach((x) => x.classList.toggle("active", x === b));
      $$(".site", card).forEach((s) => { s.hidden = b.dataset.f !== "all" && s.dataset.status !== b.dataset.f; });
    }));
  });
  const segs = [["all", "All", d.checked], ...Object.entries(labels).map(([k, v]) => [k, v, d.counts[k]])];
  return `<p class="note">Checked <b>${d.checked}</b> platforms for <code>${esc(d.username)}</code>. Green tiles have a matching account; amber tiles block automated checks - open them to verify.</p>
    <div class="seg">${segs.map(([k, v, n]) => `<button data-f="${k}" class="${k === "all" ? "active" : ""}">${v}<b>${n}</b></button>`).join("")}</div>
    <div class="sites">${d.results.map((r) => `<a class="site ${r.status}" data-status="${r.status}" href="${esc(safeUrl(r.url))}" target="_blank" rel="noopener noreferrer" title="${esc(labels[r.status])}${r.detail ? " - " + esc(r.detail) : ""}">
      <span class="dot ${r.status}"></span><span class="s-name">${esc(r.site)}</span><span class="s-cat">${esc(r.category)}</span></a>`).join("")}</div>`;
};

R.email = (d) => {
  const g = d.gravatar || {};
  return (g.exists ? `<div class="row" style="margin-bottom:14px"><img class="avatar" src="${esc(safeUrl(g.avatar))}" alt="Gravatar">
    <div>${kv([["Name", g.display_name], ["Username", g.username ? pivot(g.username, g.username, "username") : null, true], ["Location", g.location], ["Profile", g.profile_url ? link(g.profile_url) : null, true]])}
    ${g.accounts?.length ? `<div class="tags" style="margin-top:8px">${g.accounts.map((a) => `<a class="tag" href="${esc(safeUrl(a.url))}" target="_blank" rel="noopener noreferrer">${esc(a.name)}</a>`).join("")}</div>` : ""}</div></div>` : "") +
  kv([
    ["Domain", pivot(d.domain, d.domain, "domain"), true],
    ["Username", pivot(d.local_part.split("+")[0], d.local_part, "username"), true],
    ["Receives mail", yesNo(d.can_receive_mail), true],
    ["Mail provider", d.provider],
    ["Free provider", yesNo(d.free_provider, false).replace(/bad/, "neutral"), true],
    ["Disposable", yesNo(d.disposable, false), true],
    ["Role account", d.role_account ? pill("yes", "warn") : pill("no", "neutral"), true],
    ["Normalized", d.normalized !== `${d.local_part}@${d.domain}` ? d.normalized : null],
    ["Gravatar", g.exists === null ? pill("unknown") : g.exists ? pill("profile found", "good") : pill("none", "neutral"), true],
  ]) +
  (d.mx.length ? section("MX records") + `<div class="tags">${d.mx.map((m) => tag(`${m.priority} ${m.host}`)).join("")}</div>` : "") +
  (d.mx_error ? `<p class="note">MX lookup failed: ${esc(d.mx_error)}</p>` : "");
};

R.phone = (d) => kv([
  ["International", d.international], ["E.164", d.e164], ["National", d.national],
  ["Valid", yesNo(d.valid), true], ["Country", d.country], ["Region", d.region], ["Location", d.location],
  ["Carrier", d.carrier], ["Line type", d.line_type], ["Time zones", d.timezones?.join(", ")],
  ["Calling code", d.calling_code],
]) + (d.assumed_region ? `<p class="note">No country prefix given - assumed ${esc(d.assumed_region)}. Add +countrycode for accuracy.</p>` : "") +
  (d.note ? `<p class="note">${esc(d.note)}</p>` : "");

R.hash = (d) => `<div class="big-stat"><div class="grade good" style="font-size:18px">${d.bits}</div><div><b>Most likely ${esc(d.likely || "unknown")}</b><span>${d.length} hex characters · ${d.bits}-bit digest</span></div></div>` +
  section("Candidate algorithms") + `<div class="tags">${d.candidates.map((c, i) => tag(c, i === 0 ? "good" : "")).join("")}</div>` +
  section("Look it up") + `<div class="tool-links">${d.lookups.map((l) => `<a href="${esc(safeUrl(l.url))}" target="_blank" rel="noopener noreferrer">${esc(l.name)}</a>`).join("")}</div>`;

R.dorks = (d) => {
  const engines = [["google", "G"], ["bing", "B"], ["duckduckgo", "D"], ["yandex", "Y"]];
  return (d.tools.length ? section("Pivot to external tools") + `<div class="tool-links">${d.tools.map((t) => `<a href="${esc(safeUrl(t.url))}" target="_blank" rel="noopener noreferrer">${esc(t.name)}</a>`).join("")}</div>` : "") +
    Object.entries(d.groups).map(([group, dorks]) => `<div class="dork-group">${section(group)}${dorks.map((k) => `
      <div class="dork"><div class="dork-text"><b>${esc(k.label)}</b><code title="${esc(k.query)}">${esc(k.query)}</code></div>
      <div class="engines">${engines.map(([e, l]) => `<a href="${esc(safeUrl(k.links[e]))}" target="_blank" rel="noopener noreferrer" title="Search on ${e}">${l}</a>`).join("")}
      <button data-copy="${esc(k.query)}" title="Copy query">${ICON.copy}</button></div></div>`).join("")}</div>`).join("");
};

const WIDE = new Set(["username", "subdomains", "web"]);

function render(name, data, card) {
  const fn = R[name] || (name.startsWith("dorks_") ? R.dorks : null);
  if (!fn) return `<pre class="json">${esc(JSON.stringify(data, null, 2))}</pre>`;
  try { return fn(data, card); }
  catch (err) {
    console.error(err);
    return `<p class="note">Couldn't render this result nicely.</p><pre class="json">${esc(JSON.stringify(data, null, 2))}</pre>`;
  }
}

/* ================= scan orchestration ================= */
const state = { forcedType: "", scan: null };

async function api(path) {
  const resp = await fetch(path);
  const body = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(body.error || `HTTP ${resp.status}`);
  return body;
}

async function startScan(raw, forcedType = state.forcedType) {
  raw = raw.trim();
  if (!raw) { $("#q").focus(); return; }
  let det;
  try {
    det = await api(`/api/detect?q=${encodeURIComponent(raw)}&type=${encodeURIComponent(forcedType || "")}`);
  } catch (err) { toast(err.message); return; }

  const scanId = Symbol("scan");
  state.scan = { id: scanId, target: det.target, type: det.type, started: Date.now(), results: {}, modules: det.modules };
  document.body.classList.add("scanning");
  document.body.classList.remove("sidebar-open");
  $("#q").value = det.target;
  $("#results").hidden = false;
  $("#sum-target").textContent = det.target;
  $("#sum-type").textContent = det.type;
  updateBadge(det.type);
  addHistory(det.target, det.type);
  history.replaceState(null, "", `?q=${encodeURIComponent(det.target)}&type=${det.type}`);
  document.title = `${det.target} · Recon OSINT`;

  const grid = $("#grid");
  grid.innerHTML = "";
  $("#module-nav").innerHTML = det.modules.map((m) => `<a href="#card-${m.name}"><span class="dot loading" data-nav="${m.name}"></span>${esc(m.title)}</a>`).join("");
  for (const m of det.modules) grid.appendChild(makeCard(m));
  updateStats();

  const timer = setInterval(() => {
    if (state.scan?.id !== scanId) return clearInterval(timer);
    $("#stat-time").textContent = `${((Date.now() - state.scan.started) / 1000).toFixed(1)}s`;
  }, 100);

  $("#scan-btn").disabled = true;
  await Promise.all(det.modules.map((m) => runOne(m, scanId)));
  if (state.scan?.id === scanId) {
    clearInterval(timer);
    $("#stat-time").textContent = `${((Date.now() - state.scan.started) / 1000).toFixed(1)}s`;
    $("#scan-btn").disabled = false;
  }
}

function makeCard(m) {
  const card = document.createElement("article");
  card.className = `card${WIDE.has(m.name) || m.name.startsWith("dorks_") ? " wide" : ""}`;
  card.id = `card-${m.name}`;
  card.innerHTML = `
    <div class="card-head"><span class="dot loading"></span><h3>${esc(m.title)}</h3><span class="elapsed"></span>
      <div class="card-actions">
        <button data-act="retry" title="Run again" aria-label="Run again">${ICON.retry}</button>
        <button data-act="copy" title="Copy JSON" aria-label="Copy JSON">${ICON.copy}</button>
        <button data-act="collapse" title="Collapse" aria-label="Collapse">${ICON.chevron}</button>
      </div></div>
    <div class="card-body"><p class="card-desc">${esc(m.description)}</p><div class="skeleton"><i></i><i></i><i></i></div></div>`;
  card.addEventListener("click", (e) => {
    const act = e.target.closest("[data-act]")?.dataset.act;
    if (act === "collapse") card.classList.toggle("collapsed");
    if (act === "copy") copy(JSON.stringify(state.scan?.results[m.name] ?? {}, null, 2));
    if (act === "retry") runOne(m, state.scan.id);
  });
  return card;
}

async function runOne(m, scanId) {
  const card = document.getElementById(`card-${m.name}`);
  if (!card) return;
  setStatus(card, m.name, "loading");
  $(".card-body", card).innerHTML = `<p class="card-desc">${esc(m.description)}</p><div class="skeleton"><i></i><i></i><i></i></div>`;
  delete state.scan.results[m.name];
  updateStats();
  let res;
  try {
    res = await api(`/api/run/${m.name}?q=${encodeURIComponent(state.scan.target)}`);
  } catch (err) {
    res = { module: m.name, title: m.title, ok: false, error: err.message, data: null, elapsed_ms: 0 };
  }
  if (state.scan?.id !== scanId) return;
  state.scan.results[m.name] = res;
  setStatus(card, m.name, res.ok ? "ok" : "fail");
  $(".elapsed", card).textContent = `${res.elapsed_ms} ms`;
  $(".card-body", card).innerHTML = res.ok
    ? render(m.name, res.data, card)
    : `<div class="error-box">${esc(res.error)}</div>`;
  updateStats();
}

function setStatus(card, name, status) {
  $(".card-head .dot", card).className = `dot ${status}`;
  const nav = $(`[data-nav="${name}"]`);
  if (nav) nav.className = `dot ${status}`;
}

function updateStats() {
  const s = state.scan;
  const results = Object.values(s.results);
  const ok = results.filter((r) => r.ok).length;
  $("#stat-done").textContent = `${results.length}/${s.modules.length}`;
  $("#stat-ok").textContent = ok;
  $("#stat-fail").textContent = results.length - ok;
  $("#progress-bar").style.width = `${(results.length / s.modules.length) * 100}%`;
}

/* ================= detection badge ================= */
let detectTimer;
function updateBadge(type) {
  const badge = $("#type-badge");
  badge.hidden = !type;
  badge.textContent = type || "";
}
$("#q").addEventListener("input", () => {
  clearTimeout(detectTimer);
  const q = $("#q").value.trim();
  if (!q) return updateBadge("");
  detectTimer = setTimeout(async () => {
    try {
      const d = await api(`/api/detect?q=${encodeURIComponent(q)}&type=${encodeURIComponent(state.forcedType)}`);
      if ($("#q").value.trim() === q) updateBadge(d.type);
    } catch { updateBadge(""); }
  }, 180);
});

/* ================= history ================= */
const HISTORY_KEY = "recon-history";
const SHORT_TYPE = { domain: "DOM", ip: "IP", email: "MAIL", username: "USER", phone: "TEL", hash: "HASH", name: "NAME" };
function addHistory(target, type) {
  const list = store.get(HISTORY_KEY, []).filter((h) => !(h.target === target && h.type === type));
  list.unshift({ target, type, ts: Date.now() });
  store.set(HISTORY_KEY, list.slice(0, 40));
  renderHistory();
}
function renderHistory() {
  const list = store.get(HISTORY_KEY, []);
  $("#history").innerHTML = list.map((h) => `<li><button data-q="${esc(h.target)}" data-type="${esc(h.type)}">
    <span class="type-badge">${esc(SHORT_TYPE[h.type] || h.type)}</span><span class="h-target">${esc(h.target)}</span><span class="h-time">${timeAgo(h.ts)}</span></button></li>`).join("");
  $("#history-empty").hidden = list.length > 0;
}
$("#clear-history").addEventListener("click", () => { store.set(HISTORY_KEY, []); renderHistory(); });

/* ================= export ================= */
function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function toMarkdown(s) {
  const lines = [`# Recon OSINT report: \`${s.target}\``, "", `- **Type:** ${s.type}`, `- **Generated:** ${new Date().toISOString()}`, ""];
  const walk = (obj, depth) => {
    if (obj === null || obj === undefined || obj === "") return;
    const pad = "  ".repeat(depth);
    if (Array.isArray(obj)) {
      obj.slice(0, 200).forEach((v) => {
        if (v && typeof v === "object") { lines.push(`${pad}-`); walk(v, depth + 1); }
        else lines.push(`${pad}- ${v}`);
      });
    } else if (typeof obj === "object") {
      for (const [k, v] of Object.entries(obj)) {
        if (v === null || v === undefined || v === "" || (Array.isArray(v) && !v.length)) continue;
        if (typeof v === "object") { lines.push(`${pad}- **${k}:**`); walk(v, depth + 1); }
        else lines.push(`${pad}- **${k}:** ${v}`);
      }
    }
  };
  for (const m of s.modules) {
    const r = s.results[m.name];
    lines.push(`## ${m.title}`, "");
    if (!r) lines.push("_Not finished_");
    else if (!r.ok) lines.push(`_Failed: ${r.error}_`);
    else if (m.name === "web") walk({ ...r.data, headers: undefined }, 0);
    else walk(r.data, 0);
    lines.push("");
  }
  return lines.join("\n");
}
$("#export-btn").addEventListener("click", (e) => { e.stopPropagation(); $("#export-menu").hidden = !$("#export-menu").hidden; });
document.addEventListener("click", () => { $("#export-menu").hidden = true; });
$("#export-menu").addEventListener("click", (e) => {
  const kind = e.target.closest("[data-export]")?.dataset.export;
  const s = state.scan;
  if (!kind || !s) return;
  const base = `recon-${s.target.replace(/[^a-z0-9.@_-]+/gi, "_")}`;
  if (kind === "json") {
    download(`${base}.json`, JSON.stringify({ target: s.target, type: s.type, generated: new Date().toISOString(), results: s.results }, null, 2), "application/json");
  } else if (kind === "md") {
    download(`${base}.md`, toMarkdown(s), "text/markdown");
  } else if (kind === "print") {
    window.print();
  }
});

/* ================= wiring ================= */
$("#search-form").addEventListener("submit", (e) => { e.preventDefault(); startScan($("#q").value); });
$("#rerun").addEventListener("click", () => state.scan && startScan(state.scan.target, state.scan.type));
$$(".type-pill").forEach((p) => p.addEventListener("click", () => {
  state.forcedType = p.dataset.type;
  $$(".type-pill").forEach((x) => x.classList.toggle("active", x === p));
  $("#q").dispatchEvent(new Event("input"));
}));

document.addEventListener("click", (e) => {
  const trigger = e.target.closest(".pivot, .chip, .history button");
  if (trigger?.dataset.q) {
    e.preventDefault();
    const type = trigger.dataset.type || "";
    state.forcedType = "";
    $$(".type-pill").forEach((x) => x.classList.toggle("active", x.dataset.type === ""));
    window.scrollTo({ top: 0, behavior: "smooth" });
    startScan(trigger.dataset.q, type);
    return;
  }
  const cp = e.target.closest("[data-copy]");
  if (cp) copy(cp.dataset.copy);
});

document.addEventListener("keydown", (e) => {
  const typing = ["INPUT", "TEXTAREA"].includes(document.activeElement?.tagName);
  if (e.key === "/" && !typing) { e.preventDefault(); $("#q").focus(); $("#q").select(); }
  if (e.key === "Escape" && document.activeElement === $("#q")) $("#q").blur();
});

$("#theme-toggle").addEventListener("click", () => {
  const root = document.documentElement;
  const current = root.dataset.theme || "dark";
  root.dataset.theme = current === "dark" ? "light" : "dark";
  try { localStorage.setItem("recon-theme", root.dataset.theme); } catch {}
});
$("#sidebar-toggle").addEventListener("click", () => document.body.classList.toggle("sidebar-open"));

(async function init() {
  renderHistory();
  try { $("#version").textContent = `v${(await api("/api/meta")).version}`; } catch {}
  const params = new URLSearchParams(location.search);
  if (params.get("q")) startScan(params.get("q"), params.get("type") || "");
  else $("#q").focus();
})();
