"use strict";

const $ = (id) => document.getElementById(id);
const state = { users: [], status: null, editing: null, search: "", domains: null };

// ---- API ----

async function api(method, path, body) {
  const opts = { method, headers: { "X-Hysui": "1" } };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 401) {
    location.href = "/login";
    throw new Error("signed out");
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

// ---- formatting ----

function fmtBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1000)));
  const v = n / 1000 ** i;
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`;
}

function fmtSpeed(bytesPerSec) {
  const mbps = (bytesPerSec * 8) / 1e6;
  if (mbps === 0) return "0";
  if (mbps < 1) return `${(mbps * 1000).toFixed(0)} kbps`;
  return `${mbps < 10 ? mbps.toFixed(1) : mbps.toFixed(0)} Mbps`;
}

function fmtLimit(v) {
  return v > 0 ? `${+v.toFixed(2)}` : "∞";
}

function fmtDuration(sec) {
  const d = Math.floor(sec / 86400), h = Math.floor((sec % 86400) / 3600), m = Math.floor((sec % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

// ---- DOM helpers ----

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "checked" || k === "disabled") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

let toastTimer;
function toast(msg, bad = false) {
  const t = $("toast");
  t.textContent = msg;
  t.className = bad ? "show bad" : "show";
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = bad ? "bad" : ""), 2600);
}

function confirmBox(title, text, okLabel = "Confirm") {
  return new Promise((resolve) => {
    $("confirm-title").textContent = title;
    $("confirm-text").textContent = text;
    $("confirm-ok").textContent = okLabel;
    const d = $("confirm-dialog");
    const ok = () => { cleanup(); d.close(); resolve(true); };
    const cancel = () => { cleanup(); resolve(false); };
    const cleanup = () => { $("confirm-ok").removeEventListener("click", ok); d.removeEventListener("close", cancel); };
    $("confirm-ok").addEventListener("click", ok);
    d.addEventListener("close", cancel);
    d.showModal();
  });
}

// ---- rendering ----

function statusPill(u) {
  if (!u.enabled) return h("span", { class: "pill" }, "Disabled");
  if (u.overQuota) return h("span", { class: "pill bad" }, "Out of data");
  if (u.online > 0) {
    return h("span", { class: "pill ok" }, h("i", { class: "dot" }), u.online > 1 ? `Online · ${u.online}` : "Online");
  }
  return h("span", { class: "pill" }, "Offline");
}

function toggle(checked, label, onchange) {
  return h("label", { class: "switch", title: label },
    h("input", { type: "checkbox", checked, "aria-label": label, onchange }),
    h("span"));
}

async function patchUser(name, change, msg) {
  try {
    await api("PUT", `/api/users/${encodeURIComponent(name)}`, change);
    toast(msg);
  } catch (e) {
    toast(e.message, true);
  }
  refresh();
}

function closeMenus() {
  document.querySelectorAll(".menu-list").forEach((m) => (m.hidden = true));
  document.querySelectorAll("[aria-expanded=true]").forEach((b) => b.setAttribute("aria-expanded", "false"));
}

function moreMenu(u) {
  const list = h("div", { class: "menu-list", hidden: true },
    h("button", { onclick: () => kick(u) }, "Disconnect now"),
    h("button", { onclick: () => resetUsage(u) }, "Reset data usage"),
    h("button", { class: "danger", onclick: () => removeUser(u) }, "Delete user"));
  const btn = h("button", {
    class: "btn icon", "aria-label": `More actions for ${u.name}`, "aria-haspopup": "true", "aria-expanded": "false",
    onclick: (ev) => {
      ev.stopPropagation();
      const open = list.hidden;
      closeMenus();
      list.hidden = !open;
      btn.setAttribute("aria-expanded", String(open));
    },
  }, "⋯");
  return h("div", { class: "menu" }, btn, list);
}

// Built through CSSOM: the CSP forbids inline style attributes.
function usageBar(pct) {
  const fill = h("i");
  fill.style.width = `${pct}%`;
  return h("div", { class: pct >= 100 ? "bar full" : "bar" }, fill);
}

function userRow(u) {
  const used = u.tx + u.rx;
  const pct = u.quotaBytes > 0 ? Math.min(100, (used / u.quotaBytes) * 100) : 0;
  return h("tr", {},
    h("td", { class: "first" },
      h("div", { class: "uname" }, u.name),
      u.note ? h("div", { class: "note", title: u.note }, u.note) : null),
    h("td", {}, h("span", { class: "lbl" }, "Status"), statusPill(u)),
    h("td", { class: "mono" }, h("span", { class: "lbl" }, "Live"),
      h("span", {}, `↓ ${fmtSpeed(u.speedRx)}  ↑ ${fmtSpeed(u.speedTx)}`)),
    h("td", { class: "mono" }, h("span", { class: "lbl" }, "Limit (Mbps)"),
      h("span", { title: "Download / upload limit in Mbps (∞ = unlimited)" }, `↓ ${fmtLimit(u.downMbps)}  ↑ ${fmtLimit(u.upMbps)}`)),
    h("td", { class: "usage mono" }, h("span", { class: "lbl" }, "Data"),
      h("div", {},
        h("div", {}, fmtBytes(used), u.quotaBytes > 0 ? h("span", { class: "muted" }, ` / ${fmtBytes(u.quotaBytes)}`) : null),
        u.quotaBytes > 0 ? usageBar(pct) : null)),
    h("td", {}, h("span", { class: "lbl" }, "Home network"),
      toggle(u.homeAccess, `Home network access for ${u.name}`, (ev) =>
        patchUser(u.name, { homeAccess: ev.target.checked },
          ev.target.checked ? `${u.name} can reach your home network` : `${u.name} is internet-only now`))),
    h("td", {}, h("span", { class: "lbl" }, "Enabled"),
      toggle(u.enabled, `Enable ${u.name}`, (ev) =>
        patchUser(u.name, { enabled: ev.target.checked }, ev.target.checked ? `${u.name} enabled` : `${u.name} disabled`))),
    h("td", {},
      h("div", { class: "actions" },
        h("button", { class: "btn", onclick: () => showQR(u) }, "QR"),
        h("button", { class: "btn", onclick: () => openEditor(u) }, "Edit"),
        moreMenu(u))));
}

function render() {
  const q = state.search.toLowerCase();
  const users = state.users.filter((u) => !q || u.name.toLowerCase().includes(q) || (u.note || "").toLowerCase().includes(q));
  // Don't rebuild the table while a menu is open; the user is about to click something in it.
  if (document.querySelector(".menu-list:not([hidden]):not(#admin-menu)")) return;
  $("users").replaceChildren(...users.map(userRow));
  $("empty").hidden = state.users.length > 0;
}

function renderStatus() {
  const s = state.status;
  if (!s) return;
  const c = s.cert || {};
  const certPill = c.state === "ok"
    ? h("span", { class: "pill ok", title: c.notAfter ? `Certificate valid until ${new Date(c.notAfter).toLocaleDateString()}` : "" },
      h("i", { class: "dot" }), "Running")
    : c.state === "pending"
      ? h("span", { class: "pill warn", title: "Waiting for the TLS certificate" }, "Getting certificate…")
      : h("span", { class: "pill bad", title: c.error || "" }, "Certificate error");
  $("server-info").replaceChildren(
    certPill,
    h("span", { class: "mono" }, `${s.domain}:${s.port}`),
    h("span", {}, `${s.online} online · ${s.users} users`));
  const ranges = [...(s.homeRanges || []), ...(s.homeLocal || [])];
  $("footer").replaceChildren(
    h("div", {},
      `hysui ${s.version} · up ${fmtDuration(s.uptimeSec)} · TLS ${c.mode}`,
      c.notAfter ? ` · certificate until ${new Date(c.notAfter).toLocaleDateString()}` : ""),
    h("details", {},
      h("summary", {}, `What counts as "home network" (${ranges.length} ranges)`),
      h("ul", {}, ranges.map((r) => h("li", {}, r)))));
}

async function refresh() {
  try {
    state.users = await api("GET", "/api/users");
    render();
  } catch (e) {
    if (e.message !== "signed out") toast(e.message, true);
  }
}

async function refreshStatus() {
  try {
    state.status = await api("GET", "/api/status");
    renderStatus();
  } catch (_) { /* shown by refresh() */ }
}

// ---- actions ----

function genPassword(n = 24) {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const buf = new Uint32Array(n);
  crypto.getRandomValues(buf);
  return Array.from(buf, (x) => chars[x % chars.length]).join("");
}

function openEditor(u) {
  state.editing = u || null;
  $("user-title").textContent = u ? `Edit ${u.name}` : "Add user";
  $("f-name").value = u ? u.name : "";
  $("f-name").disabled = !!u;
  $("f-password").value = u ? u.password : "";
  $("f-password-hint").textContent = u
    ? "Changing it disconnects the user's devices; they need the new QR code."
    : "Leave empty to generate one.";
  $("f-down").value = u && u.downMbps ? u.downMbps : "";
  $("f-up").value = u && u.upMbps ? u.upMbps : "";
  $("f-quota").value = u && u.quotaBytes ? +(u.quotaBytes / 1e9).toFixed(3) : "";
  $("f-note").value = u ? u.note || "" : "";
  $("f-home").checked = u ? u.homeAccess : false;
  $("f-enabled").checked = u ? u.enabled : true;
  $("user-error").textContent = "";
  $("user-dialog").showModal();
  (u ? $("f-down") : $("f-name")).focus();
}

$("user-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const num = (id) => { const v = parseFloat($(id).value); return Number.isFinite(v) && v > 0 ? v : 0; };
  const body = {
    password: $("f-password").value.trim(),
    downMbps: num("f-down"),
    upMbps: num("f-up"),
    quotaBytes: Math.round(num("f-quota") * 1e9),
    note: $("f-note").value,
    homeAccess: $("f-home").checked,
    enabled: $("f-enabled").checked,
  };
  const editing = state.editing;
  try {
    let saved;
    if (editing) {
      saved = await api("PUT", `/api/users/${encodeURIComponent(editing.name)}`, body);
    } else {
      saved = await api("POST", "/api/users", { name: $("f-name").value.trim(), ...body });
    }
    $("user-dialog").close();
    toast(editing ? `${saved.name} saved` : `${saved.name} added`);
    await refresh();
    if (!editing) showQR(saved);
  } catch (e) {
    $("user-error").textContent = e.message;
  }
});

$("f-generate").addEventListener("click", () => ($("f-password").value = genPassword()));

async function showQR(u) {
  try {
    const link = await api("GET", `/api/users/${encodeURIComponent(u.name)}/link`);
    $("qr-title").textContent = `Connect ${u.name}`;
    $("qr-img").src = link.qr;
    $("qr-uri").textContent = link.uri;
    $("qr-dialog").showModal();
  } catch (e) {
    toast(e.message, true);
  }
}

$("qr-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("qr-uri").textContent);
    toast("Link copied");
  } catch (_) {
    const r = document.createRange();
    r.selectNodeContents($("qr-uri"));
    getSelection().removeAllRanges();
    getSelection().addRange(r);
    toast("Press Ctrl+C to copy");
  }
});

async function kick(u) {
  closeMenus();
  try {
    await api("POST", `/api/users/${encodeURIComponent(u.name)}/kick`);
    toast(`${u.name} disconnected; their app will reconnect`);
  } catch (e) { toast(e.message, true); }
  refresh();
}

async function resetUsage(u) {
  closeMenus();
  if (!(await confirmBox("Reset data usage?", `Set ${u.name}'s data counter back to 0.`, "Reset"))) return;
  try {
    await api("POST", `/api/users/${encodeURIComponent(u.name)}/reset-usage`);
    toast("Usage reset");
  } catch (e) { toast(e.message, true); }
  refresh();
}

async function removeUser(u) {
  closeMenus();
  if (!(await confirmBox(`Delete ${u.name}?`, "Their devices stop working immediately. This cannot be undone.", "Delete"))) return;
  try {
    await api("DELETE", `/api/users/${encodeURIComponent(u.name)}`);
    toast(`${u.name} deleted`);
  } catch (e) { toast(e.message, true); }
  refresh();
}

// ---- domains ----

const domainHints = {
  "acme-http": "Point its DNS at this server first; the certificate is requested right away. Let's Encrypt checks it on port 80, so if a reverse proxy owns port 80, forward this domain to hysui there too.",
  "acme-tls": "Point its DNS at this server first; the certificate is requested right away. Let's Encrypt checks it on TCP port 443.",
  "file": "Your certificate files must cover this domain too.",
  "self-signed": "Point its DNS at this server. Clients pin the certificate, so no new certificate is needed.",
};

let domainTimer;

function domainMsg(text, bad = false) {
  $("domain-msg").textContent = text;
  $("domain-msg").className = bad ? "msg bad" : "msg";
}

function domainCertPill(c) {
  if (c.state === "ok") {
    return h("span", { class: "pill ok" }, h("i", { class: "dot" }),
      c.notAfter ? `Certificate until ${new Date(c.notAfter).toLocaleDateString()}` : "Certificate OK");
  }
  if (c.state === "pending") return h("span", { class: "pill warn" }, "Getting certificate…");
  return h("span", { class: "pill bad" }, "Certificate error");
}

function domainRow(d) {
  const c = d.cert || {};
  return h("li", {},
    h("div", { class: "grow" },
      h("div", { class: "dname" }, d.name, d.active ? h("span", { class: "pill accent" }, "Active") : null),
      h("div", { class: "meta" },
        domainCertPill(c),
        d.dnsError
          ? h("span", { class: "bad-text" }, `DNS: ${d.dnsError}`)
          : h("span", {}, `DNS: ${d.addrs.join(", ")}`)),
      c.state === "error" && c.error ? h("div", { class: "derr", title: c.error }, c.error) : null),
    d.active ? null : h("div", { class: "actions" },
      h("button", { class: "btn", onclick: () => activateDomain(d) }, "Make active"),
      h("button", { class: "btn danger", onclick: () => removeDomain(d) }, "Remove")));
}

async function loadDomains() {
  try {
    state.domains = await api("GET", "/api/domains");
    $("domain-list").replaceChildren(...state.domains.domains.map(domainRow));
    $("d-hint").textContent = domainHints[state.domains.mode] || "";
  } catch (e) {
    if (e.message !== "signed out") domainMsg(e.message, true);
  }
}

$("domains-btn").addEventListener("click", () => {
  closeMenus();
  $("d-name").value = "";
  domainMsg("");
  $("domains-dialog").showModal();
  loadDomains();
  clearInterval(domainTimer);
  domainTimer = setInterval(() => { if (!document.hidden) loadDomains(); }, 4000); // certificate progress
});

$("domains-dialog").addEventListener("close", () => clearInterval(domainTimer));

$("domain-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const d = await api("POST", "/api/domains", { name: $("d-name").value.trim() });
    $("d-name").value = "";
    domainMsg(`${d.name} added.`);
  } catch (e) {
    domainMsg(e.message, true);
  }
  loadDomains();
});

async function activateDomain(d) {
  const old = state.domains ? state.domains.active : "the old domain";
  let text = `New QR codes and links will use ${d.name}. Devices set up with ${old} keep working while it stays in this list.`;
  if ((d.cert || {}).state !== "ok") text += " Its certificate isn't ready yet, so new links can't connect until it is.";
  if (d.dnsError) text += ` Its DNS lookup failed (${d.dnsError}).`;
  if (!(await confirmBox(`Make ${d.name} active?`, text, "Make active"))) return;
  try {
    await api("POST", `/api/domains/${encodeURIComponent(d.name)}/activate`);
    domainMsg(`${d.name} is active. Send new QR codes to users who should switch.`);
    refreshStatus();
  } catch (e) {
    domainMsg(e.message, true);
  }
  loadDomains();
}

async function removeDomain(d) {
  if (!(await confirmBox(`Remove ${d.name}?`, `Devices whose link still uses ${d.name} may stop connecting. Give them a new QR code first.`, "Remove"))) return;
  try {
    await api("DELETE", `/api/domains/${encodeURIComponent(d.name)}`);
    domainMsg(`${d.name} removed.`);
  } catch (e) {
    domainMsg(e.message, true);
  }
  loadDomains();
}

// ---- admin ----

$("admin-btn").addEventListener("click", (ev) => {
  ev.stopPropagation();
  const m = $("admin-menu");
  const open = m.hidden;
  closeMenus();
  m.hidden = !open;
  $("admin-btn").setAttribute("aria-expanded", String(open));
});

$("logout").addEventListener("click", async () => {
  await api("POST", "/api/logout").catch(() => {});
  location.href = "/login";
});

$("change-pw").addEventListener("click", () => {
  closeMenus();
  $("pw-user").value = state.status ? state.status.admin : "";
  $("pw-current").value = "";
  $("pw-new").value = "";
  $("pw-error").textContent = "";
  $("pw-dialog").showModal();
});

$("pw-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    await api("POST", "/api/admin/password", {
      username: $("pw-user").value.trim(),
      current: $("pw-current").value,
      new: $("pw-new").value,
    });
    $("pw-dialog").close();
    toast("Panel login changed");
    refreshStatus();
  } catch (e) {
    $("pw-error").textContent = e.message;
  }
});

// ---- wiring ----

document.addEventListener("click", closeMenus);
document.querySelectorAll("[data-close]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));
$("add-user").addEventListener("click", () => openEditor(null));
$("search").addEventListener("input", (ev) => { state.search = ev.target.value; render(); });

refresh();
refreshStatus();
setInterval(() => { if (!document.hidden) refresh(); }, 3000);
setInterval(() => { if (!document.hidden) refreshStatus(); }, 15000);
