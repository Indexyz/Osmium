"use strict";

const $ = (id) => document.getElementById(id);
let me = null;
let activeWS = null;
let activeSession = null;

async function api(path, opts = {}) {
  const headers = Object.assign({ "Accept": "application/json" }, opts.headers || {});
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (opts.method && opts.method !== "GET" && me) headers["X-CSRF-Token"] = me.csrf_token;
  const res = await fetch(path, { method: opts.method || "GET", headers, body: opts.body === undefined ? undefined : JSON.stringify(opts.body), credentials: "same-origin" });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) {
    const err = new Error((data && data.message) || res.statusText);
    err.status = res.status;
    err.code = data && data.code;
    throw err;
  }
  return data;
}

function show(id) {
  for (const s of ["login", "hosts", "term-view"]) $(s).hidden = s !== id;
}

async function init() {
  try {
    me = await api("/api/v1/me");
  } catch (e) {
    if (e.status === 401) { show("login"); return; }
    throw e;
  }
  $("who").textContent = (me.user.display_name || me.user.id) + (me.is_admin ? "（管理员）" : "");
  $("logout").hidden = false;
  show("hosts");
  await loadHosts();
}

function labelQuery() {
  const parts = $("filter").value.trim().split(/\s+/).filter(Boolean);
  return parts.map((p) => "label=" + encodeURIComponent(p)).join("&");
}

async function loadHosts() {
  const q = labelQuery();
  let data;
  try {
    data = await api("/api/v1/hosts" + (q ? "?" + q : ""));
  } catch (e) {
    alert("加载主机失败：" + e.message);
    return;
  }
  const tbody = $("host-rows");
  tbody.replaceChildren();
  $("hosts-empty").hidden = data.items.length > 0;
  for (const h of data.items) {
    const tr = document.createElement("tr");
    const name = document.createElement("td");
    name.textContent = h.display_name;
    name.title = h.id;
    const status = document.createElement("td");
    status.textContent = h.status;
    status.className = "status-" + h.status;
    const labels = document.createElement("td");
    for (const [k, v] of Object.entries(h.policy_labels)) {
      const span = document.createElement("span");
      span.className = "label";
      span.textContent = k + "=" + v;
      labels.append(span);
    }
    const loginTd = document.createElement("td");
    const sel = document.createElement("select");
    for (const l of h.allowed_login_users) {
      const o = document.createElement("option");
      o.value = l; o.textContent = l;
      sel.append(o);
    }
    loginTd.append(sel);
    const act = document.createElement("td");
    const btn = document.createElement("button");
    btn.textContent = "连接";
    btn.disabled = h.status !== "ready";
    btn.onclick = () => connect(h, sel.value);
    act.append(btn);
    tr.append(name, status, labels, loginTd, act);
    tbody.append(tr);
  }
}

let term = null;
let fit = null;

function ensureTerminal() {
  if (term) { term.reset(); return; }
  term = new Terminal({ cursorBlink: true, convertEol: false, fontFamily: "ui-monospace, monospace", fontSize: 14 });
  fit = new FitAddon.FitAddon();
  term.loadAddon(fit);
  term.open($("terminal"));
  const enc = new TextEncoder();
  term.onData((d) => {
    if (activeWS && activeWS.readyState === WebSocket.OPEN) activeWS.send(enc.encode(d));
  });
  term.onResize(({ rows, cols }) => {
    if (activeWS && activeWS.readyState === WebSocket.OPEN) {
      activeWS.send(JSON.stringify({ version: 1, type: "terminal.resize", payload: { rows, cols } }));
    }
  });
  window.addEventListener("resize", () => fit && fit.fit());
}

async function connect(host, login) {
  show("term-view");
  ensureTerminal();
  fit.fit();
  $("term-title").textContent = login + "@" + host.display_name;
  $("term-state").textContent = "创建会话…";
  $("term-close").hidden = false;
  $("term-back").hidden = true;
  let sess;
  try {
    sess = await api("/api/v1/ssh-sessions", {
      method: "POST",
      headers: { "Idempotency-Key": crypto.randomUUID() },
      body: { host_id: host.id, login_user: login, terminal: { rows: term.rows, cols: term.cols } },
    });
  } catch (e) {
    $("term-state").textContent = "失败：" + e.message;
    $("term-back").hidden = false;
    return;
  }
  activeSession = sess;
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(proto + "//" + location.host + sess.terminal_path, "web-ssh-terminal.v1");
  ws.binaryType = "arraybuffer";
  activeWS = ws;
  ws.onmessage = (ev) => {
    if (typeof ev.data === "string") {
      const msg = JSON.parse(ev.data);
      if (msg.type === "terminal.state") {
        $("term-state").textContent = msg.payload.state;
        if (msg.payload.state === "active") term.focus();
      } else if (msg.type === "terminal.exit") {
        const st = msg.payload.exit_status !== undefined ? "，退出码 " + msg.payload.exit_status : "";
        $("term-state").textContent = "已结束：" + msg.payload.reason + st;
      }
    } else {
      term.write(new Uint8Array(ev.data));
    }
  };
  ws.onclose = () => {
    activeWS = null;
    $("term-close").hidden = true;
    $("term-back").hidden = false;
  };
}

$("term-close").onclick = () => {
  if (activeWS && activeWS.readyState === WebSocket.OPEN) {
    activeWS.send(JSON.stringify({ version: 1, type: "terminal.close", payload: {} }));
  }
};
$("term-back").onclick = () => { show("hosts"); loadHosts(); };
$("refresh").onclick = loadHosts;
$("filter").addEventListener("keydown", (e) => { if (e.key === "Enter") loadHosts(); });
$("logout").onclick = async () => {
  try { await api("/auth/logout", { method: "POST" }); } catch (_) {}
  location.reload();
};

init();
