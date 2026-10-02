/* Identity Attack Graph — dataset-independent frontend. */

const KIND_COLOR = {
  identity: "#4fd1c5", credential: "#f59e0b", machine: "#60a5fa",
  service: "#a78bfa", permission: "#f472b6", asset: "#ef4444",
};

const REL_INFO = {
  MEMBER_OF: { label: "is a member of", privilege: "membership" },
  HAS_CREDENTIAL: { label: "has credential", privilege: "credential" },
  CREDENTIAL_FOR: { label: "authenticates as", privilege: "credential" },
  CAN_AUTH: { label: "can authenticate to", privilege: "logon" },
  ADMIN_OF: { label: "administers", privilege: "admin" },
  RUNS_ON: { label: "runs on", privilege: "execute" },
  RUNS_AS: { label: "runs as", privilege: "impersonate" },
  HAS_PERMISSION: { label: "has permission", privilege: "permission" },
  GRANTS_ACCESS: { label: "grants access to", privilege: "access" },
  CAN_ESCALATE: { label: "can escalate to", privilege: "escalate" },
  HOST_TO_SERVICE: { label: "can interact with", privilege: "execute" },
  HOST_TO_SESSION: { label: "can dump session of", privilege: "credential" },
  HOST_TO_ADMIN: { label: "can dump admin creds of", privilege: "admin" },
  HOST_TO_GROUP_ADMIN: { label: "can dump group-admin creds of", privilege: "credential" },
};

const PRIV_RANK = {
  membership: 1, permission: 2, access: 2, logon: 3, execute: 3,
  credential: 4, impersonate: 4, escalate: 5, admin: 5,
};

const state = {
  graph: null, source: null, targets: new Set(),
  excludedEdges: new Set(), simulation: null, optimal: null,
  scenariosMeta: [], plans: [], sourceLabel: "—", sourceIsDemo: false,
  pendingFile: null, showAllTargets: false, lastPaths: [],
  importOverrides: {}, previewData: null,
};

const svg = d3.select("#graph");
const width = () => svg.node().clientWidth;
const height = () => svg.node().clientHeight;

const defs = svg.append("defs");
["default", "attack", "highlight"].forEach(id => {
  defs.append("marker").attr("id", `arrow-${id}`)
    .attr("viewBox", "0 -5 10 10").attr("refX", 18).attr("refY", 0)
    .attr("markerWidth", 5).attr("markerHeight", 5).attr("orient", "auto")
    .append("path").attr("d", "M0,-5L10,0L0,5")
    .attr("fill", id === "highlight" ? "#4fd1c5" : id === "attack" ? "#b91c1c" : "#24344a");
});
const gLink = svg.append("g").attr("class", "links");
const gNode = svg.append("g").attr("class", "nodes");

function isDomain(n) {
  return (n.tags || []).includes("domain");
}
function isExternal(n) {
  return (n.tags || []).includes("external");
}
function nodeColor(n) {
  if (isDomain(n)) return isExternal(n) ? "#a855f7" : "#8b5cf6";
  return KIND_COLOR[n.kind] || "#888";
}
function edgeKey(s, t) { return `${s}->${t}`; }
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c =>
    ({ "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;" }[c]));
}

async function refreshActiveBadge() {
  const r = await fetch("/api/active");
  const a = await r.json();
  const chip = document.getElementById("source-chip");
  const name = document.getElementById("source-name");
  if (!a.active) { name.textContent = "—"; chip.classList.remove("demo"); return false; }
  state.sourceLabel = a.label || a.active;
  state.sourceIsDemo = /demo/i.test(state.sourceLabel);
  name.textContent = state.sourceLabel;
  chip.classList.toggle("demo", state.sourceIsDemo);
  return true;
}

function showStartup() {
  document.getElementById("startup").hidden = false;
  document.getElementById("import-modal").hidden = true;
}
function hideStartup() { document.getElementById("startup").hidden = true; }

async function loadDemo() {
  const btn = document.getElementById("choose-demo");
  const orig = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="tile-title">Loading&hellip;</span>
                   <span class="tile-sub">Waking the server (30&ndash;50s on free tier)</span>`;
  try {
    const r = await fetch("/api/demo/load", { method: "POST" });
    const data = await r.json();
    if (!data.ok) { alert("Failed to load demo: " + JSON.stringify(data.errors || data)); return; }
    hideStartup();
    await refreshActiveBadge();
    await loadScenarios();
    await loadActiveGraph();
  } finally {
    btn.disabled = false;
    btn.innerHTML = orig;
  }
}

async function loadScenarios() {
  const r = await fetch("/api/scenarios");
  state.scenariosMeta = await r.json();
}

function openImportModal() {
  document.getElementById("import-modal").hidden = false;
  document.getElementById("startup").hidden = true;
  document.getElementById("preview-panel").hidden = true;
  document.getElementById("import-preview").disabled = true;
  document.getElementById("import-commit").disabled = true;
  document.getElementById("import-file").value = "";
  document.getElementById("import-filename").textContent = "";
  document.getElementById("preview-table").innerHTML = "";
  document.getElementById("preview-warnings").innerHTML = "";
  document.getElementById("preview-errors").innerHTML = "";
  state.pendingFile = null;
  state.importOverrides = {};
  state.previewData = null;
}

function closeImportModal() {
  document.getElementById("import-modal").hidden = true;
  if (!state.graph) showStartup();
}

async function previewFile() {
  const file = state.pendingFile;
  if (!file) return;
  const btn = document.getElementById("import-preview");
  btn.disabled = true; btn.textContent = "Analysing…";
  try {
    const fd = new FormData();
    fd.append("file", file);
    const r = await fetch("/api/ingest/preview", { method: "POST", body: fd });
    const data = await r.json();
    renderPreview(data);
    document.getElementById("import-commit").disabled = !data.ok;
    btn.textContent = "Re-analyse";
  } finally { btn.disabled = false; }
}

function renderPreview(data) {
  state.previewData = data;
  const host = document.getElementById("preview-table");
  host.innerHTML = "";

  const s = data.stats || {};
  const summary = document.createElement("div");
  summary.className = "summary";
  summary.innerHTML = `
    <span class="num">${s.nodes ?? 0}</span> nodes ·
    <span class="num">${s.edges ?? 0}</span> edges ·
    <span class="${s.unresolved ? "bad" : "num"}">${s.unresolved ?? 0}</span> unresolved<br>
    identities ${s.identity ?? 0} · groups ${s.group ?? 0} ·
    machines ${s.machine ?? 0} · credentials ${s.credential ?? 0} ·
    services ${s.service ?? 0} · assets ${s.asset ?? 0}`;
  host.appendChild(summary);

  const NODE_TYPES = ["IDENTITY", "GROUP", "MACHINE", "SERVICE",
                      "CREDENTIAL", "ASSET", "PERMISSION", "ROLE",
                      "APPLICATION", "NETWORK"];
  const REL_TYPES = ["MEMBER_OF", "HAS_CREDENTIAL", "USES", "CAN_ACCESS",
                     "CAN_LOGIN", "RUNS", "HOSTS", "HAS_ROLE", "CAN_ADMIN",
                     "CAN_EXECUTE", "TRUSTS", "CONNECTS_TO", "OWNS",
                     "CONTAINS", "DEPENDS_ON"];
  const COL_ROLES = ["id", "name", "type", "criticality",
                     "source", "target", "privilege", "rel_type", "metadata"];

  for (const m of (data.mappings || [])) {
    const prof = (data.profiles || []).find(p => p.source === m.source) || {};
    const ov = state.importOverrides[m.source] || {};
    const card = document.createElement("div");
    card.className = "profile";

    const conf = m.confidence ?? 0;
    const cls = conf >= 0.75 ? "high" : conf >= 0.5 ? "med" : "low";
    const kind = ov.kind || m.kind;

    const kindSel = document.createElement("select");
    kindSel.className = "inline-select";
    for (const k of ["entity", "relationship", "unknown"]) {
      const o = document.createElement("option");
      o.value = k; o.textContent = k;
      if (kind === k) o.selected = true;
      kindSel.appendChild(o);
    }

    const typeSel = document.createElement("select");
    typeSel.className = "inline-select";
    const types = kind === "entity" ? NODE_TYPES : REL_TYPES;
    const current = kind === "entity"
      ? (ov.entity_type ?? m.entity_type)
      : (ov.relationship_type ?? m.relationship_type);
    for (const t of types) {
      const o = document.createElement("option");
      o.value = t; o.textContent = t;
      if (current === t) o.selected = true;
      typeSel.appendChild(o);
    }

    const head = document.createElement("div");
    head.className = "profile-head";
    head.innerHTML = `<span class="profile-name">${escapeHtml(m.source)}</span>`;
    const badge = document.createElement("span");
    badge.className = `conf ${cls}`;
    badge.textContent = Math.round(conf * 100) + "%";
    head.appendChild(badge);
    head.appendChild(kindSel);
    head.appendChild(typeSel);
    card.appendChild(head);

    const meta = document.createElement("div");
    meta.className = "profile-meta";
    meta.textContent = `${prof.rows ?? 0} rows · shape: ${prof.shape || "?"}`;
    card.appendChild(meta);

    const colRows = document.createElement("div");
    colRows.className = "col-map-editable";
    for (const c of (prof.columns || [])) {
      const roleRaw = (ov.column_map || {})[c.name]
                     || (m.column_map || {})[c.name]
                     || "metadata";
      const isMeta = roleRaw.startsWith("metadata:");
      const role = isMeta ? "metadata" : roleRaw;

      const s1 = document.createElement("div");
      s1.className = "src"; s1.textContent = c.name;
      const s2 = document.createElement("div");
      s2.className = "arr"; s2.textContent = "→";
      const s3 = document.createElement("div");
      s3.className = "dst";
      const sel = document.createElement("select");
      sel.className = "inline-select role-select";
      sel.dataset.source = m.source;
      sel.dataset.column = c.name;
      for (const r of COL_ROLES) {
        const o = document.createElement("option");
        o.value = r; o.textContent = r;
        if (role === r) o.selected = true;
        sel.appendChild(o);
      }
      s3.appendChild(sel);
      colRows.appendChild(s1);
      colRows.appendChild(s2);
      colRows.appendChild(s3);
    }
    card.appendChild(colRows);

    kindSel.addEventListener("change", () => {
      state.importOverrides[m.source] = {
        ...(state.importOverrides[m.source] || {}), kind: kindSel.value,
      };
      renderPreview(data);
    });
    typeSel.addEventListener("change", () => {
      const key = kind === "entity" ? "entity_type" : "relationship_type";
      state.importOverrides[m.source] = {
        ...(state.importOverrides[m.source] || {}), [key]: typeSel.value,
      };
    });
    for (const sel of colRows.querySelectorAll(".role-select")) {
      sel.addEventListener("change", () => {
        const src = sel.dataset.source;
        const col = sel.dataset.column;
        const r = sel.value;
        const existing = state.importOverrides[src] || {};
        const cmap = { ...(existing.column_map || {}) };
        cmap[col] = r === "metadata" ? `metadata:${col}` : r;
        state.importOverrides[src] = { ...existing, column_map: cmap };
      });
    }
    host.appendChild(card);
  }

  const warn = document.getElementById("preview-warnings");
  warn.innerHTML = "";
  const warns = data.warnings || [];
  if (warns.length) {
    warn.innerHTML = `<div class="block-title">Warnings (${warns.length})</div>` +
      warns.map(w => {
        const msg = typeof w === "string" ? w : (w.message || JSON.stringify(w));
        return `<div class="warn-item">${escapeHtml(msg)}</div>`;
      }).join("");
  }
  const err = document.getElementById("preview-errors");
  err.innerHTML = "";
  const errs = data.errors || [];
  if (errs.length) {
    err.innerHTML = `<div class="block-title">Errors (${errs.length})</div>` +
      errs.map(e => {
        const msg = typeof e === "string" ? e : (e.message || JSON.stringify(e));
        return `<div class="err-item">${escapeHtml(msg)}</div>`;
      }).join("");
  }
  document.getElementById("preview-panel").hidden = false;
}

async function commitFile() {
  const file = state.pendingFile;
  if (!file) return;
  const fd = new FormData();
  fd.append("file", file);
  fd.append("overrides", JSON.stringify(state.importOverrides || {}));
  const r = await fetch("/api/ingest/commit", { method: "POST", body: fd });
  const data = await r.json();
  if (!data.ok) { alert("Import failed: " + JSON.stringify(data.errors)); return; }
  document.getElementById("import-modal").hidden = true;
  await refreshActiveBadge();
  await loadScenarios();
  await loadActiveGraph();
}

async function loadActiveGraph() {
  const r = await fetch("/api/graph");
  if (!r.ok) { alert("No active environment: " + (await r.text())); return; }
  state.graph = await r.json();
  state.source = null;
  state.excludedEdges = new Set();
  state.optimal = null;
  state.lastPaths = [];
  state.targets = new Set(
    state.graph.nodes.filter(n => {
      if (n.kind === "asset" && n.criticality >= 5) return true;
      if (n.kind === "machine" && n.criticality >= 5) return true;
      // Domain nodes are targets by default only when there's more than one
      // (single-domain environments don't benefit from domain-targeted paths).
      const domainCount = state.graph.nodes.filter(x => (x.tags || []).includes("domain")).length;
      if ((n.tags || []).includes("domain") && domainCount > 1) return true;
      return false;
    }).map(n => n.id)
  );
  render();
  renderStats();
  renderTargets();
  updateButtons();
  document.getElementById("mitigation-section").hidden = true;
  document.getElementById("optimal-section").hidden = true;
  const info = document.getElementById("source-info");
  info.textContent = "Click a node to mark it compromised";
  info.classList.add("muted");
  document.getElementById("paths").innerHTML = "";
  document.getElementById("chokes").innerHTML = "";
  const _ds = document.getElementById("diff-section"); if (_ds) _ds.hidden = true;
  await refreshPlans();
}

function render() {
  const links = state.graph.attacker_edges.map(d => ({ ...d }));
  const nodes = state.graph.nodes.map(d => ({ ...d }));
  gLink.selectAll("*").remove();
  gNode.selectAll("*").remove();

  const link = gLink.selectAll("line").data(links).enter().append("line")
    .attr("class", d => `link ${d.kind.startsWith("HOST_TO_") ? "attack" : ""}`)
    .attr("marker-end", d => `url(#arrow-${d.kind.startsWith("HOST_TO_") ? "attack" : "default"})`)
    .attr("stroke-width", d => Math.max(0.5, 2.2 - d.weight));

  const node = gNode.selectAll("g.node").data(nodes, d => d.id).enter().append("g")
    .attr("class", "node")
    .call(d3.drag()
      .on("start", (e, d) => { if (!e.active) state.simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (e, d) => { d.fx = e.x; d.fy = e.y; })
      .on("end", (e, d) => { if (!e.active) state.simulation.alphaTarget(0); d.fx = null; d.fy = null; })
    )
    .on("click", (e, d) => {
      if (e.shiftKey) {
        state.targets.has(d.id) ? state.targets.delete(d.id) : state.targets.add(d.id);
        renderTargets();
      } else { state.source = d.id; }
      updateButtons();
      paintSelection();
      renderSourceInfo();
    });

  node.append("circle")
    .attr("r", d => isDomain(d) ? 12 : 6 + d.criticality * 1.8)
    .attr("fill", d => nodeColor(d))
    .attr("stroke", d => isDomain(d) ? "#e9d5ff" : "#0b1017")
    .attr("stroke-width", d => isDomain(d) ? 2 : 1.5);

  node.append("text").attr("class", "node-label")
    .attr("x", 12).attr("y", 3)
    .text(d => d.name.length > 22 ? d.name.slice(0, 20) + "…" : d.name);

  state.simulation = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id(d => d.id).distance(60).strength(0.35))
    .force("charge", d3.forceManyBody().strength(-180))
    .force("center", d3.forceCenter(width() / 2, height() / 2))
    .force("collide", d3.forceCollide(20))
    .on("tick", () => {
      link.attr("x1", d => d.source.x).attr("y1", d => d.source.y)
          .attr("x2", d => d.target.x).attr("y2", d => d.target.y);
      node.attr("transform", d => `translate(${d.x},${d.y})`);
    });

  paintSelection();
  paintExclusions();
  bindEdgeProvenance();
}

function renderStats() {
  const c = { identity: 0, credential: 0, machine: 0, service: 0, permission: 0, asset: 0 };
  let groups = 0;
  for (const n of state.graph.nodes) {
    if (n.kind === "identity" && (n.tags || []).includes("group")) { groups++; continue; }
    if (c[n.kind] !== undefined) c[n.kind]++;
  }
  const declared = state.graph.edges.length;
  const attacker = state.graph.attacker_edges.length;
  const set = (id, v) => document.getElementById(id).textContent = v;
  set("stat-identities", c.identity);
  set("stat-groups", groups);
  set("stat-credentials", c.credential);
  set("stat-machines", c.machine);
  set("stat-services", c.service);
  set("stat-permissions", c.permission);
  set("stat-assets", c.asset);
  set("stat-relations", attacker + " (" + declared + " declared)");
}

function paintSelection() {
  gNode.selectAll("circle")
    .attr("stroke", d =>
      d.id === state.source ? "#ef4444" :
      state.targets.has(d.id) ? "#f59e0b" : "#0b1017")
    .attr("stroke-width", d =>
      d.id === state.source || state.targets.has(d.id) ? 3 : 1.5);
}

function paintExclusions() {
  gLink.selectAll("line").classed("excluded", d => {
    const s = d.source.id || d.source;
    const t = d.target.id || d.target;
    return state.excludedEdges.has(edgeKey(s, t));
  });
}

async function renderSourceInfo() {
  const el = document.getElementById("source-info");
  if (!state.source) {
    el.textContent = "Click a node to mark it compromised";
    el.classList.add("muted"); return;
  }
  const n = state.graph.nodes.find(x => x.id === state.source);
  el.classList.remove("muted");
  el.innerHTML = `<strong>${escapeHtml(n.name)}</strong><br>` +
    `<span class="meta">${n.kind} · criticality ${n.criticality}</span>` +
    `<div class="blast-block" id="blast-block">` +
    `<div class="blast-title">Computing blast radius…</div></div>`;
  try {
    const r = await fetch(`/api/blast-radius/${state.source}`);
    renderBlastRadius(await r.json());
  } catch (e) {
    document.getElementById("blast-block").innerHTML =
      `<div class="blast-title" style="color:#ef4444">Blast radius unavailable</div>`;
  }
}

function renderBlastRadius(data) {
  const byKind = { identity: 0, credential: 0, machine: 0, service: 0, permission: 0, asset: 0 };
  const jewels = [];
  for (const item of data.reachable) {
    byKind[item.kind] = (byKind[item.kind] || 0) + 1;
    if (item.kind === "asset" && item.criticality >= 4) jewels.push(item);
  }
  const block = document.getElementById("blast-block");
  if (!block) return;
  let html = `<div class="blast-title">Blast radius</div>`;
  html += `<div class="blast-row"><span>Reachable nodes</span><span class="num">${data.count}</span></div>`;
  if (byKind.identity)   html += `<div class="blast-row"><span>Identities</span><span class="num">${byKind.identity}</span></div>`;
  if (byKind.machine)    html += `<div class="blast-row"><span>Machines</span><span class="num">${byKind.machine}</span></div>`;
  if (byKind.credential) html += `<div class="blast-row"><span>Credentials</span><span class="num">${byKind.credential}</span></div>`;
  html += `<div class="blast-row jewels"><span>Crown jewels</span><span class="num">${jewels.length}</span></div>`;
  if (jewels.length) {
    html += `<div class="blast-jewels">`;
    for (const j of jewels.slice(0, 6))
      html += `<span class="j">• ${escapeHtml(j.name)} (${j.hops}h)</span>`;
    html += `</div>`;
  }
  block.innerHTML = html;
}

function renderTargets() {
  const ul = document.getElementById("targets");
  ul.innerHTML = "";
  // Crown jewels = assets + high-crit machines + domain nodes.
  // Anything that could be the goal of an attacker.
  const isCrownCandidate = (n) => {
    if (n.kind === "asset") return true;
    if (n.kind === "machine" && n.criticality >= 5) return true;
    if ((n.tags || []).includes("domain")) return true;
    return false;
  };
  let jewels = state.graph.nodes.filter(isCrownCandidate);
  if (!state.showAllTargets) jewels = jewels.filter(j => j.criticality >= 4);
  jewels.sort((a, b) => b.criticality - a.criticality);

  const toolbar = document.createElement("div");
  toolbar.className = "targets-toolbar";
  toolbar.innerHTML = `
    <label><input type="checkbox" id="show-all-targets" ${state.showAllTargets ? "checked" : ""}>
    Show all assets</label>
    <span>${state.targets.size} selected</span>`;
  ul.appendChild(toolbar);
  toolbar.querySelector("#show-all-targets").onchange = (e) => {
    state.showAllTargets = e.target.checked; renderTargets();
  };

  for (const j of jewels) {
    const li = document.createElement("li");
    li.className = state.targets.has(j.id) ? "target" : "";
    li.innerHTML = `${escapeHtml(j.name)} <span class="meta">crit ${j.criticality}</span>`;
    li.onclick = () => {
      state.targets.has(j.id) ? state.targets.delete(j.id) : state.targets.add(j.id);
      renderTargets(); paintSelection(); updateButtons();
    };
    ul.appendChild(li);
  }
  document.getElementById("target-count").textContent = state.targets.size;
}

function updateButtons() {
  const ok = !!state.source && state.targets.size > 0;
  document.getElementById("analyse").disabled = !ok;
  document.getElementById("optimal").disabled = !ok;
  document.getElementById("reset").disabled = state.excludedEdges.size === 0;
}

async function analyse() {
  const exclusions = [...state.excludedEdges].map(k => {
    const [s, t] = k.split("->"); return { source: s, target: t };
  });
  const body = { source: state.source, targets: [...state.targets],
                 excluded_edges: exclusions, max_paths: 8 };
  const r = await fetch("/api/mitigate", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await r.json();
  state.lastPaths = data.after.paths;
  renderPaths(data.after.paths, data.after.strategies);
  renderMitigationBanner(data);
  const q = new URLSearchParams({
    source: state.source, targets: [...state.targets].join(","),
  });
  const r2 = await fetch(`/api/choke-points?${q}`);
  renderChokes(await r2.json());
  paintExclusions(); updateButtons();
}

async function findOptimal() {
  const exclusions = [...state.excludedEdges].map(k => {
    const [s, t] = k.split("->"); return { source: s, target: t };
  });
  const body = { source: state.source, targets: [...state.targets],
                 excluded_edges: exclusions };
  const r = await fetch("/api/min-cut", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) { alert("Min-cut failed: " + (await r.text())); return; }
  state.optimal = await r.json();
  renderOptimal(state.optimal);
}

function privilegeForPath(p) {
  let max = 0, label = "none";
  for (const s of p.steps) {
    const info = REL_INFO[s.kind] || { privilege: "access" };
    const r = PRIV_RANK[info.privilege] || 0;
    if (r > max) { max = r; label = info.privilege; }
  }
  return label;
}
function techniquesForPath(p) {
  const set = new Set();
  for (const s of p.steps) if (s.technique) set.add(s.technique);
  return [...set];
}
function severityForPath(p) {
  const priv = privilegeForPath(p);
  const rank = PRIV_RANK[priv] || 0;
  if (p.hops <= 4 && rank >= 4) return { level: "trivial", label: "TRIVIAL" };
  if (p.hops <= 4) return { level: "easy", label: "EASY" };
  if (p.hops <= 7 && rank >= 4) return { level: "easy", label: "EASY" };
  if (p.hops <= 8) return { level: "moderate", label: "MODERATE" };
  return { level: "hard", label: "HARD" };
}

function renderPaths(paths, strategies) {
  // If strategies were provided by the backend, render the grouped view.
  // Otherwise fall back to the flat list.
  const ol = document.getElementById("paths");
  ol.innerHTML = "";

  if (!paths.length) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No reachable paths under current cuts.";
    ol.appendChild(li);
    return;
  }

  if (!strategies || !strategies.length) {
    strategies = [{ representative: paths[0], variants: paths, variant_count: paths.length }];
  }

  const header = document.createElement("div");
  header.className = "paths-header";
  header.innerHTML = `<span class="paths-count">
    <strong>${strategies.length}</strong> strateg${strategies.length === 1 ? "y" : "ies"}
    · <span class="muted">${paths.length} total path${paths.length === 1 ? "" : "s"}</span>
  </span>`;
  ol.appendChild(header);

  strategies.forEach((grp, gi) => {
    const p = grp.representative || grp;
    const target = state.graph.nodes.find(n => n.id === p.target);
    const priv = privilegeForPath(p);
    const techs = techniquesForPath(p);
    const sev = severityForPath(p);
    const crossed = p.steps.some(s => s.kind === "CAN_ESCALATE" || s.kind === "HOST_TO_ADMIN");
    const crossesTrust = p.steps.some(s => {
      const src = state.graph.nodes.find(n => n.id === s.source);
      const dst = state.graph.nodes.find(n => n.id === s.target);
      return isDomain(src) || isDomain(dst);
    });

    const chainLines = p.steps.map(s => {
      const src = state.graph.nodes.find(n => n.id === s.source);
      const dst = state.graph.nodes.find(n => n.id === s.target);
      const info = REL_INFO[s.kind] || { label: s.kind.toLowerCase() };
      return `<div class="step-line">` +
        `<span class="node">${escapeHtml(src ? src.name : s.source)}</span>` +
        `<span class="rel">—${escapeHtml(info.label)}→</span>` +
        `<span class="node">${escapeHtml(dst ? dst.name : s.target)}</span>` +
        (s.technique ? `<span class="tech">[${escapeHtml(s.technique)}]</span>` : "") +
        `</div>`;
    }).join("");

    const landmarkLine = (grp.landmark_names && grp.landmark_names.length)
      ? grp.landmark_names.map(n => `<span class="landmark">${escapeHtml(n)}</span>`).join(" → ")
      : "";

    const variantLine = grp.variant_count > 1
      ? `<div class="variant-line" data-gi="${gi}">
           + ${grp.variant_count - 1} alternate route${grp.variant_count === 2 ? "" : "s"}
           (cost ${grp.best_cost.toFixed(1)} – ${grp.worst_cost.toFixed(1)})
           <button class="expand-btn" data-gi="${gi}">show</button>
         </div>`
      : "";

    const variantsHtml = grp.variant_count > 1 ? `
      <div class="variants" id="variants-${gi}" hidden>
        ${grp.variants.slice(1, 12).map((v, vi) => {
          const vChain = v.steps.map(s => {
            const a = state.graph.nodes.find(n => n.id === s.source);
            const b = state.graph.nodes.find(n => n.id === s.target);
            const info = REL_INFO[s.kind] || { label: s.kind.toLowerCase() };
            return `<div class="step-line">` +
              `<span class="node">${escapeHtml(a ? a.name : s.source)}</span>` +
              `<span class="rel">—${escapeHtml(info.label)}→</span>` +
              `<span class="node">${escapeHtml(b ? b.name : s.target)}</span>` +
              (s.technique ? `<span class="tech">[${escapeHtml(s.technique)}]</span>` : "") +
              `</div>`;
          }).join("");
          return `<div class="variant">
            <div class="variant-head">Variant ${vi + 2} · cost ${v.cost} · ${v.hops} hops</div>
            ${vChain}
          </div>`;
        }).join("")}
      </div>` : "";

    const div = document.createElement("div");
    div.className = "path-card strategy-card";
    div.innerHTML = `
      <div class="head-row">
        <div class="title"><span class="sev sev-${sev.level}">${sev.label}</span>
          Strategy ${gi + 1} → ${escapeHtml(target ? target.name : p.target)}</div>
        <button class="copy-btn" title="Copy this strategy as a report">copy</button>
      </div>
      ${landmarkLine ? `<div class="landmarks"><span class="k">Key hops:</span> ${landmarkLine}</div>` : ""}
      <div class="attrs">
        <span class="k">Best path</span><span class="v">${p.hops} hops · cost ${p.cost}</span>
        <span class="k">Required privilege</span><span class="v">${escapeHtml(priv)}</span>
        <span class="k">Techniques</span><span class="v">${techs.length ? escapeHtml(techs.join(", ")) : "—"}</span>
        ${crossesTrust ? `<span class="k">Crosses trust</span><span class="v" style="color:#a855f7">YES — external domain</span>` : ""}
      </div>
      ${variantLine}
      <div class="why"><div class="block-title">Why this path exists (best variant)</div>${chainLines}</div>
      ${variantsHtml}`;

    div.addEventListener("click", (e) => {
      if (e.target.classList.contains("copy-btn")) return;
      if (e.target.classList.contains("expand-btn")) return;
      div.classList.toggle("open");
      highlightPath(p);
    });
    div.querySelector(".copy-btn").addEventListener("click", (e) => {
      e.stopPropagation();
      copyPath(p, div.querySelector(".copy-btn"));
    });
    const expandBtn = div.querySelector(".expand-btn");
    if (expandBtn) {
      expandBtn.addEventListener("click", (e) => {
        e.stopPropagation();
        const vid = `variants-${expandBtn.dataset.gi}`;
        const el = document.getElementById(vid);
        if (el) {
          el.hidden = !el.hidden;
          expandBtn.textContent = el.hidden ? "show" : "hide";
        }
      });
    }
    ol.appendChild(div);
  });
}

function copyPath(p, btn) {
  const src = state.graph.nodes.find(n => n.id === p.source);
  const tgt = state.graph.nodes.find(n => n.id === p.target);
  const sev = severityForPath(p);
  const priv = privilegeForPath(p);
  const techs = techniquesForPath(p);
  const lines = [];
  lines.push(`Potential attack path: ${src ? src.name : p.source} → ${tgt ? tgt.name : p.target}`);
  lines.push(`Severity: ${sev.label}`);
  lines.push(`Hops: ${p.hops}`);
  lines.push(`Required privilege: ${priv}`);
  lines.push(`Techniques: ${techs.length ? techs.join(", ") : "none recorded"}`);
  lines.push("");
  lines.push("Chain:");
  for (const s of p.steps) {
    const a = state.graph.nodes.find(n => n.id === s.source);
    const b = state.graph.nodes.find(n => n.id === s.target);
    const info = REL_INFO[s.kind] || { label: s.kind.toLowerCase() };
    lines.push(`  ${a ? a.name : s.source} --[${s.kind}: ${info.label}]--> ${b ? b.name : s.target}${s.technique ? " [" + s.technique + "]" : ""}`);
  }
  lines.push("");
  lines.push(`Source data: ${state.sourceLabel}`);
  lines.push(`Generated: ${new Date().toISOString()}`);
  const text = lines.join("\n");
  const copy = () => {
    const orig = btn.textContent;
    btn.textContent = "copied"; btn.classList.add("done");
    setTimeout(() => { btn.textContent = orig; btn.classList.remove("done"); }, 1500);
  };
  if (navigator.clipboard && window.isSecureContext !== false) {
    navigator.clipboard.writeText(text).then(copy).catch(() => fallbackCopy(text, copy));
  } else { fallbackCopy(text, copy); }
}
function fallbackCopy(text, done) {
  const ta = document.createElement("textarea");
  ta.value = text; document.body.appendChild(ta); ta.select();
  try { document.execCommand("copy"); done(); } catch (e) { alert("Copy failed"); }
  document.body.removeChild(ta);
}

function highlightPath(p) {
  const edgeSet = new Set(p.steps.map(s => edgeKey(s.source, s.target)));
  gLink.selectAll("line").classed("highlight", d => {
    const k = edgeKey(d.source.id || d.source, d.target.id || d.target);
    return edgeSet.has(k) && !state.excludedEdges.has(k);
  });
}

function renderMitigationBanner(data) {
  const section = document.getElementById("mitigation-section");
  const el = document.getElementById("mitigation-banner");
  if (data.excluded_edge_count === 0) { section.hidden = true; return; }
  section.hidden = false;
  const removed = data.removed_path_count;
  const verdict = removed > 0
    ? `<span class="good">${removed} path${removed === 1 ? "" : "s"} eliminated</span>`
    : `<span class="bad">No paths eliminated</span>`;
  el.innerHTML = `
    <div>${verdict} by cutting <strong>${data.excluded_edge_count}</strong> edge${data.excluded_edge_count === 1 ? "" : "s"}.</div>
    <div class="row"><span>Paths</span><span><span class="bad">${data.before.count}</span> &rarr; <span class="good">${data.after.count}</span></span></div>`;
}

function renderChokes(chokes) {
  const ol = document.getElementById("chokes");
  ol.innerHTML = "";
  if (!chokes.length) { ol.innerHTML = '<li class="muted">No choke points</li>'; return; }
  for (const c of chokes.slice(0, 8)) {
    const li = document.createElement("li");
    li.innerHTML = `${escapeHtml(c.name)} <span class="meta">breaks ${c.breaks_targets.length} target(s)</span>`;
    ol.appendChild(li);
  }
}

function renderOptimal(data) {
  const section = document.getElementById("optimal-section");
  section.hidden = false;
  document.getElementById("optimal-banner").innerHTML = `
    <div>Total fix cost: <span class="cost">${data.total_cost}</span></div>
    <div>Mitigations: ${data.mitigations.length} (${data.nodes_cut.length} node, ${data.edges_cut.length} edge)</div>
    <div>Paths: <span class="partial">${data.before.count}</span> &rarr; <span class="severed">${data.after.count}</span></div>
    <div>${data.severed ? '<span class="severed">All paths severed ✓</span>' : '<span class="partial">Partial cut</span>'}</div>`;
  const list = document.getElementById("optimal-list");
  list.innerHTML = "";
  for (const m of [...data.edges_cut, ...data.nodes_cut]) {
    const div = document.createElement("div");
    div.className = "mit-item";
    if (m.type === "edge") {
      div.innerHTML = `<div class="label"><span class="kind-tag">CUT EDGE</span>${escapeHtml(m.edge_kind)}
        <span class="detail">${escapeHtml(m.source_name)} &rarr; ${escapeHtml(m.target_name)}</span></div>
        <div class="cost-badge">${m.cost}</div>`;
      div.onclick = () => {
        state.excludedEdges.add(edgeKey(m.source, m.target));
        paintExclusions(); updateButtons(); analyse();
      };
    } else {
      div.innerHTML = `<div class="label"><span class="kind-tag">DISABLE</span>${escapeHtml(m.kind)}
        <span class="detail">${escapeHtml(m.name)}</span></div>
        <div class="cost-badge">${m.cost}</div>`;
      div.onclick = () => {
        for (const ae of state.graph.attacker_edges)
          if (ae.source === m.id || ae.target === m.id)
            state.excludedEdges.add(edgeKey(ae.source, ae.target));
        paintExclusions(); updateButtons(); analyse();
      };
    }
    list.appendChild(div);
  }
}

async function refreshPlans() {
  const r = await fetch("/api/active");
  const a = await r.json();
  if (!a.active) { state.plans = []; renderPlans(); return; }
  const r2 = await fetch(`/api/plans?scenario=${encodeURIComponent(a.active)}`);
  state.plans = await r2.json();
  renderPlans();
}
function renderPlans() {
  const list = document.getElementById("plans-list");
  list.innerHTML = "";
  document.getElementById("plans-count").textContent = state.plans.length;
  if (!state.plans.length) {
    list.innerHTML = '<div class="empty">No saved plans for this scenario.</div>'; return;
  }
  for (const p of state.plans) {
    const div = document.createElement("div");
    div.className = "plan-item";
    const when = new Date(p.created_at).toLocaleString();
    const srcNode = state.graph.nodes.find(n => n.id === p.source);
    const srcName = srcNode ? srcNode.name : p.source;
    div.innerHTML = `<div class="head">
        <span class="name">${p.excluded_edges.length} cuts → ${p.targets.length} target(s)</span>
        <span class="when">${when}</span></div>
      <div class="detail">source: ${escapeHtml(srcName)} · cost ${p.total_cost ?? 0}</div>
      <div class="actions"><button class="apply-btn">Apply</button>
        <button class="delete-btn">Delete</button></div>`;
    div.querySelector(".apply-btn").onclick = (e) => {
      e.stopPropagation();
      for (const k of p.excluded_edges) state.excludedEdges.add(k);
      state.source = p.source;
      state.targets = new Set(p.targets);
      renderTargets(); paintSelection(); renderSourceInfo(); updateButtons();
      analyse();
    };
    div.querySelector(".delete-btn").onclick = async (e) => {
      e.stopPropagation();
      if (!confirm("Delete this plan?")) return;
      await fetch(`/api/plans/${p.id}`, { method: "DELETE" });
      await refreshPlans();
    };
    list.appendChild(div);
  }
}
async function saveCurrentPlan() {
  if (!state.source) { alert("Select a source first."); return; }
  if (!state.excludedEdges.size) { alert("No cuts to save yet."); return; }
  const r = await fetch("/api/active");
  const a = await r.json();
  if (!a.active) { alert("No active scenario."); return; }
  const notes = prompt("Notes for this plan (optional):", "") || "";
  const body = { scenario: a.active, source: state.source, targets: [...state.targets],
                 excluded_edges: [...state.excludedEdges],
                 total_cost: state.optimal ? state.optimal.total_cost : 0, notes };
  const r2 = await fetch("/api/plans", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r2.ok) { alert("Save failed: " + (await r2.text())); return; }
  await refreshPlans();
}

function lookupNode(id) {
  return state.graph ? state.graph.nodes.find(n => n.id === id) : null;
}
function showProvenance(edgeInfo) {
  const box = document.getElementById("provenance");
  const body = document.getElementById("prov-body");
  const src = lookupNode(edgeInfo.source);
  const dst = lookupNode(edgeInfo.target);
  const srcAttrs = (src && src.attributes) || {};
  const dstAttrs = (dst && dst.attributes) || {};
  const row = (k, v) => `<div class="prov-row"><span class="k">${escapeHtml(k)}</span><span class="v">${escapeHtml(String(v))}</span></div>`;
  const lines = [];
  lines.push(row("Edge", `${edgeInfo.source} → ${edgeInfo.target}`));
  lines.push(row("Kind", edgeInfo.kind));
  if (edgeInfo.technique) lines.push(row("Technique", edgeInfo.technique));
  lines.push(row("Weight", edgeInfo.weight));
  lines.push(row("Origin", edgeInfo.origin || srcAttrs.origin || "OBSERVED"));
  if (srcAttrs.source) lines.push(row("Source file", srcAttrs.source));
  if (srcAttrs.row !== undefined) lines.push(row("Source row", String(srcAttrs.row)));
  if (dstAttrs.source) lines.push(row("Target file", dstAttrs.source));
  if (dstAttrs.row !== undefined) lines.push(row("Target row", String(dstAttrs.row)));
  body.innerHTML = lines.join("") +
    `<div class="prov-note">This relationship exists because the imported data contains an explicit reference between these nodes. Nothing is fabricated.</div>`;
  box.hidden = false;
}
function bindEdgeProvenance() {
  gLink.selectAll("line").on("click", (ev, d) => {
    ev.stopPropagation(); showProvenance(d);
  });
}

async function exportReport() {
  if (!state.source) { alert("Select a compromised identity first."); return; }
  if (state.targets.size === 0) { alert("Select at least one crown jewel."); return; }
  const btn = document.getElementById("export-report");
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = "Generating…";
  try {
    const exclusions = [...state.excludedEdges].map(k => {
      const [s, t] = k.split("->"); return { source: s, target: t };
    });
    const body = { source: state.source, targets: [...state.targets],
                   excluded_edges: exclusions, include_optimal: true };
    const r = await fetch("/api/report", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) { alert("Report failed: " + (await r.text())); return; }
    const md = await r.text();
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
    const label = (state.sourceLabel || "report").replace(/[^a-z0-9]+/gi, "_").slice(0, 40);
    a.download = `iag-report-${label}-${ts}.md`;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
    btn.textContent = "Downloaded ✓";
    setTimeout(() => { btn.textContent = orig; }, 1500);
  } finally { btn.disabled = false; }
}

document.getElementById("choose-demo").onclick = loadDemo;
document.getElementById("choose-import").onclick = openImportModal;
document.getElementById("change-source").onclick = () => showStartup();
document.getElementById("import-file").onchange = (ev) => {
  const f = ev.target.files[0];
  state.pendingFile = f || null;
  document.getElementById("import-filename").textContent = f ? f.name : "";
  document.getElementById("import-preview").disabled = !f;
  document.getElementById("import-commit").disabled = true;
  document.getElementById("preview-panel").hidden = true;
};
document.getElementById("import-preview").onclick = previewFile;
document.getElementById("import-commit").onclick = commitFile;
document.getElementById("import-cancel").onclick = closeImportModal;
document.getElementById("analyse").onclick = analyse;
document.getElementById("optimal").onclick = findOptimal;
document.getElementById("reset").onclick = () => {
  state.excludedEdges = new Set(); state.optimal = null;
  document.getElementById("optimal-section").hidden = true;
  paintExclusions(); updateButtons();
  if (state.source) analyse();
};
document.getElementById("optimal-apply").onclick = () => {
  if (!state.optimal) return;
  for (const m of state.optimal.edges_cut) state.excludedEdges.add(edgeKey(m.source, m.target));
  for (const m of state.optimal.nodes_cut)
    for (const ae of state.graph.attacker_edges)
      if (ae.source === m.id || ae.target === m.id)
        state.excludedEdges.add(edgeKey(ae.source, ae.target));
  paintExclusions(); updateButtons(); analyse();
};
document.getElementById("optimal-save").onclick = async () => {
  if (!state.optimal) return;
  for (const m of state.optimal.edges_cut) state.excludedEdges.add(edgeKey(m.source, m.target));
  for (const m of state.optimal.nodes_cut)
    for (const ae of state.graph.attacker_edges)
      if (ae.source === m.id || ae.target === m.id)
        state.excludedEdges.add(edgeKey(ae.source, ae.target));
  paintExclusions(); updateButtons();
  await saveCurrentPlan();
};
document.getElementById("optimal-close").onclick = () => {
  document.getElementById("optimal-section").hidden = true;
};
document.getElementById("save-current-plan").onclick = saveCurrentPlan;
document.getElementById("export-report").onclick = exportReport;

window.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  document.getElementById("optimal-section").hidden = true;
  if (!document.getElementById("import-modal").hidden) closeImportModal();
});
window.addEventListener("resize", () => {
  if (state.simulation) {
    state.simulation.force("center", d3.forceCenter(width() / 2, height() / 2));
    state.simulation.alpha(0.3).restart();
  }
});

(async () => {
  const active = await refreshActiveBadge();
  if (active) { await loadScenarios(); await loadActiveGraph(); }
  else { showStartup(); }
})();


async function exportHtml() {
  if (!state.source) { alert("Select a compromised identity first."); return; }
  if (state.targets.size === 0) { alert("Select at least one crown jewel."); return; }
  const btn = document.getElementById("export-html");
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = "Opening…";
  try {
    const exclusions = [...state.excludedEdges].map(k => {
      const [s, t] = k.split("->"); return { source: s, target: t };
    });
    const body = { source: state.source, targets: [...state.targets],
                   excluded_edges: exclusions, include_optimal: true };
    const r = await fetch("/api/report/html", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) { alert("Report failed: " + (await r.text())); return; }
    const html = await r.text();
    const w = window.open("", "_blank");
    w.document.open(); w.document.write(html); w.document.close();
  } finally { btn.disabled = false; btn.textContent = orig; }
}

document.getElementById("export-html").onclick = exportHtml;

// =============================================================
// Snapshots and diff
// =============================================================

async function takeSnapshot() {
  const btn = document.getElementById("snapshot-btn");
  btn.disabled = true;
  const orig = btn.textContent;
  try {
    const r = await fetch("/api/snapshots/save", { method: "POST" });
    if (!r.ok) { alert("Snapshot failed: " + (await r.text())); return; }
    const data = await r.json();
    btn.textContent = `Saved #${data.snapshot_id}`;
    btn.classList.add("armed");
    setTimeout(() => { btn.textContent = orig; btn.classList.remove("armed"); }, 2000);
  } finally { btn.disabled = false; }
}

async function openDiffPicker() {
  const r = await fetch("/api/snapshots");
  const snaps = await r.json();
  if (!snaps.length) {
    alert("No snapshots yet. Click Snapshot first to capture the current graph state.");
    return;
  }
  // Build a simple prompt with a list
  const lines = snaps.map(s =>
    `${s.id}: ${s.scenario} · ${s.node_count}n / ${s.edge_count}e · ${new Date(s.captured_at).toLocaleString()}`
  );
  const pick = prompt(
    "Enter the snapshot ID to compare AGAINST (the older one):\n\n" + lines.join("\n"),
    snaps[snaps.length - 1].id
  );
  if (!pick) return;
  const older_id = parseInt(pick, 10);
  if (isNaN(older_id)) { alert("Invalid ID"); return; }

  // The "current" snapshot is the newest one whose scenario matches the active one.
  const active_r = await fetch("/api/active");
  const active = await active_r.json();
  const current = snaps.find(s => s.scenario === active.active);
  if (!current) {
    alert("Current scenario has not been snapshotted. Click Snapshot first.");
    return;
  }
  if (current.id === older_id) {
    alert("Pick a different snapshot to compare against.");
    return;
  }

  await showDiff(older_id, current.id);
}

async function showDiff(id_a, id_b) {
  const r = await fetch("/api/diff", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ snapshot_a: id_a, snapshot_b: id_b }),
  });
  if (!r.ok) { alert("Diff failed: " + (await r.text())); return; }
  const data = await r.json();
  renderDiff(data);
}

function renderDiff(data) {
  const section = document.getElementById("diff-section");
  const banner = document.getElementById("diff-banner");
  const content = document.getElementById("diff-content");
  section.hidden = false;

  const delta = data.summary.attack_surface_delta;
  const cls = delta > 0 ? "delta-positive" : delta < 0 ? "delta-negative" : "delta-neutral";
  const sign = delta > 0 ? "+" : "";
  const verdict = delta > 0
    ? "security got worse"
    : delta < 0
      ? "security improved"
      : "no net change";

  const a = new Date(data.captured_a).toLocaleString();
  const b = new Date(data.captured_b).toLocaleString();

  banner.innerHTML = `
    <div><span class="${cls}">${sign}${delta}</span> attack-surface delta · ${verdict}</div>
    <div class="meta-line">${data.summary.edges_added} added · ${data.summary.edges_removed} removed ·
    ${data.summary.nodes_added + data.summary.nodes_removed} node changes</div>
    <div class="meta-line">From ${a} → ${b}</div>`;

  const groups = [];
  if (data.edges_added.length) {
    groups.push(`<div class="delta-group">
      <div class="group-title">New edges (${data.edges_added.length})</div>
      ${data.edges_added.map(e => edgeItem(e, "added")).join("")}
    </div>`);
  }
  if (data.edges_removed.length) {
    groups.push(`<div class="delta-group">
      <div class="group-title">Removed edges (${data.edges_removed.length})</div>
      ${data.edges_removed.map(e => edgeItem(e, "removed")).join("")}
    </div>`);
  }
  if (data.nodes_added.length) {
    groups.push(`<div class="delta-group">
      <div class="group-title">New nodes (${data.nodes_added.length})</div>
      ${data.nodes_added.map(n => nodeItem(n, "added")).join("")}
    </div>`);
  }
  if (data.nodes_removed.length) {
    groups.push(`<div class="delta-group">
      <div class="group-title">Removed nodes (${data.nodes_removed.length})</div>
      ${data.nodes_removed.map(n => nodeItem(n, "removed")).join("")}
    </div>`);
  }
  if (data.criticality_changes.length) {
    groups.push(`<div class="delta-group">
      <div class="group-title">Criticality changes (${data.criticality_changes.length})</div>
      ${data.criticality_changes.map(c =>
        `<div class="delta-item">${escapeHtml(c.name)}: ${c.from} → ${c.to}</div>`
      ).join("")}
    </div>`);
  }
  if (!groups.length) {
    content.innerHTML = `<div class="empty">No changes between these two snapshots.</div>`;
  } else {
    content.innerHTML = groups.join("");
  }
}

function edgeItem(e, dir) {
  const sevCls = e.severity >= 8 ? "high" : e.severity >= 5 ? "med" : "";
  return `<div class="delta-item ${dir}">
    <span class="sev-badge ${sevCls}">sev ${e.severity}</span>
    <span class="kind">${escapeHtml(e.kind)}</span>
    ${escapeHtml(e.source_name)} → ${escapeHtml(e.target_name)}
  </div>`;
}

function nodeItem(n, dir) {
  return `<div class="delta-item ${dir}">
    <span class="kind">${escapeHtml(n.kind)}</span>
    ${escapeHtml(n.name)} <span class="meta">crit ${n.criticality}</span>
  </div>`;
}

document.getElementById("snapshot-btn").onclick = takeSnapshot;
document.getElementById("diff-btn").onclick = openDiffPicker;
