import { api } from "../api.js";
import { esc, fmtTime, NODE_COLORS } from "../format.js";
import { icon, iconPaths } from "../icons.js";
import { emptyState, loading, pageHeader } from "../ui.js";

const ICONS = { USER: "user", DEVICE: "monitor", IP_ADDRESS: "globe", APPLICATION: "app-window", RESOURCE: "file-text", USB_PERIPHERAL: "usb" };
const TYPE_ORDER = ["USER", "DEVICE", "IP_ADDRESS", "APPLICATION", "RESOURCE", "USB_PERIPHERAL"];
const NODE_W = 168;
const NODE_H = 46;
const COL_GAP = 240;
const ROW_GAP = 96;

function layout(nodes) {
  const byType = new Map();
  const pos = new Map();
  // Only entity types that are present get a column, so the graph stays compact.
  const present = TYPE_ORDER.filter((t) => nodes.some((n) => n.type === t));
  // Chain nodes first within each column so the attack path sits at the top.
  const sorted = [...nodes].sort((a, b) => Number(b.chain) - Number(a.chain));
  for (const n of sorted) {
    const col = Math.max(0, present.indexOf(n.type));
    const row = byType.get(n.type) ?? 0;
    byType.set(n.type, row + 1);
    pos.set(n.id, { x: col * COL_GAP, y: row * ROW_GAP });
  }
  return pos;
}

function edgePath(s, t) {
  const sy = s.y + NODE_H / 2;
  const ty = t.y + NODE_H / 2;
  // Edges that skip columns arc above the row so they never run behind intermediate nodes.
  const span = Math.round(Math.abs(t.x - s.x) / COL_GAP);
  const lift = span > 1 && Math.abs(ty - sy) < ROW_GAP / 2 ? 34 + 18 * (span - 2) : 0;
  if (t.x > s.x) {
    const x1 = s.x + NODE_W, x2 = t.x, dx = (x2 - x1) / 2;
    return { d: `M ${x1} ${sy} C ${x1 + dx} ${sy - lift * 1.33}, ${x2 - dx} ${ty - lift * 1.33}, ${x2} ${ty}`, mx: (x1 + x2) / 2, my: (sy + ty) / 2 - lift };
  }
  if (t.x < s.x) {
    const x1 = s.x, x2 = t.x + NODE_W, dx = (x1 - x2) / 2;
    return { d: `M ${x1} ${sy} C ${x1 - dx} ${sy - lift * 1.33}, ${x2 + dx} ${ty - lift * 1.33}, ${x2} ${ty}`, mx: (x1 + x2) / 2, my: (sy + ty) / 2 - lift };
  }
  const x = s.x + NODE_W, bulge = 60 + Math.abs(ty - sy) * 0.15;
  return { d: `M ${x} ${sy} C ${x + bulge} ${sy}, ${x + bulge} ${ty}, ${x} ${ty}`, mx: x + bulge * 0.75, my: (sy + ty) / 2 };
}

export default async function AttackGraphPage(view, ctx) {
  const header = pageHeader("Attack Graph", "Nodes are actual entities, edges are actual observed relationships — click a node to trace its events.");
  view.innerHTML = `<div class="stack">${header}${loading(520)}</div>`;
  let data;
  try {
    data = await api.graph();
  } catch (err) {
    if (!ctx.alive()) return;
    view.innerHTML = `<div class="stack">${header}${emptyState("No graph data",
      "The graph backend is unreachable — the page stays up and will recover when the API responds.")}</div>`;
    return;
  }
  if (!ctx.alive()) return;
  if (!data.nodes.length) {
    view.innerHTML = `<div class="stack">${header}${emptyState("No graph data",
      "Ingest events via a demo first — the graph is built strictly from stored event relationships.")}</div>`;
    return;
  }

  const pos = layout(data.nodes);
  const nodeById = new Map(data.nodes.map((n) => [n.id, n]));
  let stageIndex = null;
  let selectedId = null;
  const tf = { x: 0, y: 0, k: 1 };

  view.innerHTML = `<div class="stack">
    ${header}
    ${data.stages.length ? `<div class="row-sm" data-testid="graph-stage-scrubber">
      <span class="eyebrow t-muted">Scrub:</span>
      <button class="scrub-btn active" data-stage="all" data-testid="graph-stage-all">FULL CHAIN</button>
      ${data.stages.map((s, i) => `<button class="scrub-btn" data-stage="${i}" data-testid="graph-stage-${s.stage_num}">STAGE ${s.stage_num} · ${esc(fmtTime(s.timestamp))} · ${esc(s.name)}</button>`).join("")}
    </div>` : ""}
    <div class="stack-md">
      <div class="graph-canvas" id="canvas" data-testid="attack-graph-canvas">
        <svg id="svg" xmlns="http://www.w3.org/2000/svg">
          <defs>
            <pattern id="grid-dots" width="24" height="24" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r="1" fill="#1E293B" /></pattern>
            <marker id="arrow-chain" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#00E5FF" /></marker>
            <marker id="arrow-base" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0L10 5L0 10z" fill="#475569" /></marker>
          </defs>
          <rect width="100%" height="100%" fill="url(#grid-dots)" />
          <g id="world"></g>
        </svg>
        <div class="graph-controls">
          <button id="zoom-in" aria-label="Zoom in">${icon("plus", 14)}</button>
          <button id="zoom-out" aria-label="Zoom out">${icon("minus", 14)}</button>
          <button id="fit" aria-label="Fit view">${icon("maximize", 14)}</button>
        </div>
      </div>
      <div id="evidence-panel"></div>
      <div class="row text-11 t-dim">
        ${Object.entries(NODE_COLORS).map(([t, c]) => `<span class="row-xs"><span class="legend-swatch" style="background:${c}"></span>${t.replace("_", " ")}</span>`).join("")}
        <span class="ml-auto">cyan edges = attack-chain relations · scroll to zoom · drag to pan · click nodes</span>
      </div>
    </div>
    <p class="mono text-11 t-dim" data-testid="graph-source-note">graph built from: ${esc(data.generated_from)} — relationships come from the event data, not from decoration.</p>
  </div>`;

  const canvas = view.querySelector("#canvas");
  const world = view.querySelector("#world");
  const panel = view.querySelector("#evidence-panel");

  const applyTf = () => world.setAttribute("transform", `translate(${tf.x} ${tf.y}) scale(${tf.k})`);

  const fit = () => {
    const xs = [...pos.values()];
    const minX = Math.min(...xs.map((p) => p.x)), maxX = Math.max(...xs.map((p) => p.x)) + NODE_W + 80;
    const minY = Math.min(...xs.map((p) => p.y)) - 80, maxY = Math.max(...xs.map((p) => p.y)) + NODE_H; // room for arcs
    const w = canvas.clientWidth || 800, h = canvas.clientHeight || 520;
    const pad = 0.12;
    const k = Math.min(1.4, Math.max(0.2, Math.min(w / ((maxX - minX) * (1 + pad * 2)), h / ((maxY - minY) * (1 + pad * 2) || 1))));
    tf.k = k;
    tf.x = (w - (maxX - minX) * k) / 2 - minX * k;
    tf.y = (h - (maxY - minY) * k) / 2 - minY * k;
    applyTf();
  };

  const draw = () => {
    const stageTime = stageIndex != null ? new Date(data.stages[stageIndex].timestamp).getTime() : null;
    const visible = data.edges.filter((e) => stageTime == null || new Date(e.timestamp).getTime() <= stageTime);
    const touched = new Set(visible.flatMap((e) => [e.source, e.target]));
    const neighbors = new Set();
    if (selectedId) visible.forEach((e) => {
      if (e.source === selectedId) neighbors.add(e.target);
      if (e.target === selectedId) neighbors.add(e.source);
    });

    const edgesSvg = visible.map((e) => {
      const s = pos.get(e.source), t = pos.get(e.target);
      if (!s || !t) return "";
      const p = edgePath(s, t);
      const faded = selectedId && e.source !== selectedId && e.target !== selectedId;
      const label = e.relation.replace(/_/g, " ");
      const lw = label.length * 5.6 + 8;
      return `<g class="g-edge" style="opacity:${faded ? 0.2 : 1}">
        <path d="${p.d}" fill="none" stroke="${e.chain ? "#00E5FF" : "#334155"}" stroke-width="${e.chain ? 2 : 1.2}"
          marker-end="url(#${e.chain ? "arrow-chain" : "arrow-base"})" class="${e.chain && !selectedId ? "edge-animated" : ""}" />
        <rect x="${p.mx - lw / 2}" y="${p.my - 7}" width="${lw}" height="14" rx="3" fill="#0B1120" fill-opacity=".88" />
        <text class="g-edge-label" x="${p.mx}" y="${p.my + 3}" text-anchor="middle">${esc(label)}</text>
      </g>`;
    }).join("");

    const nodesSvg = data.nodes.map((n) => {
      const p = pos.get(n.id);
      const color = NODE_COLORS[n.type] ?? "#38BDF8";
      const isSel = n.id === selectedId;
      const dim = (selectedId && !isSel && !neighbors.has(n.id)) || (stageTime != null && !touched.has(n.id));
      const label = n.label.length > 19 ? n.label.slice(0, 18) + "…" : n.label;
      return `<g class="g-node" data-node="${esc(n.id)}" data-testid="graph-node" transform="translate(${p.x} ${p.y})" style="opacity:${dim ? 0.28 : 1}">
        ${n.chain && !dim ? `<rect x="-3" y="-3" width="${NODE_W + 6}" height="${NODE_H + 6}" rx="10" fill="${color}" fill-opacity=".10" />` : ""}
        <rect class="box" width="${NODE_W}" height="${NODE_H}" rx="8" stroke="${isSel ? "#00E5FF" : dim ? "#1E293B" : color}" stroke-width="${isSel ? 2 : 1.2}" />
        <g transform="translate(12 15) scale(0.667)" fill="none" stroke="${color}" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round">${iconPaths(ICONS[n.type] ?? "file-text")}</g>
        <text class="label" x="36" y="20">${esc(label)}</text>
        <text class="kind" x="36" y="34" fill="${color}">${esc(n.type.replace("_", " "))}</text>
        <title>${esc(n.label)} — ${n.event_ids.length} source event(s)</title>
      </g>`;
    }).join("");
    world.innerHTML = edgesSvg + nodesSvg;

    const node = selectedId ? nodeById.get(selectedId) : null;
    panel.innerHTML = node ? `<div class="card card-pad-sm b-cyan" data-testid="graph-evidence-panel">
      <div class="row between mb-2"><p class="mono text-sm t-cyan">${esc(node.id)}</p>
        <button class="text-btn text-xs" id="clear-sel" data-testid="graph-evidence-close" style="color:var(--slate-400)">clear selection</button></div>
      <p class="eyebrow mb-2">Observed relationships — ${node.event_ids.length} source event(s) · click to open the raw log</p>
      <div class="row-sm">${node.event_ids.map((eid) => `<button class="tag tag-outline" style="padding:4px 8px;font-size:12px;cursor:pointer" data-event-id="${esc(eid)}" data-testid="graph-evidence-event">${esc(eid)}</button>`).join("")}</div>
      <p class="mt-2 text-11 t-dim">Every node and edge is derived from stored events — open Evidence or Log Explorer and search these IDs to trace the raw logs.</p>
    </div>` : "";
  };

  // --- interaction: pan, zoom, select
  let drag = null;
  const onPointerDown = (e) => {
    if (e.button !== 0 || e.target.closest(".graph-controls")) return;
    drag = { x: e.clientX, y: e.clientY, tx: tf.x, ty: tf.y, moved: false, node: e.target.closest("[data-node]")?.dataset.node };
    canvas.setPointerCapture(e.pointerId);
  };
  const onPointerMove = (e) => {
    if (!drag) return;
    const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
    if (!drag.moved && Math.hypot(dx, dy) > 4) {
      drag.moved = true;
      canvas.classList.add("dragging");
    }
    if (drag.moved) {
      tf.x = drag.tx + dx;
      tf.y = drag.ty + dy;
      applyTf();
    }
  };
  const onPointerUp = () => {
    if (!drag) return;
    if (!drag.moved) {
      selectedId = drag.node ?? null; // click on empty canvas clears selection
      draw();
    }
    canvas.classList.remove("dragging");
    drag = null;
  };
  const zoomAt = (factor, cx, cy) => {
    const k = Math.min(3, Math.max(0.2, tf.k * factor));
    const f = k / tf.k;
    tf.x = cx - (cx - tf.x) * f;
    tf.y = cy - (cy - tf.y) * f;
    tf.k = k;
    applyTf();
  };
  const onWheel = (e) => {
    e.preventDefault();
    const r = canvas.getBoundingClientRect();
    zoomAt(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX - r.left, e.clientY - r.top);
  };
  canvas.addEventListener("pointerdown", onPointerDown);
  canvas.addEventListener("pointermove", onPointerMove);
  canvas.addEventListener("pointerup", onPointerUp);
  canvas.addEventListener("pointercancel", onPointerUp);
  canvas.addEventListener("wheel", onWheel, { passive: false });
  view.querySelector("#zoom-in").addEventListener("click", () => zoomAt(1.2, canvas.clientWidth / 2, canvas.clientHeight / 2));
  view.querySelector("#zoom-out").addEventListener("click", () => zoomAt(1 / 1.2, canvas.clientWidth / 2, canvas.clientHeight / 2));
  view.querySelector("#fit").addEventListener("click", fit);

  const onClick = (e) => {
    const sb = e.target.closest("[data-stage]");
    if (sb) {
      stageIndex = sb.dataset.stage === "all" ? null : Number(sb.dataset.stage);
      view.querySelectorAll("[data-stage]").forEach((b) => b.classList.toggle("active", b === sb));
      draw();
    }
    if (e.target.closest("#clear-sel")) {
      selectedId = null;
      draw();
    }
  };
  view.addEventListener("click", onClick);
  const onResize = () => fit();
  window.addEventListener("resize", onResize);

  draw();
  fit();
  return () => {
    view.removeEventListener("click", onClick);
    window.removeEventListener("resize", onResize);
  };
}
