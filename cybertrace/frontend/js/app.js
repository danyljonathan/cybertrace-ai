// App shell: client-side router, navigation, header status chip, global event delegation.
import { api, onInvalidate } from "./api.js";
import { esc, STATE_DOT, STATE_LABELS } from "./format.js";
import { hydrateIcons, icon } from "./icons.js";
import { closeEventDialog, errorState, openEventDialog } from "./ui.js";

import Dashboard from "./pages/dashboard.js";
import DemoCenter from "./pages/demo.js";
import ThreatDetection from "./pages/detection.js";
import AttackChain from "./pages/chain.js";
import AttackTimeline from "./pages/timeline.js";
import AttackGraphPage from "./pages/graph.js";
import Evidence from "./pages/evidence.js";
import Explanation from "./pages/explanation.js";
import LogExplorer from "./pages/logs.js";
import Architecture from "./pages/architecture.js";

const NAV = [
  { to: "/", label: "Dashboard", icon: "layout-dashboard", id: "dashboard", page: Dashboard },
  { to: "/demo", label: "Demo Center", icon: "play-circle", id: "demo", page: DemoCenter },
  { to: "/threat-detection", label: "Threat Detection", icon: "shield-alert", id: "detection", page: ThreatDetection },
  { to: "/attack-chain", label: "Attack Chain", icon: "git-branch", id: "chain", page: AttackChain },
  { to: "/attack-timeline", label: "Attack Timeline", icon: "clock", id: "timeline", page: AttackTimeline },
  { to: "/attack-graph", label: "Attack Graph", icon: "share-2", id: "graph", page: AttackGraphPage },
  { to: "/evidence", label: "Evidence", icon: "file-check", id: "evidence", page: Evidence },
  { to: "/explanation", label: "Explanation", icon: "brain", id: "explanation", page: Explanation },
  { to: "/logs", label: "Log Explorer", icon: "terminal", id: "logs", page: LogExplorer },
  { to: "/architecture", label: "Architecture", icon: "cpu", id: "architecture", page: Architecture },
];

const view = document.getElementById("view");
let cleanup = null;
let renderToken = 0;

function normalizePath(path) {
  const p = path.replace(/\/+$/, "") || "/";
  return NAV.some((n) => n.to === p) ? p : "/";
}

function renderNav(path) {
  document.getElementById("desktop-nav").innerHTML = NAV.map((n) =>
    `<a href="${n.to}" data-link data-testid="nav-link-${n.id}" class="nav-link${n.to === path ? " active" : ""}">${esc(n.label)}</a>`).join("");
  document.getElementById("mobile-nav").innerHTML = NAV.map((n) =>
    `<a href="${n.to}" data-link data-testid="nav-link-${n.id}" class="drawer-link${n.to === path ? " active" : ""}">${icon(n.icon, 16)} ${esc(n.label)}</a>`).join("");
}

async function render() {
  const path = normalizePath(location.pathname);
  if (path !== location.pathname) history.replaceState(null, "", path);
  const route = NAV.find((n) => n.to === path);
  renderNav(path);
  closeDrawer();
  if (typeof cleanup === "function") {
    try { cleanup(); } catch { /* page already gone */ }
  }
  cleanup = null;
  const token = ++renderToken;
  const ctx = { alive: () => token === renderToken, rerender: render };
  document.title = `${route.label} · CYBERTRACE AI`;
  try {
    cleanup = await route.page(view, ctx);
  } catch (err) {
    console.error(err);
    if (token === renderToken) view.innerHTML = errorState(err);
  }
}

export function navigate(to) {
  if (to === location.pathname) return render();
  history.pushState(null, "", to);
  window.scrollTo({ top: 0 });
  render();
}

// ------------------------------------------------------------- status chip
async function refreshStatus() {
  const dot = document.getElementById("status-dot");
  const label = document.getElementById("status-label");
  try {
    const s = await api.stats();
    const status = s.system_status ?? "NO_DATA";
    const color = STATE_DOT[status] ?? "#64748B";
    dot.style.background = color;
    dot.style.boxShadow = `0 0 8px ${color}`;
    label.textContent = STATE_LABELS[status] ?? status;
  } catch {
    dot.style.background = "#64748B";
    dot.style.boxShadow = "none";
    label.textContent = "API OFFLINE";
  }
}

// ------------------------------------------------------------------ drawer
const drawer = document.getElementById("drawer");
const backdrop = document.getElementById("drawer-backdrop");
function openDrawer() {
  drawer.classList.add("open");
  drawer.setAttribute("aria-hidden", "false");
  backdrop.hidden = false;
}
function closeDrawer() {
  drawer.classList.remove("open");
  drawer.setAttribute("aria-hidden", "true");
  backdrop.hidden = true;
}

// ---------------------------------------------------------------- wiring
document.addEventListener("click", (e) => {
  const link = e.target.closest("a[data-link]");
  if (link && !e.metaKey && !e.ctrlKey && !e.shiftKey && !e.altKey && e.button === 0 && link.target !== "_blank") {
    e.preventDefault();
    navigate(new URL(link.href).pathname);
    return;
  }
  const evBtn = e.target.closest("[data-event-id]");
  if (evBtn) {
    e.preventDefault();
    openEventDialog(evBtn.dataset.eventId);
    return;
  }
  if (e.target.closest("[data-action=reload]")) render();
});

document.getElementById("menu-btn").addEventListener("click", openDrawer);
document.getElementById("drawer-close").addEventListener("click", closeDrawer);
backdrop.addEventListener("click", closeDrawer);
document.getElementById("modal-close").addEventListener("click", closeEventDialog);
document.getElementById("modal").addEventListener("click", (e) => {
  if (e.target.id === "modal") closeEventDialog();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") {
    closeEventDialog();
    closeDrawer();
  }
});
window.addEventListener("popstate", render);
onInvalidate(() => refreshStatus());

hydrateIcons();
render();
refreshStatus();
setInterval(refreshStatus, 20_000);
