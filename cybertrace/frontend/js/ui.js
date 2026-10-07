// Shared UI building blocks. Each returns an HTML string; all dynamic text goes through esc().
import { api } from "./api.js";
import { esc, fmtDateTimeSec, STATE_LABELS, TIER_COLORS } from "./format.js";
import { icon } from "./icons.js";

export const PIPELINE_STAGE_NAMES = [
  "Log Ingestion", "Normalization", "Entity Extraction", "Behavioral Baseline",
  "Anomaly Detection", "Event Correlation", "Sequence / Order Analysis",
  "Attack Chain Reconstruction", "Evidence Validation", "Risk Assessment",
  "Explanation", "Recommended Action", "Verdict",
];

export const syntheticBadge = () => `<span class="badge badge-synthetic">SYNTHETIC DEMONSTRATION DATA</span>`;

export function stateBadge(state, testid = "") {
  const cls = STATE_LABELS[state] ? `state-${state}` : "state-NO_DATA";
  return `<span class="badge ${cls}"${testid ? ` data-testid="${esc(testid)}"` : ""}>${esc(STATE_LABELS[state] ?? state)}</span>`;
}

export function stateDot(state) {
  const map = { NORMAL: "#10B981", SUSPICIOUS_EVENT: "#F59E0B", POSSIBLE_INCIDENT: "#F97316", HIGH_CONFIDENCE_ATTACK: "#EF4444" };
  const c = map[state] ?? "#64748B";
  return `<span class="dot" style="background:${c};box-shadow:0 0 6px ${c}"></span>`;
}

export function pageHeader(title, subtitle, right = syntheticBadge()) {
  return `<div class="row between">
    <div class="min-w-0"><h1 class="h1">${esc(title)}</h1><p class="lead">${esc(subtitle)}</p></div>
    <div class="row-sm">${right}</div>
  </div>`;
}

export function statusBanner({ status, verdict, mode, riskScore, riskTier }) {
  const kind = status === "ATTACK_DETECTED" ? "attack" : status === "NO_DATA" ? "nodata"
    : status === "POSSIBLE_INCIDENT" ? "possible" : "quiet";
  const ic = { attack: "siren", nodata: "radar", possible: "triangle-alert", quiet: "shield-check" }[kind];
  const emoji = { attack: "🔴", nodata: "⚪", possible: "🟠", quiet: "🟢" }[kind];
  const head = String(verdict ?? "").split("—")[0].trim();
  const badge = riskScore != null && (riskScore > 0 || kind === "attack")
    ? `RISK SCORE: ${riskScore}/100 (${riskTier ?? ""})`
    : "STATUS: " + ({ nodata: "NO DATA", possible: "REVIEW NEEDED", quiet: "NORMAL / QUIET", attack: "ATTACK" }[kind]);
  return `<section class="banner banner-${kind}" data-testid="status-banner">
    <span class="banner-icon ${kind}">${icon(ic, 22)}</span>
    <div class="min-w-0 flex-1">
      <p class="h2" data-testid="status-banner-verdict">${emoji} ${esc(head)}</p>
      <p class="mt-1 text-sm relaxed t-300">${esc(verdict)}</p>
    </div>
    <div class="banner-right">
      <span class="banner-badge ${kind}" data-testid="status-banner-badge">${esc(badge)}</span>
      ${mode ? `<span class="mono label-xs">last run: ${esc(mode)} dataset</span>` : ""}
    </div>
  </section>`;
}

export function emptyState(title, message) {
  return `<div class="empty">
    <span class="empty-icon">${icon("radar", 22)}</span>
    <h3 class="text-lg semibold t-200">${esc(title)}</h3>
    <p class="text-sm relaxed t-muted">${esc(message)}</p>
    <a href="/demo" data-link class="btn btn-primary btn-sm mt-2" data-testid="empty-state-go-demo">${icon("play-circle", 14)} Open Demo Center</a>
  </div>`;
}

export function quietState(testid, title, message) {
  return `<div class="empty quiet-state" data-testid="${esc(testid)}">
    <h3 class="text-lg semibold t-emerald">${esc(title)}</h3>
    <p class="text-sm relaxed t-muted">${esc(message)}</p>
    <a href="/demo" data-link class="link">Open Demo Center →</a>
  </div>`;
}

export function errorState(err) {
  return `<div class="empty">
    <span class="empty-icon">${icon("triangle-alert", 22)}</span>
    <h3 class="text-lg semibold t-200">Backend unreachable</h3>
    <p class="text-sm relaxed t-muted">${esc(err?.message || "The API did not respond.")} The page will recover automatically once the API responds.</p>
    <button class="btn btn-outline btn-sm mt-2" data-action="reload">${icon("refresh", 14)} Retry</button>
  </div>`;
}

export function loading(height = 160) {
  return `<div class="skeleton" style="height:${height}px"></div>`;
}

export function windowSelect(id, value, testid, optionPrefix) {
  return `<select id="${esc(id)}" class="select w-40" data-testid="${esc(testid)}">
    ${["15", "30", "60"].map((m) => `<option value="${m}" data-testid="${esc(optionPrefix)}-${m}"${String(value) === m ? " selected" : ""}>${m} minutes</option>`).join("")}
  </select>`;
}

// ------------------------------------------------------------------ pipeline
export function pipelineVisualizer(stages, running, progress) {
  const items = PIPELINE_STAGE_NAMES.map((name, i) => {
    const report = !running && stages ? stages.find((s) => s.stage_num === i + 1) : undefined;
    const done = running ? i < progress : !!report;
    const active = running && i === progress;
    const num = String(i + 1).padStart(2, "0");
    const ic = running
      ? active ? icon("loader", 15, "spin t-cyan") : done ? icon("check-circle", 15, "t-cyan-400") : icon("circle", 15, "t-faint")
      : icon("check-circle", 15, report ? "t-cyan-400" : "t-faint");
    return `<li class="stage-item ${active ? "active" : done ? "done" : "pending"}" data-testid="pipeline-stage-${i + 1}">
      <span class="mono text-xs t-dim" style="margin-top:2px">${num}</span>
      <span style="margin-top:2px">${ic}</span>
      <span class="min-w-0 flex-1">
        <span class="text-sm medium ${done || active ? "t-100" : "t-dim"}" style="display:block">${esc(name)}</span>
        ${report ? `<span class="mono text-11 snug t-dim" style="display:block">${esc(report.detail)}</span>` : ""}
        ${!report && !running ? `<span class="mono text-11 t-faint" style="display:block">awaiting run</span>` : ""}
      </span>
    </li>`;
  }).join("");
  return `<div class="card" data-testid="pipeline-visualizer">
    <div class="row between mb-4">
      <h3 class="section-title">Detection Pipeline — 13 stages</h3>
      <span class="mono text-11 t-dim">${running ? `executing stage ${Math.min(progress + 1, 13)}/13` : "deterministic · explainable"}</span>
    </div>
    <ol class="stack-xs" style="gap:6px">${items}</ol>
  </div>`;
}

// ---------------------------------------------------------------- risk gauge
const ARC_LEN = Math.PI * 85;

export function riskGauge(risk) {
  const score = risk?.score ?? 0;
  const tier = risk && (risk.score > 0 || risk.factors.length > 0) ? risk.tier : null;
  const color = tier ? TIER_COLORS[tier] ?? "#38BDF8" : "#334155";
  const filled = (Math.min(100, Math.max(0, score)) / 100) * ARC_LEN;
  const factors = risk && risk.factors.length > 0
    ? `<ul class="stack-sm" style="gap:10px">${risk.factors.map((f) => `
        <li class="inner row between" style="align-items:flex-start;flex-wrap:nowrap">
          <span class="min-w-0"><span class="text-sm medium t-100" style="display:block">${esc(f.factor)}</span>
          <span class="text-xs snug t-muted" style="display:block">${esc(f.detail)}</span></span>
          <span class="mono text-sm bold t-cyan shrink-0">+${esc(f.points)}</span>
        </li>`).join("")}</ul>
       <p class="mono text-11 t-dim mt-2">${esc(risk.formula)}</p>`
    : `<p class="inner text-sm t-muted" style="padding:12px">No attack chain — risk is derived only from correlated evidence, so the score stays at zero while the system is quiet.</p>`;
  return `<div class="card" data-testid="risk-gauge">
    <h3 class="section-title">Explainable Risk Score</h3>
    <div class="gauge-body mt-4">
      <div class="gauge-wrap">
        <svg width="200" height="118" viewBox="0 0 200 118" role="img" aria-label="Risk score ${risk ? score : "none"}">
          <path d="M 15 110 A 85 85 0 0 1 185 110" fill="none" stroke="#1E293B" stroke-width="14" stroke-linecap="round" />
          <path class="gauge-arc" d="M 15 110 A 85 85 0 0 1 185 110" fill="none" stroke="${color}" stroke-width="14" stroke-linecap="round"
            stroke-dasharray="0 ${ARC_LEN}" data-target="${filled} ${ARC_LEN}" style="transition: stroke-dasharray .6s ease" />
          <text class="gauge-score" x="100" y="92" text-anchor="middle" data-testid="risk-gauge-score">${risk ? score : "—"}</text>
        </svg>
        <span class="gauge-tier" data-testid="risk-gauge-tier" style="color:${tier ? color : "#64748B"}">${tier ? `${tier} · ${score}/100` : "NO ACTIVE CHAIN"}</span>
      </div>
      <div class="w-full min-w-0 flex-1">${factors}</div>
    </div>
    <div class="row-sm mt-4 mono text-10 t-dim">
      <span>TIERS:</span><span>0-29 LOW</span><span>·</span><span>30-59 MEDIUM</span><span>·</span><span>60-79 HIGH</span><span>·</span><span>80-100 CRITICAL</span>
      <span class="ml-auto">NORMAL = no score claimed</span>
    </div>
  </div>`;
}

// Animate gauges after insertion (stroke-dasharray transition needs a frame).
export function animateGauges(root) {
  requestAnimationFrame(() => root.querySelectorAll(".gauge-arc").forEach((p) => p.setAttribute("stroke-dasharray", p.dataset.target)));
}

// ---------------------------------------------------------------- stat cards
export function statCards(stats) {
  const cards = [
    ["stat-card-total-events", "TOTAL EVENTS", stats?.total_events ?? 0,
      stats ? `${stats.events_today} on latest day · ${stats.users} users · ${stats.devices} devices` : "—", "database", "t-cyan", "b-cyan"],
    ["stat-card-suspicious", "SUSPICIOUS EVENTS", stats?.suspicious_events ?? 0,
      "isolated anomalies held below incident level", "shield-alert", "t-amber-400", "b-amber"],
    ["stat-card-incidents", "POSSIBLE INCIDENTS", stats?.possible_incidents ?? 0,
      "2+ related anomalies, no pattern match", "triangle-alert", "t-orange", "b-orange"],
    ["stat-card-attacks", "HIGH-CONFIDENCE ATTACKS", stats?.high_confidence_attacks ?? 0,
      "correlated chains with verified evidence", "siren", "t-rose-400", "b-rose"],
  ];
  return `<div class="grid grid-gap-md sm-2 lg-4">${cards.map(([id, label, value, sub, ic, color, border]) => `
    <div class="card card-pad-sm hover-lift ${border}" data-testid="${id}">
      <div class="row between"><span class="text-11 semibold upper t-muted">${label}</span>${icon(ic, 16, color)}</div>
      <p class="mono text-3xl bold t-white mt-2">${esc(value)}</p>
      <p class="text-xs t-dim mt-1">${esc(sub)}</p>
    </div>`).join("")}</div>`;
}

export function priorityTag(p) {
  return `<span class="prio prio-${esc(p)}">${esc(p)}</span>`;
}

// --------------------------------------------------------------------- toast
export function toast(type, title, description = "") {
  const host = document.getElementById("toaster");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  const ic = type === "error" ? icon("triangle-alert", 16, "t-rose-400") : type === "success" ? icon("check-circle", 16, "t-emerald-400") : icon("radar", 16, "t-cyan");
  el.innerHTML = `<span style="margin-top:1px">${ic}</span><div class="min-w-0"><p class="toast-title">${esc(title)}</p>${description ? `<p class="toast-desc">${esc(description)}</p>` : ""}</div>`;
  host.appendChild(el);
  setTimeout(() => {
    el.classList.add("leaving");
    setTimeout(() => el.remove(), 220);
  }, 4500);
}

// ------------------------------------------------------------- event dialog
const FIELDS = [
  ["Event ID", "event_id"], ["Event Type", "event_type"], ["Action", "action"], ["User", "user"],
  ["Device", "device"], ["IP", "ip"], ["Application", "application"], ["Resource", "resource"],
  ["Location", "location"], ["Severity", "severity"], ["Source", "source_tag"],
];

let lastFocus = null;

export async function openEventDialog(eventId) {
  const modal = document.getElementById("modal");
  const body = document.getElementById("modal-body");
  lastFocus = document.activeElement;
  const header = `<h2 id="modal-title" class="mono text-base t-cyan">${esc(eventId)}</h2>
    <p class="text-sm t-muted mt-1">Raw normalized security event — SYNTHETIC DEMONSTRATION DATA</p>`;
  body.innerHTML = `${header}<p class="center text-sm t-dim" style="padding:24px 0">Loading event…</p>`;
  modal.hidden = false;
  document.getElementById("modal-close").focus();
  try {
    const ev = await api.event(eventId);
    if (modal.hidden) return;
    const rows = FIELDS.map(([label, key]) => `<tr><td class="text-xs upper t-dim" style="letter-spacing:.05em">${label}</td>
      <td class="mono t-200" style="text-align:right">${esc(ev[key] ?? "—")}</td></tr>`).join("");
    const meta = Object.keys(ev.metadata || {}).length
      ? `<div class="mt-4"><p class="text-xs upper t-dim mb-2" style="letter-spacing:.05em">Metadata</p>
         <pre data-testid="event-detail-metadata">${esc(JSON.stringify(ev.metadata, null, 2))}</pre></div>` : "";
    body.innerHTML = `${header}<table class="table mt-4"><tbody>${rows}
      <tr><td class="text-xs upper t-dim" style="letter-spacing:.05em">Timestamp</td><td class="mono t-200" style="text-align:right">${esc(fmtDateTimeSec(ev.timestamp))}</td></tr>
      </tbody></table>${meta}`;
  } catch (err) {
    body.innerHTML = `${header}<p class="center text-sm t-rose" style="padding:24px 0">${esc(err.message)}</p>`;
  }
}

export function closeEventDialog() {
  const modal = document.getElementById("modal");
  if (modal.hidden) return;
  modal.hidden = true;
  if (lastFocus && typeof lastFocus.focus === "function") lastFocus.focus();
}
