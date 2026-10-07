import { api } from "../api.js";
import { esc, fmtTime } from "../format.js";
import { icon } from "../icons.js";
import {
  animateGauges, emptyState, loading, pageHeader, priorityTag, riskGauge, statCards, stateBadge, statusBanner,
} from "../ui.js";

function volumeChart(daily) {
  if (!daily || daily.length === 0) return `<p class="mt-4 text-sm t-dim">No volume data.</p>`;
  const max = Math.max(1, ...daily.map((d) => d.count));
  const nice = Math.ceil(max / 4) * 4 || 4;
  const ticks = [nice, (nice * 3) / 4, nice / 2, nice / 4, 0];
  return `<div class="mt-4" data-testid="dashboard-volume-chart">
    <div class="bars">
      <div class="bars-grid">${ticks.map((t) => `<div><span>${Math.round(t)}</span></div>`).join("")}</div>
      ${daily.map((d) => `<div class="bar-col">
        <span class="bar-tip">${esc(d.date)} · ${d.count} events</span>
        <div class="bar" style="height:${(d.count / nice) * 100}%"></div>
      </div>`).join("")}
    </div>
    <div class="bar-labels">${daily.map((d) => `<span>${esc(d.date.slice(5))}</span>`).join("")}</div>
  </div>`;
}

export default async function Dashboard(view, ctx) {
  const header = pageHeader("SOC Command Dashboard",
    "Entity correlation across users, devices, IPs, applications and resources.");
  view.innerHTML = `<div class="stack">${header}${loading(110)}${loading(320)}</div>`;

  let stats;
  try {
    stats = await api.stats();
  } catch (err) {
    if (!ctx.alive()) return;
    view.innerHTML = `<div class="stack">${header}${emptyState("The detection engine has not run yet",
      "The analysis backend is unreachable right now — the dashboard shell stays up and will recover automatically once the API responds.")}</div>`;
    return;
  }
  const [analysis, recent] = await Promise.all([
    api.analysis().catch(() => null),
    api.events({ limit: 8 }).catch(() => ({ items: [], total: 0 })),
  ]);
  if (!ctx.alive()) return;

  const banner = statusBanner({
    status: stats.system_status, verdict: stats.verdict_message, mode: stats.last_run_mode,
    riskScore: stats.risk_score, riskTier: stats.risk_tier,
  });

  if (!stats.has_analysis) {
    view.innerHTML = `<div class="stack">${header}${emptyState("The detection engine has not run yet",
      "Run a synthetic demo to ingest security logs and watch CyberTrace correlate them into an evidence-backed attack story.")}</div>`;
    return;
  }

  const chain = analysis?.chains?.[0];
  const rows = (recent.items ?? []).map((ev) => `
    <tr class="row-click" data-event-id="${esc(ev.event_id)}" data-testid="recent-event-row-${esc(ev.event_id)}">
      <td class="t-muted">${esc(fmtTime(ev.timestamp))}</td>
      <td class="t-cyan">${esc(ev.event_id)}</td>
      <td>${esc(ev.event_type)}</td>
      <td>${esc(ev.user ?? "—")}</td>
      <td>${esc(ev.resource ?? ev.metadata?.usb_device ?? ev.metadata?.destination ?? "—")}</td>
    </tr>`).join("") || `<tr><td colspan="5" class="center t-dim" style="padding:16px">No events stored.</td></tr>`;

  const chainCard = chain ? `
    <div class="stack-sm" data-testid="dashboard-chain-summary">
      <p class="text-sm medium t-100">${esc(chain.pattern_name)}</p>
      <div class="row-sm">${stateBadge(chain.state, "dashboard-chain-state")}
        <span class="mono text-xs t-muted">${esc(fmtTime(chain.first_seen))} → ${esc(fmtTime(chain.last_seen))} UTC · window ${esc(chain.window_minutes)} min</span>
      </div>
      <ol class="stack-xs mt-2" style="gap:6px">${chain.stages.map((s) => `
        <li class="inner row-sm" style="padding:6px 12px;flex-wrap:nowrap">
          <span class="mono text-11 t-dim">${esc(fmtTime(s.timestamp))}</span>
          <span class="text-xs ${s.derived ? "italic t-amber" : "t-200"}">${esc(s.name)}</span>
          <span class="ml-auto mono text-11 t-cyan">+${esc(s.risk_contribution)}</span>
        </li>`).join("")}</ol>
    </div>` : `
    <div class="inner-lg b-emerald bg-emerald" data-testid="dashboard-quiet-card">
      <p class="text-sm medium t-emerald">${stats.system_status === "POSSIBLE_INCIDENT" ? "Possible incident — under review" : "System remains quiet"}</p>
      <p class="mt-1 text-xs relaxed t-muted">No sufficient correlated evidence — the engine builds no attack chain without
        multiple related signals that follow a registered pattern. This is the false-positive control working as designed.</p>
    </div>`;

  const recs = chain && chain.recommendations.length > 0
    ? `<ul class="stack-sm" data-testid="dashboard-recommendations">${chain.recommendations.slice(0, 3).map((r) => `
        <li class="inner row between" style="flex-wrap:nowrap;align-items:flex-start">
          <span class="text-xs snug t-200">${esc(r.action)}</span>${priorityTag(r.priority)}
        </li>`).join("")}</ul>`
    : `<p class="text-sm t-dim">No actions — nothing to remediate while the system is quiet.</p>`;

  view.innerHTML = `<div class="stack">
    ${header}
    ${banner}
    ${statCards(stats)}
    <div class="grid lg-12">
      <div class="stack col-7">
        ${riskGauge(chain?.risk ?? null)}
        <section class="card">
          <h3 class="section-title">Event volume — last 7 days (UTC)</h3>
          ${volumeChart(stats.daily_volume)}
        </section>
        <section class="card">
          <div class="row between mb-3">
            <h3 class="section-title">Recent events</h3>
            <a href="/logs" data-link class="link" data-testid="dashboard-link-logs">Log Explorer ${icon("arrow-right", 12)}</a>
          </div>
          <div class="table-wrap" data-testid="dashboard-recent-events">
            <table class="table table-mono">
              <thead><tr><th>Time</th><th>Event</th><th>Type</th><th>User</th><th>Resource</th></tr></thead>
              <tbody class="t-300">${rows}</tbody>
            </table>
          </div>
        </section>
      </div>
      <div class="stack col-5">
        <section class="card">
          <div class="row between mb-3">
            <h3 class="section-title">${icon("git-branch", 13)} Active attack chain</h3>
            <a href="/attack-chain" data-link class="link" data-testid="dashboard-link-chain">Open ${icon("arrow-right", 12)}</a>
          </div>
          ${chainCard}
        </section>
        <section class="card">
          <div class="row between mb-3">
            <h3 class="section-title">${icon("list-checks", 13)} Recommended actions</h3>
            <a href="/explanation" data-link class="link" data-testid="dashboard-link-explanation">Explanation ${icon("arrow-right", 12)}</a>
          </div>
          ${recs}
        </section>
        <a href="/demo" data-link class="btn btn-primary btn-lg" data-testid="dashboard-link-demo" style="white-space:normal;height:auto;min-height:44px;padding:10px 18px">
          Open Demo Center — run the attack or clean scenario
        </a>
      </div>
    </div>
  </div>`;
  animateGauges(view);
}
