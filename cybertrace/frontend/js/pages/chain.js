import { api } from "../api.js";
import { esc, fmtTime } from "../format.js";
import { icon } from "../icons.js";
import { animateGauges, emptyState, loading, pageHeader, quietState, riskGauge, stateBadge } from "../ui.js";

function stageCard(stage) {
  const entities = Object.entries(stage.entities).flatMap(([k, vs]) =>
    vs.map((v) => `<span class="tag tag-outline">${esc(k)}: ${esc(v)}</span>`)).join("");
  const evidence = stage.evidence.map((row, i) => `
    <tr>
      <td class="mono" style="padding-left:12px"><button class="text-btn" data-event-id="${esc(row.event_id)}" data-testid="stage-evidence-event-${stage.stage_num}-${i}">${esc(row.event_id)}</button></td>
      <td class="mono t-muted">${esc(fmtTime(row.timestamp))}</td>
      <td class="mono t-300">${esc(row.field)}</td>
      <td class="mono t-100">${esc(row.value)}</td>
      <td class="t-dim">${esc(row.note)}</td>
    </tr>`).join("");
  return `<div class="card ${stage.derived ? "b-dashed-amber bg-amber-faint" : ""}" data-testid="attack-chain-stage-${stage.stage_num}">
    <div class="row">
      <span class="stage-num ${stage.derived ? "derived" : ""}">${esc(stage.stage_num)}</span>
      <h3 class="h3">${esc(stage.name)}</h3>
      <span class="mono text-sm t-cyan">${esc(fmtTime(stage.timestamp))} UTC</span>
      <span class="tag tag-mitre">MITRE ${esc(stage.mitre_id)}</span>
      <span class="ml-auto mono text-xs t-cyan">risk +${esc(stage.risk_contribution)}</span>
    </div>
    <div class="row-xs mt-3">${entities}</div>
    <p class="mt-3 text-sm relaxed t-300">${esc(stage.reason)}</p>
    <div class="mt-3 inner" style="padding:0">
      <p class="row-xs text-11 semibold upper t-muted" style="padding:8px 12px;border-bottom:1px solid var(--border-inner)">${icon("file-check", 12)} Evidence — proof for this stage</p>
      <div class="table-wrap"><table class="table table-compact" data-testid="stage-evidence-${stage.stage_num}"><tbody>${evidence}</tbody></table></div>
    </div>
    ${stage.derived ? `<p class="mt-2 mono text-11 upper t-amber-400">System interpretation — derived from the evidenced stages above (no separate source event)</p>` : ""}
  </div>`;
}

export default async function AttackChain(view, ctx) {
  const header = pageHeader("Attack Chain", "Reconstructed stages in observed order — click any evidence row to open the raw event.");
  view.innerHTML = `<div class="stack">${header}${loading(90)}${loading(300)}</div>`;
  const analysis = await api.analysis();
  if (!ctx.alive()) return;
  const chain = analysis?.chains?.[0];
  if (!analysis) {
    view.innerHTML = `<div class="stack">${header}${emptyState("No analysis stored", "Run a demo first — the chain is reconstructed only from correlated evidence.")}</div>`;
    return;
  }
  if (!chain) {
    view.innerHTML = `<div class="stack">${header}${quietState("chain-quiet-state", "No attack chain claimed",
      "The engine stays quiet without sufficient correlated evidence — a chain is only built when a registered multi-stage pattern is observed in order. This is the false-positive control working as designed.")}</div>`;
    return;
  }
  const more = analysis.chains.length > 1
    ? `<p class="mono text-11 t-dim">${analysis.chains.length} chains detected — showing the highest-risk chain ${esc(chain.id)}.</p>` : "";
  view.innerHTML = `<div class="stack">
    ${header}
    <div class="card b-rose row" data-testid="chain-header">
      <div class="min-w-0">
        <p class="h2">${esc(chain.pattern_name)}</p>
        <p class="mono text-11 t-dim">pattern ${esc(chain.pattern_id)} · ${esc(chain.users.join(", "))} · window ${esc(chain.window_minutes)} min · events ${esc(chain.event_ids.join(", "))}</p>
      </div>
      <div class="ml-auto row-sm">${stateBadge(chain.state, "chain-state-badge")}</div>
    </div>
    ${more}
    ${riskGauge(chain.risk)}
    <div>${chain.stages.map((s, i) => `${i > 0 ? `<div class="connector" data-testid="stage-connector-${i}">${icon("arrow-down", 18)}</div>` : ""}${stageCard(s)}`).join("")}</div>
  </div>`;
  animateGauges(view);
}
