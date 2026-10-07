import { api } from "../api.js";
import { esc, fmtTime } from "../format.js";
import { icon } from "../icons.js";
import { emptyState, loading, pageHeader, quietState } from "../ui.js";

function downloadJson(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default async function Evidence(view, ctx) {
  const header = pageHeader("Evidence Ledger", "Every proof row links to its source event — no stage is claimed without it.");
  view.innerHTML = `<div class="stack">${header}${loading(400)}</div>`;
  const analysis = await api.analysis();
  if (!ctx.alive()) return;
  const chain = analysis?.chains?.[0];
  if (!analysis) {
    view.innerHTML = `<div class="stack">${header}${emptyState("No analysis stored", "Run a demo first — evidence is validated against stored events by the pipeline.")}</div>`;
    return;
  }
  if (!chain) {
    view.innerHTML = `<div class="stack">${header}${quietState("evidence-quiet-state", "No evidence ledger",
      "Nothing to prove while the system is quiet — the engine stays silent on benign activity rather than generating alerts.")}</div>`;
    return;
  }
  const rows = chain.stages.flatMap((s) => s.evidence.map((r) => ({ ...r, stage: s.stage_num, stageName: s.name })));
  const distinct = new Set(rows.map((r) => r.event_id)).size;
  const validation = analysis.pipeline.find((p) => p.stage_num === 9);
  view.innerHTML = `<div class="stack">
    ${header}
    <div class="row" data-testid="evidence-summary">
      <span class="tag tag-cyan" style="padding:6px 12px;font-size:12px">${rows.length} evidence rows</span>
      <span class="tag tag-outline" style="padding:6px 12px;font-size:12px">${distinct} distinct source events</span>
      <span class="tag tag-outline" style="padding:6px 12px;font-size:12px">chain ${esc(chain.id)} · ${chain.stages.length} stages</span>
      ${validation ? `<span class="mono text-11 t-emerald">${icon("check-circle", 12)} ${esc(validation.detail)}</span>` : ""}
      <button class="btn btn-outline btn-sm ml-auto" id="export-evidence" data-testid="evidence-export">${icon("download", 14)} Export case JSON</button>
    </div>
    <div class="card card-pad-xs">
      <div class="table-wrap"><table class="table table-mono table-pad" data-testid="evidence-card-table">
        <thead><tr><th>Time</th><th>Event</th><th>Stage</th><th>Field</th><th>Value</th><th>Proof note</th></tr></thead>
        <tbody>${rows.map((r, i) => `
          <tr class="row-click" data-event-id="${esc(r.event_id)}" data-testid="evidence-row-${esc(r.event_id)}-${i}">
            <td class="t-muted">${esc(fmtTime(r.timestamp))}</td>
            <td class="nowrap"><span class="row-xs t-cyan">${icon("file-check", 12)} ${esc(r.event_id)}</span></td>
            <td class="t-dim nowrap">${esc(r.stage)}. ${esc(r.stageName)}</td>
            <td class="t-300">${esc(r.field)}</td>
            <td class="semibold t-100">${esc(r.value)}</td>
            <td class="t-dim">${esc(r.note)}</td>
          </tr>`).join("")}</tbody>
      </table></div>
    </div>
  </div>`;
  view.querySelector("#export-evidence").addEventListener("click", () => {
    downloadJson(`cybertrace-${chain.id}-case.json`, {
      generated_at: analysis.created_at, chain_id: chain.id, pattern: chain.pattern_name, state: chain.state,
      risk: chain.risk, timeline: chain.stages.map((s) => ({ stage: s.stage_num, name: s.name, timestamp: s.timestamp, mitre: s.mitre_id, event_ids: s.event_ids, reason: s.reason })),
      evidence: rows, explanation: chain.explanation, recommendations: chain.recommendations,
      note: "SYNTHETIC DEMONSTRATION DATA",
    });
  });
}
