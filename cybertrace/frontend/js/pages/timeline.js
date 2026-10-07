import { api } from "../api.js";
import { esc, fmtTime, fmtTimeSec } from "../format.js";
import { icon } from "../icons.js";
import { emptyState, loading, pageHeader, quietState } from "../ui.js";

export default async function AttackTimeline(view, ctx) {
  const header = pageHeader("Attack Timeline", "Chronological order generated from actual event timestamps — never reordered by the UI.");
  view.innerHTML = `<div class="stack">${header}${loading(420)}</div>`;
  const analysis = await api.analysis();
  if (!ctx.alive()) return;
  const chain = analysis?.chains?.[0];
  if (!analysis) {
    view.innerHTML = `<div class="stack">${header}${emptyState("No analysis stored", "Run a demo first — the timeline is generated from the attack chain's evidence.")}</div>`;
    return;
  }
  if (!chain) {
    view.innerHTML = `<div class="stack">${header}${quietState("timeline-quiet-state", "Nothing on the timeline",
      "No coordinated attack detected — the system remains quiet. Every timeline entry must trace back to a stored event, so no timeline exists without a chain.")}</div>`;
    return;
  }
  const items = chain.stages.map((s) => `
    <li data-testid="timeline-stage-${s.stage_num}">
      <span class="tl-dot ${s.derived ? "derived" : ""}"></span>
      <p class="mono text-sm bold t-cyan">${esc(fmtTimeSec(s.timestamp))} UTC</p>
      <div class="inner-lg mt-2 ${s.derived ? "b-dashed-amber bg-amber-faint" : ""}">
        <div class="row-sm">
          <span class="text-sm semibold ${s.derived ? "t-amber italic" : "t-100"}">${esc(s.stage_num)}. ${esc(s.name)}</span>
          <span class="tag tag-mitre">MITRE ${esc(s.mitre_id)}</span>
          <span class="ml-auto mono text-11 t-cyan">risk +${esc(s.risk_contribution)}</span>
        </div>
        <p class="mt-2 text-xs relaxed t-300">${esc(s.reason)}</p>
        <div class="mt-2 row-sm">
          ${s.event_ids.map((eid) => `<button class="evid-btn" data-event-id="${esc(eid)}" data-testid="timeline-evidence-${s.stage_num}-${esc(eid)}">Evidence: ${esc(eid)}</button>`).join("")}
          ${Object.entries(s.entities).flatMap(([k, vs]) => vs.map((v) => `<span class="mono text-11 t-dim">${esc(k)}: ${esc(v)}</span>`)).join("")}
        </div>
      </div>
    </li>`).join("");
  view.innerHTML = `<div class="stack">
    ${header}
    <section class="card" data-testid="attack-timeline-container">
      <div class="row mb-6">
        ${icon("clock", 16, "t-cyan")}
        <h2 class="h3">${esc(chain.pattern_name)}</h2>
        <span class="mono text-xs t-muted">${esc(fmtTime(chain.first_seen))} → ${esc(fmtTime(chain.last_seen))} UTC · investigation window ${esc(chain.window_minutes)} min</span>
      </div>
      <ol class="timeline">${items}</ol>
      <p class="mt-4 mono text-11 t-dim">Source of truth: event timestamps in the stored logs. The final marker is the engine's interpretation of the stages before it.</p>
    </section>
  </div>`;
}
