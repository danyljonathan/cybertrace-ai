import { api } from "../api.js";
import { esc, fmtTime } from "../format.js";
import {
  emptyState, loading, pageHeader, pipelineVisualizer, stateBadge, stateDot, toast, windowSelect,
} from "../ui.js";

const LADDER = [
  { state: "NORMAL", rule: "0 anomalies", text: "Nothing to report — all evaluated events match the behavioral baseline." },
  { state: "SUSPICIOUS_EVENT", rule: "1 anomaly", text: "Recorded as a single signal. No correlation — never escalated." },
  { state: "POSSIBLE_INCIDENT", rule: "2 related anomalies", text: "Anomalies sharing entities (device/IP/resource/app) inside the investigation window." },
  { state: "HIGH_CONFIDENCE_ATTACK", rule: "3+ related anomalies + registered pattern match", text: "The ordered stage sequence of a registered attack pattern is observed." },
];

const WEIGHTS = [
  ["Unusual Login", "+15", "Login from a location, IP or device not in the user's baseline"],
  ["Unusual Resource Access", "+20", "First-time access to a resource with no baseline history"],
  ["New USB Device", "+20", "Removable device not in the user's baseline"],
  ["File Copy to Removable Media", "+25", "Copying to a new USB device / first-time resource"],
  ["Large Transfer to New Destination", "+25", ">= 100 MB sent to a destination never seen for the user"],
  ["Strong Entity Correlation", "+10", "3+ anomalies sharing entities in matching order within the window"],
];

let windowMinutes = null;

export default async function ThreatDetection(view, ctx) {
  const header = pageHeader("Threat Detection", "How logs become anomalies, correlations and a verdict — every threshold published.");
  view.innerHTML = `<div class="stack">${header}${loading(60)}${loading(400)}</div>`;
  let busy = false;

  const paint = (a) => {
    if (!a) {
      view.innerHTML = `<div class="stack">${header}${emptyState("No analysis stored",
        "Run a demo first — the detection engine then shows its full trace here: anomalies, correlation groups and the escalation decision.")}</div>`;
      return;
    }
    windowMinutes = windowMinutes ?? String(a.window_minutes);
    const anomalies = a.anomalies.map((an) => `
      <div class="card card-pad-sm" data-testid="anomaly-card-${esc(an.id)}">
        <div class="row-sm">${stateBadge(an.state, `anomaly-state-${an.id}`)}
          <span class="text-sm medium t-100">${esc(an.title)}</span>
          <span class="ml-auto mono text-xs bold t-cyan">+${esc(an.risk_points)}</span></div>
        <p class="mt-2 text-xs relaxed t-300">${esc(an.reason)}</p>
        <div class="mt-2 row-sm mono text-11 t-dim">
          <button class="text-btn" data-event-id="${esc(an.event_id)}" data-testid="anomaly-event-link-${esc(an.id)}">${esc(an.event_id)}</button>
          <span>${esc(fmtTime(an.timestamp))} UTC</span>
          ${Object.entries(an.entities).map(([k, vs]) => `<span class="tag">${esc(k)}: ${esc(vs.join(", "))}</span>`).join("")}
        </div>
      </div>`).join("") || `<p class="text-sm t-dim" data-testid="no-anomalies">Zero anomalies — every evaluated event matched the behavioral baseline.</p>`;

    const correlations = a.correlations.map((c) => `
      <div class="card card-pad-sm" data-testid="correlation-card-${esc(c.id)}">
        <div class="row-sm">${stateBadge(c.state, `correlation-state-${c.id}`)}
          <span class="mono text-xs t-muted">${esc(c.anomaly_ids.join(" + "))} · span ${esc(c.span_minutes)} min · window ${esc(c.window_minutes)} min</span></div>
        <p class="mt-2 text-xs relaxed t-300">${esc(c.reason)}</p>
        ${c.shared_entities && Object.keys(c.shared_entities).length ? `<div class="mt-2 row-xs">${Object.entries(c.shared_entities).map(([k, vs]) =>
          `<span class="tag tag-cyan">shared ${esc(k)}: ${esc(vs.join(", "))}</span>`).join("")}</div>` : ""}
      </div>`).join("");

    const isolatedNote = a.isolated_anomalies.length > 0
      ? `<p class="callout callout-amber" data-testid="isolated-note">${a.isolated_anomalies.length} isolated signal(s) held at SUSPICIOUS EVENT — the engine
          stays quiet without multiple related signals (false-positive control).</p>` : "";

    view.innerHTML = `<div class="stack">
      ${header}
      <div class="row">
        <label class="eyebrow t-muted" for="detect-window">Investigation window</label>
        ${windowSelect("detect-window", windowMinutes, "detection-window-select", "detection-window-option")}
        <button class="btn btn-outline btn-sm" id="rerun" data-testid="rerun-analysis-button" ${busy ? "disabled" : ""}>${busy ? "Re-running…" : "Re-run analysis"}</button>
        <span class="mono text-11 t-dim">last run: ${esc(fmtTime(a.created_at))} UTC · window ${esc(a.window_minutes)} min · ${esc(a.summary.baseline_events)} baseline events · ${esc(a.summary.evaluated_events)} evaluated</span>
      </div>
      ${pipelineVisualizer(a.pipeline, false, 0)}
      <section>
        <h3 class="section-title mb-3">Escalation ladder — deterministic thresholds</h3>
        <div class="grid grid-gap-sm sm-2 xl-4" data-testid="escalation-ladder">${LADDER.map((l) => `
          <div class="card card-pad-sm">
            <div class="row-sm">${stateDot(l.state)}${stateBadge(l.state, `ladder-badge-${l.state}`)}</div>
            <p class="mt-2 mono text-xs bold t-cyan">${esc(l.rule)}</p>
            <p class="mt-1 text-xs snug t-muted">${esc(l.text)}</p>
          </div>`).join("")}</div>
      </section>
      <section class="card">
        <h3 class="section-title">Risk weight table — never random</h3>
        <div class="table-wrap mt-3"><table class="table" data-testid="risk-weights-table">
          <thead><tr><th>Evidence</th><th>Weight</th><th>Why</th></tr></thead>
          <tbody>${WEIGHTS.map(([f, p, w]) => `<tr><td class="t-200">${esc(f)}</td><td class="mono bold t-cyan">${p}</td><td class="text-xs t-muted">${esc(w)}</td></tr>`).join("")}</tbody>
        </table></div>
      </section>
      <section>
        <h3 class="section-title mb-3">Anomalies (${a.anomalies.length})</h3>
        <div class="grid grid-gap-sm xl-2">${anomalies}</div>
      </section>
      <section>
        <h3 class="section-title mb-3">Correlation groups (${a.correlations.length})</h3>
        <div class="stack-md">${correlations}${isolatedNote}
          ${!a.correlations.length && !a.isolated_anomalies.length ? `<p class="text-sm t-dim">No correlation groups — nothing to link.</p>` : ""}</div>
      </section>
    </div>`;
  };

  const load = async () => {
    const a = await api.analysis();
    if (ctx.alive()) paint(a);
    return a;
  };

  const onClick = async (e) => {
    if (!e.target.closest("#rerun") || busy) return;
    busy = true;
    e.target.closest("#rerun").disabled = true;
    e.target.closest("#rerun").textContent = "Re-running…";
    try {
      const res = await api.analyze(Number(windowMinutes));
      toast("success", `Analysis re-run — ${res.summary.anomalies} anomalies, ${res.summary.high_confidence_attacks} chain(s)`);
    } catch (err) {
      toast("error", "Analysis failed — is the backend reachable?", err.message);
    } finally {
      busy = false;
      if (ctx.alive()) await load();
    }
  };
  const onChange = (e) => {
    if (e.target.id === "detect-window") windowMinutes = e.target.value;
  };
  view.addEventListener("click", onClick);
  view.addEventListener("change", onChange);
  await load();
  return () => {
    view.removeEventListener("click", onClick);
    view.removeEventListener("change", onChange);
  };
}
