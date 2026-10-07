import { api } from "../api.js";
import { esc } from "../format.js";
import { icon } from "../icons.js";
import { pageHeader, PIPELINE_STAGE_NAMES } from "../ui.js";

const JUDGING = [
  ["A. Links separate events into one chain, in the right order",
    "Anomalies sharing entities within the window are ordered by real timestamps and matched against a registered pattern", "/attack-timeline"],
  ["B. Identifies attacks without excessive false alarms",
    "1 anomaly = SUSPICIOUS, 2 = POSSIBLE INCIDENT, only a matched ordered pattern = HIGH-CONFIDENCE ATTACK", "/threat-detection"],
  ["C. Catches all the real attacks / extends to new ones",
    "Pattern registry (active + roadmap) and anomaly rule registry are data, not code changes — two active patterns ship today", "/architecture"],
  ["D. Connects users, devices, IPs and apps",
    "Entity extraction builds the correlation substrate; the graph renders only observed relationships", "/attack-graph"],
  ["E. Stays quiet on clean logs",
    "Clean demo: benign USB copy raises nothing; one isolated signal stays at SUSPICIOUS", "/demo"],
  ["F. Accurate attack timeline",
    "Timeline is generated from actual event timestamps — 09:12 → 09:16 → 09:21 → 09:23", "/attack-timeline"],
  ["G. Explains WHY it is an attack",
    "Observed evidence and system interpretation are strictly separated; AI only rephrases engine output", "/explanation"],
];

export default async function Architecture(view, ctx) {
  const registry = (patterns) => patterns.map((p) => `
    <div class="inner-lg" style="padding:16px">
      <div class="row-sm">
        <span class="mono text-sm t-100">${esc(p.name)}</span>
        <span class="badge ${p.status === "active" ? "tag-cyan" : "badge-synthetic"}" data-testid="pattern-status-${esc(p.id)}">${esc(p.status.toUpperCase())}</span>
        <span class="ml-auto mono text-10 t-dim">${esc(p.id)}</span>
      </div>
      <p class="mt-2 text-xs relaxed t-muted">${esc(p.description)}</p>
      <div class="mt-2 row-xs mono text-11">${p.stages.map((s, i) => `${i > 0 ? `<span class="t-faint">${icon("arrow-right", 10)}</span>` : ""}
        <span class="tag ${p.status === "active" ? "tag-cyan" : ""}" style="border:0">${esc(s.name)} · ${esc(s.mitre_id)}</span>`).join("")}</div>
    </div>`).join("");

  const paint = (patterns, loadingPatterns, error) => {
    view.innerHTML = `<div class="stack">
      ${pageHeader("Architecture", "Detection-first, AI-second — every threshold deterministic and published.")}
      <section class="card">
        <h2 class="section-title">${icon("workflow", 14, "t-cyan")} Detection pipeline — 13 deterministic stages</h2>
        <div class="grid grid-gap-sm cols-2 sm-3 lg-4 xl-5 mt-4" data-testid="architecture-pipeline">${PIPELINE_STAGE_NAMES.map((n, i) => `
          <div class="inner row-sm" style="flex-wrap:nowrap"><span class="mono text-xs t-cyan">${String(i + 1).padStart(2, "0")}</span><span class="text-xs t-200">${esc(n)}</span></div>`).join("")}
        </div>
      </section>
      <div class="grid lg-2">
        <section class="card">
          <h2 class="section-title">${icon("cpu", 14, "t-cyan")} Role of AI — detection is never delegated</h2>
          <div class="stack-sm mt-4">${[
            ["1", "Deterministic engine", "Anomalies, correlation, ordering, stages, evidence and risk are computed by published rules — reproducible on every run.", "b-cyan-strong"],
            ["2", "Structured facts only", "The AI layer receives the verified chain as JSON. It is prompted to rephrase — never to invent events, entities or timestamps.", ""],
            ["3", "Deterministic fallback", "No GEMINI_API_KEY, API error or timeout → the rule-based narrative is served. The app stays fully functional.", "b-emerald"],
          ].map(([n, t, b, cls]) => `<div class="inner-lg ${cls}"><p class="mono text-11 t-dim">STEP ${n}</p><p class="text-sm medium t-100">${esc(t)}</p><p class="mt-1 text-xs relaxed t-muted">${esc(b)}</p></div>`).join("")}</div>
        </section>
        <section class="card">
          <h2 class="section-title">${icon("scale", 14, "t-cyan")} False-positive control</h2>
          <div class="stack-sm mt-4">${[
            ["LADDER", "NORMAL → SUSPICIOUS EVENT (1 anomaly) → POSSIBLE INCIDENT (2 related) → HIGH-CONFIDENCE ATTACK (3+ related + registered ordered pattern)."],
            ["CORRELATION IS STRICT", "Anomalies correlate only when they share a principal AND a non-user entity (device / IP / resource / app / USB) inside the investigation window — never on time alone."],
            ["NO BASELINE, NO CLAIM", "Events from users without baseline history are not scored, so an unfamiliar dataset cannot flood the analyst with alerts."],
            ["NO EVIDENCE, NO STAGE", "A chain stage is emitted only when its supporting event exists in the store; the pipeline validates every evidence row against stored events."],
          ].map(([h, b]) => `<div class="inner-lg"><p class="mono text-xs t-cyan">${h}</p><p class="mt-1 text-xs relaxed t-300">${esc(b)}</p></div>`).join("")}</div>
        </section>
      </div>
      <section class="card">
        <h2 class="section-title">${icon("git-branch", 14, "t-cyan")} Attack-pattern registry — the extension point</h2>
        <p class="mt-2 text-xs t-dim">Adding a new multi-stage attack means adding an entry here (plus its anomaly rules) — detector code does not change.</p>
        <div class="stack-md mt-3" data-testid="pattern-registry">
          ${patterns ? registry(patterns) : ""}
          ${loadingPatterns ? `<p class="text-sm t-dim">Loading registry…</p>` : ""}
          ${error ? `<p class="text-sm t-rose">Registry unavailable — ${esc(error.message)}</p>` : ""}
        </div>
      </section>
      <section class="card">
        <h2 class="section-title">${icon("layers", 14, "t-cyan")} Judging-criteria map</h2>
        <div class="table-wrap mt-3"><table class="table" data-testid="judging-map">
          <thead><tr><th>Criterion</th><th>Where it lives</th><th>See it</th></tr></thead>
          <tbody>${JUDGING.map(([c, w, l]) => `<tr><td class="t-200" style="padding-top:10px;padding-bottom:10px">${esc(c)}</td><td class="text-xs snug t-muted">${esc(w)}</td>
            <td><a href="${l}" data-link class="mono text-xs t-cyan" data-testid="judging-link-${l.replace("/", "") || "dashboard"}">${l}</a></td></tr>`).join("")}</tbody>
        </table></div>
      </section>
      <section class="card" data-testid="team-card">
        <h2 class="section-title">Build provenance</h2>
        <div class="grid grid-gap-md sm-2 mt-3 text-sm t-300">
          <div class="stack-xs mono text-xs">
            <span>EVENT: HackNex 2026 — Internal Qualifier</span>
            <span>PROBLEM: HNX26PSI03 — AI-Powered Cyber Threat Intelligence</span>
            <span>TEAM: HNX-INT-035 — SkillIssue</span>
            <span>STACK: FastAPI + SQLite · vanilla JS SPA (no build step) · Gemini (optional)</span>
          </div>
          <div>
            <p class="mono label-xs">Team members</p>
            <ul class="stack-xs mt-1 text-xs t-300"><li>Harshan Nandha R</li><li>Danyl Jonathan D</li><li>S. M. Navaneetha Krishnan</li><li>Sugandh</li></ul>
          </div>
        </div>
      </section>
    </div>`;
  };

  paint(null, true, null);
  try {
    const patterns = await api.patterns();
    if (ctx.alive()) paint(patterns, false, null);
  } catch (err) {
    if (ctx.alive()) paint(null, false, err);
  }
}
