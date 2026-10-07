import { api } from "../api.js";
import { esc, fmtTime } from "../format.js";
import { icon } from "../icons.js";
import { pageHeader, pipelineVisualizer, stateBadge, statusBanner, toast, windowSelect } from "../ui.js";

const ATTACK_STAGES = [
  { time: "09:12", name: "Unusual login", detail: "user_001 authenticates from 203.0.113.99 (Singapore, SG) — never seen in their baseline" },
  { time: "09:16", name: "Unusual file access", detail: "same user reads confidential_project_files — no prior access history" },
  { time: "09:21", name: "USB connected", detail: "a new removable device (usb_device_03) is attached to device_07" },
  { time: "09:23", name: "File copy to USB", detail: "2.1 GB of the accessed files are copied to that USB device" },
];

const CLEAN_FACTS = [
  "Normal logins from known IPs, devices and locations for all 8 synthetic users",
  "Regular file access to in-baseline resources",
  "A routine, in-baseline USB backup by the operator user_006",
  "Exactly ONE isolated signal (a conference login) — held at SUSPICIOUS, never escalated",
];

// Survives navigation within the session, like the original page's component state.
const session = { windowMinutes: "30", result: null };

function outcome(result, running) {
  if (!result) {
    return running ? `<p class="mt-4 text-sm t-dim">Running the 13-stage pipeline…</p>`
      : `<p class="mt-4 text-sm t-dim">No run in this session yet. The dashboard reflects the latest stored analysis.</p>`;
  }
  const res = result.analysis;
  const chain = res.chains[0];
  const s = res.summary;
  const stats = [["EVENTS", s.total_events], ["ANOMALIES", s.anomalies], ["INCIDENTS", s.possible_incidents], ["ATTACKS", s.high_confidence_attacks]];
  const body = chain ? `
    <div class="inner-lg b-rose bg-rose" style="padding:16px" data-testid="demo-result-attack">
      <div class="row-sm">${stateBadge(chain.state, "demo-result-state")}
        <span class="mono text-xs t-rose">RISK ${esc(chain.risk.score)}/100 (${esc(chain.risk.tier)})</span></div>
      <p class="mt-2 text-sm medium t-100">${esc(chain.pattern_name)}</p>
      <ol class="stack-xs mt-2">${chain.stages.map((st) => `
        <li class="row-sm mono text-xs t-300" style="flex-wrap:nowrap">
          <span class="t-dim">${esc(fmtTime(st.timestamp))}</span><span class="${st.derived ? "italic t-amber" : ""}">${esc(st.name)}</span>
          <button class="ml-auto text-btn" data-event-id="${esc(st.event_ids[0])}">${esc(st.event_ids[0])}</button>
        </li>`).join("")}</ol>
      <div class="row-sm mt-3">${[["/attack-chain", "Chain"], ["/attack-timeline", "Timeline"], ["/attack-graph", "Graph"],
        ["/evidence", "Evidence"], ["/explanation", "Explanation"], ["/threat-detection", "Detection"]].map(([to, label], i) =>
        `<a href="${to}" data-link class="link-chip" data-testid="result-link-${label.toLowerCase()}">${i === 0 ? "Inspect: " : ""}${label}</a>`).join("")}
      </div>
    </div>` : `
    <div class="inner-lg b-emerald bg-emerald" style="padding:16px" data-testid="demo-result-quiet">
      <p class="text-sm semibold t-emerald">${s.possible_incidents > 0 ? "POSSIBLE INCIDENT — NO ATTACK CLAIMED" : "NO COORDINATED ATTACK DETECTED"}</p>
      <p class="mt-1 text-xs relaxed t-300">System remains quiet — no sufficient correlated evidence.
        ${s.isolated_signals > 0 ? ` ${s.isolated_signals} isolated signal${s.isolated_signals > 1 ? "s were" : " was"} held at SUSPICIOUS EVENT: the escalation ladder requires multiple related signals before anything escalates.` : ""}</p>
      ${result.scenario === "clean" ? `<p class="mt-2 row-xs mono text-11 t-dim">${icon("usb", 12)} In-baseline USB activity (operator backup) raised no anomaly at all.</p>` : ""}
      <div class="row-sm mt-3"><a href="/threat-detection" data-link class="link-chip">Inspect: Detection</a><a href="/attack-graph" data-link class="link-chip">Graph</a></div>
    </div>`;
  return `<div class="mt-4 stack-md">
    <div class="grid grid-gap-sm cols-2 sm-4" data-testid="demo-result-stats">
      ${stats.map(([l, v]) => `<div class="inner center"><p class="mono text-xl bold t-white">${esc(v)}</p><p class="label-xs">${l}</p></div>`).join("")}
    </div>
    ${body}
    <p class="mono text-11 t-dim">ingested ${esc(result.events_ingested)} events (${esc(result.baseline_events)} baseline ambient · ${esc(s.evaluated_events)} evaluated) — ${esc(res.scenario_label)}</p>
  </div>`;
}

export default async function DemoCenter(view, ctx) {
  let running = false;
  let progress = 0;
  let timer = null;
  let storedPipeline = null;

  const paint = () => {
    const res = session.result?.analysis;
    const trace = res?.pipeline ?? storedPipeline;
    view.innerHTML = `<div class="stack">
      ${pageHeader("Demo Center", "Two deterministic scenarios — one reconstructs a coordinated attack, one must stay quiet.")}
      ${res ? statusBanner({ status: res.summary.system_status, verdict: res.summary.verdict_message, mode: session.result.scenario, riskScore: res.summary.risk_score, riskTier: res.summary.risk_tier }) : ""}
      <div class="grid lg-2">
        <section class="card b-rose" style="display:flex;flex-direction:column" data-testid="demo-card-attack">
          <div class="row-sm">${icon("siren", 18, "t-rose-400")}<h2 class="h2">Multi-Stage Attack Demo</h2></div>
          <p class="eyebrow mt-1">Official HackNex example scenario</p>
          <ol class="stack-sm mt-4" style="gap:10px">${ATTACK_STAGES.map((s, i) => `
            <li class="inner row-sm" style="align-items:flex-start;flex-wrap:nowrap;gap:12px">
              <span class="mono text-xs bold t-cyan">${s.time}</span>
              <span class="min-w-0"><span class="text-sm t-100" style="display:block">${i + 1}. ${esc(s.name)}</span>
              <span class="text-xs snug t-muted" style="display:block">${esc(s.detail)}</span></span>
            </li>`).join("")}</ol>
          <p class="callout callout-rose mt-4">EXPECTED: correlated chain → HIGH-CONFIDENCE ATTACK · RISK 90/100 (CRITICAL)</p>
          <div style="flex:1"></div>
          <button class="btn btn-danger btn-lg mt-4" data-run="attack" data-testid="btn-run-attack-demo" ${running ? "disabled" : ""}>
            ${icon("play-circle", 16)} ${running ? "Running…" : "RUN MULTI-STAGE ATTACK DEMO"}</button>
        </section>
        <section class="card b-emerald" style="display:flex;flex-direction:column" data-testid="demo-card-clean">
          <div class="row-sm">${icon("shield-check", 18, "t-emerald-400")}<h2 class="h2">Clean Log Demo</h2></div>
          <p class="eyebrow mt-1">Benign activity — false-positive control</p>
          <ul class="stack-sm mt-4" style="gap:10px">${CLEAN_FACTS.map((f) => `
            <li class="inner row-sm" style="align-items:flex-start;flex-wrap:nowrap">
              ${icon("check-circle", 14, "t-emerald-400")}<span class="text-xs snug t-300">${esc(f)}</span>
            </li>`).join("")}</ul>
          <p class="callout callout-emerald mt-4">EXPECTED: NO COORDINATED ATTACK DETECTED — system remains quiet</p>
          <div style="flex:1"></div>
          <button class="btn btn-success btn-lg mt-4" data-run="clean" data-testid="btn-run-clean-demo" ${running ? "disabled" : ""}>
            ${icon("play-circle", 16)} ${running ? "Running…" : "RUN CLEAN LOG DEMO"}</button>
        </section>
      </div>
      <div class="row">
        <label class="eyebrow t-muted" for="window-select">Investigation window</label>
        ${windowSelect("window-select", session.windowMinutes, "demo-window-select", "window-option")}
        <p class="text-11 t-dim flex-1" style="min-width:240px">Correlation only links anomalies that share entities within this window — running a demo
          regenerates the full synthetic dataset deterministically.</p>
      </div>
      <div class="grid lg-2">
        <div id="pipeline-slot">${pipelineVisualizer(trace, running, progress)}</div>
        <section class="card" data-testid="demo-result-panel">
          <h3 class="section-title">Outcome</h3>
          ${outcome(session.result, running)}
        </section>
      </div>
    </div>`;
  };

  const run = async (scenario) => {
    if (running) return;
    running = true;
    progress = 0;
    session.result = null;
    paint();
    const started = Date.now();
    timer = setInterval(() => {
      progress = Math.min(progress + 1, 12);
      const slot = view.querySelector("#pipeline-slot");
      if (slot) slot.innerHTML = pipelineVisualizer(null, true, progress);
    }, 140);
    try {
      const res = await api.runDemo(scenario, Number(session.windowMinutes));
      // Let the stage animation reach the end so the 13 steps are visible.
      const wait = Math.max(0, 13 * 140 - (Date.now() - started));
      await new Promise((r) => setTimeout(r, wait));
      session.result = res;
      const s = res.analysis.summary;
      if (s.high_confidence_attacks > 0) {
        toast("error", `HIGH-CONFIDENCE ATTACK — risk ${s.risk_score}/100 (${s.risk_tier})`,
          `${s.anomalies} anomalies correlated into an evidence-backed chain`);
      } else {
        toast("success", "Clean demo complete — system remains quiet", "No sufficient correlated evidence to escalate.");
      }
    } catch (err) {
      toast("error", "Demo run failed — is the backend reachable?", err.message);
    } finally {
      clearInterval(timer);
      timer = null;
      running = false;
      if (ctx.alive()) paint();
    }
  };

  const onClick = (e) => {
    const btn = e.target.closest("[data-run]");
    if (btn) run(btn.dataset.run);
  };
  const onChange = (e) => {
    if (e.target.id === "window-select") session.windowMinutes = e.target.value;
  };
  view.addEventListener("click", onClick);
  view.addEventListener("change", onChange);

  paint();
  if (!session.result) {
    const stored = await api.analysis().catch(() => null);
    if (ctx.alive() && stored && !running) {
      storedPipeline = stored.pipeline;
      paint();
    }
  }

  return () => {
    view.removeEventListener("click", onClick);
    view.removeEventListener("change", onChange);
    if (timer) clearInterval(timer);
  };
}
