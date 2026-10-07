import { api } from "../api.js";
import { esc } from "../format.js";
import { icon } from "../icons.js";
import { animateGauges, emptyState, loading, pageHeader, priorityTag, riskGauge, stateBadge, syntheticBadge, toast } from "../ui.js";

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Fallback for non-secure contexts (plain http on a LAN IP).
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

export default async function Explanation(view, ctx) {
  const subtitle = "Why CyberTrace believes something is an attack — and what to do next.";
  view.innerHTML = `<div class="stack">${pageHeader("Explanation", subtitle)}${loading(300)}</div>`;
  const data = await api.explanation("latest");
  if (!ctx.alive()) return;
  if (!data) {
    view.innerHTML = `<div class="stack">${pageHeader("Explanation", subtitle)}${emptyState("Nothing to explain yet",
      "The explanation engine answers for attack chains only — and stays silent on benign activity. Run the attack demo to generate one.")}</div>`;
    return;
  }
  const ex = data.explanation;
  const aiMode = ex.generated_by !== "deterministic-rules";
  const engineBadge = `<span data-testid="explanation-engine-badge" class="badge ${aiMode ? "t-violet" : "t-cyan"}" style="border-color:${aiMode ? "rgba(139,92,246,.4)" : "rgba(6,182,212,.4)"};background:${aiMode ? "rgba(139,92,246,.1)" : "rgba(6,182,212,.1)"};font-weight:400;letter-spacing:.1em">
    ${aiMode ? `AI NARRATIVE: ${esc(ex.generated_by)} — REPHRASED ENGINE OUTPUT ONLY` : "ENGINE: DETERMINISTIC RULES"}</span>`;

  view.innerHTML = `<div class="stack">
    ${pageHeader("Explanation", "WHY THIS WAS FLAGGED — observed evidence first, interpretation second.", engineBadge + syntheticBadge())}
    <div class="card card-pad-sm row" data-testid="explanation-chain-header">
      ${stateBadge(data.state, "explanation-state")}
      <p class="h3">${esc(data.chain_name)}</p>
      <span class="ml-auto mono text-xs t-muted">risk ${esc(data.risk.score)}/100 (${esc(data.risk.tier)}) · pattern ${esc(data.pattern_id)}</span>
    </div>
    <div class="grid lg-2">
      <section class="card" data-testid="explanation-observed-facts">
        <h2 class="section-title">${icon("eye", 14, "t-cyan")} Observed evidence — hard facts</h2>
        <ul class="stack-sm mt-4" style="gap:10px">${ex.observed_evidence.map((f) => `
          <li class="inner row-sm" style="align-items:flex-start;flex-wrap:nowrap;gap:10px"><span class="bullet"></span>
          <span class="mono text-xs relaxed t-200">${esc(f)}</span></li>`).join("")}</ul>
        <p class="mt-3 text-11 t-dim">Every fact above is a stored event — verify each in the Evidence ledger or Log Explorer.</p>
      </section>
      <section class="card" data-testid="explanation-ai-reasoning">
        <h2 class="section-title">${icon("sparkles", 14, "t-amber")} System interpretation — why this is an attack</h2>
        <ol class="stack-sm mt-4" style="gap:10px">${ex.interpretation.map((step, i) => `
          <li class="inner row-sm" style="align-items:flex-start;flex-wrap:nowrap;gap:10px">
          <span class="mono text-xs bold t-amber">${i + 1}.</span>
          <span class="text-xs relaxed t-200">${esc(step.replace(/^\d+\.\s*/, ""))}</span></li>`).join("")}</ol>
        <p class="mt-3 text-11 t-dim">Clearly separated from the observed facts: this column is the engine's reasoning, never new evidence.</p>
      </section>
    </div>
    <div class="card b-rose bg-rose" data-testid="explanation-conclusion">
      <p class="text-xs semibold upper t-rose">Conclusion</p>
      <p class="mt-2 text-base relaxed t-100">${esc(ex.conclusion)}</p>
    </div>
    ${riskGauge(data.risk)}
    <section class="card">
      <h2 class="section-title">Analyst narrative</h2>
      <p class="mt-3 text-sm relaxed t-200" data-testid="explanation-narrative">${esc(ex.narrative || "The deterministic narrative is generated with the analysis.")}</p>
    </section>
    <section>
      <h2 class="section-title mb-3">Recommended actions</h2>
      <div class="grid grid-gap-sm md-2" data-testid="recommended-actions">${data.recommendations.map((r, i) => `
        <div class="card card-pad-sm row between" style="align-items:flex-start;flex-wrap:nowrap">
          <div class="min-w-0">
            <div class="row-sm">${priorityTag(r.priority)}<span class="mono label-xs">${esc(r.category)}</span></div>
            <p class="mt-2 text-sm snug t-100">${esc(r.action)}</p>
          </div>
          <button class="copy-btn" data-copy="${i}" data-testid="action-remediation-button">${icon("check", 12)} copy</button>
        </div>`).join("") || `<p class="text-sm t-dim">No remediation actions for this state.</p>`}</div>
    </section>
  </div>`;
  animateGauges(view);
  view.querySelectorAll("[data-copy]").forEach((btn) => btn.addEventListener("click", async () => {
    const ok = await copyText(data.recommendations[Number(btn.dataset.copy)].action);
    toast(ok ? "success" : "error", ok ? "Action copied to clipboard" : "Could not copy to clipboard");
  }));
}
