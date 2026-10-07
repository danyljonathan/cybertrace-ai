import { api } from "../api.js";
import { esc, fmtDateTime } from "../format.js";
import { icon } from "../icons.js";
import { pageHeader, toast } from "../ui.js";

const PAGE_SIZE = 50;
const state = { q: "", user: "", eventType: "", offset: 0 };

export default async function LogExplorer(view, ctx) {
  let debounce = null;
  let reqId = 0;
  let uploading = false;

  view.innerHTML = `<div class="stack">
    ${pageHeader("Log Explorer", "The raw normalized event store — every anomaly, chain and graph node traces back here.")}
    <section class="card card-pad-sm" data-testid="log-import">
      <div class="row between">
        <h3 class="section-title">${icon("upload", 14, "t-cyan")} Import your own logs</h3>
        <span class="text-11 t-dim">JSON array / JSON Lines / CSV · fields: timestamp, user, device, ip, application, resource, event_type, action, location, usb_device, destination, bytes, baseline</span>
      </div>
      <div class="grid grid-gap-sm md-2 mt-3">
        <label class="dropzone" id="dropzone" data-testid="log-import-dropzone">
          <input type="file" id="file-input" accept=".json,.jsonl,.csv,application/json,text/csv" hidden />
          ${icon("upload", 18)}<br /><span id="drop-label">Drop a log file here or click to browse (max 10 MB)</span>
        </label>
        <div class="stack-sm">
          <div class="row radio-row">
            <label><input type="radio" name="mode" value="append" checked /> Append to current store (evaluated against the existing baseline)</label>
            <label><input type="radio" name="mode" value="replace" /> Replace store (rows with <code>baseline: true</code> form the baseline; else the last 24h are evaluated)</label>
          </div>
          <div class="row-sm">
            <button class="btn btn-primary btn-sm" id="upload-btn" data-testid="log-import-button" disabled>${icon("upload", 14)} Import &amp; analyze</button>
            <a class="link" href="/samples/network_exfiltration_logs.json" download>${icon("download", 12)} sample: network exfiltration</a>
            <a class="link" href="/samples/custom_logs_template.csv" download>${icon("download", 12)} CSV template</a>
          </div>
          <p class="mono text-11 t-dim" id="upload-result"></p>
        </div>
      </div>
    </section>
    <div class="row">
      <input class="input max-w-xs" id="q" data-testid="log-explorer-search-input" placeholder="Search event id, user, device, ip, resource…" value="${esc(state.q)}" />
      <input class="input w-52" id="user" data-testid="log-explorer-user-input" placeholder="user filter (e.g. user_001)" value="${esc(state.user)}" />
      <select class="select w-56" id="etype" data-testid="log-explorer-type-select"><option value="">All event types</option></select>
      <span class="ml-auto mono text-xs t-dim" id="count" data-testid="log-explorer-count"></span>
      <div class="row-sm">
        <button class="btn btn-outline btn-sm btn-icon" id="prev" data-testid="log-explorer-prev" aria-label="Previous page">${icon("chevron-left", 14)}</button>
        <button class="btn btn-outline btn-sm btn-icon" id="next" data-testid="log-explorer-next" aria-label="Next page">${icon("chevron-right", 14)}</button>
      </div>
    </div>
    <div class="card card-pad-xs">
      <div class="table-wrap"><table class="table table-mono table-pad" data-testid="log-explorer-table" style="font-size:12.5px">
        <thead><tr><th>Time (UTC)</th><th>Event ID</th><th>Type</th><th>Action</th><th>User</th><th>Device</th><th>IP</th><th>App</th><th>Resource</th><th>Location</th></tr></thead>
        <tbody id="rows"><tr><td colspan="10" class="center t-dim" style="padding:24px">Loading events…</td></tr></tbody>
      </table></div>
    </div>
  </div>`;

  const $ = (sel) => view.querySelector(sel);

  const loadTypes = async () => {
    try {
      const stats = await api.stats();
      if (!ctx.alive()) return;
      $("#etype").innerHTML = `<option value="" data-testid="log-type-all">All event types</option>` +
        stats.events_by_type.map((t) => `<option value="${esc(t.type)}" data-testid="log-type-${esc(t.type)}"${t.type === state.eventType ? " selected" : ""}>${esc(t.type)} (${t.count})</option>`).join("");
    } catch { /* filter stays usable without counts */ }
  };

  const loadRows = async () => {
    const id = ++reqId;
    try {
      const page = await api.events({ q: state.q, user: state.user, event_type: state.eventType, limit: PAGE_SIZE, offset: state.offset });
      if (!ctx.alive() || id !== reqId) return;
      const total = page.total;
      $("#count").textContent = `${total} events · showing ${Math.min(state.offset + 1, total)}–${Math.min(state.offset + PAGE_SIZE, total)}`;
      $("#prev").disabled = state.offset === 0;
      $("#next").disabled = state.offset + PAGE_SIZE >= total;
      $("#rows").innerHTML = page.items.map((ev) => `
        <tr class="row-click" data-event-id="${esc(ev.event_id)}" data-testid="log-row-${esc(ev.event_id)}">
          <td class="t-muted nowrap">${esc(fmtDateTime(ev.timestamp).replace(" UTC", ""))}</td>
          <td class="t-cyan nowrap">${esc(ev.event_id)}</td>
          <td class="t-200">${esc(ev.event_type)}</td>
          <td class="t-muted">${esc(ev.action ?? "—")}</td>
          <td class="t-200">${esc(ev.user ?? "—")}</td>
          <td class="t-300">${esc(ev.device ?? "—")}</td>
          <td class="t-300">${esc(ev.ip ?? "—")}</td>
          <td class="t-300">${esc(ev.application ?? "—")}</td>
          <td class="t-300">${esc(ev.resource ?? ev.metadata?.usb_device ?? ev.metadata?.destination ?? "—")}</td>
          <td class="t-dim">${esc(ev.location ?? "—")}</td>
        </tr>`).join("") || `<tr><td colspan="10" class="center t-dim" style="padding:24px" data-testid="log-explorer-empty">No events match the filters.</td></tr>`;
    } catch (err) {
      if (ctx.alive() && id === reqId) $("#rows").innerHTML = `<tr><td colspan="10" class="center t-rose" style="padding:24px">${esc(err.message)}</td></tr>`;
    }
  };

  const onInput = (e) => {
    if (e.target.id !== "q" && e.target.id !== "user") return;
    state[e.target.id] = e.target.value;
    state.offset = 0;
    clearTimeout(debounce);
    debounce = setTimeout(loadRows, 200);
  };
  const onChange = (e) => {
    if (e.target.id === "etype") {
      state.eventType = e.target.value;
      state.offset = 0;
      loadRows();
    } else if (e.target.id === "file-input") {
      pickFile(e.target.files?.[0]);
    }
  };
  let file = null;
  const pickFile = (f) => {
    file = f || null;
    $("#drop-label").textContent = file ? `${file.name} (${(file.size / 1024).toFixed(1)} KB)` : "Drop a log file here or click to browse (max 10 MB)";
    $("#upload-btn").disabled = !file || uploading;
  };
  const onClick = async (e) => {
    if (e.target.closest("#prev")) { state.offset = Math.max(0, state.offset - PAGE_SIZE); loadRows(); }
    if (e.target.closest("#next")) { state.offset += PAGE_SIZE; loadRows(); }
    if (e.target.closest("#upload-btn") && file && !uploading) {
      uploading = true;
      $("#upload-btn").disabled = true;
      $("#upload-result").textContent = "Uploading and running the 13-stage pipeline…";
      try {
        const mode = view.querySelector("input[name=mode]:checked").value;
        const res = await api.upload(file, mode, 30);
        const s = res.summary;
        const msg = `${res.ingested} events imported (${res.error_count} rejected) · ${s.anomalies} anomalies · ${s.high_confidence_attacks} attack chain(s) · status ${s.system_status}`;
        if (ctx.alive()) $("#upload-result").textContent = msg + (res.errors.length ? ` · first issue: ${res.errors[0]}` : "");
        toast(s.high_confidence_attacks ? "error" : "success",
          s.high_confidence_attacks ? `HIGH-CONFIDENCE ATTACK in imported logs — risk ${s.risk_score}/100` : "Import analyzed — no coordinated attack", msg);
        state.offset = 0;
        if (ctx.alive()) { loadTypes(); loadRows(); }
      } catch (err) {
        const detail = err.body?.detail;
        const text = typeof detail === "string" ? detail : detail?.message ? `${detail.message}: ${(detail.errors || []).slice(0, 2).join("; ")}` : err.message;
        if (ctx.alive()) $("#upload-result").textContent = `Import failed — ${text}`;
        toast("error", "Import failed", text);
      } finally {
        uploading = false;
        if (ctx.alive()) $("#upload-btn").disabled = !file;
      }
    }
  };
  const dz = $("#dropzone");
  const over = (e) => { e.preventDefault(); dz.classList.add("over"); };
  const leave = () => dz.classList.remove("over");
  const drop = (e) => { e.preventDefault(); leave(); pickFile(e.dataTransfer.files?.[0]); };
  dz.addEventListener("dragover", over);
  dz.addEventListener("dragleave", leave);
  dz.addEventListener("drop", drop);

  view.addEventListener("input", onInput);
  view.addEventListener("change", onChange);
  view.addEventListener("click", onClick);
  await Promise.all([loadTypes(), loadRows()]);
  return () => {
    clearTimeout(debounce);
    view.removeEventListener("input", onInput);
    view.removeEventListener("change", onChange);
    view.removeEventListener("click", onClick);
  };
}
