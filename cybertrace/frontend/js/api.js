// Fetch layer over the FastAPI backend, plus a tiny query cache with invalidation.
// BASE is relative so the same build works locally and behind any single-origin deploy.
// Set window.CYBERTRACE_API (e.g. in index.html) to point at a separately hosted backend.
const BASE = (window.CYBERTRACE_API || "") + "/api";

export class ApiError extends Error {
  constructor(status, body) {
    super(typeof body?.detail === "string" ? body.detail : `request failed with ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.body = body;
  }
}

async function request(method, path, body, isForm = false) {
  let res;
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      headers: body === undefined || isForm ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : isForm ? body : JSON.stringify(body),
    });
  } catch (err) {
    throw new ApiError(0, { detail: "The backend is unreachable — is the server running?" });
  }
  if (!res.ok) {
    const errBody = await res.json().catch(() => null);
    throw new ApiError(res.status, errBody);
  }
  if (res.status === 204) return undefined;
  return res.json();
}

export const apiGet = (path) => request("GET", path);
export const apiPost = (path, body) => request("POST", path, body ?? {});
export const apiUpload = (path, formData) => request("POST", path, formData, true);

// ---------------------------------------------------------------- query cache
const cache = new Map(); // key -> { promise, at }
const listeners = new Set();

export function query(key, fn, { maxAgeMs = 15_000 } = {}) {
  const hit = cache.get(key);
  if (hit && Date.now() - hit.at < maxAgeMs) return hit.promise;
  const promise = fn();
  cache.set(key, { promise, at: Date.now() });
  promise.catch(() => cache.delete(key)); // never cache failures
  return promise;
}

export function invalidate(prefixes) {
  for (const k of [...cache.keys()]) {
    if (prefixes.some((p) => k === p || k.startsWith(p + ":"))) cache.delete(k);
  }
  listeners.forEach((fn) => fn(prefixes));
}

export function onInvalidate(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

// Swallow 404s (= "nothing stored yet") into null; rethrow real failures.
async function orNull(promise) {
  try {
    return await promise;
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}

export const api = {
  stats: () => query("stats", () => apiGet("/stats"), { maxAgeMs: 5_000 }),
  analysis: () => query("analysis", () => orNull(apiGet("/analysis/latest"))),
  events: (filters = {}) => {
    const params = new URLSearchParams();
    if (filters.q) params.set("q", filters.q);
    if (filters.user) params.set("user", filters.user);
    if (filters.event_type) params.set("event_type", filters.event_type);
    params.set("limit", String(filters.limit ?? 100));
    params.set("offset", String(filters.offset ?? 0));
    const qs = params.toString();
    return query(`events:${qs}`, () => apiGet(`/events?${qs}`), { maxAgeMs: 5_000 });
  },
  event: (id) => query(`event:${id}`, () => apiGet(`/events/${encodeURIComponent(id)}`), { maxAgeMs: 60_000 }),
  graph: () => query("graph", () => apiGet("/graph")),
  explanation: (id = "latest") => query(`explanation:${id}`, () => orNull(apiGet(`/explanation/${id}`))),
  patterns: () => query("patterns", () => apiGet("/demo/patterns"), { maxAgeMs: 600_000 }),

  async runDemo(scenario, windowMinutes) {
    const res = await apiPost(`/demo/${scenario}`, { window_minutes: windowMinutes });
    invalidate(["stats", "analysis", "events", "event", "graph", "explanation"]);
    return res;
  },
  async analyze(windowMinutes) {
    const res = await apiPost("/analyze", { window_minutes: windowMinutes });
    invalidate(["stats", "analysis", "graph", "explanation"]);
    return res;
  },
  async upload(file, mode, windowMinutes) {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("mode", mode);
    fd.append("window_minutes", String(windowMinutes));
    const res = await apiUpload("/events/upload", fd);
    invalidate(["stats", "analysis", "events", "event", "graph", "explanation"]);
    return res;
  },
  async reset() {
    const res = await apiPost("/reset");
    invalidate(["stats", "analysis", "events", "event", "graph", "explanation"]);
    return res;
  },
};
