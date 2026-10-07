// Formatting + severity styling helpers. All times are displayed in UTC.

export function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const asDate = (iso) => new Date(iso);

export function fmtTime(iso) {
  return asDate(iso).toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "UTC" });
}

export function fmtTimeSec(iso) {
  return asDate(iso).toLocaleTimeString("en-GB", {
    hour: "2-digit", minute: "2-digit", second: "2-digit", timeZone: "UTC",
  });
}

export function fmtDateTime(iso) {
  return asDate(iso).toLocaleString("en-GB", {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "UTC",
  }) + " UTC";
}

export function fmtDateTimeSec(iso) {
  return asDate(iso).toLocaleString("en-GB", {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit", timeZone: "UTC",
  }) + " UTC";
}

export function fmtBytes(n) {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} GB`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} MB`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} KB`;
  return `${n} B`;
}

export const STATE_LABELS = {
  NORMAL: "NORMAL",
  SUSPICIOUS_EVENT: "SUSPICIOUS EVENT",
  POSSIBLE_INCIDENT: "POSSIBLE INCIDENT",
  HIGH_CONFIDENCE_ATTACK: "HIGH-CONFIDENCE ATTACK",
  NO_DATA: "AWAITING DATA",
  QUIET: "SYSTEM QUIET",
  ATTACK_DETECTED: "ATTACK DETECTED",
};

export const STATE_DOT = {
  NORMAL: "#10B981",
  QUIET: "#10B981",
  SUSPICIOUS_EVENT: "#F59E0B",
  POSSIBLE_INCIDENT: "#F97316",
  HIGH_CONFIDENCE_ATTACK: "#EF4444",
  ATTACK_DETECTED: "#EF4444",
  NO_DATA: "#64748B",
};

export const TIER_COLORS = { LOW: "#10B981", MEDIUM: "#F59E0B", HIGH: "#F97316", CRITICAL: "#EF4444" };

export const NODE_COLORS = {
  USER: "#38BDF8",
  DEVICE: "#818CF8",
  IP_ADDRESS: "#F43F5E",
  APPLICATION: "#A855F7",
  RESOURCE: "#F59E0B",
  USB_PERIPHERAL: "#EF4444",
};
