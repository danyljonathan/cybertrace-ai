"""CyberTrace detection engine — 13 deterministic, explainable pipeline stages.

    1 Log Ingestion            6 Event Correlation             11 Explanation
    2 Normalization            7 Sequence / Order Analysis     12 Recommended Action
    3 Entity Extraction        8 Attack Chain Reconstruction   13 Verdict
    4 Behavioral Baseline      9 Evidence Validation
    5 Anomaly Detection       10 Risk Assessment

Escalation ladder (false-positive control):
    0 anomalies                              -> NORMAL
    1 isolated anomaly                       -> SUSPICIOUS_EVENT (never escalated)
    2+ related anomalies                     -> POSSIBLE_INCIDENT
    3+ related anomalies + ordered pattern   -> HIGH_CONFIDENCE_ATTACK

"Related" is strict: same principal AND a shared non-user entity (device / IP / resource /
application / USB / destination) inside the investigation window — never time alone.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .patterns import ANOMALY_RULES, CORRELATION_BONUS, PLAYBOOK, active_patterns, risk_tier

ENTITY_KEYS = ("user", "device", "ip", "application", "resource", "usb_device", "destination")
LINK_KEYS = ("device", "ip", "resource", "application", "usb_device", "destination")
LARGE_TRANSFER_BYTES = 100_000_000

STAGE_DEFS = [
    ("Log Ingestion", "Load raw security log events from the stream"),
    ("Normalization", "Normalize fields, types and timestamps (UTC, aware)"),
    ("Entity Extraction", "Extract users, devices, IPs, apps, resources, USB devices"),
    ("Behavioral Baseline", "Learn per-user normals from ambient history"),
    ("Anomaly Detection", "Apply the explainable rule registry to evaluated events"),
    ("Event Correlation", "Link anomalies via shared entities inside the investigation window"),
    ("Sequence / Order Analysis", "Verify chronological ordering and window fit"),
    ("Attack Chain Reconstruction", "Match ordered patterns and rebuild the chain"),
    ("Evidence Validation", "Every stage must reference existing source events"),
    ("Risk Assessment", "Deterministic weighted score from evidence (0-100)"),
    ("Explanation", "Build observed-evidence vs interpretation narrative"),
    ("Recommended Action", "Derive playbook actions from observed stages"),
    ("Verdict", "System status decision from the escalation ladder"),
]


# --------------------------------------------------------------------------- helpers
def parse_ts(value: str) -> datetime:
    s = str(value).strip().replace(" ", "T", 1)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def hms(ts: str) -> str:
    return parse_ts(ts).strftime("%H:%M:%S")


def hm(ts: str) -> str:
    return parse_ts(ts).strftime("%H:%M")


def fmt_bytes(n: int | float) -> str:
    n = float(n)
    if n >= 1e9:
        return f"{n / 1e9:.1f} GB"
    if n >= 1e6:
        return f"{n / 1e6:.0f} MB"
    if n >= 1e3:
        return f"{n / 1e3:.0f} KB"
    return f"{int(n)} B"


def _bytes_of(ev: dict) -> int | None:
    b = (ev.get("metadata") or {}).get("bytes")
    try:
        return int(b) if b is not None else None
    except (TypeError, ValueError):
        return None


def entities_of(ev: dict) -> dict[str, list[str]]:
    meta = ev.get("metadata") or {}
    out: dict[str, list[str]] = {}
    for k in ENTITY_KEYS:
        v = meta.get(k) if k in ("usb_device", "destination") else ev.get(k)
        if v not in (None, ""):
            out[k] = [str(v)]
    return out


def _known(values: set[str]) -> str:
    return ", ".join(sorted(values)) if values else "none"


# ------------------------------------------------------------------------- baseline
@dataclass
class Baseline:
    events: int = 0
    locations: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    devices: set[str] = field(default_factory=set)
    resources: set[str] = field(default_factory=set)
    apps: set[str] = field(default_factory=set)
    usb: set[str] = field(default_factory=set)
    destinations: set[str] = field(default_factory=set)
    login_hours: set[int] = field(default_factory=set)


def build_baselines(events: list[dict]) -> dict[str, Baseline]:
    out: dict[str, Baseline] = defaultdict(Baseline)
    for ev in events:
        u = ev.get("user")
        if not u:
            continue
        b = out[u]
        b.events += 1
        meta = ev.get("metadata") or {}
        if ev.get("location"):
            b.locations.add(ev["location"])
        if ev.get("ip"):
            b.ips.add(ev["ip"])
        if ev.get("device"):
            b.devices.add(ev["device"])
        if ev.get("resource"):
            b.resources.add(ev["resource"])
        if ev.get("application"):
            b.apps.add(ev["application"])
        if meta.get("usb_device"):
            b.usb.add(str(meta["usb_device"]))
        if meta.get("destination"):
            b.destinations.add(str(meta["destination"]))
        if ev.get("event_type") == "AUTH_LOGIN":
            b.login_hours.add(parse_ts(ev["timestamp"]).hour)
    return dict(out)


# -------------------------------------------------------------------- anomaly rules
def _rule_login(ev: dict, b: Baseline) -> str | None:
    if ev.get("event_type") != "AUTH_LOGIN":
        return None
    if str((ev.get("metadata") or {}).get("auth_result", "success")).lower() not in ("success", "ok", "true"):
        return None
    user, loc, ip, dev = ev.get("user"), ev.get("location"), ev.get("ip"), ev.get("device")
    clauses: list[str] = []
    if loc and loc not in b.locations:
        clauses.append(f"logged in from a new location '{loc}' that is not in the user's baseline "
                       f"(known: {_known(b.locations)})")
    if ip and ip not in b.ips:
        clauses.append(f"source IP {ip} was never seen for this user (known: {_known(b.ips)})")
    if dev and dev not in b.devices:
        clauses.append(f"device {dev} was never used by this user (known: {_known(b.devices)})")
    if not clauses:
        return None
    if not clauses[0].startswith("logged in"):
        clauses[0] = "logged in, and " + clauses[0]
    return f"User {user} " + " and ".join(clauses) + "."


def _rule_resource(ev: dict, b: Baseline) -> str | None:
    if ev.get("event_type") != "FILE_ACCESS" or not ev.get("resource"):
        return None
    if ev["resource"] in b.resources:
        return None
    return (f"User {ev.get('user')} has no previous access history for resource '{ev['resource']}' in the "
            f"baseline data (known resources: {_known(b.resources)}).")


def _rule_usb(ev: dict, b: Baseline) -> str | None:
    usb = (ev.get("metadata") or {}).get("usb_device")
    if ev.get("event_type") != "USB_CONNECT" or not usb or usb in b.usb:
        return None
    return (f"USB device '{usb}' connected to {ev.get('device')} is not in user {ev.get('user')}'s baseline "
            f"(known USB devices: {_known(b.usb)}).")


def _rule_copy(ev: dict, b: Baseline) -> str | None:
    usb = (ev.get("metadata") or {}).get("usb_device")
    if ev.get("event_type") != "FILE_COPY" or not usb:
        return None
    new_usb = usb not in b.usb
    new_res = bool(ev.get("resource")) and ev["resource"] not in b.resources
    if not (new_usb or new_res):
        return None
    size = _bytes_of(ev)
    what = f"{fmt_bytes(size)} copied" if size else "Data copied"
    src = f" from '{ev['resource']}'" if ev.get("resource") else ""
    why = []
    if new_usb:
        why.append(f"which is not in user {ev.get('user')}'s baseline")
    if new_res:
        why.append("the resource has no prior access history")
    return f"{what}{src} to USB device '{usb}', " + " and ".join(why) + "."


def _rule_outbound(ev: dict, b: Baseline) -> str | None:
    dest = (ev.get("metadata") or {}).get("destination")
    size = _bytes_of(ev)
    if ev.get("event_type") != "NETWORK_CONNECTION" or not dest or not size:
        return None
    if size < LARGE_TRANSFER_BYTES or dest in b.destinations:
        return None
    return (f"{fmt_bytes(size)} sent by {ev.get('user')} to '{dest}', a destination never seen for this user "
            f"(known: {_known(b.destinations)}), above the {fmt_bytes(LARGE_TRANSFER_BYTES)} threshold.")


RULES = (
    ("NEW_LOCATION_LOGIN", _rule_login),
    ("NEW_RESOURCE_ACCESS", _rule_resource),
    ("USB_CONNECTION", _rule_usb),
    ("FILE_COPY_TO_REMOVABLE", _rule_copy),
    ("LARGE_OUTBOUND_TRANSFER", _rule_outbound),
)


# ----------------------------------------------------------------------- evidence
def evidence_rows(ev: dict) -> list[dict[str, str]]:
    eid, ts, meta = ev["event_id"], ev["timestamp"], ev.get("metadata") or {}
    rows = [{"field": "event_type", "value": f"{ev['event_type']} / {ev.get('action') or '—'}",
             "note": "Raw event type and action"}]
    spec = [
        ("user", ev.get("user"), "Principal involved"),
        ("device", ev.get("device"), "Device involved"),
        ("ip", ev.get("ip"), "Source IP address"),
        ("location", ev.get("location"), "Geographic location"),
        ("application", ev.get("application"), "Application involved"),
        ("resource", ev.get("resource"), "Resource involved"),
        ("usb_device", meta.get("usb_device"), "Removable device"),
        ("destination", meta.get("destination"), "Network destination"),
    ]
    rows += [{"field": f, "value": str(v), "note": n} for f, v, n in spec if v not in (None, "")]
    size = _bytes_of(ev)
    if size is not None:
        rows.append({"field": "bytes", "value": f"{size:,}", "note": "Data volume"})
    return [{"event_id": eid, "timestamp": ts, **r} for r in rows]


def _evidence_matches(row: dict, ev: dict | None) -> bool:
    if ev is None or ev["timestamp"] != row["timestamp"]:
        return False
    f, meta = row["field"], ev.get("metadata") or {}
    if f == "event_type":
        return row["value"] == f"{ev['event_type']} / {ev.get('action') or '—'}"
    if f == "bytes":
        size = _bytes_of(ev)
        return size is not None and row["value"] == f"{size:,}"
    actual = meta.get(f) if f in ("usb_device", "destination") else ev.get(f)
    return actual is not None and str(actual) == row["value"]


def observed_fact(ev: dict) -> str:
    meta = ev.get("metadata") or {}
    parts = [f"{ev['event_id']} @ {hms(ev['timestamp'])} UTC · {ev['event_type']} {ev.get('action') or ''}:"
             f" {ev.get('user') or 'unknown user'}"]
    if ev.get("ip"):
        parts.append(f"from IP {ev['ip']}")
    if ev.get("location"):
        parts.append(f"({ev['location']})")
    if ev.get("device"):
        parts.append(f"on {ev['device']}")
    if ev.get("resource"):
        parts.append(f"accessing '{ev['resource']}'")
    if meta.get("usb_device"):
        parts.append(f"via USB '{meta['usb_device']}'")
    if meta.get("destination"):
        parts.append(f"to '{meta['destination']}'")
    size = _bytes_of(ev)
    if size is not None:
        parts.append(f"[{fmt_bytes(size)}]")
    return " · ".join(parts)


# ----------------------------------------------------------------------- the engine
def split_baseline(events: list[dict]) -> tuple[list[dict], list[dict], str]:
    """Baseline = ambient-tagged history; without it, the most recent EVAL_HOURS are evaluated."""
    from .config import EVAL_HOURS

    ambient = [e for e in events if e.get("source_tag") == "ambient"]
    if ambient:
        return ambient, [e for e in events if e.get("source_tag") != "ambient"], "tagged"
    if not events:
        return [], [], "empty"
    latest = max(parse_ts(e["timestamp"]) for e in events)
    cutoff = latest - timedelta(hours=EVAL_HOURS)
    base = [e for e in events if parse_ts(e["timestamp"]) <= cutoff]
    evaluated = [e for e in events if parse_ts(e["timestamp"]) > cutoff]
    return base, evaluated, f"time-split (last {EVAL_HOURS}h evaluated)"


def _shared_entities(group: list[dict]) -> dict[str, list[str]]:
    n = len(group)
    counts: dict[tuple[str, str], int] = defaultdict(int)
    for a in group:
        for k, vs in a["entities"].items():
            for v in vs:
                counts[(k, v)] += 1
    shared: dict[str, list[str]] = defaultdict(list)
    for (k, v), c in sorted(counts.items()):
        if c * 2 > n:  # held by a strict majority of the related anomalies
            shared[k].append(v)
    return dict(shared)


def _related(a: dict, b: dict, window: timedelta) -> bool:
    if a["user"] != b["user"] or not a["user"]:
        return False
    if abs(a["_dt"] - b["_dt"]) > window:
        return False
    for k in LINK_KEYS:
        if set(a["entities"].get(k, [])) & set(b["entities"].get(k, [])):
            return True
    return False


def _correlate(anomalies: list[dict], window: timedelta) -> list[list[dict]]:
    """Union-find over strictly-related pairs, then split so each group's span fits the window."""
    parent = list(range(len(anomalies)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    for i in range(len(anomalies)):
        for j in range(i + 1, len(anomalies)):
            if anomalies[j]["_dt"] - anomalies[i]["_dt"] > window:
                break  # sorted by time — nothing later can be inside the window
            if _related(anomalies[i], anomalies[j], window):
                parent[find(j)] = find(i)
    comps: dict[int, list[dict]] = defaultdict(list)
    for i, a in enumerate(anomalies):
        comps[find(i)].append(a)
    groups: list[list[dict]] = []
    for comp in comps.values():
        comp.sort(key=lambda a: (a["_dt"], a["id"]))
        current: list[dict] = []
        for a in comp:
            if current and a["_dt"] - current[0]["_dt"] > window:
                groups.append(current)
                current = []
            current.append(a)
        groups.append(current)
    groups.sort(key=lambda g: g[0]["_dt"])
    return groups


def _match_pattern(group: list[dict]) -> tuple[dict, list[tuple[dict, dict]]] | None:
    """Return the best active pattern whose stages are all observed in chronological order."""
    best = None
    for p in active_patterns():
        mapping = p["anomaly_mapping"]
        matched: list[tuple[dict, dict]] = []
        idx = 0
        for a in group:  # group is time-ordered
            if idx >= len(p["stages"]):
                break
            if mapping.get(a["anomaly_type"]) == p["stages"][idx]["key"]:
                matched.append((a, p["stages"][idx]))
                idx += 1
        if idx == len(p["stages"]) and (best is None or len(matched) > len(best[1])):
            best = (p, matched)
    return best


def _build_chain(chain_num: int, pattern: dict, matched: list[tuple[dict, dict]],
                 shared: dict[str, list[str]], window_minutes: int, ev_by_id: dict[str, dict]) -> dict:
    stages, factors, event_ids = [], [], []
    for i, (a, st) in enumerate(matched, start=1):
        ev = ev_by_id[a["event_id"]]
        event_ids.append(ev["event_id"])
        stages.append({
            "stage_num": i, "stage_type": st["key"], "name": st["name"], "timestamp": ev["timestamp"],
            "entities": a["entities"], "event_ids": [ev["event_id"]], "evidence": evidence_rows(ev),
            "reason": a["reason"], "risk_contribution": a["risk_points"], "mitre_id": st["mitre_id"],
            "derived": False,
        })
        ents = [v for k in ("user", "device", "ip", "resource") for v in a["entities"].get(k, [])]
        factors.append({"factor": a["title"], "points": a["risk_points"],
                        "detail": f"{ev['event_id']} @ {hms(ev['timestamp'])} — {' / '.join(ents)}"})
    n = len(matched)
    shared_keys = sorted(shared)
    factors.append({
        "factor": "Strong entity correlation", "points": CORRELATION_BONUS,
        "detail": f"{n} anomalies share {', '.join(shared_keys)} and occur within {window_minutes} minutes "
                  f"in matching order",
    })
    raw = sum(f["points"] for f in factors)
    score = min(100, raw)
    formula = " + ".join(f"{f['factor']} +{f['points']}" for f in factors) + f" = {score}/100"
    if raw > 100:
        formula += f" (capped from {raw})"
    synth_entities = {k: shared[k] for k in ("user", "device", "ip") if k in shared}
    stages.append({
        "stage_num": n + 1,
        "stage_type": pattern["synthesis"].upper().replace(" ", "_"),
        "name": pattern["synthesis"],
        "timestamp": stages[-1]["timestamp"],
        "entities": synth_entities,
        "event_ids": list(event_ids),
        "evidence": [row for s in stages for row in s["evidence"]],
        "reason": pattern["synthesis_reason"].format(n=n),
        "risk_contribution": CORRELATION_BONUS,
        "mitre_id": pattern["synthesis_mitre"],
        "derived": True,
    })

    def uniq(key: str) -> list[str]:
        seen: list[str] = []
        for eid in event_ids:
            v = ev_by_id[eid].get(key)
            if v and v not in seen:
                seen.append(v)
        return seen

    recs: list[dict] = []
    for s in stages:
        for r in PLAYBOOK.get(s["stage_type"], []):
            if r not in recs:
                recs.append(dict(r))

    chain = {
        "id": f"CHN-{chain_num:04d}",
        "pattern_id": pattern["id"],
        "pattern_name": pattern["name"],
        "name": pattern["name"],
        "state": "HIGH_CONFIDENCE_ATTACK",
        "risk": {"score": score, "tier": risk_tier(score), "factors": factors, "formula": formula},
        "stages": stages,
        "event_ids": event_ids,
        "window_minutes": window_minutes,
        "users": uniq("user"), "devices": uniq("device"), "ips": uniq("ip"),
        "apps": uniq("application"), "resources": uniq("resource"),
        "first_seen": stages[0]["timestamp"],
        "last_seen": stages[-1]["timestamp"],
        "recommendations": recs,
    }
    chain["explanation"] = deterministic_explanation(chain, ev_by_id, pattern)
    return chain


def deterministic_explanation(chain: dict, ev_by_id: dict[str, dict], pattern: dict) -> dict:
    real = [s for s in chain["stages"] if not s["derived"]]
    observed = [observed_fact(ev_by_id[s["event_ids"][0]]) for s in real]
    interp = [f"{i}. {s['reason']}" for i, s in enumerate(real, start=1)]
    interp.append(
        f"{len(real) + 1}. These events share the same user/device and occur in a meaningful chronological "
        f"sequence within the investigation window, matching the registered pattern '{pattern['name']}'."
    )
    steps = "; ".join(f"{hm(s['timestamp'])} {s['name']} ({s['event_ids'][0]})" for s in real)
    first_action = next((r["action"] for r in chain["recommendations"] if r["priority"] == "IMMEDIATE"), None)
    narrative = (
        f"Between {hm(chain['first_seen'])} and {hm(chain['last_seen'])} UTC, {', '.join(chain['users'])} on "
        f"{', '.join(chain['devices']) or 'an unknown device'} produced {len(real)} anomalous events that "
        f"CyberTrace linked into a single chain: {steps}. Each step is individually explainable against the "
        f"user's 14-day behavioral baseline, and together they follow the registered pattern "
        f"'{pattern['name']}' in order, scoring {chain['risk']['score']}/100 ({chain['risk']['tier']}). "
        f"{pattern['conclusion']}"
        + (f" First response: {first_action[0].lower() + first_action[1:]}." if first_action else "")
    )
    return {
        "observed_evidence": observed,
        "interpretation": interp,
        "conclusion": pattern["conclusion"],
        "generated_by": "deterministic-rules",
        "narrative": narrative,
    }


def run_analysis(events: list[dict], *, window_minutes: int, mode: str | None,
                 scenario_label: str | None = None) -> dict[str, Any]:
    window = timedelta(minutes=window_minutes)
    pipeline: list[dict] = []

    def report(inp: int, out: int, detail: str) -> None:
        num = len(pipeline) + 1
        name, desc = STAGE_DEFS[num - 1]
        pipeline.append({"stage_num": num, "name": name, "description": desc,
                         "input_count": inp, "output_count": out, "detail": detail})

    # 1 Ingestion
    baseline_events, evaluated, split_mode = split_baseline(events)
    report(0, len(events), f"{len(events)} events loaded ({len(baseline_events)} baseline + "
                           f"{len(evaluated)} evaluated; split: {split_mode})")

    # 2 Normalization — storage already holds normalized events; verify timestamps parse.
    for e in events:
        e["_dt"] = parse_ts(e["timestamp"])
    report(len(events), len(events), "All timestamps normalized to UTC; entity fields trimmed")

    # 3 Entity extraction
    ent: dict[str, set[str]] = defaultdict(set)
    for e in events:
        for k, vs in entities_of(e).items():
            ent[k].update(vs)
    ent_total = sum(len(v) for v in ent.values())
    report(len(events), ent_total,
           f"{len(ent['user'])} users · {len(ent['device'])} devices · {len(ent['ip'])} IPs · "
           f"{len(ent['application'])} apps · {len(ent['resource'])} resources · "
           f"{len(ent['usb_device'])} USB devices")

    # 4 Baseline
    baselines = build_baselines(baseline_events)
    report(len(baseline_events), len(baselines),
           f"{len(baseline_events)} baseline events profiled for {len(baselines)} users "
           f"(locations, IPs, devices, resources, apps, USB devices, destinations)")

    # 5 Anomaly detection
    anomalies: list[dict] = []
    skipped_no_baseline = 0
    for ev in sorted(evaluated, key=lambda e: (e["_dt"], e["event_id"])):
        b = baselines.get(ev.get("user") or "")
        if b is None:
            skipped_no_baseline += 1  # conservative: no baseline -> no claim
            continue
        for atype, rule in RULES:
            reason = rule(ev, b)
            if reason:
                meta = ANOMALY_RULES[atype]
                anomalies.append({
                    "id": f"ANM-{len(anomalies) + 1:04d}", "event_id": ev["event_id"],
                    "timestamp": ev["timestamp"], "user": ev.get("user"), "device": ev.get("device"),
                    "ip": ev.get("ip"), "resource": ev.get("resource"), "anomaly_type": atype,
                    "title": meta["title"], "reason": reason, "state": "SUSPICIOUS_EVENT",
                    "risk_points": meta["points"], "entities": entities_of(ev), "_dt": ev["_dt"],
                })
                break  # one anomaly per event — the most specific rule wins
    detail = f"{len(anomalies)} anomalies across {len(evaluated)} evaluated events"
    if skipped_no_baseline:
        detail += f" ({skipped_no_baseline} events from users without a baseline were not scored)"
    report(len(evaluated), len(anomalies), detail)

    # 6 Correlation
    groups = _correlate(anomalies, window)
    related = [g for g in groups if len(g) >= 2]
    isolated = [g[0] for g in groups if len(g) == 1]
    report(len(anomalies), len(related),
           f"{len(related)} correlation group(s); window = {window_minutes} min; linkage requires same user "
           f"+ shared non-user entities")

    # 7 Ordering
    report(len(related), len(related),
           "All groups ordered by actual event timestamps; spans within the investigation window"
           if related else "No related groups to order")

    # 8 Chain reconstruction
    ev_by_id = {e["event_id"]: e for e in events}
    correlations, chains = [], []
    for g in related:
        shared = _shared_entities(g)
        span = (g[-1]["_dt"] - g[0]["_dt"]).total_seconds() / 60
        shared_txt = ", ".join(f"{k}: {', '.join(v)}" for k, v in shared.items()) or "entities pairwise"
        base_reason = (f"{len(g)} related anomalies share {shared_txt} and occur within a "
                       f"{span:g}-minute span (investigation window: {window_minutes} min).")
        match = _match_pattern(g) if len(g) >= 3 else None
        corr = {
            "id": f"COR-{len(correlations) + 1:04d}",
            "anomaly_ids": [a["id"] for a in g], "event_ids": [a["event_id"] for a in g],
            "shared_entities": shared, "window_minutes": window_minutes, "span_minutes": round(span, 1),
            "pattern_id": None, "pattern_match": None,
        }
        if match:
            pattern, matched = match
            seq = " -> ".join(st["name"] for _, st in matched)
            corr["pattern_id"] = pattern["id"]
            corr["pattern_match"] = f"Observed in order: {seq} (pattern {pattern['id']})"
            corr["state"] = "HIGH_CONFIDENCE_ATTACK"
            corr["reason"] = f"{base_reason} Escalated to HIGH_CONFIDENCE_ATTACK: {corr['pattern_match']}."
            chains.append(_build_chain(len(chains) + 1, pattern, matched, shared, window_minutes, ev_by_id))
        else:
            corr["state"] = "POSSIBLE_INCIDENT"
            corr["reason"] = (f"{base_reason} Held at POSSIBLE_INCIDENT: no registered attack pattern was "
                              f"observed in order, so no attack is claimed.")
        for a in g:
            a["state"] = corr["state"]
        correlations.append(corr)
    report(len(related), len(chains),
           f"{len(chains)} chain(s) reconstructed" +
           (f" from {', '.join(sorted({c['pattern_id'] for c in chains}))}" if chains else
            " — no registered ordered pattern observed"))

    # 9 Evidence validation
    rows = [r for c in chains for s in c["stages"] for r in s["evidence"]]
    ok = sum(1 for r in rows if _evidence_matches(r, ev_by_id.get(r["event_id"])))
    report(len(rows), ok, f"{ok}/{len(rows)} evidence rows verified against stored events"
                          + (" — every stage has proof" if ok == len(rows) else " — UNVERIFIED ROWS PRESENT"))
    if ok != len(rows):  # never claim a stage without proof
        chains = [c for c in chains if all(_evidence_matches(r, ev_by_id.get(r["event_id"]))
                                           for s in c["stages"] for r in s["evidence"])]

    # 10 Risk
    chains.sort(key=lambda c: -c["risk"]["score"])
    top = chains[0] if chains else None
    report(len(chains), len(chains),
           f"Top chain risk {top['risk']['score']}/100 ({top['risk']['tier']}): {top['risk']['formula']}"
           if top else "No chain — no risk score claimed")

    # 11 Explanation, 12 Recommendations
    report(len(chains), len(chains),
           "Deterministic explanation generated from stages and evidence; AI may rephrase downstream"
           if chains else "Nothing to explain — the explanation engine answers for attack chains only")
    n_recs = sum(len(c["recommendations"]) for c in chains)
    report(len(chains), n_recs, f"{n_recs} recommended action(s) produced")

    # 13 Verdict
    possible = sum(1 for c in correlations if c["state"] == "POSSIBLE_INCIDENT")
    if chains:
        status = "ATTACK_DETECTED"
        n_ev = len({e for c in chains for e in c["event_ids"]})
        verdict = (f"HIGH-CONFIDENCE ATTACK DETECTED — {len(chains)} coordinated attack chain"
                   f"{'s' if len(chains) > 1 else ''} reconstructed from {n_ev} correlated events "
                   f"(risk {top['risk']['score']}/100 {top['risk']['tier']}).")
    elif possible:
        status = "POSSIBLE_INCIDENT"
        verdict = (f"POSSIBLE INCIDENT — {possible} group(s) of related anomalies found, but no registered "
                   f"attack pattern was observed in order. Analyst review recommended; no attack is claimed.")
    else:
        status = "QUIET"
        verdict = ("NO COORDINATED ATTACK DETECTED — system remains quiet: no sufficient correlated evidence"
                   + (f" ({len(isolated)} isolated signal{'s' if len(isolated) != 1 else ''} held at "
                      f"SUSPICIOUS EVENT)." if isolated else ". All evaluated events match the baseline."))
    report(len(correlations), 1, verdict.split(" — ")[0])

    for e in events:
        e.pop("_dt", None)
    for a in anomalies:
        a.pop("_dt", None)

    summary = {
        "total_events": len(events),
        "evaluated_events": len(evaluated),
        "baseline_events": len(baseline_events),
        "anomalies": len(anomalies),
        "suspicious_events": len(isolated),
        "possible_incidents": possible,
        "high_confidence_attacks": len(chains),
        "isolated_signals": len(isolated),
        "system_status": status,
        "verdict_message": verdict,
        "risk_score": top["risk"]["score"] if top else 0,
        "risk_tier": top["risk"]["tier"] if top else "LOW",
    }
    return {
        "id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "mode": mode,
        "window_minutes": window_minutes,
        "scenario_label": scenario_label or "Stored event set",
        "baseline_mode": split_mode,
        "pipeline": pipeline,
        "summary": summary,
        "anomalies": anomalies,
        "correlations": correlations,
        "chains": chains,
        "isolated_anomalies": [a["id"] for a in isolated],
    }
