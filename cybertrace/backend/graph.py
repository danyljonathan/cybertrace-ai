"""Entity-relationship graph built strictly from stored events.

Nodes are real entities (users, devices, IPs, applications, resources, USB peripherals);
edges are relationships observed in events. Nothing is decorative: every node and edge
carries the event ids it came from.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from .engine import parse_ts

CONTEXT_HOURS = 24
MAX_CONTEXT_EVENTS = 12
MAX_QUIET_EVENTS = 40


def _relations(ev: dict) -> list[tuple[str, str, str, str, str]]:
    """(source_type, source_label, target_type, target_label, relation) tuples for one event."""
    meta = ev.get("metadata") or {}
    u, d, ip, app, res = ev.get("user"), ev.get("device"), ev.get("ip"), ev.get("application"), ev.get("resource")
    usb, dest = meta.get("usb_device"), meta.get("destination")
    et = ev.get("event_type")
    out: list[tuple[str, str, str, str, str]] = []
    if et == "AUTH_LOGIN":
        if u and ip:
            out.append(("USER", u, "IP_ADDRESS", ip, "LOGGED_IN_FROM"))
        if u and d:
            out.append(("USER", u, "DEVICE", d, "ON_DEVICE"))
    elif et == "FILE_ACCESS":
        if u and res:
            out.append(("USER", u, "RESOURCE", res, "ACCESSED"))
        if app and res:
            out.append(("APPLICATION", app, "RESOURCE", res, "OPENED"))
    elif et == "USB_CONNECT":
        if d and usb:
            out.append(("DEVICE", d, "USB_PERIPHERAL", usb, "USB_PORT"))
        if u and usb:
            out.append(("USER", u, "USB_PERIPHERAL", usb, "ATTACHED"))
    elif et == "FILE_COPY":
        if u and usb:
            out.append(("USER", u, "USB_PERIPHERAL", usb, "COPIED_TO"))
        if res and usb:
            out.append(("RESOURCE", res, "USB_PERIPHERAL", usb, "COPIED_TO"))
    elif et == "APP_USAGE":
        if u and app:
            out.append(("USER", u, "APPLICATION", app, "USED"))
    elif et == "NETWORK_CONNECTION":
        if u and dest:
            out.append(("USER", u, "IP_ADDRESS", dest, "SENT_DATA_TO"))
        elif u and ip:
            out.append(("USER", u, "IP_ADDRESS", ip, "CONNECTED_TO"))
    else:
        if u and res:
            out.append(("USER", u, "RESOURCE", res, "ACCESSED"))
        elif u and d:
            out.append(("USER", u, "DEVICE", d, "ON_DEVICE"))
    return out


def _assemble(events: list[dict], chain_ids: set[str]) -> tuple[list[dict], list[dict]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    # Chain events first so chain nodes/edges keep their chain timestamps.
    ordered = sorted(events, key=lambda e: (e["event_id"] not in chain_ids, e["timestamp"]))
    for ev in ordered:
        is_chain = ev["event_id"] in chain_ids
        for st, sl, tt, tl, rel in _relations(ev):
            sid, tid = f"{st}:{sl}", f"{tt}:{tl}"
            for nid, ntype, label in ((sid, st, sl), (tid, tt, tl)):
                n = nodes.setdefault(nid, {"id": nid, "type": ntype, "label": label, "chain": False,
                                           "event_ids": []})
                n["chain"] = n["chain"] or is_chain
                if ev["event_id"] not in n["event_ids"]:
                    n["event_ids"].append(ev["event_id"])
            eid = f"{sid}|{tid}|{rel}"
            e = edges.setdefault(eid, {"id": eid, "source": sid, "target": tid, "relation": rel,
                                       "timestamp": ev["timestamp"], "event_ids": [], "chain": False})
            e["chain"] = e["chain"] or is_chain
            if ev["event_id"] not in e["event_ids"]:
                e["event_ids"].append(ev["event_id"])
    # Edges that are only context take their latest observation time.
    ts_of = {ev["event_id"]: ev["timestamp"] for ev in events}
    for e in edges.values():
        if not e["chain"]:
            e["timestamp"] = max(ts_of[i] for i in e["event_ids"])
    node_list = sorted(nodes.values(), key=lambda n: (not n["chain"], n["type"], n["label"]))
    edge_list = sorted(edges.values(), key=lambda e: (not e["chain"], e["timestamp"]))
    return node_list, edge_list


def build_graph(analysis: dict | None, events: list[dict]) -> dict[str, Any]:
    if not events:
        return {"generated_from": "no events", "nodes": [], "edges": [], "stages": []}
    by_id = {e["event_id"]: e for e in events}
    chain = analysis["chains"][0] if analysis and analysis.get("chains") else None

    if chain:
        chain_ids = set(chain["event_ids"])
        first = parse_ts(chain["first_seen"])
        users = set(chain["users"])
        resources = set(chain["resources"])
        devices = set(chain["devices"])
        context = [
            e for e in events
            if e["event_id"] not in chain_ids
            and first - timedelta(hours=CONTEXT_HOURS) <= parse_ts(e["timestamp"]) <= first
            and (e.get("user") in users or e.get("resource") in resources or e.get("device") in devices)
        ]
        context = sorted(context, key=lambda e: e["timestamp"], reverse=True)[:MAX_CONTEXT_EVENTS]
        selected = [by_id[i] for i in chain["event_ids"] if i in by_id] + context
        nodes, edges = _assemble(selected, chain_ids)
        stages = [{"stage_num": s["stage_num"], "name": s["name"], "timestamp": s["timestamp"]}
                  for s in chain["stages"]]
        return {"generated_from": f"chain:{chain['id']} + {len(context)} context events (prior {CONTEXT_HOURS}h)",
                "nodes": nodes, "edges": edges, "stages": stages}

    # Quiet system: show the evaluated activity so analysts can still see who touched what.
    anomaly_ids = {a["event_id"] for a in (analysis or {}).get("anomalies", [])}
    evaluated = [e for e in events if e.get("source_tag") != "ambient"] or events
    evaluated = sorted(evaluated, key=lambda e: e["timestamp"], reverse=True)[:MAX_QUIET_EVENTS]
    nodes, edges = _assemble(evaluated, anomaly_ids)
    return {"generated_from": f"{len(evaluated)} most recent evaluated events (no attack chain — highlighted "
                              f"edges are isolated anomalies)",
            "nodes": nodes, "edges": edges, "stages": []}
