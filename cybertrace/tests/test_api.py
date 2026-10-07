"""End-to-end checks against the judging criteria: ordering, evidence, false positives, ingestion."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def client():
    return TestClient(create_app(":memory:"))


def test_no_data_state(client):
    s = client.get("/api/stats").json()
    assert s["has_analysis"] is False and s["system_status"] == "NO_DATA"
    assert client.get("/api/analysis/latest").json() is None
    assert client.get("/api/explanation/latest").json() is None
    assert client.get("/api/explanation/CHN-0001").status_code == 404
    assert client.get("/api/graph").json()["nodes"] == []
    assert client.post("/api/analyze", json={"window_minutes": 30}).status_code == 409


@pytest.mark.parametrize("window", [15, 30, 60])
def test_attack_chain_in_order_with_proof(client, window):
    r = client.post("/api/demo/attack", json={"window_minutes": window})
    assert r.status_code == 200
    a = r.json()["analysis"]
    assert a["summary"]["system_status"] == "ATTACK_DETECTED"
    assert a["summary"]["high_confidence_attacks"] == 1
    chain = a["chains"][0]
    assert chain["risk"]["score"] == 90 and chain["risk"]["tier"] == "CRITICAL"
    real = [s for s in chain["stages"] if not s["derived"]]
    assert [s["stage_type"] for s in real] == [
        "UNUSUAL_LOGIN", "UNUSUAL_RESOURCE_ACCESS", "USB_CONNECTION", "FILE_COLLECTION_COPY"]
    assert [s["timestamp"][11:16] for s in real] == ["09:12", "09:16", "09:21", "09:23"]
    assert [s["timestamp"] for s in real] == sorted(s["timestamp"] for s in real)
    # every stage has evidence that resolves to a stored event
    for stage in chain["stages"]:
        assert stage["evidence"]
        for row in stage["evidence"]:
            assert client.get(f"/api/events/{row['event_id']}").status_code == 200
    validation = next(p for p in a["pipeline"] if p["stage_num"] == 9)
    assert validation["input_count"] == validation["output_count"] > 0
    assert len(a["pipeline"]) == 13
    assert set(chain["users"]) == {"user_001"} and "device_07" in chain["devices"]


def test_clean_logs_stay_quiet(client):
    a = client.post("/api/demo/clean", json={"window_minutes": 30}).json()["analysis"]
    s = a["summary"]
    assert s["system_status"] == "QUIET"
    assert s["high_confidence_attacks"] == 0 and s["possible_incidents"] == 0
    assert s["anomalies"] == 1 and s["isolated_signals"] == 1
    assert a["anomalies"][0]["state"] == "SUSPICIOUS_EVENT"
    assert a["chains"] == []
    assert client.get("/api/explanation/latest").json() is None


def test_reanalyze_keeps_mode_and_window(client):
    client.post("/api/demo/attack", json={"window_minutes": 30})
    a = client.post("/api/analyze", json={"window_minutes": 60}).json()
    assert a["mode"] == "attack" and a["window_minutes"] == 60
    assert client.get("/api/stats").json()["high_confidence_attacks"] == 1


def test_window_validation(client):
    assert client.post("/api/demo/attack", json={"window_minutes": 1}).status_code == 422
    assert client.post("/api/demo/unknown", json={}).status_code == 422


def test_graph_entities_and_relations(client):
    client.post("/api/demo/attack", json={"window_minutes": 30})
    g = client.get("/api/graph").json()
    ids = {n["id"] for n in g["nodes"]}
    for needed in ("USER:user_001", "DEVICE:device_07", "IP_ADDRESS:203.0.113.99",
                   "RESOURCE:confidential_project_files", "USB_PERIPHERAL:usb_device_03"):
        assert needed in ids
    assert all(e["source"] in ids and e["target"] in ids for e in g["edges"])
    assert any(e["relation"] == "COPIED_TO" and e["chain"] for e in g["edges"])
    assert len(g["stages"]) == 5


def test_explanation_separates_facts_and_interpretation(client):
    client.post("/api/demo/attack", json={"window_minutes": 30})
    ex = client.get("/api/explanation/latest").json()
    assert len(ex["explanation"]["observed_evidence"]) == 4
    assert len(ex["explanation"]["interpretation"]) == 5
    assert ex["explanation"]["narrative"]
    assert any(r["priority"] == "IMMEDIATE" for r in ex["recommendations"])


def test_event_search_and_pagination(client):
    client.post("/api/demo/attack", json={"window_minutes": 30})
    page = client.get("/api/events", params={"q": "203.0.113.99", "limit": 50}).json()
    assert page["total"] == 3
    page = client.get("/api/events", params={"event_type": "USB_CONNECT"}).json()
    assert all(e["event_type"] == "USB_CONNECT" for e in page["items"])
    assert client.get("/api/events/EVT-99999").status_code == 404


def test_upload_network_exfiltration_sample(client):
    raw = (ROOT / "frontend" / "samples" / "network_exfiltration_logs.json").read_bytes()
    r = client.post("/api/events/upload", files={"file": ("sample.json", raw, "application/json")},
                    data={"mode": "replace", "window_minutes": "30"})
    assert r.status_code == 200, r.text
    s = r.json()["summary"]
    assert s["high_confidence_attacks"] == 1
    chain = client.get("/api/analysis/latest").json()["chains"][0]
    assert chain["pattern_id"] == "DATA_EXFILTRATION_NETWORK"
    assert chain["users"] == ["j.smith"]


def test_upload_csv_template(client):
    raw = (ROOT / "frontend" / "samples" / "custom_logs_template.csv").read_bytes()
    r = client.post("/api/events/upload", files={"file": ("t.csv", raw, "text/csv")}, data={"mode": "replace"})
    assert r.status_code == 200, r.text
    chain = client.get("/api/analysis/latest").json()["chains"][0]
    assert chain["pattern_id"] == "DATA_EXFILTRATION_REMOVABLE_MEDIA"


def test_upload_rejects_garbage(client):
    r = client.post("/api/events/upload", files={"file": ("x.json", b"{not json", "application/json")})
    assert r.status_code == 422
    r = client.post("/api/events/upload", files={"file": ("x.json", b'[{"foo": 1}]', "application/json")})
    assert r.status_code == 422


def test_spa_and_static_routes(client):
    for path in ("/", "/demo", "/attack-graph", "/logs"):
        r = client.get(path)
        assert r.status_code == 200 and "CYBERTRACE AI" in r.text
    assert client.get("/js/app.js").headers["content-type"].startswith(("application/javascript", "text/javascript"))
    assert client.get("/css/app.css").status_code == 200
    assert client.get("/js/missing.js").status_code == 404
    assert client.head("/").status_code == 200
    assert client.get("/favicon.ico").status_code == 200
    assert client.get("/api/nope").status_code == 404
    assert client.get("/../backend/main.py").status_code in (404, 200) and "create_app" not in client.get("/../backend/main.py").text
