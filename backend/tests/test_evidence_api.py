from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _event(event_id: str, timestamp: str, process: str = "powershell.exe") -> dict:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "event_type": "process_creation",
        "severity": "high",
        "host": {"hostname": "ws-evidence-01", "ip": "10.0.0.20"},
        "user": {"username": "analyst", "domain": "LAB"},
        "process": {"name": process, "pid": 1001, "command_line": "powershell.exe -EncodedCommand AAAA"},
        "source": {"vendor": "Synthetic", "product": "SOC Telemetry", "version": "1.0"},
        "data": {},
    }


def test_evidence_ledger_and_timeline_are_provenance_linked() -> None:
    suffix = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
    first = f"ev-{suffix}-1"
    second = f"ev-{suffix}-2"
    base = datetime.now(timezone.utc)

    for event_id, offset in ((first, 0), (second, 60)):
        event = _event(event_id, (base.timestamp() + offset))
        event["timestamp"] = datetime.fromtimestamp(base.timestamp() + offset, tz=timezone.utc).isoformat()
        assert client.post("/api/v1/events", json=event).status_code == 201

    investigations = client.get("/api/v1/investigations").json()
    investigation = next(item for item in investigations if first in {e["event_id"] for e in item["timeline"]})

    evidence = client.get(f"/api/v1/investigations/{investigation['investigation_id']}/evidence")
    assert evidence.status_code == 200
    ledger = evidence.json()
    assert ledger["item_count"] >= 3
    assert any(item["reference_id"] == first for item in ledger["items"])
    assert any(item["evidence_type"] == "rule_hit" for item in ledger["items"])
    assert all(item["provenance"] for item in ledger["items"])

    timeline = client.get(f"/api/v1/investigations/{investigation['investigation_id']}/timeline")
    assert timeline.status_code == 200
    assert timeline.json()["events"][0]["event_id"] == first
    assert timeline.json()["events"][1]["event_id"] == second


def test_unknown_investigation_returns_404() -> None:
    response = client.get("/api/v1/investigations/INV-DOES-NOT-EXIST/evidence")
    assert response.status_code == 404
