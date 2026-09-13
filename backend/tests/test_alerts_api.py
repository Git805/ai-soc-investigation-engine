from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def payload(alert_id: str = "alert-api-001") -> dict:
    return {
        "alert_id": alert_id,
        "timestamp": "2026-09-13T10:15:30Z",
        "title": "Suspicious PowerShell execution",
        "severity": "high",
        "status": "new",
        "source": "synthetic-edr",
        "description": "PowerShell was launched from a document process.",
        "event_ids": ["evt-api-001", "evt-api-002"],
    }


def test_create_and_retrieve_alert_from_collection():
    response = client.post("/api/v1/alerts", json=payload())
    assert response.status_code == 201
    assert response.json()["alert_id"] == "alert-api-001"

    listed = client.get("/api/v1/alerts")
    assert listed.status_code == 200
    assert any(item["alert_id"] == "alert-api-001" for item in listed.json())


def test_duplicate_alert_is_rejected():
    client.post("/api/v1/alerts", json=payload("alert-api-duplicate"))
    response = client.post("/api/v1/alerts", json=payload("alert-api-duplicate"))
    assert response.status_code == 409
