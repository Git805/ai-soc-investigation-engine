from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def payload(event_id: str = "evt-api-001") -> dict:
    return {
        "event_id": event_id,
        "timestamp": "2026-09-13T10:15:30Z",
        "event_type": "process_creation",
        "severity": "medium",
        "host": {"hostname": "WS-001", "ip": "10.10.10.25"},
        "user": {"username": "jdoe"},
        "process": {"name": "powershell.exe", "pid": 4212},
        "source": {"product": "EDR", "vendor": "synthetic"},
    }


def test_create_and_retrieve_event():
    response = client.post("/api/v1/events", json=payload())
    assert response.status_code == 201
    assert response.json()["event_id"] == "evt-api-001"

    fetched = client.get("/api/v1/events/evt-api-001")
    assert fetched.status_code == 200
    assert fetched.json()["process"]["name"] == "powershell.exe"


def test_duplicate_event_is_rejected():
    client.post("/api/v1/events", json=payload("evt-api-duplicate"))
    response = client.post("/api/v1/events", json=payload("evt-api-duplicate"))
    assert response.status_code == 409
