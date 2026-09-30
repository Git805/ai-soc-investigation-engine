from fastapi.testclient import TestClient
import uuid

from app.main import app

client = TestClient(app)
EVENT_CREATE_ID = f"evt-api-test-{uuid.uuid4().hex}"


def payload(event_id: str = "evt-create-test-001") -> dict:
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
    event_id = f"evt-api-{uuid.uuid4().hex}"

    response = client.post("/api/v1/events", json=payload(event_id))
    assert response.status_code == 201
    assert response.json()["event_id"] == event_id

    fetched = client.get(f"/api/v1/events/{event_id}")
    assert fetched.status_code == 200
    assert fetched.json()["process"]["name"] == "powershell.exe"


def test_duplicate_event_is_rejected():
    client.post("/api/v1/events", json=payload("evt-api-duplicate"))
    response = client.post("/api/v1/events", json=payload("evt-api-duplicate"))
    assert response.status_code == 409
