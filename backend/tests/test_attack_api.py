from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_attack_endpoint_exists():
    response = client.get("/api/v1/attack")
    assert response.status_code == 200
    body = response.json()
    assert body["framework"] == "MITRE ATT&CK"
    assert isinstance(body["mappings"], list)
