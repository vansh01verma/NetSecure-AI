from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_scan_requires_authorization():
    response = client.post("/scan", json={
        "target": "192.168.1.10",
        "authorized": False
    })
    assert response.status_code == 403

def test_scan_rejects_public_target():
    response = client.post("/scan", json={
        "target": "8.8.8.8",
        "authorized": True
    })
    assert response.status_code == 422
