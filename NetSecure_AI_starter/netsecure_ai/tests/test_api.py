from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_health():
    assert client.get("/health").json()["status"] == "ok"

def test_authorization_required():
    r = client.post("/scan", json={"target": "192.168.1.10", "ports": [80]})
    assert r.status_code == 403

def test_public_target_rejected():
    r = client.post("/scan", json={"target": "8.8.8.8", "authorized": True, "ports": [53]})
    assert r.status_code == 403

def test_chat_fallback():
    r = client.post("/chat", json={"message": "Explain findings"})
    assert r.status_code == 200
    assert r.json()["model_connected"] is False

def test_invalid_report_format():
    r = client.post("/report", json={"target": "192.168.1.10", "authorized": True, "ports": [80], "format": "pdf"})
    assert r.status_code == 422
