from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_root_and_health():
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json()["service"] == "PhishGuard AI"

    resp2 = client.get("/health")
    assert resp2.status_code == 200
    assert resp2.json()["status"] == "ok"


def test_api_health():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "database" in data
    assert "threat_intelligence" in data
    assert data["threat_intelligence"]["provider"] == "VirusTotal API v3"
