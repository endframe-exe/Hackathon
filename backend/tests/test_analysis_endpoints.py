from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_analyze_legitimate_url():
    payload = {"url": "https://www.google.com"}
    response = client.post("/api/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["input_type"] == "url"
    assert data["risk_level"] in ("LOW", "MEDIUM")
    assert data["risk_score"] < 50.0
    assert "safety_disclaimer" in data
    assert data["phishing_dna"]["lexical"] is not None


def test_analyze_phishing_url_brand_impersonation():
    # Deceptive URL using PayPal brand token with abused TLD .tk
    payload = {"url": "http://paypal-security-account.tk/webscr/login"}
    response = client.post("/api/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in ("HIGH", "CRITICAL")
    assert data["risk_score"] >= 65.0
    # Check identity DNA
    assert data["phishing_dna"]["identity"]["is_brand_impersonation"] is True
    assert data["phishing_dna"]["identity"]["targeted_brand"] == "paypal"
    # Check indicators
    titles = [ind["title"] for ind in data["indicators"]]
    assert any("Brand Impersonation Target: Paypal" in t for t in titles)
    assert any("High-Risk Top-Level Domain" in t for t in titles)


def test_analyze_ip_host_url():
    payload = {"url": "http://192.168.1.1:8080/login/verify"}
    response = client.post("/api/analyze/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["phishing_dna"]["lexical"]["has_ip_address"] is True
    titles = [ind["title"] for ind in data["indicators"]]
    assert any("IP Address Used Directly as Host" in t for t in titles)


def test_analyze_benign_message():
    payload = {
        "message": "Hi Alice, please review the draft notes for tomorrow's project meeting.",
        "sender": "bob@legitcorp.com",
        "subject": "Tomorrow's meeting agenda"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["input_type"] == "message"
    assert data["risk_level"] == "LOW"
    assert data["risk_score"] < 25.0


def test_analyze_phishing_message_urgency_and_credentials():
    payload = {
        "message": (
            "Your Microsoft 365 password expires within 24 hours. "
            "Immediate action required: verify your password now at "
            "http://login-microsoft-portal.xyz/verify or account will be permanently closed."
        ),
        "sender": "admin-security@gmail.com",
        "subject": "URGENT: Microsoft 365 Password Expiration"
    }
    response = client.post("/api/analyze/message", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_level"] in ("HIGH", "CRITICAL")
    assert data["risk_score"] >= 65.0
    behavior = data["phishing_dna"]["behavior"]
    assert behavior["urgency_detected"] is True
    assert behavior["credential_intent"] is True
    assert len(data["recommendations"]) > 0


def test_get_history_endpoint():
    response = client.get("/api/history?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert isinstance(data["items"], list)
