from fastapi.testclient import TestClient
import os

# Set API Key env var BEFORE importing app to ensure config picks it up if needed,
# though we usually patch settings. But simpler to set it here if config loads at import time.
# However, app.config might already be loaded if imported elsewhere. 
# Best practice: Override settings.

from app.config import settings
settings.API_KEY = "TEST123"

from app.main import app

client = TestClient(app)

def test_health_check():
    """
    Requirement: GET /health returns status 200 and JSON { "status": "ok" }
    """
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

def test_auth_missing_api_key():
    """
    Requirement: POST /honeypot without x-api-key returns 401
    """
    response = client.post("/honeypot", json={"message": "hello"})
    assert response.status_code == 401
    # Check detail if possible, though status is priority
    assert response.json()["message"] == "Missing API Key"

def test_auth_wrong_api_key():
    """
    Requirement: POST /honeypot with wrong x-api-key returns 403
    """
    response = client.post(
        "/honeypot", 
        headers={"x-api-key": "WRONG_KEY"},
        json={"message": "hello"}
    )
    assert response.status_code == 403
    assert response.json()["message"] == "Invalid API Key"

def test_valid_honeypot_response_structure():
    """
    Requirement: POST /honeypot with correct key returns 200 and required fields
    """
    response = client.post(
        "/honeypot",
        headers={"x-api-key": "TEST123"},
        json={"message": "Hello scammer"}
    )
    assert response.status_code == 200
    data = response.json()
    
    required_fields = [
        "is_scam", "scam_type", "confidence", "persona_used", 
        "next_message", "extracted_intelligence", "session_state"
    ]
    for field in required_fields:
        assert field in data

def test_phishing_message():
    """
    Requirement: phishing message -> is_scam true, scam_type phishing, urls not empty
    """
    msg = "Urgent! Login immediately to verify account: http://scam-link.com/login"
    response = client.post(
        "/honeypot",
        headers={"x-api-key": "TEST123"},
        json={"message": msg}
    )
    assert response.status_code == 200
    data = response.json()
    
    assert data["is_scam"] is True
    assert data["scam_type"] == "phishing"
    assert len(data["extracted_intelligence"]["urls"]) > 0

def test_benign_message():
    """
    Requirement: benign message -> is_scam false, persona_used 'none', next_message ''
    """
    msg = "Hey, just checking in. How are you?"
    response = client.post(
        "/honeypot",
        headers={"x-api-key": "TEST123"},
        json={"message": msg}
    )
    assert response.status_code == 200
    data = response.json()
    
    assert data["is_scam"] is False
    assert data["persona_used"] == "none"
    assert data["next_message"] == ""
