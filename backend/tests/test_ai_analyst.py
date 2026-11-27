import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import SessionLocal, engine, Base
from backend.app.models.event import SecurityEvent
from backend.app.models.alert import SecurityAlert
from backend.app.services.ai_analyst import (
    explain_alert_with_ai,
    chat_with_ai_analyst,
    AI_SOC_DISCLAIMER
)
from backend.app.schemas.ai_analyst import AnalystChatRequest, ChatMessage

@pytest.fixture(scope="module", autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)

@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@pytest.fixture
def sample_brute_force_alert(db_session):
    alert = SecurityAlert(
        title="Potential Brute-Force Authentication Anomaly on 'admin' from 198.51.100.99",
        description="Observed 5 failed authentication attempts against account 'admin' from 198.51.100.99.",
        severity="CRITICAL",
        status="NEW",
        rule_name="RULE_AUTH_BRUTE_FORCE",
        source_ip="198.51.100.99",
        target_user="admin",
        evidence={
            "failed_attempts": 5,
            "target_account": "admin",
            "source_ip": "198.51.100.99",
            "is_privileged_account": True,
            "time_window_seconds": 30.5
        }
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    return alert

# ============================================================================
# 1. Alert Explanation Service Tests
# ============================================================================

def test_explain_alert_brute_force(db_session, sample_brute_force_alert):
    explanation = explain_alert_with_ai(db_session, sample_brute_force_alert.id)
    
    assert explanation.alert_id == sample_brute_force_alert.id
    assert explanation.severity == "CRITICAL"
    assert explanation.rule_name == "RULE_AUTH_BRUTE_FORCE"
    assert "admin" in explanation.what_happened
    assert "198.51.100.99" in explanation.what_happened
    assert len(explanation.why_suspicious) > 20
    assert len(explanation.potential_impact) > 20
    assert len(explanation.defensive_recommendations) >= 3
    assert explanation.mitre_attack_mapping is not None
    assert "T1110" in explanation.mitre_attack_mapping["technique"]
    assert AI_SOC_DISCLAIMER in explanation.disclaimer
    assert explanation.provider in ["GEMINI_2_5_FLASH", "GROUNDED_SOC_ENGINE"]

def test_explain_nonexistent_alert_raises(db_session):
    with pytest.raises(ValueError) as exc:
        explain_alert_with_ai(db_session, 999999)
    assert "not found" in str(exc.value).lower()

# ============================================================================
# 2. Chat Assistant Service Tests
# ============================================================================

def test_chat_analyst_general_question(db_session):
    req = AnalystChatRequest(
        message="What are standard containment priorities for a SOC?",
        chat_history=[]
    )
    res = chat_with_ai_analyst(db_session, req)
    assert res.reply is not None
    assert len(res.reply) > 50
    assert len(res.suggested_followups) >= 2

def test_chat_analyst_with_alert_context_containment(db_session, sample_brute_force_alert):
    req = AnalystChatRequest(
        message="What should I do first to contain this threat?",
        alert_id=sample_brute_force_alert.id,
        chat_history=[]
    )
    res = chat_with_ai_analyst(db_session, req)
    assert res.referenced_alert_id == sample_brute_force_alert.id
    assert "198.51.100.99" in res.reply or "firewall" in res.reply.lower()

def test_chat_analyst_firewall_rule_request(db_session, sample_brute_force_alert):
    req = AnalystChatRequest(
        message="Generate an iptables firewall block rule for this attacker",
        alert_id=sample_brute_force_alert.id,
        chat_history=[]
    )
    res = chat_with_ai_analyst(db_session, req)
    assert "iptables" in res.reply.lower()
    assert "198.51.100.99" in res.reply

def test_chat_analyst_mitre_mapping_request(db_session, sample_brute_force_alert):
    req = AnalystChatRequest(
        message="What MITRE ATT&CK technique is this?",
        alert_id=sample_brute_force_alert.id,
        chat_history=[]
    )
    res = chat_with_ai_analyst(db_session, req)
    assert "T1110" in res.reply or "Credential Access" in res.reply

# ============================================================================
# 3. AI Analyst API Endpoint Tests
# ============================================================================

def test_api_explain_alert_get(sample_brute_force_alert):
    with TestClient(app) as client:
        res = client.get(f"/api/v1/ai-analyst/explain/{sample_brute_force_alert.id}")
        assert res.status_code == 200
        data = res.json()
        assert data["alert_id"] == sample_brute_force_alert.id
        assert data["alert_title"] == sample_brute_force_alert.title
        assert len(data["defensive_recommendations"]) >= 2

def test_api_explain_alert_post(sample_brute_force_alert):
    with TestClient(app) as client:
        res = client.post("/api/v1/ai-analyst/explain", json={"alert_id": sample_brute_force_alert.id})
        assert res.status_code == 200
        data = res.json()
        assert data["alert_id"] == sample_brute_force_alert.id

def test_api_explain_nonexistent_returns_404():
    with TestClient(app) as client:
        res = client.get("/api/v1/ai-analyst/explain/999999")
        assert res.status_code == 404
        assert res.json()["error"]["code"] == "ALERT_NOT_FOUND"

def test_api_chat_endpoint(sample_brute_force_alert):
    with TestClient(app) as client:
        payload = {
            "message": "Is this an automated bot?",
            "alert_id": sample_brute_force_alert.id,
            "chat_history": [
                {"role": "user", "content": "Hello analyst"},
                {"role": "assistant", "content": "Ready to assist."}
            ]
        }
        res = client.post("/api/v1/ai-analyst/chat", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert "reply" in data
        assert len(data["reply"]) > 20

def test_api_chat_empty_message_rejected():
    with TestClient(app) as client:
        res = client.post("/api/v1/ai-analyst/chat", json={"message": "   "})
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "EMPTY_MESSAGE"

def test_api_ai_analyst_status():
    with TestClient(app) as client:
        res = client.get("/api/v1/ai-analyst/status")
        assert res.status_code == 200
        data = res.json()
        assert "gemini_configured" in data
        assert "model" in data
        assert len(data["capabilities"]) >= 3
