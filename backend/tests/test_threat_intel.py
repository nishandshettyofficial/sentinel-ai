import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import SessionLocal, engine, Base
from backend.app.models.event import SecurityEvent
from backend.app.models.alert import SecurityAlert
from backend.app.services.threat_intelligence import (
    normalize_indicator,
    investigate_indicator,
    fetch_abuseipdb_data,
    fetch_virustotal_data
)

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

# ============================================================================
# 1. Normalization & Defanging Tests
# ============================================================================

def test_normalize_indicator_ip_formats():
    # Standard IPv4
    ip, itype, is_priv = normalize_indicator("8.8.8.8")
    assert ip == "8.8.8.8"
    assert itype == "IP"
    assert is_priv is False

    # Defanged IPv4
    ip_defanged, itype_def, _ = normalize_indicator("185[.]220[.]101[.]45")
    assert ip_defanged == "185.220.101.45"
    assert itype_def == "IP"

    # RFC1918 Private IP
    ip_priv, itype_p, is_priv = normalize_indicator("192.168.1.100")
    assert ip_priv == "192.168.1.100"
    assert itype_p == "IP"
    assert is_priv is True

def test_normalize_indicator_domain_formats():
    # URL to clean domain
    dom, dtype, _ = normalize_indicator("https://evil-corp.com/login/auth?ref=1")
    assert dom == "evil-corp.com"
    assert dtype == "DOMAIN"

    # Defanged hxxps
    dom_def, _, _ = normalize_indicator("hxxps://tunnel-stage[.]verify[.]top/beacon")
    assert dom_def == "tunnel-stage.verify.top"

# ============================================================================
# 2. Indicator Investigation Tests
# ============================================================================

def test_investigate_confirmed_malicious_ip(db_session):
    report = investigate_indicator(db_session, "185.220.101.45")
    assert report.indicator == "185.220.101.45"
    assert report.indicator_type == "IP"
    assert report.verdict == "MALICIOUS"
    assert report.threat_level == "CRITICAL"
    assert report.confidence_score >= 80
    assert "Tor Exit Node" in report.threat_categories
    assert report.abuseipdb is not None
    assert report.abuseipdb.abuse_score >= 80
    assert report.virustotal is not None
    assert report.virustotal.malicious_votes > 0
    assert "perimeter" in report.recommendation.lower() or "block" in report.recommendation.lower()

def test_investigate_confirmed_malicious_c2_domain(db_session):
    report = investigate_indicator(db_session, "tunnel-stage-verify.top")
    assert report.indicator == "tunnel-stage-verify.top"
    assert report.indicator_type == "DOMAIN"
    assert report.verdict == "MALICIOUS"
    assert report.threat_level == "CRITICAL"
    assert report.confidence_score >= 80
    assert "C2 Domain" in report.threat_categories

def test_investigate_benign_clean_indicator(db_session):
    report = investigate_indicator(db_session, "8.8.8.8")
    assert report.indicator == "8.8.8.8"
    assert report.verdict == "BENIGN"
    assert report.threat_level == "CLEAN"
    assert report.confidence_score == 0
    assert "Public DNS Resolver" in report.threat_categories

def test_investigate_private_rfc1918_ip(db_session):
    report = investigate_indicator(db_session, "10.0.0.15")
    assert report.indicator == "10.0.0.15"
    assert report.is_private_ip is True
    assert "Internal RFC1918" in report.threat_categories
    assert "RFC1918" in report.summary

def test_investigate_unknown_unrated_indicator(db_session):
    # Clearly distinguished from confirmed malicious
    report = investigate_indicator(db_session, "completely-unknown-vendor-portal-992.net")
    assert report.indicator == "completely-unknown-vendor-portal-992.net"
    assert report.verdict == "UNKNOWN"
    assert report.threat_level == "UNKNOWN"
    assert report.confidence_score == 0
    assert "UNRATED" in report.summary.upper()

# ============================================================================
# 3. Missing API Keys and Error Handling
# ============================================================================

def test_graceful_missing_api_keys():
    # Even if keys are empty strings, functions return gracefully without crashing
    abuse_res = fetch_abuseipdb_data("1.2.3.4")
    assert abuse_res is not None
    assert abuse_res.status in ["NOT_CONFIGURED", "CURATED_BASELINE", "LIVE_API"]

    vt_res = fetch_virustotal_data("example-random.org", "DOMAIN")
    assert vt_res is not None
    assert vt_res.status in ["NOT_CONFIGURED", "CURATED_BASELINE", "LIVE_API"]

# ============================================================================
# 4. Local SOC Telemetry Cross-Reference
# ============================================================================

def test_investigate_indicator_correlates_local_events(db_session):
    test_ip = "192.0.2.144"
    ev = SecurityEvent(
        source_ip=test_ip,
        event_type="AUTH_FAILED",
        action="LOGIN_WEB",
        status="FAILURE",
        user_identity="soc_tester",
        raw_log=f"Auth failure from {test_ip}"
    )
    db_session.add(ev)
    db_session.commit()

    report = investigate_indicator(db_session, test_ip)
    assert report.internal_soc_activity.observed_in_local_logs is True
    assert report.internal_soc_activity.events_count >= 1
    assert "soc_tester" in report.internal_soc_activity.associated_users

# ============================================================================
# 5. Threat Intelligence API Endpoints Tests
# ============================================================================

def test_api_investigate_get_endpoint():
    with TestClient(app) as client:
        res = client.get("/api/v1/threat-intel/investigate?indicator=185.220.101.45")
        assert res.status_code == 200
        data = res.json()
        assert data["indicator"] == "185.220.101.45"
        assert data["verdict"] == "MALICIOUS"
        assert data["confidence_score"] >= 80

def test_api_investigate_post_endpoint():
    with TestClient(app) as client:
        res = client.post("/api/v1/threat-intel/investigate", json={"indicator": "8.8.8.8"})
        assert res.status_code == 200
        data = res.json()
        assert data["indicator"] == "8.8.8.8"
        assert data["verdict"] == "BENIGN"

def test_api_investigate_empty_indicator_rejected():
    with TestClient(app) as client:
        res = client.get("/api/v1/threat-intel/investigate?indicator=   ")
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "EMPTY_INDICATOR"

def test_api_sample_indicators_list():
    with TestClient(app) as client:
        res = client.get("/api/v1/threat-intel/samples")
        assert res.status_code == 200
        samples = res.json()
        assert len(samples) >= 5
        assert any(s["indicator"] == "185.220.101.45" for s in samples)

def test_api_threat_intel_provider_status():
    with TestClient(app) as client:
        res = client.get("/api/v1/threat-intel/status")
        assert res.status_code == 200
        data = res.json()
        assert "virustotal" in data
        assert "abuseipdb" in data
        assert "curated_baseline" in data
