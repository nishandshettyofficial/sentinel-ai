import datetime
import pytest
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.core.database import SessionLocal, engine, Base
from backend.app.models.event import SecurityEvent
from backend.app.models.alert import SecurityAlert
from backend.app.services.detection_engine import evaluate_rules, analyze_events_and_detect_threats, ANOMALY_DISCLAIMER

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

def make_event(
    event_type="AUTH_FAILED",
    action="SSH_LOGIN",
    status="FAILURE",
    source_ip="192.168.1.50",
    user_identity="john.doe",
    destination_ip="10.0.0.5",
    details=None,
    delta_seconds=0
):
    base_ts = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    ts = base_ts + datetime.timedelta(seconds=delta_seconds)
    return SecurityEvent(
        timestamp=ts,
        source_ip=source_ip,
        destination_ip=destination_ip,
        user_identity=user_identity,
        event_type=event_type,
        action=action,
        status=status,
        details=details or {},
        raw_log=f"[{ts}] {event_type} {action} {source_ip} {user_identity} {status}"
    )

# ============================================================================
# Rule 1 Tests: RULE_AUTH_BRUTE_FORCE
# ============================================================================

def test_rule_brute_force_normal_user_severity_tiers():
    # 2 failures -> LOW
    events_low = [make_event(user_identity="user_a", source_ip="203.0.113.1") for _ in range(2)]
    alerts_low = evaluate_rules(events_low)
    bf_low = [a for a in alerts_low if a.rule_name == "RULE_AUTH_BRUTE_FORCE"]
    assert len(bf_low) == 1
    assert bf_low[0].severity == "LOW"
    assert bf_low[0].evidence["verification_status"] == "UNCONFIRMED_ANOMALY"
    assert ANOMALY_DISCLAIMER in bf_low[0].evidence["disclaimer"]

    # 3 failures -> MEDIUM
    events_med = [make_event(user_identity="user_b", source_ip="203.0.113.2") for _ in range(3)]
    alerts_med = evaluate_rules(events_med)
    bf_med = [a for a in alerts_med if a.rule_name == "RULE_AUTH_BRUTE_FORCE"]
    assert len(bf_med) == 1
    assert bf_med[0].severity == "MEDIUM"

    # 4 failures -> HIGH
    events_high = [make_event(user_identity="user_c", source_ip="203.0.113.3") for _ in range(4)]
    alerts_high = evaluate_rules(events_high)
    bf_high = [a for a in alerts_high if a.rule_name == "RULE_AUTH_BRUTE_FORCE"]
    assert len(bf_high) == 1
    assert bf_high[0].severity == "HIGH"

    # 5 failures -> CRITICAL
    events_crit = [make_event(user_identity="user_d", source_ip="203.0.113.4") for _ in range(5)]
    alerts_crit = evaluate_rules(events_crit)
    bf_crit = [a for a in alerts_crit if a.rule_name == "RULE_AUTH_BRUTE_FORCE"]
    assert len(bf_crit) == 1
    assert bf_crit[0].severity == "CRITICAL"

def test_rule_brute_force_privileged_account_escalation():
    # root with 2 failures -> HIGH
    events_root_2 = [make_event(user_identity="root", source_ip="198.51.100.1") for _ in range(2)]
    alerts = evaluate_rules(events_root_2)
    bf = [a for a in alerts if a.rule_name == "RULE_AUTH_BRUTE_FORCE"]
    assert len(bf) == 1
    assert bf[0].severity == "HIGH"
    assert bf[0].evidence["is_privileged_account"] is True

    # admin with 3 failures -> CRITICAL
    events_admin_3 = [make_event(user_identity="admin", source_ip="198.51.100.2") for _ in range(3)]
    alerts = evaluate_rules(events_admin_3)
    bf = [a for a in alerts if a.rule_name == "RULE_AUTH_BRUTE_FORCE"]
    assert len(bf) == 1
    assert bf[0].severity == "CRITICAL"

# ============================================================================
# Rule 2 Tests: RULE_AUTH_PASSWORD_SPRAYING
# ============================================================================

def test_rule_password_spraying_horizontal_probing():
    # Single IP targeting 3 distinct accounts -> HIGH
    events = [
        make_event(source_ip="185.220.101.99", user_identity="alice"),
        make_event(source_ip="185.220.101.99", user_identity="bob"),
        make_event(source_ip="185.220.101.99", user_identity="charlie"),
    ]
    alerts = evaluate_rules(events)
    spray = [a for a in alerts if a.rule_name == "RULE_AUTH_PASSWORD_SPRAYING"]
    assert len(spray) == 1
    assert spray[0].severity == "HIGH"
    assert spray[0].evidence["distinct_accounts_count"] == 3
    assert set(spray[0].evidence["targeted_accounts"]) == {"alice", "bob", "charlie"}
    assert spray[0].evidence["verification_status"] == "UNCONFIRMED_ANOMALY"

def test_rule_password_spraying_critical_tier():
    # Single IP targeting 5 distinct accounts -> CRITICAL
    events = [
        make_event(source_ip="185.220.101.99", user_identity=f"user_{i}")
        for i in range(5)
    ]
    alerts = evaluate_rules(events)
    spray = [a for a in alerts if a.rule_name == "RULE_AUTH_PASSWORD_SPRAYING"]
    assert len(spray) == 1
    assert spray[0].severity == "CRITICAL"
    assert spray[0].evidence["distinct_accounts_count"] == 5

# ============================================================================
# Rule 3 Tests: RULE_MULTI_IP_ACCOUNT_ACCESS
# ============================================================================

def test_rule_multi_ip_account_access_medium():
    # Same account accessed from 2 IPs with SUCCESS -> MEDIUM
    events = [
        make_event(event_type="AUTH_SUCCESS", action="LOGIN_SSO", status="SUCCESS", source_ip="192.168.1.10", user_identity="sarah.lead"),
        make_event(event_type="AUTH_SUCCESS", action="LOGIN_WEB", status="SUCCESS", source_ip="185.199.108.15", user_identity="sarah.lead")
    ]
    alerts = evaluate_rules(events)
    multi = [a for a in alerts if a.rule_name == "RULE_MULTI_IP_ACCOUNT_ACCESS"]
    assert len(multi) == 1
    assert multi[0].severity == "MEDIUM"
    assert multi[0].evidence["distinct_ip_count"] == 2
    assert "192.168.1.10" in multi[0].evidence["distinct_ips"]
    assert "185.199.108.15" in multi[0].evidence["distinct_ips"]
    assert multi[0].evidence["verification_status"] == "UNCONFIRMED_ANOMALY"

def test_rule_multi_ip_account_access_high_and_critical():
    # 2 IPs with mixed SUCCESS and FAILURE -> HIGH
    events_mixed = [
        make_event(event_type="AUTH_SUCCESS", action="LOGIN_SSO", status="SUCCESS", source_ip="192.168.1.10", user_identity="dev_lead"),
        make_event(event_type="AUTH_FAILED", action="LOGIN_WEB", status="FAILURE", source_ip="203.0.113.88", user_identity="dev_lead")
    ]
    alerts_mixed = evaluate_rules(events_mixed)
    multi_mixed = [a for a in alerts_mixed if a.rule_name == "RULE_MULTI_IP_ACCOUNT_ACCESS"]
    assert len(multi_mixed) == 1
    assert multi_mixed[0].severity == "HIGH"

    # 3 distinct IPs with a failure -> CRITICAL
    events_3 = [
        make_event(event_type="AUTH_SUCCESS", action="LOGIN_SSO", status="SUCCESS", source_ip="10.0.0.1", user_identity="sec_director"),
        make_event(event_type="AUTH_SUCCESS", action="LOGIN_WEB", status="SUCCESS", source_ip="10.0.0.2", user_identity="sec_director"),
        make_event(event_type="AUTH_FAILED", action="LOGIN_WEB", status="BLOCKED", source_ip="203.0.113.99", user_identity="sec_director")
    ]
    alerts_3 = evaluate_rules(events_3)
    multi_3 = [a for a in alerts_3 if a.rule_name == "RULE_MULTI_IP_ACCOUNT_ACCESS"]
    assert len(multi_3) == 1
    assert multi_3[0].severity == "CRITICAL"
    assert multi_3[0].evidence["distinct_ip_count"] == 3

# ============================================================================
# Rule 4 Tests: RULE_ACTIVITY_SPIKE
# ============================================================================

def test_rule_activity_spike_severity_tiers():
    # 6 events -> LOW
    events_6 = [make_event(event_type="API_REQUEST", action="PING", status="SUCCESS", source_ip="194.26.29.11", user_identity="daemon") for _ in range(6)]
    alerts_6 = evaluate_rules(events_6)
    spike_6 = [a for a in alerts_6 if a.rule_name == "RULE_ACTIVITY_SPIKE"]
    assert len(spike_6) == 1
    assert spike_6[0].severity == "LOW"
    assert spike_6[0].evidence["event_count"] == 6

    # 8 events -> MEDIUM
    events_8 = [make_event(event_type="API_REQUEST", action="PING", status="SUCCESS", source_ip="194.26.29.12", user_identity="daemon") for _ in range(8)]
    alerts_8 = evaluate_rules(events_8)
    spike_8 = [a for a in alerts_8 if a.rule_name == "RULE_ACTIVITY_SPIKE"]
    assert len(spike_8) == 1
    assert spike_8[0].severity == "MEDIUM"

    # 12 events -> HIGH
    events_12 = [make_event(event_type="API_REQUEST", action="PING", status="SUCCESS", source_ip="194.26.29.13", user_identity="daemon") for _ in range(12)]
    alerts_12 = evaluate_rules(events_12)
    spike_12 = [a for a in alerts_12 if a.rule_name == "RULE_ACTIVITY_SPIKE"]
    assert len(spike_12) == 1
    assert spike_12[0].severity == "HIGH"

    # 20 events -> CRITICAL
    events_20 = [make_event(event_type="API_REQUEST", action="PING", status="SUCCESS", source_ip="194.26.29.14", user_identity="daemon") for _ in range(20)]
    alerts_20 = evaluate_rules(events_20)
    spike_20 = [a for a in alerts_20 if a.rule_name == "RULE_ACTIVITY_SPIKE"]
    assert len(spike_20) == 1
    assert spike_20[0].severity == "CRITICAL"

# ============================================================================
# Auxiliary Rules Tests
# ============================================================================

def test_rule_privilege_escalation():
    ev = make_event(
        event_type="PRIVILEGE_ESCALATION",
        action="SUDO_EXEC",
        status="FAILURE",
        user_identity="temp_intern",
        details={"command": "sudo /bin/bash"}
    )
    alerts = evaluate_rules([ev])
    sudo_alerts = [a for a in alerts if a.rule_name == "RULE_HOST_SUDO_VIOLATION"]
    assert len(sudo_alerts) == 1
    assert sudo_alerts[0].severity == "HIGH"
    assert sudo_alerts[0].evidence["verification_status"] == "UNCONFIRMED_ANOMALY"

def test_rule_port_scan():
    ev = make_event(
        event_type="PORT_SCAN",
        action="TCP_SYN_SWEEP",
        status="BLOCKED",
        source_ip="91.240.118.172",
        details={"scanned_ports": [21, 22, 80, 443, 3389, 8080, 8443]}
    )
    alerts = evaluate_rules([ev])
    scan_alerts = [a for a in alerts if a.rule_name == "RULE_PERIMETER_PORT_SCAN"]
    assert len(scan_alerts) == 1
    assert scan_alerts[0].severity == "HIGH"
    assert len(scan_alerts[0].evidence["scanned_ports"]) == 7

def test_rule_c2_beacon():
    ev = make_event(
        event_type="C2_BEACON",
        action="DNS_TUNNEL_QUERY",
        status="BLOCKED",
        source_ip="192.168.1.77",
        details={"domain": "c2-verify.org"}
    )
    alerts = evaluate_rules([ev])
    c2_alerts = [a for a in alerts if a.rule_name == "RULE_NETWORK_C2_BEACON"]
    assert len(c2_alerts) == 1
    assert c2_alerts[0].severity == "HIGH"
    assert c2_alerts[0].evidence["domain"] == "c2-verify.org"

# ============================================================================
# Database & API Integration Tests
# ============================================================================

def test_analyze_events_and_detect_threats_persists_to_db(db_session):
    events = [
        make_event(user_identity="target_db_user", source_ip="198.51.100.77")
        for _ in range(4)
    ]
    for ev in events:
        db_session.add(ev)
    db_session.commit()

    created_alerts = analyze_events_and_detect_threats(db_session, events)
    assert len(created_alerts) >= 1
    db_alert = db_session.query(SecurityAlert).filter(SecurityAlert.target_user == "target_db_user").first()
    assert db_alert is not None
    assert db_alert.severity == "HIGH"
    assert db_alert.rule_name == "RULE_AUTH_BRUTE_FORCE"

def test_alerts_api_query_and_filtering():
    with TestClient(app) as client:
        # 1. Fetch alerts
        res = client.get("/api/v1/alerts?limit=10")
        assert res.status_code == 200
        data = res.json()
        assert "items" in data
        assert "total" in data
        assert "total_pages" in data

        # 2. Filter by severity
        res_crit = client.get("/api/v1/alerts?severity=CRITICAL")
        assert res_crit.status_code == 200
        data_crit = res_crit.json()
        for item in data_crit["items"]:
            assert item["severity"] == "CRITICAL"

        # 3. Update alert status
        first_alert = data["items"][0]
        alert_id = first_alert["id"]
        res_patch = client.patch(f"/api/v1/alerts/{alert_id}/status", json={"status": "INVESTIGATING"})
        assert res_patch.status_code == 200
        assert res_patch.json()["status"] == "INVESTIGATING"

        # 4. Fetch single alert
        res_single = client.get(f"/api/v1/alerts/{alert_id}")
        assert res_single.status_code == 200
        assert res_single.json()["id"] == alert_id
        assert res_single.json()["status"] == "INVESTIGATING"
