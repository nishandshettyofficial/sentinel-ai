import pytest
from io import BytesIO
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.log_parser import parse_csv_content, parse_json_content

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_parse_csv_content_valid():
    csv_data = """timestamp,source_ip,user_identity,event_type,action,status
2026-11-27T08:00:00Z,192.168.1.50,john.doe,AUTH_SUCCESS,LOGIN,SUCCESS
2026-11-27T08:01:00Z,192.168.1.51,jane.smith,AUTH_FAILED,LOGIN,FAILURE
"""
    records, errors = parse_csv_content(csv_data)
    assert len(errors) == 0
    assert len(records) == 2
    assert records[0]["source_ip"] == "192.168.1.50"
    assert records[0]["user_identity"] == "john.doe"
    assert records[0]["status"] == "SUCCESS"
    assert records[1]["status"] == "FAILURE"

def test_parse_json_content_valid():
    json_data = """[
        {"time": "2026-11-27T08:00:00Z", "ip": "10.0.0.1", "username": "admin", "type": "AUTH_FAILED", "status": "FAILURE"},
        {"time": "2026-11-27T08:01:00Z", "ip": "10.0.0.2", "username": "guest", "type": "AUTH_SUCCESS", "status": "SUCCESS"}
    ]"""
    records, errors = parse_json_content(json_data)
    assert len(errors) == 0
    assert len(records) == 2
    assert records[0]["source_ip"] == "10.0.0.1"
    assert records[0]["user_identity"] == "admin"
    assert records[0]["status"] == "FAILURE"

def test_api_list_samples(client):
    response = client.get("/api/v1/logs/samples")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 3
    keys = [item["key"] for item in data]
    assert "ssh_bruteforce" in keys
    assert "password_spraying" in keys

def test_api_ingest_sample_ssh_bruteforce(client):
    response = client.post("/api/v1/logs/sample/ssh_bruteforce")
    assert response.status_code == 200
    data = response.json()
    assert data["records_parsed"] >= 7
    assert data["records_stored"] >= 7
    assert data["alerts_detected"] >= 1
    # Check that a brute-force alert was generated
    alert_rules = [a["rule_name"] for a in data["alerts"]]
    assert "RULE_AUTH_BRUTE_FORCE" in alert_rules
    # Verify severity is critical for root brute-force
    bf_alert = next(a for a in data["alerts"] if a["rule_name"] == "RULE_AUTH_BRUTE_FORCE")
    assert bf_alert["severity"] == "CRITICAL"
    assert bf_alert["target_user"] == "root"

def test_api_ingest_sample_password_spraying(client):
    response = client.post("/api/v1/logs/sample/password_spraying")
    assert response.status_code == 200
    data = response.json()
    assert data["records_parsed"] >= 4
    assert data["alerts_detected"] >= 1
    alert_rules = [a["rule_name"] for a in data["alerts"]]
    assert "RULE_AUTH_PASSWORD_SPRAYING" in alert_rules

def test_api_upload_csv_file(client):
    csv_bytes = b"""timestamp,source_ip,destination_ip,user_identity,event_type,action,status,details
2026-11-27T08:30:00Z,172.16.0.4,10.0.0.5,operator,AUTH_FAILED,LOGIN,FAILURE,{}
2026-11-27T08:30:30Z,172.16.0.4,10.0.0.5,operator,AUTH_FAILED,LOGIN,FAILURE,{}
2026-11-27T08:31:00Z,172.16.0.4,10.0.0.5,operator,AUTH_FAILED,LOGIN,FAILURE,{}
"""
    files = {"file": ("test_audit.csv", BytesIO(csv_bytes), "text/csv")}
    response = client.post("/api/v1/logs/upload", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["records_parsed"] == 3
    assert data["records_stored"] == 3
    assert data["alerts_detected"] >= 1

def test_api_get_log_records(client):
    response = client.get("/api/v1/logs/records?page=1&limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert data["page"] == 1
    assert len(data["items"]) > 0
