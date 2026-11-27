import pytest
from io import BytesIO
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.services.log_parser import parse_csv_content, parse_json_content
from backend.app.core.errors import SentinelException

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

def test_parse_csv_invalid_empty():
    with pytest.raises(SentinelException) as exc:
        parse_csv_content("   \n\n  ")
    assert exc.value.code == "EMPTY_LOG_FILE"

def test_parse_csv_invalid_binary():
    with pytest.raises(SentinelException) as exc:
        parse_csv_content("some\x00binary\x00data")
    assert exc.value.code == "INVALID_FILE_FORMAT"

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

def test_parse_json_invalid_syntax():
    with pytest.raises(SentinelException) as exc:
        parse_json_content("[{'bad': json}")
    assert exc.value.code in ["MALFORMED_JSON", "MALFORMED_JSON_ITEM"]

def test_api_list_samples(client):
    response = client.get("/api/v1/logs/samples")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 4
    keys = [item["key"] for item in data]
    assert "ssh_bruteforce" in keys
    assert "password_spraying" in keys
    assert "enterprise_audit" in keys

def test_api_download_sample(client):
    response = client.get("/api/v1/logs/sample/ssh_bruteforce/download")
    assert response.status_code == 200
    assert "text/csv" in response.headers.get("content-type", "")
    assert "root,AUTH_FAILED" in response.text

def test_api_ingest_sample_ssh_bruteforce(client):
    response = client.post("/api/v1/logs/sample/ssh_bruteforce")
    assert response.status_code == 200
    data = response.json()
    assert data["records_parsed"] >= 7
    assert data["records_stored"] >= 7
    assert data["alerts_detected"] >= 1
    alert_rules = [a["rule_name"] for a in data["alerts"]]
    assert "RULE_AUTH_BRUTE_FORCE" in alert_rules
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

def test_api_upload_empty_file_fails_safely(client):
    files = {"file": ("empty.csv", BytesIO(b""), "text/csv")}
    response = client.post("/api/v1/logs/upload", files=files)
    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] in ["EMPTY_FILE", "EMPTY_LOG_FILE"]

def test_api_upload_binary_file_fails_safely(client):
    files = {"file": ("binary.bin", BytesIO(b"\x7fELF\x02\x01\x01\x00\x00\x00"), "application/octet-stream")}
    response = client.post("/api/v1/logs/upload", files=files)
    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == "INVALID_FILE_FORMAT"

def test_api_get_log_records(client):
    response = client.get("/api/v1/logs/records?page=1&limit=10&time_range=24h")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert data["page"] == 1
    assert len(data["items"]) > 0

def test_api_export_logs(client):
    csv_resp = client.get("/api/v1/logs/export?format=csv&limit=10")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.headers["content-type"]
    assert "source_ip,destination_ip" in csv_resp.text

    json_resp = client.get("/api/v1/logs/export?format=json&limit=10")
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["content-type"]
    json_data = json_resp.json()
    assert isinstance(json_data, list)
