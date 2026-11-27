import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_basic_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["subsystems"]["database"] == "connected"
    assert data["subsystems"]["detection_engine"] == "active"

def test_detailed_health_endpoint(client):
    response = client.get("/api/v1/health/detailed")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"]["status"] == "connected"
    assert "latency_ms" in data["database"]
    assert "uptime_seconds" in data
    assert data["telemetry"]["events_ingested"] >= 0
    assert data["detection_engine"]["rules_count"] >= 5
    assert len(data["detection_engine"]["rules"]) >= 5

def test_telemetry_headers_present(client):
    response = client.get("/")
    assert response.status_code == 200
    # Verify correlation tracking headers injected by middleware
    assert "x-request-id" in response.headers
    assert "x-process-time" in response.headers
    assert response.headers["x-process-time"].endswith("ms")

def test_structured_error_on_404(client):
    response = client.get("/non-existent-api-path")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
    assert "timestamp" in data
    assert "request_id" in data

def test_structured_error_on_validation_failure(client):
    # Send invalid type for limit (e.g. string "invalid" instead of int)
    response = client.get("/api/v1/logs/records?limit=not-an-int")
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert len(data["error"]["details"]) > 0
    assert "request_id" in data
