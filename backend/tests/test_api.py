import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "subsystems" in data

def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "Sentinel AI SOC Engine"

def test_dashboard_summary(client):
    response = client.get("/api/v1/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert "total_events" in data
    assert "total_alerts" in data
    assert "severity_distribution" in data
    assert data["total_events"] > 0
    assert data["total_alerts"] > 0
    assert data["severity_distribution"]["critical"] >= 1

def test_dashboard_trends(client):
    response = client.get("/api/v1/dashboard/trends")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert "timestamp" in data[0]
    assert "events" in data[0]

def test_recent_activity(client):
    response = client.get("/api/v1/dashboard/recent-activity")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert "event_type" in data[0]
    assert "source_ip" in data[0]

def test_recent_alerts(client):
    response = client.get("/api/v1/dashboard/alerts")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0
    assert "severity" in data[0]
    assert "rule_name" in data[0]
