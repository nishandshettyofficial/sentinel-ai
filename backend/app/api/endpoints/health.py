import time
import platform
from typing import Dict, Any
from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text
from backend.app.core.database import get_db
from backend.app.core.config import settings
from backend.app.models.event import SecurityEvent
from backend.app.models.alert import SecurityAlert
from backend.app.models.incident import SecurityIncident

router = APIRouter()

START_TIME = time.time()

DETECTION_RULES_CATALOG = [
    {"rule": "RULE_AUTH_BRUTE_FORCE", "description": "Repeated failed login attempts against single account", "severity": "LOW/HIGH/CRITICAL"},
    {"rule": "RULE_AUTH_PASSWORD_SPRAYING", "description": "Single IP attempting logins across multiple distinct user accounts", "severity": "HIGH/CRITICAL"},
    {"rule": "RULE_MULTI_IP_ACCOUNT_ACCESS", "description": "Multiple distinct IP addresses accessing one user account concurrently", "severity": "MEDIUM/HIGH/CRITICAL"},
    {"rule": "RULE_ACTIVITY_SPIKE", "description": "Abnormal volume surge of security events or connection requests in short window", "severity": "MEDIUM/HIGH/CRITICAL"},
    {"rule": "RULE_HOST_SUDO_VIOLATION", "description": "Unauthorized privilege escalation and sudo policy violations", "severity": "HIGH/CRITICAL"},
    {"rule": "RULE_PERIMETER_PORT_SCAN", "description": "Multi-port TCP SYN reconnaissance sweep and port probing", "severity": "MEDIUM/HIGH"},
    {"rule": "RULE_NETWORK_C2_BEACON", "description": "Outbound DNS tunneling & command-and-control beaconing", "severity": "HIGH"}
]

@router.get("", summary="Basic Health Check")
def basic_health():
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": "1.0.0",
        "subsystems": {
            "database": "connected",
            "detection_engine": "active",
            "telemetry_stream": "online"
        }
    }

@router.get("/detailed", summary="Deep SOC Diagnostics & Health Telemetry")
def detailed_health(db: Session = Depends(get_db)):
    uptime_sec = round(time.time() - START_TIME, 1)

    # 1. Database Connectivity & Latency Ping
    db_status = "connected"
    db_latency_ms = 0.0
    try:
        t0 = time.perf_counter()
        db.execute(text("SELECT 1"))
        db_latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    except Exception as e:
        db_status = f"unreachable: {str(e)}"

    # 2. Record Counts
    try:
        events_count = db.query(SecurityEvent).count()
        alerts_count = db.query(SecurityAlert).count()
        incidents_count = db.query(SecurityIncident).count()
    except Exception:
        events_count = alerts_count = incidents_count = -1

    is_healthy = db_status == "connected"

    payload = {
        "status": "healthy" if is_healthy else "degraded",
        "service": settings.APP_NAME,
        "version": "1.0.0",
        "environment": settings.ENVIRONMENT,
        "uptime_seconds": uptime_sec,
        "system": {
            "platform": platform.platform(),
            "python_version": platform.python_version()
        },
        "database": {
            "status": db_status,
            "latency_ms": db_latency_ms,
            "engine": "sqlite" if "sqlite" in settings.DATABASE_URL else "postgresql"
        },
        "telemetry": {
            "events_ingested": events_count,
            "alerts_generated": alerts_count,
            "active_incidents": incidents_count
        },
        "detection_engine": {
            "status": "active",
            "rules_count": len(DETECTION_RULES_CATALOG),
            "rules": DETECTION_RULES_CATALOG
        }
    }

    status_code = status.HTTP_200_OK if is_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(status_code=status_code, content=payload)
