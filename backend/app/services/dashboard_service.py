from typing import List, Dict, Any
import datetime
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.app.models.event import SecurityEvent
from backend.app.models.alert import SecurityAlert
from backend.app.models.incident import SecurityIncident
from backend.app.schemas.dashboard import DashboardSummary, SeverityCount, TrendPoint

def get_dashboard_summary(db: Session) -> DashboardSummary:
    total_events = db.query(SecurityEvent).count()
    total_alerts = db.query(SecurityAlert).count()
    open_incidents = db.query(SecurityIncident).filter(SecurityIncident.status.in_(["OPEN", "IN_PROGRESS"])).count()
    threats_blocked = db.query(SecurityEvent).filter(SecurityEvent.status == "BLOCKED").count()

    critical_count = db.query(SecurityAlert).filter(SecurityAlert.severity == "CRITICAL").count()
    high_count = db.query(SecurityAlert).filter(SecurityAlert.severity == "HIGH").count()
    medium_count = db.query(SecurityAlert).filter(SecurityAlert.severity == "MEDIUM").count()
    low_count = db.query(SecurityAlert).filter(SecurityAlert.severity == "LOW").count()

    return DashboardSummary(
        total_events=total_events,
        total_alerts=total_alerts,
        open_incidents=open_incidents,
        threats_blocked=threats_blocked,
        severity_distribution=SeverityCount(
            critical=critical_count,
            high=high_count,
            medium=medium_count,
            low=low_count
        ),
        system_status="OPERATIONAL" if critical_count == 0 else "ELEVATED_THREAT"
    )

def get_dashboard_trends(db: Session) -> List[TrendPoint]:
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    points = []
    
    # Build 6 timeline buckets (past 6 hours, 1 hour increments)
    for i in range(5, -1, -1):
        window_start = now - datetime.timedelta(hours=i+1)
        window_end = now - datetime.timedelta(hours=i)
        label = (now - datetime.timedelta(hours=i)).strftime("%H:00")

        events_count = db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.timestamp < window_end
        ).count()

        failed_count = db.query(SecurityEvent).filter(
            SecurityEvent.timestamp >= window_start,
            SecurityEvent.timestamp < window_end,
            SecurityEvent.status.in_(["FAILURE", "BLOCKED"])
        ).count()

        alerts_count = db.query(SecurityAlert).filter(
            SecurityAlert.created_at >= window_start,
            SecurityAlert.created_at < window_end
        ).count()

        points.append(TrendPoint(
            timestamp=label,
            events=events_count,
            failed_logins=failed_count,
            alerts=alerts_count
        ))

    return points

def get_recent_activity(db: Session, limit: int = 10) -> List[Dict[str, Any]]:
    events = db.query(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    results = []
    for ev in events:
        severity = "LOW"
        if ev.status == "BLOCKED" or ev.event_type in ["C2_BEACON", "PORT_SCAN"]:
            severity = "HIGH"
        elif ev.event_type == "PRIVILEGE_ESCALATION" or ev.event_type == "AUTH_FAILED":
            severity = "MEDIUM" if ev.status == "FAILURE" else "CRITICAL"
        elif ev.status == "SUCCESS":
            severity = "LOW"

        results.append({
            "id": ev.id,
            "timestamp": ev.timestamp,
            "event_type": ev.event_type,
            "action": ev.action,
            "source_ip": ev.source_ip,
            "destination_ip": ev.destination_ip,
            "user_identity": ev.user_identity,
            "status": ev.status,
            "severity": severity,
            "details": ev.details
        })
    return results

def get_recent_alerts(db: Session, limit: int = 6) -> List[SecurityAlert]:
    return db.query(SecurityAlert).order_by(SecurityAlert.created_at.desc()).limit(limit).all()
