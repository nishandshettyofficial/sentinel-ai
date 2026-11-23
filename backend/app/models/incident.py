import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from backend.app.core.database import Base

class SecurityIncident(Base):
    __tablename__ = "security_incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), index=True)
    severity = Column(String(20), index=True) # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(30), default="OPEN", index=True) # OPEN, IN_PROGRESS, CONTAINED, CLOSED
    assigned_analyst = Column(String(100), default="Security Lead")
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    summary = Column(Text, nullable=True)
    findings = Column(Text, nullable=True)
    remediation_steps = Column(JSON, nullable=True)
    associated_alert_ids = Column(JSON, nullable=True)
