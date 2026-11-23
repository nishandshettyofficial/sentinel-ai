import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from backend.app.core.database import Base

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), index=True)
    description = Column(Text)
    severity = Column(String(20), index=True) # CRITICAL, HIGH, MEDIUM, LOW
    status = Column(String(30), default="NEW", index=True) # NEW, INVESTIGATING, RESOLVED, DISMISSED
    rule_name = Column(String(100), index=True) # e.g. BRUTE_FORCE_LOGIN, IMPOSSIBLE_TRAVEL
    source_ip = Column(String(45), nullable=True, index=True)
    target_user = Column(String(100), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    evidence = Column(JSON, nullable=True) # supporting telemetry and event IDs
