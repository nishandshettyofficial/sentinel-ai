import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from backend.app.core.database import Base

class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    source_ip = Column(String(45), index=True)
    destination_ip = Column(String(45), nullable=True)
    user_identity = Column(String(100), nullable=True, index=True)
    event_type = Column(String(50), index=True) # e.g. AUTH_FAILED, AUTH_SUCCESS, PORT_SCAN, PRIVILEGE_ESCALATION
    action = Column(String(50)) # e.g. LOGIN, LOGOUT, FILE_ACCESS, API_REQUEST
    status = Column(String(20)) # SUCCESS, FAILURE, BLOCKED
    raw_log = Column(Text, nullable=True)
    details = Column(JSON, nullable=True)
