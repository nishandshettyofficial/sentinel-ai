from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict

class SeverityCount(BaseModel):
    critical: int
    high: int
    medium: int
    low: int

class DashboardSummary(BaseModel):
    total_events: int
    total_alerts: int
    open_incidents: int
    threats_blocked: int
    severity_distribution: SeverityCount
    system_status: str

class TrendPoint(BaseModel):
    timestamp: str
    events: int
    failed_logins: int
    alerts: int

class RecentActivityItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    event_type: str
    action: str
    source_ip: str
    destination_ip: Optional[str] = None
    user_identity: Optional[str] = None
    status: str
    severity: Optional[str] = "LOW"
    details: Optional[Dict[str, Any]] = None

class AlertItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    description: str
    severity: str
    status: str
    rule_name: str
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    created_at: datetime
    evidence: Optional[Dict[str, Any]] = None
