from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class IndicatorLookupRequest(BaseModel):
    indicator: str = Field(..., description="IP address or domain to investigate")

class AbuseIPDBResult(BaseModel):
    status: str # "LIVE_API", "CURATED_BASELINE", "NOT_CONFIGURED", "RATE_LIMITED", "ERROR"
    abuse_score: int
    total_reports: int
    last_reported_at: Optional[str] = None
    is_whitelisted: bool = False
    is_tor: bool = False
    country_code: Optional[str] = None
    country_name: Optional[str] = None
    isp: Optional[str] = None
    usage_type: Optional[str] = None
    error_message: Optional[str] = None

class VirusTotalResult(BaseModel):
    status: str # "LIVE_API", "CURATED_BASELINE", "NOT_CONFIGURED", "RATE_LIMITED", "ERROR"
    malicious_votes: int = 0
    suspicious_votes: int = 0
    harmless_votes: int = 0
    undetected_votes: int = 0
    reputation_score: int = 0
    categories: List[str] = []
    registrar_or_as_owner: Optional[str] = None
    country: Optional[str] = None
    error_message: Optional[str] = None

class InternalSOCActivity(BaseModel):
    observed_in_local_logs: bool = False
    events_count: int = 0
    alerts_count: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    associated_users: List[str] = []
    associated_actions: List[str] = []
    associated_alert_ids: List[int] = []

class ThreatInvestigationReport(BaseModel):
    indicator: str
    indicator_type: str # "IP" or "DOMAIN"
    verdict: str # "BENIGN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"
    confidence_score: int # 0 to 100
    threat_level: str # "CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN", "UNKNOWN"
    summary: str
    threat_categories: List[str] = []
    geolocation: Dict[str, Any] = {}
    is_private_ip: bool = False
    
    abuseipdb: Optional[AbuseIPDBResult] = None
    virustotal: Optional[VirusTotalResult] = None
    internal_soc_activity: InternalSOCActivity
    
    recommendation: str
    analyzed_at: datetime
    sources_consulted: List[str] = []
