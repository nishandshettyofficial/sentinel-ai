from typing import List, Dict, Any
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from backend.app.core.database import get_db
from backend.app.core.config import settings
from backend.app.core.errors import SentinelException
from backend.app.schemas.threat_intel import (
    IndicatorLookupRequest,
    ThreatInvestigationReport
)
from backend.app.services.threat_intelligence import (
    investigate_indicator,
    CURATED_INTEL_DB
)

router = APIRouter()

SAMPLE_INDICATORS = [
    {
        "indicator": "185.220.101.45",
        "type": "IP",
        "label": "Tor Exit Node (SSH Brute-Force)",
        "risk": "CRITICAL",
        "description": "Known high-risk Tor relay actively attempting SSH password brute-forcing."
    },
    {
        "indicator": "198.51.100.42",
        "type": "IP",
        "label": "Credential Spraying Node",
        "risk": "HIGH",
        "description": "Commercial VPS attempting horizontal password spraying against employees."
    },
    {
        "indicator": "tunnel-stage-verify.top",
        "type": "DOMAIN",
        "label": "DNS Tunneling C2 Domain",
        "risk": "CRITICAL",
        "description": "Newly registered .top domain used for command-and-control exfiltration."
    },
    {
        "indicator": "91.240.118.172",
        "type": "IP",
        "label": "Port Scanner & Recon Host",
        "risk": "MEDIUM",
        "description": "External host executing aggressive TCP SYN port sweeps."
    },
    {
        "indicator": "8.8.8.8",
        "type": "IP",
        "label": "Google Public DNS",
        "risk": "CLEAN",
        "description": "Trusted public recursive DNS resolver (Benign baseline)."
    },
    {
        "indicator": "192.168.1.105",
        "type": "IP",
        "label": "Internal Workstation (RFC1918)",
        "risk": "CLEAN",
        "description": "Local internal engineering subnet address."
    },
    {
        "indicator": "unrated-test-host.org",
        "type": "DOMAIN",
        "label": "Unrated Indicator (Unknown)",
        "risk": "UNKNOWN",
        "description": "Sample unrated domain with zero public reputation records."
    }
]

@router.get("/investigate", response_model=ThreatInvestigationReport, summary="Investigate IP or Domain via GET")
def investigate_indicator_get(
    indicator: str = Query(..., min_length=1, description="IP address or domain to analyze"),
    db: Session = Depends(get_db)
):
    if not indicator.strip():
        raise SentinelException(
            message="Indicator query parameter cannot be empty.",
            code="EMPTY_INDICATOR",
            status_code=status.HTTP_400_BAD_REQUEST
        )
    return investigate_indicator(db, indicator)

@router.post("/investigate", response_model=ThreatInvestigationReport, summary="Investigate IP or Domain via POST")
def investigate_indicator_post(
    payload: IndicatorLookupRequest,
    db: Session = Depends(get_db)
):
    if not payload.indicator.strip():
        raise SentinelException(
            message="Indicator payload cannot be empty.",
            code="EMPTY_INDICATOR",
            status_code=status.HTTP_400_BAD_REQUEST
        )
    return investigate_indicator(db, payload.indicator)

@router.get("/samples", summary="List Sample Threat Intelligence Indicators")
def get_sample_indicators():
    return SAMPLE_INDICATORS

@router.get("/status", summary="Threat Intelligence Provider Configuration Status")
def get_provider_status():
    return {
        "virustotal": {
            "configured": bool(settings.VIRUSTOTAL_API_KEY.strip()),
            "provider": "VirusTotal v3 REST API",
            "capabilities": ["IP Reputation", "Domain Analysis", "Category Tagging"]
        },
        "abuseipdb": {
            "configured": bool(settings.ABUSEIPDB_API_KEY.strip()),
            "provider": "AbuseIPDB v2 Check API",
            "capabilities": ["Abuse Confidence Score", "Reporting History", "Tor Detection", "ISP / Geo"]
        },
        "curated_baseline": {
            "active": True,
            "indicators_cached": len(CURATED_INTEL_DB),
            "description": "High-fidelity curated threat baseline used for testing and fallback."
        },
        "local_soc_correlation": {
            "active": True,
            "description": "Real-time cross-referencing with Sentinel AI event repository and active alerts."
        }
    }
