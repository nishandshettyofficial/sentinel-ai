import re
import ipaddress
import datetime
from typing import Tuple, Dict, Any, Optional, List
import httpx
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.app.core.config import settings
from backend.app.models.event import SecurityEvent
from backend.app.models.alert import SecurityAlert
from backend.app.schemas.threat_intel import (
    ThreatInvestigationReport,
    AbuseIPDBResult,
    VirusTotalResult,
    InternalSOCActivity
)

# ---------------------------------------------------------------------------
# Curated Baseline Intelligence for Realistic SOC Investigation & Testing
# ---------------------------------------------------------------------------
CURATED_INTEL_DB: Dict[str, Dict[str, Any]] = {
    # 1. High-risk Tor Exit Node / SSH Brute-Force IP
    "185.220.101.45": {
        "type": "IP",
        "verdict": "MALICIOUS",
        "confidence_score": 98,
        "threat_level": "CRITICAL",
        "threat_categories": ["Tor Exit Node", "SSH Brute-Force", "Scanner"],
        "summary": "Confirmed high-risk Tor Exit node actively engaged in automated SSH credential stuffing attacks across cloud providers.",
        "geolocation": {"country": "Germany", "country_code": "DE", "city": "Frankfurt", "asn": "AS208323", "org": "Tor Project Relay"},
        "abuseipdb": {
            "status": "CURATED_BASELINE",
            "abuse_score": 98,
            "total_reports": 1420,
            "last_reported_at": "2026-11-27T07:30:00Z",
            "is_whitelisted": False,
            "is_tor": True,
            "country_code": "DE",
            "country_name": "Germany",
            "isp": "Zwiebelfreunde e.V.",
            "usage_type": "Hosting / Data Center"
        },
        "virustotal": {
            "status": "CURATED_BASELINE",
            "malicious_votes": 38,
            "suspicious_votes": 5,
            "harmless_votes": 0,
            "undetected_votes": 49,
            "reputation_score": -42,
            "categories": ["tor-node", "brute-force", "botnet"],
            "registrar_or_as_owner": "AS208323",
            "country": "DE"
        },
        "recommendation": "Block all inbound perimeter ingress from this IP at edge firewalls and terminate active sessions."
    },

    # 2. Credential Spraying Scanner
    "198.51.100.42": {
        "type": "IP",
        "verdict": "MALICIOUS",
        "confidence_score": 85,
        "threat_level": "HIGH",
        "threat_categories": ["Password Spraying", "Lateral Probing", "Proxy"],
        "summary": "Observed in distributed credential spray campaigns targeting cloud identity providers (OIDC / OAuth).",
        "geolocation": {"country": "United States", "country_code": "US", "city": "Chicago", "asn": "AS64496", "org": "Cloud VPS Hosting"},
        "abuseipdb": {
            "status": "CURATED_BASELINE",
            "abuse_score": 85,
            "total_reports": 312,
            "last_reported_at": "2026-11-27T08:15:00Z",
            "is_whitelisted": False,
            "is_tor": False,
            "country_code": "US",
            "country_name": "United States",
            "isp": "ColoCrossing Hosting",
            "usage_type": "Commercial VPS"
        },
        "virustotal": {
            "status": "CURATED_BASELINE",
            "malicious_votes": 19,
            "suspicious_votes": 4,
            "harmless_votes": 1,
            "undetected_votes": 68,
            "reputation_score": -28,
            "categories": ["credential-harvester", "scanner"],
            "registrar_or_as_owner": "AS64496",
            "country": "US"
        },
        "recommendation": "Enforce strict rate limits on authentication endpoints and trigger immediate MFA prompts for targeted users."
    },

    # 3. Aggressive Brute-Force Attacker
    "203.0.113.88": {
        "type": "IP",
        "verdict": "MALICIOUS",
        "confidence_score": 92,
        "threat_level": "CRITICAL",
        "threat_categories": ["SSH Brute-Force", "Dictionary Attack", "Botnet Node"],
        "summary": "Source of high-velocity SSH credential brute-forcing targeting privileged administrative accounts.",
        "geolocation": {"country": "Netherlands", "country_code": "NL", "city": "Amsterdam", "asn": "AS197000", "org": "Bulletproof Hosting Services"},
        "abuseipdb": {
            "status": "CURATED_BASELINE",
            "abuse_score": 92,
            "total_reports": 640,
            "last_reported_at": "2026-11-27T08:13:00Z",
            "is_whitelisted": False,
            "is_tor": False,
            "country_code": "NL",
            "country_name": "Netherlands",
            "isp": "Serverius Holding B.V.",
            "usage_type": "Dedicated Hosting"
        },
        "virustotal": {
            "status": "CURATED_BASELINE",
            "malicious_votes": 24,
            "suspicious_votes": 3,
            "harmless_votes": 0,
            "undetected_votes": 65,
            "reputation_score": -35,
            "categories": ["brute-force", "ssh-scanner"],
            "registrar_or_as_owner": "AS197000",
            "country": "NL"
        },
        "recommendation": "Blacklist IP at perimeter border routers and inspect endpoint auth logs for successful compromised logins."
    },

    # 4. Reconnaissance & Port Scanning Host
    "91.240.118.172": {
        "type": "IP",
        "verdict": "SUSPICIOUS",
        "confidence_score": 68,
        "threat_level": "MEDIUM",
        "threat_categories": ["Port Scanner", "SYN Sweep", "Reconnaissance"],
        "summary": "Automated network scanner actively probing internet ranges for exposed administrative ports (21, 22, 3389, 8080).",
        "geolocation": {"country": "Russia", "country_code": "RU", "city": "Moscow", "asn": "AS49505", "org": "Selectel Network"},
        "abuseipdb": {
            "status": "CURATED_BASELINE",
            "abuse_score": 68,
            "total_reports": 185,
            "last_reported_at": "2026-11-27T08:20:00Z",
            "is_whitelisted": False,
            "is_tor": False,
            "country_code": "RU",
            "country_name": "Russian Federation",
            "isp": "Selectel Ltd",
            "usage_type": "Data Center"
        },
        "virustotal": {
            "status": "CURATED_BASELINE",
            "malicious_votes": 8,
            "suspicious_votes": 6,
            "harmless_votes": 2,
            "undetected_votes": 76,
            "reputation_score": -14,
            "categories": ["network-scanner", "port-prober"],
            "registrar_or_as_owner": "AS49505",
            "country": "RU"
        },
        "recommendation": "Verify external firewall rules; close unneeded port forwards and monitor edge IDS alerts."
    },

    # 5. Command & Control Server Infrastructure
    "194.26.29.99": {
        "type": "IP",
        "verdict": "MALICIOUS",
        "confidence_score": 96,
        "threat_level": "CRITICAL",
        "threat_categories": ["Command & Control (C2)", "DNS Tunneling", "Malware Drop"],
        "summary": "Confirmed active Command & Control (C2) server associated with DNS tunneling and remote access trojans.",
        "geolocation": {"country": "Seychelles", "country_code": "SC", "city": "Victoria", "asn": "AS200052", "org": "Offshore VPS Provider"},
        "abuseipdb": {
            "status": "CURATED_BASELINE",
            "abuse_score": 96,
            "total_reports": 820,
            "last_reported_at": "2026-11-27T08:25:00Z",
            "is_whitelisted": False,
            "is_tor": False,
            "country_code": "SC",
            "country_name": "Seychelles",
            "isp": "Offshore Cloud Infrastructure",
            "usage_type": "Hosting"
        },
        "virustotal": {
            "status": "CURATED_BASELINE",
            "malicious_votes": 42,
            "suspicious_votes": 3,
            "harmless_votes": 0,
            "undetected_votes": 47,
            "reputation_score": -55,
            "categories": ["c2", "malware", "dns-tunnel"],
            "registrar_or_as_owner": "AS200052",
            "country": "SC"
        },
        "recommendation": "Immediately sever network connection to host, quarantine communicating internal devices, and initiate forensic image."
    },

    # 6. Malicious C2 Domain
    "tunnel-stage-verify.top": {
        "type": "DOMAIN",
        "verdict": "MALICIOUS",
        "confidence_score": 94,
        "threat_level": "CRITICAL",
        "threat_categories": ["C2 Domain", "DNS Tunneling", "Newly Registered Domain"],
        "summary": "High-risk domain registered recently on cheap TLD (.top) used as an exfiltration point for DNS tunneling C2 beacons.",
        "geolocation": {"country": "Iceland", "country_code": "IS", "registrar": "NameSilo LLC", "created_date": "2026-11-15"},
        "virustotal": {
            "status": "CURATED_BASELINE",
            "malicious_votes": 28,
            "suspicious_votes": 5,
            "harmless_votes": 0,
            "undetected_votes": 59,
            "reputation_score": -48,
            "categories": ["c2-domain", "dns-tunneling", "phishing"],
            "registrar_or_as_owner": "NameSilo LLC",
            "country": "IS"
        },
        "recommendation": "Sinkhole domain at recursive DNS resolvers and search enterprise DNS logs for historical resolution lookups."
    },

    # 7. Suspicious C2 Domain
    "sync-cdn-telemetry.xyz": {
        "type": "DOMAIN",
        "verdict": "SUSPICIOUS",
        "confidence_score": 65,
        "threat_level": "MEDIUM",
        "threat_categories": ["Suspicious Domain", "Typosquatting", "Unclassified CDN"],
        "summary": "Domain masquerading as telemetry CDN; exhibits sporadic low-frequency beaconing patterns.",
        "geolocation": {"country": "Panama", "country_code": "PA", "registrar": "NameCheap, Inc.", "created_date": "2026-10-02"},
        "virustotal": {
            "status": "CURATED_BASELINE",
            "malicious_votes": 7,
            "suspicious_votes": 8,
            "harmless_votes": 2,
            "undetected_votes": 75,
            "reputation_score": -12,
            "categories": ["suspicious", "typosquatting"],
            "registrar_or_as_owner": "NameCheap, Inc.",
            "country": "PA"
        },
        "recommendation": "Monitor outbound proxy requests to this domain and check if endpoint applications legitimately communicate with it."
    },

    # 8. Clean / Benign Known Good: Google Public DNS
    "8.8.8.8": {
        "type": "IP",
        "verdict": "BENIGN",
        "confidence_score": 0,
        "threat_level": "CLEAN",
        "threat_categories": ["Public DNS Resolver", "Trusted Anycast", "Benign Infrastructure"],
        "summary": "Google Public DNS primary recursive resolver. Verified legitimate global internet infrastructure.",
        "geolocation": {"country": "United States", "country_code": "US", "city": "Mountain View", "asn": "AS15169", "org": "Google LLC"},
        "abuseipdb": {
            "status": "CURATED_BASELINE",
            "abuse_score": 0,
            "total_reports": 0,
            "is_whitelisted": True,
            "is_tor": False,
            "country_code": "US",
            "country_name": "United States",
            "isp": "Google LLC",
            "usage_type": "Public Anycast DNS"
        },
        "virustotal": {
            "status": "CURATED_BASELINE",
            "malicious_votes": 0,
            "suspicious_votes": 0,
            "harmless_votes": 88,
            "undetected_votes": 4,
            "reputation_score": 100,
            "categories": ["clean", "dns", "google"],
            "registrar_or_as_owner": "Google LLC",
            "country": "US"
        },
        "recommendation": "No action required. Indicator is verified clean global public infrastructure."
    },

    # 9. Clean / Benign Known Good: Cloudflare DNS
    "1.1.1.1": {
        "type": "IP",
        "verdict": "BENIGN",
        "confidence_score": 0,
        "threat_level": "CLEAN",
        "threat_categories": ["Public DNS Resolver", "Cloudflare Anycast", "Benign Infrastructure"],
        "summary": "Cloudflare 1.1.1.1 public recursive DNS service. Verified safe internet infrastructure.",
        "geolocation": {"country": "Australia", "country_code": "AU", "city": "Sydney", "asn": "AS13335", "org": "Cloudflare, Inc."},
        "abuseipdb": {
            "status": "CURATED_BASELINE",
            "abuse_score": 0,
            "total_reports": 0,
            "is_whitelisted": True,
            "is_tor": False,
            "country_code": "AU",
            "country_name": "Australia",
            "isp": "Cloudflare, Inc.",
            "usage_type": "Public Anycast DNS"
        },
        "virustotal": {
            "status": "CURATED_BASELINE",
            "malicious_votes": 0,
            "suspicious_votes": 0,
            "harmless_votes": 89,
            "undetected_votes": 3,
            "reputation_score": 100,
            "categories": ["clean", "dns", "cloudflare"],
            "registrar_or_as_owner": "Cloudflare, Inc.",
            "country": "AU"
        },
        "recommendation": "No action required. Indicator is safe trusted infrastructure."
    },

    # 10. Clean / Benign Domain: google.com
    "google.com": {
        "type": "DOMAIN",
        "verdict": "BENIGN",
        "confidence_score": 0,
        "threat_level": "CLEAN",
        "threat_categories": ["Search Engine", "Trusted Authority", "Top Alexa Domain"],
        "summary": "Official domain of Google LLC. Fully trusted global service.",
        "geolocation": {"country": "United States", "country_code": "US", "registrar": "MarkMonitor, Inc."},
        "virustotal": {
            "status": "CURATED_BASELINE",
            "malicious_votes": 0,
            "suspicious_votes": 0,
            "harmless_votes": 91,
            "undetected_votes": 1,
            "reputation_score": 100,
            "categories": ["clean", "search", "google"],
            "registrar_or_as_owner": "MarkMonitor, Inc.",
            "country": "US"
        },
        "recommendation": "No action required. Well-known trusted domain."
    }
}

# ---------------------------------------------------------------------------
# Indicator Validation & Normalization
# ---------------------------------------------------------------------------
def normalize_indicator(raw: str) -> Tuple[str, str, bool]:
    """
    Cleans defanged indicators (e.g. 1[.]1[.]1[.]1 -> 1.1.1.1, evil[.]com -> evil.com),
    strips schemes, paths, and returns (clean_indicator, indicator_type, is_private).
    """
    clean = raw.strip()
    # Strip protocol prefix
    clean = re.sub(r"^hxxps?://", "", clean, flags=re.IGNORECASE)
    clean = re.sub(r"^https?://", "", clean, flags=re.IGNORECASE)
    # Refang brackets
    clean = clean.replace("[.]", ".").replace("[:]", ":")
    # Strip paths, query params, ports
    clean = clean.split("/")[0].split("?")[0].strip()

    # If domain has port (e.g. domain.com:8080), remove port
    if ":" in clean and not clean.count(":") >= 2: # not IPv6
        clean = clean.split(":")[0]

    # Check if IP
    try:
        ip_obj = ipaddress.ip_address(clean)
        is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        return clean, "IP", is_private
    except ValueError:
        pass

    # Check if Domain
    return clean.lower(), "DOMAIN", False


# ---------------------------------------------------------------------------
# Public API Client Helpers: AbuseIPDB
# ---------------------------------------------------------------------------
def fetch_abuseipdb_data(ip: str) -> AbuseIPDBResult:
    """
    Queries AbuseIPDB v2 API if key is configured, handles rate limits and errors gracefully,
    or falls back to curated baseline intelligence.
    """
    api_key = settings.ABUSEIPDB_API_KEY.strip()
    
    # 1. If live API key is configured, execute live HTTP query
    if api_key:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        try:
            with httpx.Client(timeout=4.0) as client:
                res = client.get(url, headers=headers, params=params)
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    return AbuseIPDBResult(
                        status="LIVE_API",
                        abuse_score=data.get("abuseConfidenceScore", 0),
                        total_reports=data.get("totalReports", 0),
                        last_reported_at=data.get("lastReportedAt"),
                        is_whitelisted=data.get("isWhitelisted", False),
                        is_tor=data.get("isTor", False),
                        country_code=data.get("countryCode"),
                        country_name=data.get("countryName"),
                        isp=data.get("isp"),
                        usage_type=data.get("usageType")
                    )
                elif res.status_code == 429:
                    return AbuseIPDBResult(
                        status="RATE_LIMITED",
                        abuse_score=0,
                        total_reports=0,
                        error_message="AbuseIPDB daily API rate limit exceeded."
                    )
                else:
                    return AbuseIPDBResult(
                        status="ERROR",
                        abuse_score=0,
                        total_reports=0,
                        error_message=f"AbuseIPDB API returned status code {res.status_code}."
                    )
        except Exception as e:
            # Network failure or timeout, return graceful error status
            return AbuseIPDBResult(
                status="ERROR",
                abuse_score=0,
                total_reports=0,
                error_message=f"AbuseIPDB network lookup timeout: {str(e)}"
            )

    # 2. Check Curated Intelligence Baseline if key not provided
    if ip in CURATED_INTEL_DB and "abuseipdb" in CURATED_INTEL_DB[ip]:
        raw_db = CURATED_INTEL_DB[ip]["abuseipdb"]
        return AbuseIPDBResult(**raw_db)

    # 3. Not configured and not in curated baseline
    return AbuseIPDBResult(
        status="NOT_CONFIGURED",
        abuse_score=0,
        total_reports=0,
        error_message="ABUSEIPDB_API_KEY environment variable not set. Add key to .env for live lookups."
    )


# ---------------------------------------------------------------------------
# Public API Client Helpers: VirusTotal
# ---------------------------------------------------------------------------
def fetch_virustotal_data(indicator: str, indicator_type: str) -> VirusTotalResult:
    """
    Queries VirusTotal v3 API for IP or Domain if key is configured,
    handles rate limits and missing keys gracefully, or falls back to curated baseline.
    """
    api_key = settings.VIRUSTOTAL_API_KEY.strip()

    # 1. Live API query
    if api_key:
        endpoint = "ip_addresses" if indicator_type == "IP" else "domains"
        url = f"https://www.virustotal.com/api/v3/{endpoint}/{indicator}"
        headers = {"x-apikey": api_key}
        try:
            with httpx.Client(timeout=4.0) as client:
                res = client.get(url, headers=headers)
                if res.status_code == 200:
                    data = res.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    reputation = data.get("reputation", 0)
                    categories = list(data.get("categories", {}).values())

                    return VirusTotalResult(
                        status="LIVE_API",
                        malicious_votes=malicious,
                        suspicious_votes=suspicious,
                        harmless_votes=harmless,
                        undetected_votes=undetected,
                        reputation_score=reputation,
                        categories=categories[:8],
                        registrar_or_as_owner=data.get("as_owner") or data.get("registrar"),
                        country=data.get("country")
                    )
                elif res.status_code == 429:
                    return VirusTotalResult(
                        status="RATE_LIMITED",
                        error_message="VirusTotal API request quota exceeded."
                    )
                elif res.status_code == 404:
                    return VirusTotalResult(
                        status="NOT_FOUND",
                        error_message="Indicator has not been scanned or observed in VirusTotal database."
                    )
                else:
                    return VirusTotalResult(
                        status="ERROR",
                        error_message=f"VirusTotal API returned status {res.status_code}."
                    )
        except Exception as e:
            return VirusTotalResult(
                status="ERROR",
                error_message=f"VirusTotal API network failure: {str(e)}"
            )

    # 2. Check Curated Intelligence Baseline
    if indicator in CURATED_INTEL_DB and "virustotal" in CURATED_INTEL_DB[indicator]:
        raw_vt = CURATED_INTEL_DB[indicator]["virustotal"]
        return VirusTotalResult(**raw_vt)

    # 3. Not configured
    return VirusTotalResult(
        status="NOT_CONFIGURED",
        error_message="VIRUSTOTAL_API_KEY environment variable not set. Add key to .env for live lookups."
    )


# ---------------------------------------------------------------------------
# Internal SOC Telemetry Correlation
# ---------------------------------------------------------------------------
def correlate_internal_soc_activity(db: Session, indicator: str) -> InternalSOCActivity:
    """
    Searches Sentinel AI's local database (SecurityEvent & SecurityAlert)
    to check whether this IP or domain has been observed in our own ingested telemetry.
    """
    events_query = db.query(SecurityEvent).filter(
        or_(
            SecurityEvent.source_ip == indicator,
            SecurityEvent.destination_ip == indicator,
            SecurityEvent.raw_log.ilike(f"%{indicator}%")
        )
    )

    events_count = events_query.count()
    if events_count == 0:
        return InternalSOCActivity(
            observed_in_local_logs=False,
            events_count=0,
            alerts_count=0
        )

    all_events = events_query.order_by(SecurityEvent.timestamp.asc()).all()
    first_seen = all_events[0].timestamp if all_events else None
    last_seen = all_events[-1].timestamp if all_events else None

    users = list({ev.user_identity for ev in all_events if ev.user_identity})
    actions = list({ev.action for ev in all_events if ev.action})

    # Query matching alerts
    alerts_query = db.query(SecurityAlert).filter(
        or_(
            SecurityAlert.source_ip == indicator,
            SecurityAlert.description.ilike(f"%{indicator}%")
        )
    )
    alerts = alerts_query.all()
    alert_ids = [al.id for al in alerts]

    return InternalSOCActivity(
        observed_in_local_logs=True,
        events_count=events_count,
        alerts_count=len(alerts),
        first_seen=first_seen,
        last_seen=last_seen,
        associated_users=users[:6],
        associated_actions=actions[:6],
        associated_alert_ids=alert_ids
    )


# ---------------------------------------------------------------------------
# Master Threat Intelligence Orchestrator
# ---------------------------------------------------------------------------
def investigate_indicator(db: Session, raw_indicator: str) -> ThreatInvestigationReport:
    """
    Investigates an IP address or domain across public threat intelligence sources,
    correlates with internal SOC telemetry, calculates risk score, and generates
    an actionable SOC intelligence report.
    """
    indicator, indicator_type, is_private = normalize_indicator(raw_indicator)
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    sources_consulted = []

    # 1. Check Internal SOC activity in local database
    internal_act = correlate_internal_soc_activity(db, indicator)
    if internal_act.observed_in_local_logs:
        sources_consulted.append("Sentinel AI Internal Telemetry")

    # 2. Handle RFC1918 Private Internal Addresses
    if is_private:
        sources_consulted.append("RFC1918 Address Space Parser")
        verdict = "SUSPICIOUS" if internal_act.alerts_count > 0 else "BENIGN"
        threat_level = "MEDIUM" if internal_act.alerts_count > 0 else "CLEAN"
        score = 45 if internal_act.alerts_count > 0 else 0
        summary = (
            f"Indicator '{indicator}' is an RFC1918 private/internal IPv4 address. "
            f"Public threat intelligence databases (AbuseIPDB, VirusTotal) do not index internal private subnets. "
            f"{f'Observed in {internal_act.events_count} local events with {internal_act.alerts_count} triggered alerts.' if internal_act.observed_in_local_logs else 'No abnormal internal activity observed.'}"
        )
        recommendation = (
            "Verify internal host asset inventory and inspect host endpoint configuration."
            if internal_act.alerts_count > 0 else
            "Standard internal network traffic. No external threat intelligence action required."
        )

        return ThreatInvestigationReport(
            indicator=indicator,
            indicator_type="IP",
            verdict=verdict,
            confidence_score=score,
            threat_level=threat_level,
            summary=summary,
            threat_categories=["Internal RFC1918", "Private Network"] + (["Internal Anomaly"] if internal_act.alerts_count > 0 else []),
            geolocation={"network": "Internal Private Subnet", "scope": "Local LAN / VPC"},
            is_private_ip=True,
            abuseipdb=None,
            virustotal=None,
            internal_soc_activity=internal_act,
            recommendation=recommendation,
            analyzed_at=now,
            sources_consulted=sources_consulted
        )

    # 3. Query AbuseIPDB (for IPs)
    abuse_result = None
    if indicator_type == "IP":
        abuse_result = fetch_abuseipdb_data(indicator)
        sources_consulted.append(f"AbuseIPDB ({abuse_result.status})")

    # 4. Query VirusTotal (for IPs and Domains)
    vt_result = fetch_virustotal_data(indicator, indicator_type)
    sources_consulted.append(f"VirusTotal ({vt_result.status})")

    # 5. Check if we have curated metadata for known indicator
    curated = CURATED_INTEL_DB.get(indicator)
    
    # Calculate unified confidence score and verdict
    # Logic:
    # - If indicator is known malicious in curated or high Abuse/VT score:
    # - Clearly distinguish UNKNOWN indicators from CONFIRMED MALICIOUS indicators
    abuse_score = abuse_result.abuse_score if abuse_result else 0
    vt_malicious = vt_result.malicious_votes if vt_result else 0
    vt_suspicious = vt_result.suspicious_votes if vt_result else 0

    if curated:
        verdict = curated["verdict"]
        score = curated["confidence_score"]
        threat_level = curated["threat_level"]
        summary = curated["summary"]
        categories = list(curated["threat_categories"])
        geolocation = dict(curated["geolocation"])
        recommendation = curated["recommendation"]
    else:
        # Dynamic calculation based on live public API telemetry
        has_public_data = (
            (abuse_result and abuse_result.status == "LIVE_API") or 
            (vt_result and vt_result.status == "LIVE_API")
        )

        if not has_public_data:
            # Indicator has no reports or external intelligence configured
            verdict = "UNKNOWN"
            score = 0
            threat_level = "UNKNOWN"
            categories = ["Unrated Indicator", "No Public Threat Intel Reports"]
            geolocation = {"country": "Unknown / Unresolved", "org": "N/A"}
            summary = (
                f"Indicator '{indicator}' is currently UNRATED in public threat intelligence sources. "
                f"No active abuse reports or malicious signatures were identified. "
                f"Avoid treating an unrated indicator as safe without monitoring."
            )
            recommendation = (
                f"Treat indicator as unverified. Cross-reference with internal authentication logs and monitor for repeated connection requests."
            )
        else:
            # We have live API data
            score = max(abuse_score, min(100, vt_malicious * 4 + vt_suspicious * 2))
            geolocation = {
                "country": (abuse_result and abuse_result.country_name) or (vt_result and vt_result.country) or "Global",
                "country_code": (abuse_result and abuse_result.country_code) or "XX",
                "isp": (abuse_result and abuse_result.isp) or (vt_result and vt_result.registrar_or_as_owner) or "N/A"
            }
            categories = []
            if abuse_result and abuse_result.is_tor:
                categories.append("Tor Exit Node")
            if vt_result and vt_result.categories:
                categories.extend(vt_result.categories[:4])

            if score >= 70 or vt_malicious >= 5:
                verdict = "MALICIOUS"
                threat_level = "CRITICAL" if score >= 85 else "HIGH"
                if not categories:
                    categories.append("Malicious Indicator")
                summary = (
                    f"Confirmed high-risk indicator with significant abuse reports "
                    f"(Abuse Score: {abuse_score}%, VirusTotal detections: {vt_malicious})."
                )
                recommendation = "Enforce immediate perimeter firewall blocking and inspect communicating hosts."
            elif score >= 20 or vt_suspicious >= 2:
                verdict = "SUSPICIOUS"
                threat_level = "MEDIUM"
                if not categories:
                    categories.append("Suspicious Indicator")
                summary = (
                    f"Elevated risk score ({score}%) observed in public threat repositories. "
                    f"Possible automated scanner or shared proxy."
                )
                recommendation = "Apply conditional access challenges and closely monitor communication frequency."
            else:
                verdict = "BENIGN"
                threat_level = "CLEAN"
                categories = ["Benign / Low Risk"]
                summary = f"Indicator has clean public reputation (Abuse Score: {abuse_score}%, VirusTotal detections: {vt_malicious})."
                recommendation = "Standard legitimate traffic. No mitigation required."

    # If internal SOC events are present, enrich summary and threat categories
    if internal_act.observed_in_local_logs:
        categories.append(f"Local Activity ({internal_act.events_count} events)")
        if internal_act.alerts_count > 0:
            categories.append(f"Internal Alerts ({internal_act.alerts_count})")
            if verdict == "UNKNOWN":
                verdict = "SUSPICIOUS"
                threat_level = "MEDIUM"
                score = max(score, 50)
                summary += f" However, it has triggered {internal_act.alerts_count} security alerts in local Sentinel AI telemetry."

    return ThreatInvestigationReport(
        indicator=indicator,
        indicator_type=indicator_type,
        verdict=verdict,
        confidence_score=score,
        threat_level=threat_level,
        summary=summary,
        threat_categories=categories,
        geolocation=geolocation,
        is_private_ip=False,
        abuseipdb=abuse_result,
        virustotal=vt_result,
        internal_soc_activity=internal_act,
        recommendation=recommendation,
        analyzed_at=now,
        sources_consulted=sources_consulted
    )
