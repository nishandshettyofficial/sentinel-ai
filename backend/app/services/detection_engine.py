import datetime
from typing import List, Dict, Any, Tuple
from collections import defaultdict
from sqlalchemy.orm import Session
from backend.app.models.event import SecurityEvent
from backend.app.models.alert import SecurityAlert

PRIVILEGED_ACCOUNTS = {"root", "admin", "administrator", "sysadmin", "superuser"}

def analyze_events_and_detect_threats(
    db: Session,
    events: List[SecurityEvent]
) -> List[SecurityAlert]:
    """
    Evaluates correlation rules over newly ingested events and historical window
    to generate actionable SecurityAlert records with structured evidence.
    """
    if not events:
        return []

    alerts_created: List[SecurityAlert] = []
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    # Buckets for correlation
    ip_failed_logins = defaultdict(list)        # source_ip -> list of events
    ip_targeted_users = defaultdict(lambda: defaultdict(list)) # source_ip -> user -> list of events
    ip_port_scans = defaultdict(list)           # source_ip -> list of events

    for ev in events:
        is_auth_fail = (
            ev.event_type in ["AUTH_FAILED", "LOGIN_FAILED", "AUTHENTICATION_FAILURE"] or 
            (ev.action in ["LOGIN", "SSH_LOGIN", "LOGIN_WEB", "AUTH"] and ev.status in ["FAILURE", "BLOCKED"])
        )
        if is_auth_fail and ev.source_ip:
            ip_failed_logins[ev.source_ip].append(ev)
            user_key = ev.user_identity or "unknown"
            ip_targeted_users[ev.source_ip][user_key].append(ev)

        if ev.event_type == "PORT_SCAN" or ev.action in ["PORT_SCAN", "TCP_SYN_SWEEP"]:
            ip_port_scans[ev.source_ip].append(ev)

        # Single-event rule: Privilege Escalation
        if ev.event_type == "PRIVILEGE_ESCALATION" or "SUDO" in (ev.action or ""):
            if ev.status in ["FAILURE", "BLOCKED"]:
                alert = SecurityAlert(
                    title=f"Unauthorized Privilege Escalation by '{ev.user_identity or 'unknown'}'",
                    description=(
                        f"Host/User '{ev.user_identity}' attempted unauthorized privilege escalation "
                        f"via action '{ev.action}'. Verdict: {ev.status}."
                    ),
                    severity="HIGH",
                    status="NEW",
                    rule_name="RULE_HOST_SUDO_VIOLATION",
                    source_ip=ev.source_ip,
                    target_user=ev.user_identity,
                    created_at=ev.timestamp or now,
                    evidence={
                        "event_id": ev.id,
                        "action": ev.action,
                        "details": ev.details,
                        "raw_log": ev.raw_log
                    }
                )
                db.add(alert)
                alerts_created.append(alert)

        # Single-event rule: C2 Beaconing
        if ev.event_type == "C2_BEACON":
            domain = (ev.details or {}).get("domain") or "unknown-c2-domain"
            alert = SecurityAlert(
                title=f"Command & Control (C2) Beaconing Detected",
                description=(
                    f"Outbound C2 communication attempt detected from internal endpoint {ev.source_ip} "
                    f"to suspicious domain {domain}."
                ),
                severity="HIGH",
                status="NEW",
                rule_name="RULE_NETWORK_C2_BEACON",
                source_ip=ev.source_ip,
                target_user=ev.user_identity,
                created_at=ev.timestamp or now,
                evidence={
                    "event_id": ev.id,
                    "destination_ip": ev.destination_ip,
                    "domain": domain,
                    "details": ev.details
                }
            )
            db.add(alert)
            alerts_created.append(alert)

    # Correlation Rule 1: Brute Force Authentication
    for ip, user_dict in ip_targeted_users.items():
        # Check if single IP is attacking multiple distinct accounts (Password Spraying)
        if len(user_dict) >= 3:
            total_attempts = sum(len(ev_list) for ev_list in user_dict.values())
            target_list = list(user_dict.keys())
            event_ids = [ev.id for ev_list in user_dict.values() for ev in ev_list]
            
            alert = SecurityAlert(
                title=f"Distributed Password Spraying Detected from {ip}",
                description=(
                    f"Source IP {ip} targeted {len(target_list)} distinct user accounts "
                    f"with {total_attempts} failed authentication attempts."
                ),
                severity="CRITICAL",
                status="NEW",
                rule_name="RULE_AUTH_PASSWORD_SPRAYING",
                source_ip=ip,
                target_user=f"{len(target_list)} accounts",
                created_at=now,
                evidence={
                    "total_attempts": total_attempts,
                    "targeted_users": target_list,
                    "event_ids": event_ids[:20],
                    "recommendation": "Enforce immediate IP blacklist at perimeter gateway."
                }
            )
            db.add(alert)
            alerts_created.append(alert)

        # Check per-user repeated failed logins (Brute Force)
        for user, ev_list in user_dict.items():
            if len(ev_list) >= 3:
                # Avoid duplicating if already caught by password spraying on single user
                is_priv = user.lower() in PRIVILEGED_ACCOUNTS
                severity = "CRITICAL" if (is_priv or len(ev_list) >= 5) else "HIGH"
                event_ids = [ev.id for ev in ev_list]

                alert = SecurityAlert(
                    title=f"Brute-Force Authentication Attack on '{user}' from {ip}",
                    description=(
                        f"Detected {len(ev_list)} consecutive failed login attempts against account '{user}' "
                        f"originating from {ip}."
                    ),
                    severity=severity,
                    status="NEW",
                    rule_name="RULE_AUTH_BRUTE_FORCE",
                    source_ip=ip,
                    target_user=user,
                    created_at=now,
                    evidence={
                        "failed_attempts": len(ev_list),
                        "targeted_account": user,
                        "privileged": is_priv,
                        "event_ids": event_ids[:20],
                        "recommendation": f"Lock account '{user}' and block IP {ip}."
                    }
                )
                db.add(alert)
                alerts_created.append(alert)

    # Correlation Rule 2: Port Scanning / Reconnaissance
    for ip, ev_list in ip_port_scans.items():
        if len(ev_list) >= 1:
            scanned_ports = []
            for ev in ev_list:
                ports = (ev.details or {}).get("scanned_ports") or []
                if isinstance(ports, list):
                    scanned_ports.extend(ports)
            scanned_ports = list(set(scanned_ports))

            severity = "HIGH" if len(scanned_ports) >= 5 or len(ev_list) >= 3 else "MEDIUM"
            alert = SecurityAlert(
                title=f"Network Reconnaissance & Port Sweep from {ip}",
                description=(
                    f"Source host {ip} executed rapid connection sweep scanning ports: "
                    f"{', '.join(map(str, scanned_ports[:8])) or 'multiple targets'}."
                ),
                severity=severity,
                status="NEW",
                rule_name="RULE_PERIMETER_PORT_SCAN",
                source_ip=ip,
                target_user=None,
                created_at=now,
                evidence={
                    "probes_count": len(ev_list),
                    "scanned_ports": scanned_ports,
                    "event_ids": [ev.id for ev in ev_list]
                }
            )
            db.add(alert)
            alerts_created.append(alert)

    if alerts_created:
        db.commit()

    return alerts_created
