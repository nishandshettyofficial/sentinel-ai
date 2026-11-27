import datetime
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict, Counter
from sqlalchemy.orm import Session
from backend.app.models.event import SecurityEvent
from backend.app.models.alert import SecurityAlert

# Privileged accounts that warrant escalated alert severity
PRIVILEGED_ACCOUNTS = {
    "root", "admin", "administrator", "sysadmin", "superuser", 
    "operator", "master", "service_admin", "secops"
}

# Universal non-definitive disclaimer required for all security alerts
ANOMALY_DISCLAIMER = (
    "Alert represents a detected behavioral anomaly and must be investigated "
    "before confirming as malicious."
)

def _is_auth_failure(ev: SecurityEvent) -> bool:
    """Helper to detect whether an event represents a failed authentication attempt."""
    ev_type = (ev.event_type or "").upper()
    action = (ev.action or "").upper()
    status = (ev.status or "").upper()

    if ev_type in ["AUTH_FAILED", "LOGIN_FAILED", "AUTHENTICATION_FAILURE", "FAILED_LOGIN"]:
        return True
    if action in ["LOGIN", "SSH_LOGIN", "LOGIN_WEB", "AUTH", "LOGIN_SSO", "API_AUTH"]:
        return status in ["FAILURE", "BLOCKED", "FAILED", "DENIED", "REJECTED"]
    return False

def evaluate_rules(events: List[SecurityEvent]) -> List[SecurityAlert]:
    """
    Evaluates correlation rules over an input batch of SecurityEvent objects in-memory.
    Returns generated SecurityAlert instances with structured evidence and objective wording.
    Does not require an active database session.
    """
    if not events:
        return []

    alerts: List[SecurityAlert] = []
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    # -------------------------------------------------------------
    # Rule 1 & Rule 2: Authentication Failures & Password Spraying
    # -------------------------------------------------------------
    # ip -> user -> list of events
    ip_user_failures: Dict[str, Dict[str, List[SecurityEvent]]] = defaultdict(lambda: defaultdict(list))
    # user -> ip -> list of events
    user_ip_events: Dict[str, Dict[str, List[SecurityEvent]]] = defaultdict(lambda: defaultdict(list))
    # ip -> list of all events
    ip_all_events: Dict[str, List[SecurityEvent]] = defaultdict(list)
    # ip -> port scan events
    ip_port_scans: Dict[str, List[SecurityEvent]] = defaultdict(list)

    for ev in events:
        src_ip = (ev.source_ip or "").strip()
        user = (ev.user_identity or "").strip()

        if src_ip:
            ip_all_events[src_ip].append(ev)

        if user and user.lower() not in ["none", "null", "unknown", "-", "anonymous"]:
            if src_ip:
                user_ip_events[user][src_ip].append(ev)

        if _is_auth_failure(ev) and src_ip:
            target_account = user if user else "unknown"
            ip_user_failures[src_ip][target_account].append(ev)

        ev_type = (ev.event_type or "").upper()
        action = (ev.action or "").upper()
        if ev_type == "PORT_SCAN" or action in ["PORT_SCAN", "TCP_SYN_SWEEP"]:
            if src_ip:
                ip_port_scans[src_ip].append(ev)

        # ---------------------------------------------------------
        # Single-event rule: Unauthorized Privilege Escalation
        # ---------------------------------------------------------
        if ev_type == "PRIVILEGE_ESCALATION" or "SUDO" in action:
            ev_status = (ev.status or "").upper()
            if ev_status in ["FAILURE", "BLOCKED", "DENIED"]:
                target = ev.user_identity or "unknown"
                is_priv = target.lower() in PRIVILEGED_ACCOUNTS
                sev = "CRITICAL" if is_priv else "HIGH"
                alert = SecurityAlert(
                    title=f"Potential Privilege Escalation Anomaly on '{target}'",
                    description=(
                        f"Host/User '{target}' executed unauthorized command '{ev.action}'. "
                        f"Status: {ev.status}. Flagged for policy violation. "
                        f"Note: This alert reflects an unconfirmed security anomaly pending SOC verification."
                    ),
                    severity=sev,
                    status="NEW",
                    rule_name="RULE_HOST_SUDO_VIOLATION",
                    source_ip=ev.source_ip,
                    target_user=ev.user_identity,
                    created_at=ev.timestamp or now,
                    evidence={
                        "event_ids": [ev.id] if ev.id else [],
                        "action": ev.action,
                        "details": ev.details,
                        "raw_log": ev.raw_log,
                        "anomaly_classification": "SUSPECTED_PRIVILEGE_ESCALATION",
                        "verification_status": "UNCONFIRMED_ANOMALY",
                        "disclaimer": ANOMALY_DISCLAIMER,
                        "recommendation": f"Verify user '{target}' administrative privileges and inspect local audit logs."
                    }
                )
                alerts.append(alert)

        # ---------------------------------------------------------
        # Single-event rule: Command & Control (C2) Beaconing
        # ---------------------------------------------------------
        if ev_type == "C2_BEACON":
            domain = (ev.details or {}).get("domain") or "suspicious-endpoint"
            alert = SecurityAlert(
                title=f"Potential C2 Beaconing Communication Anomaly from {ev.source_ip or 'endpoint'}",
                description=(
                    f"Outbound communication pattern matching C2 beaconing observed from internal IP {ev.source_ip} "
                    f"to destination domain '{domain}'. Flagged for perimeter anomaly. "
                    f"Note: Unconfirmed anomaly pending verification of legitimate background software telemetry."
                ),
                severity="HIGH",
                status="NEW",
                rule_name="RULE_NETWORK_C2_BEACON",
                source_ip=ev.source_ip,
                target_user=ev.user_identity,
                created_at=ev.timestamp or now,
                evidence={
                    "event_ids": [ev.id] if ev.id else [],
                    "destination_ip": ev.destination_ip,
                    "domain": domain,
                    "details": ev.details,
                    "anomaly_classification": "SUSPECTED_C2_BEACON",
                    "verification_status": "UNCONFIRMED_ANOMALY",
                    "disclaimer": ANOMALY_DISCLAIMER,
                    "recommendation": f"Isolate endpoint {ev.source_ip} and review host process connections."
                }
            )
            alerts.append(alert)

    # -------------------------------------------------------------
    # RULE 2: Unusual Login Patterns / Distributed Password Spraying
    # -------------------------------------------------------------
    for ip, user_dict in ip_user_failures.items():
        distinct_users = list(user_dict.keys())
        # Horizontal attack across 3 or more accounts
        if len(distinct_users) >= 3:
            total_attempts = sum(len(evs) for evs in user_dict.values())
            event_ids = [ev.id for evs in user_dict.values() for ev in evs if ev.id]
            any_privileged = any(u.lower() in PRIVILEGED_ACCOUNTS for u in distinct_users)
            
            # Severity mapping: >= 5 accounts or targeting privileged account is CRITICAL, else HIGH
            severity = "CRITICAL" if (len(distinct_users) >= 5 or any_privileged) else "HIGH"
            sample_accounts = ", ".join(distinct_users[:5])
            if len(distinct_users) > 5:
                sample_accounts += f" (+{len(distinct_users) - 5} more)"

            alert = SecurityAlert(
                title=f"Potential Password Spraying Anomaly from {ip}",
                description=(
                    f"Source IP {ip} was observed targeting {len(distinct_users)} distinct accounts "
                    f"({sample_accounts}) with {total_attempts} failed authentication attempts. "
                    f"Flagged for unusual horizontal credential probing. "
                    f"Note: This alert reflects an unconfirmed security anomaly pending SOC triage."
                ),
                severity=severity,
                status="NEW",
                rule_name="RULE_AUTH_PASSWORD_SPRAYING",
                source_ip=ip,
                target_user=f"{len(distinct_users)} accounts",
                created_at=now,
                evidence={
                    "source_ip": ip,
                    "distinct_accounts_count": len(distinct_users),
                    "targeted_accounts": distinct_users,
                    "total_failed_attempts": total_attempts,
                    "event_ids": event_ids[:30],
                    "anomaly_classification": "SUSPECTED_PASSWORD_SPRAYING",
                    "verification_status": "UNCONFIRMED_ANOMALY",
                    "disclaimer": ANOMALY_DISCLAIMER,
                    "recommendation": f"Inspect ingress gateway logs for IP {ip}; enforce temporary perimeter block if unrecognized."
                }
            )
            alerts.append(alert)

    # -------------------------------------------------------------
    # RULE 1: Repeated Failed Login Attempts (Brute-Force)
    # -------------------------------------------------------------
    for ip, user_dict in ip_user_failures.items():
        for user, ev_list in user_dict.items():
            failed_count = len(ev_list)
            if failed_count >= 2:
                is_priv = user.lower() in PRIVILEGED_ACCOUNTS
                # Severity scale:
                # Privileged: 2 -> HIGH, >=3 -> CRITICAL
                # Normal: 2 -> LOW, 3 -> MEDIUM, 4 -> HIGH, >=5 -> CRITICAL
                if is_priv:
                    sev = "CRITICAL" if failed_count >= 3 else "HIGH"
                else:
                    if failed_count >= 5:
                        sev = "CRITICAL"
                    elif failed_count == 4:
                        sev = "HIGH"
                    elif failed_count == 3:
                        sev = "MEDIUM"
                    else:
                        sev = "LOW"

                event_ids = [ev.id for ev in ev_list if ev.id]

                # Calculate duration if timestamps exist
                time_window_sec = 0.0
                valid_ts = [ev.timestamp for ev in ev_list if ev.timestamp]
                if len(valid_ts) >= 2:
                    sorted_ts = sorted(valid_ts)
                    time_window_sec = (sorted_ts[-1] - sorted_ts[0]).total_seconds()

                alert = SecurityAlert(
                    title=f"Potential Brute-Force Authentication Anomaly on '{user}' from {ip}",
                    description=(
                        f"Observed {failed_count} failed authentication attempts targeting account '{user}' "
                        f"originating from source IP {ip}. Flagged as a potential automated authentication attack. "
                        f"Note: This alert represents an unconfirmed behavioral anomaly requiring SOC investigation before taking punitive action."
                    ),
                    severity=sev,
                    status="NEW",
                    rule_name="RULE_AUTH_BRUTE_FORCE",
                    source_ip=ip,
                    target_user=user,
                    created_at=now,
                    evidence={
                        "failed_attempts": failed_count,
                        "target_account": user,
                        "source_ip": ip,
                        "is_privileged_account": is_priv,
                        "time_window_seconds": time_window_sec,
                        "event_ids": event_ids[:30],
                        "anomaly_classification": "SUSPECTED_BRUTE_FORCE",
                        "verification_status": "UNCONFIRMED_ANOMALY",
                        "disclaimer": ANOMALY_DISCLAIMER,
                        "recommendation": f"Verify account '{user}' status; consider enforcing MFA challenge or temporary lockout."
                    }
                )
                alerts.append(alert)

    # -------------------------------------------------------------
    # RULE 3: Multiple IP Addresses Accessing One Account
    # -------------------------------------------------------------
    for user, ip_dict in user_ip_events.items():
        distinct_ips = list(ip_dict.keys())
        if len(distinct_ips) >= 2:
            all_user_events = [ev for ev_list in ip_dict.values() for ev in ev_list]
            event_ids = [ev.id for ev in all_user_events if ev.id]

            # Count status distribution
            status_counts = Counter(ev.status or "UNKNOWN" for ev in all_user_events)
            has_failures = any(k in ["FAILURE", "BLOCKED", "DENIED"] for k in status_counts.keys())
            
            # Severity mapping:
            # >= 3 distinct IPs: CRITICAL if failures present or >=4 IPs, else HIGH
            # 2 distinct IPs: HIGH if failures present, else MEDIUM
            if len(distinct_ips) >= 3:
                sev = "CRITICAL" if (has_failures or len(distinct_ips) >= 4) else "HIGH"
            else:
                sev = "HIGH" if has_failures else "MEDIUM"

            ips_sample = ", ".join(distinct_ips[:4])
            if len(distinct_ips) > 4:
                ips_sample += f" (+{len(distinct_ips) - 4} more)"

            alert = SecurityAlert(
                title=f"Potential Multi-IP Concurrent Access Anomaly for '{user}'",
                description=(
                    f"User identity '{user}' was accessed or authenticated from {len(distinct_ips)} distinct "
                    f"IP addresses ({ips_sample}) within the telemetry window. "
                    f"Flagged for potential credential sharing, session hijacking, or impossible travel. "
                    f"Note: Unconfirmed anomaly pending verification of authorized VPN or multi-device usage."
                ),
                severity=sev,
                status="NEW",
                rule_name="RULE_MULTI_IP_ACCOUNT_ACCESS",
                source_ip=", ".join(distinct_ips[:3]),
                target_user=user,
                created_at=now,
                evidence={
                    "target_user": user,
                    "distinct_ip_count": len(distinct_ips),
                    "distinct_ips": distinct_ips,
                    "total_events": len(all_user_events),
                    "status_breakdown": dict(status_counts),
                    "event_ids": event_ids[:30],
                    "anomaly_classification": "SUSPECTED_MULTI_IP_ACCESS",
                    "verification_status": "UNCONFIRMED_ANOMALY",
                    "disclaimer": ANOMALY_DISCLAIMER,
                    "recommendation": f"Prompt user '{user}' to confirm recent sign-in locations and check for active VPN connections."
                }
            )
            alerts.append(alert)

    # -------------------------------------------------------------
    # RULE 4: Suspicious Activity Spikes
    # -------------------------------------------------------------
    for ip, ev_list in ip_all_events.items():
        event_count = len(ev_list)
        # Threshold: 6 or more events from single IP within the ingested dataset
        if event_count >= 6:
            # Severity scale based on volume surge:
            # 6 - 7 events: LOW
            # 8 - 11 events: MEDIUM
            # 12 - 19 events: HIGH
            # >= 20 events: CRITICAL
            if event_count >= 20:
                sev = "CRITICAL"
            elif event_count >= 12:
                sev = "HIGH"
            elif event_count >= 8:
                sev = "MEDIUM"
            else:
                sev = "LOW"

            # Determine dominant action
            actions = [ev.action or ev.event_type or "UNKNOWN" for ev in ev_list]
            dominant_action = Counter(actions).most_common(1)[0][0]

            # Calculate burst duration
            time_window_sec = 0.0
            valid_ts = [ev.timestamp for ev in ev_list if ev.timestamp]
            if len(valid_ts) >= 2:
                sorted_ts = sorted(valid_ts)
                time_window_sec = (sorted_ts[-1] - sorted_ts[0]).total_seconds()

            event_ids = [ev.id for ev in ev_list if ev.id]

            time_desc = f"{round(time_window_sec, 1)} seconds" if time_window_sec > 0 else "the ingestion window"

            alert = SecurityAlert(
                title=f"Suspicious Telemetry Activity Spike Detected from {ip}",
                description=(
                    f"Observed sudden activity spike of {event_count} events originating from source IP {ip} "
                    f"(dominant action: '{dominant_action}') within {time_desc}. "
                    f"Flagged for potential automated scanning, rate limit threshold breach, or denial-of-service probing. "
                    f"Note: This alert reflects an unconfirmed security anomaly pending baseline traffic verification."
                ),
                severity=sev,
                status="NEW",
                rule_name="RULE_ACTIVITY_SPIKE",
                source_ip=ip,
                target_user=ev_list[0].user_identity if ev_list else None,
                created_at=now,
                evidence={
                    "source_ip": ip,
                    "event_count": event_count,
                    "dominant_action": dominant_action,
                    "time_window_seconds": time_window_sec,
                    "event_ids": event_ids[:30],
                    "anomaly_classification": "SUSPECTED_ACTIVITY_SPIKE",
                    "verification_status": "UNCONFIRMED_ANOMALY",
                    "disclaimer": ANOMALY_DISCLAIMER,
                    "recommendation": f"Inspect ingress traffic rate from {ip} and verify against normal operational baselines."
                }
            )
            alerts.append(alert)

    # -------------------------------------------------------------
    # Auxiliary Rule: Perimeter Reconnaissance & Port Sweeps
    # -------------------------------------------------------------
    for ip, ev_list in ip_port_scans.items():
        if len(ev_list) >= 1:
            scanned_ports = []
            for ev in ev_list:
                ports = (ev.details or {}).get("scanned_ports") or []
                if isinstance(ports, list):
                    scanned_ports.extend(ports)
            scanned_ports = sorted(list(set(scanned_ports)))

            if len(scanned_ports) >= 6 or len(ev_list) >= 4:
                sev = "HIGH"
            elif len(scanned_ports) >= 3 or len(ev_list) >= 2:
                sev = "MEDIUM"
            else:
                sev = "LOW"
            event_ids = [ev.id for ev in ev_list if ev.id]

            alert = SecurityAlert(
                title=f"Potential Network Reconnaissance & Port Sweep from {ip}",
                description=(
                    f"Source host {ip} executed rapid connection sweep probing ports: "
                    f"{', '.join(map(str, scanned_ports[:8])) or 'multiple perimeter targets'}. "
                    f"Flagged as potential reconnaissance scan. "
                    f"Note: Unconfirmed anomaly pending verification of authorized vulnerability assessment."
                ),
                severity=sev,
                status="NEW",
                rule_name="RULE_PERIMETER_PORT_SCAN",
                source_ip=ip,
                target_user=None,
                created_at=now,
                evidence={
                    "source_ip": ip,
                    "probes_count": len(ev_list),
                    "scanned_ports": scanned_ports,
                    "event_ids": event_ids[:30],
                    "anomaly_classification": "SUSPECTED_PORT_SCAN",
                    "verification_status": "UNCONFIRMED_ANOMALY",
                    "disclaimer": ANOMALY_DISCLAIMER,
                    "recommendation": f"Check perimeter firewall rules and verify whether {ip} is an authorized internal/external scanner."
                }
            )
            alerts.append(alert)

    return alerts

def analyze_events_and_detect_threats(
    db: Session,
    events: List[SecurityEvent]
) -> List[SecurityAlert]:
    """
    Evaluates correlation rules over newly ingested events and commits
    new SecurityAlert records to the database.
    """
    if not events:
        return []

    alerts_created = evaluate_rules(events)

    for alert in alerts_created:
        db.add(alert)

    if alerts_created:
        db.commit()
        for alert in alerts_created:
            db.refresh(alert)

    return alerts_created
