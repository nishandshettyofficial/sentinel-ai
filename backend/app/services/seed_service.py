import datetime
from sqlalchemy.orm import Session
from backend.app.models.event import SecurityEvent
from backend.app.models.alert import SecurityAlert
from backend.app.models.incident import SecurityIncident

def seed_initial_security_data(db: Session):
    # Only seed if no events exist
    if db.query(SecurityEvent).count() > 0:
        return

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    # 1. Realistic security events
    sample_events = [
        # Normal user logins
        {"mins_ago": 180, "ip": "192.168.1.105", "dst": "10.0.0.5", "user": "sarah.dev", "type": "AUTH_SUCCESS", "action": "LOGIN_WEB", "status": "SUCCESS", "details": {"agent": "Mozilla/5.0", "mfa": True}},
        {"mins_ago": 160, "ip": "192.168.1.112", "dst": "10.0.0.5", "user": "marcus.sec", "type": "AUTH_SUCCESS", "action": "LOGIN_SSO", "status": "SUCCESS", "details": {"agent": "Sentinel-CLI/1.2", "mfa": True}},
        
        # Brute force attack cluster against admin portal
        {"mins_ago": 120, "ip": "185.220.101.45", "dst": "10.0.0.8", "user": "root", "type": "AUTH_FAILED", "action": "SSH_LOGIN", "status": "FAILURE", "details": {"port": 22, "failure_reason": "invalid_password"}},
        {"mins_ago": 118, "ip": "185.220.101.45", "dst": "10.0.0.8", "user": "admin", "type": "AUTH_FAILED", "action": "SSH_LOGIN", "status": "FAILURE", "details": {"port": 22, "failure_reason": "invalid_password"}},
        {"mins_ago": 115, "ip": "185.220.101.45", "dst": "10.0.0.8", "user": "administrator", "type": "AUTH_FAILED", "action": "SSH_LOGIN", "status": "FAILURE", "details": {"port": 22, "failure_reason": "invalid_password"}},
        {"mins_ago": 112, "ip": "185.220.101.45", "dst": "10.0.0.8", "user": "ubuntu", "type": "AUTH_FAILED", "action": "SSH_LOGIN", "status": "FAILURE", "details": {"port": 22, "failure_reason": "invalid_password"}},
        {"mins_ago": 110, "ip": "185.220.101.45", "dst": "10.0.0.8", "user": "root", "type": "AUTH_FAILED", "action": "SSH_LOGIN", "status": "BLOCKED", "details": {"rule": "IP_RATE_LIMIT_TRIGGERED"}},

        # Reconnaissance / Port Scan
        {"mins_ago": 95, "ip": "45.154.255.89", "dst": "10.0.0.12", "user": None, "type": "PORT_SCAN", "action": "TCP_SYN_SWEEP", "status": "BLOCKED", "details": {"scanned_ports": [21, 22, 80, 443, 3389, 8080], "flags": "SYN"}},
        
        # Internal API anomaly
        {"mins_ago": 80, "ip": "192.168.1.140", "dst": "10.0.0.20", "user": "app-service-account", "type": "API_ANOMALY", "action": "BULK_DATA_EXPORT", "status": "SUCCESS", "details": {"endpoint": "/api/v2/records", "volume_mb": 450}},

        # Privilege escalation attempt
        {"mins_ago": 50, "ip": "192.168.1.204", "dst": "10.0.0.15", "user": "temp_intern", "type": "PRIVILEGE_ESCALATION", "action": "SUDO_EXEC", "status": "FAILURE", "details": {"command": "sudo /bin/bash", "terminal": "pts/3"}},

        # Suspected C2 beaconing
        {"mins_ago": 25, "ip": "192.168.1.77", "dst": "194.26.29.112", "user": "workstation-07", "type": "C2_BEACON", "action": "DNS_TUNNEL_QUERY", "status": "BLOCKED", "details": {"domain": "sync-cdn-telemetry.xyz", "protocol": "DNS-over-UDP"}},
        
        # Ongoing clean activity
        {"mins_ago": 10, "ip": "192.168.1.105", "dst": "10.0.0.5", "user": "sarah.dev", "type": "AUTH_SUCCESS", "action": "TOKEN_REFRESH", "status": "SUCCESS", "details": {"status": "ok"}},
        {"mins_ago": 2, "ip": "10.0.0.2", "dst": "10.0.0.5", "user": "soc_monitor", "type": "HEALTH_CHECK", "action": "HEARTBEAT", "status": "SUCCESS", "details": {"uptime_seconds": 86400}}
    ]

    for item in sample_events:
        event = SecurityEvent(
            timestamp=now - datetime.timedelta(minutes=item["mins_ago"]),
            source_ip=item["ip"],
            destination_ip=item["dst"],
            user_identity=item["user"],
            event_type=item["type"],
            action=item["action"],
            status=item["status"],
            details=item["details"],
            raw_log=f"[{now - datetime.timedelta(minutes=item['mins_ago'])}] {item['type']} action={item['action']} src={item['ip']} dst={item['dst']} user={item['user']} status={item['status']}"
        )
        db.add(event)

    # 2. Correlated Security Alerts
    sample_alerts = [
        {
            "title": "SSH Brute-Force Password Spraying Detected",
            "description": "5 consecutive failed authentication attempts against root/admin accounts from external IP 185.220.101.45 within 10 minutes.",
            "severity": "CRITICAL",
            "status": "INVESTIGATING",
            "rule_name": "RULE_AUTH_BRUTE_FORCE",
            "source_ip": "185.220.101.45",
            "target_user": "root",
            "mins_ago": 110,
            "evidence": {
                "failed_attempts": 5,
                "targeted_users": ["root", "admin", "administrator", "ubuntu"],
                "mitigation": "Automated IP block enforced at perimeter firewall"
            }
        },
        {
            "title": "Suspected Command & Control (C2) DNS Tunneling",
            "description": "Internal host 192.168.1.77 generated high-frequency DNS requests to unclassified high-risk domain sync-cdn-telemetry.xyz.",
            "severity": "HIGH",
            "status": "NEW",
            "rule_name": "RULE_NETWORK_C2_BEACON",
            "source_ip": "192.168.1.77",
            "target_user": "workstation-07",
            "mins_ago": 25,
            "evidence": {
                "destination_ip": "194.26.29.112",
                "domain": "sync-cdn-telemetry.xyz",
                "reputation": "Suspicious / Newly Registered Domain"
            }
        },
        {
            "title": "Unauthorized Privilege Escalation Attempt",
            "description": "User 'temp_intern' attempted to spawn root interactive bash shell via sudoers violation.",
            "severity": "MEDIUM",
            "status": "NEW",
            "rule_name": "RULE_HOST_SUDO_VIOLATION",
            "source_ip": "192.168.1.204",
            "target_user": "temp_intern",
            "mins_ago": 50,
            "evidence": {
                "command": "sudo /bin/bash",
                "host": "srv-internal-build01"
            }
        },
        {
            "title": "External Reconnaissance Port Sweep",
            "description": "Aggressive TCP SYN sweep scanning common administrative ports (21, 22, 80, 443, 3389).",
            "severity": "LOW",
            "status": "RESOLVED",
            "rule_name": "RULE_PERIMETER_PORT_SCAN",
            "source_ip": "45.154.255.89",
            "target_user": None,
            "mins_ago": 95,
            "evidence": {
                "scanned_ports": [21, 22, 80, 443, 3389, 8080],
                "outcome": "Packets dropped by edge gateway"
            }
        }
    ]

    for item in sample_alerts:
        alert = SecurityAlert(
            title=item["title"],
            description=item["description"],
            severity=item["severity"],
            status=item["status"],
            rule_name=item["rule_name"],
            source_ip=item["source_ip"],
            target_user=item["target_user"],
            created_at=now - datetime.timedelta(minutes=item["mins_ago"]),
            evidence=item["evidence"]
        )
        db.add(alert)

    # 3. Active Incident
    incident = SecurityIncident(
        title="INC-2026-001: External SSH Credential Attack & Perimeter Breach Attempt",
        severity="CRITICAL",
        status="IN_PROGRESS",
        assigned_analyst="Security Lead",
        created_at=now - datetime.timedelta(minutes=105),
        summary="Attacker originating from 185.220.101.45 executed automated dictionary attacks against perimeter bastion gateway.",
        findings="Perimeter rate-limiting automatically mitigated authentication attempts. Host 10.0.0.8 verified uncompromised. Recommended firewall IP blacklisting.",
        remediation_steps=[
            "Blocked source IP 185.220.101.45 at edge firewall",
            "Rotated credentials for target test accounts",
            "Enforced mandatory SSH key authentication"
        ],
        associated_alert_ids=[1]
    )
    db.add(incident)

    db.commit()
