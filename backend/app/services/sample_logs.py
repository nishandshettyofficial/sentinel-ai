from typing import Dict, Any

SAMPLE_LOGS: Dict[str, Dict[str, Any]] = {
    "ssh_bruteforce": {
        "filename": "ssh_bruteforce_attack.csv",
        "format": "csv",
        "description": "7 consecutive failed SSH root/admin logins from external IP 203.0.113.88",
        "content": """timestamp,source_ip,destination_ip,user_identity,event_type,action,status,details
2026-11-27T08:10:00Z,203.0.113.88,10.0.0.5,root,AUTH_FAILED,SSH_LOGIN,FAILURE,"{""port"": 22, ""error"": ""invalid_key""}"
2026-11-27T08:10:30Z,203.0.113.88,10.0.0.5,root,AUTH_FAILED,SSH_LOGIN,FAILURE,"{""port"": 22, ""error"": ""bad_password""}"
2026-11-27T08:11:00Z,203.0.113.88,10.0.0.5,root,AUTH_FAILED,SSH_LOGIN,FAILURE,"{""port"": 22, ""error"": ""bad_password""}"
2026-11-27T08:11:30Z,203.0.113.88,10.0.0.5,root,AUTH_FAILED,SSH_LOGIN,FAILURE,"{""port"": 22, ""error"": ""bad_password""}"
2026-11-27T08:12:00Z,203.0.113.88,10.0.0.5,root,AUTH_FAILED,SSH_LOGIN,FAILURE,"{""port"": 22, ""error"": ""bad_password""}"
2026-11-27T08:12:30Z,203.0.113.88,10.0.0.5,root,AUTH_FAILED,SSH_LOGIN,FAILURE,"{""port"": 22, ""error"": ""bad_password""}"
2026-11-27T08:13:00Z,203.0.113.88,10.0.0.5,root,AUTH_FAILED,SSH_LOGIN,BLOCKED,"{""port"": 22, ""mitigation"": ""firewall_block""}"
"""
    },
    "password_spraying": {
        "filename": "password_spray_telemetry.json",
        "format": "json",
        "description": "Single external IP (198.51.100.42) attempting logins across 5 different employees",
        "content": """[
  {
    "timestamp": "2026-11-27T08:15:00Z",
    "source_ip": "198.51.100.42",
    "destination_ip": "10.0.0.10",
    "user_identity": "alice.johnson",
    "event_type": "AUTH_FAILED",
    "action": "LOGIN_WEB",
    "status": "FAILURE",
    "details": {"client": "curl/7.88.1", "auth_protocol": "OIDC"}
  },
  {
    "timestamp": "2026-11-27T08:15:30Z",
    "source_ip": "198.51.100.42",
    "destination_ip": "10.0.0.10",
    "user_identity": "bob.smith",
    "event_type": "AUTH_FAILED",
    "action": "LOGIN_WEB",
    "status": "FAILURE",
    "details": {"client": "curl/7.88.1", "auth_protocol": "OIDC"}
  },
  {
    "timestamp": "2026-11-27T08:16:00Z",
    "source_ip": "198.51.100.42",
    "destination_ip": "10.0.0.10",
    "user_identity": "carol.white",
    "event_type": "AUTH_FAILED",
    "action": "LOGIN_WEB",
    "status": "FAILURE",
    "details": {"client": "curl/7.88.1", "auth_protocol": "OIDC"}
  },
  {
    "timestamp": "2026-11-27T08:16:30Z",
    "source_ip": "198.51.100.42",
    "destination_ip": "10.0.0.10",
    "user_identity": "david.lee",
    "event_type": "AUTH_FAILED",
    "action": "LOGIN_WEB",
    "status": "FAILURE",
    "details": {"client": "curl/7.88.1", "auth_protocol": "OIDC"}
  }
]"""
    },
    "recon_and_sudo": {
        "filename": "recon_and_escalation.csv",
        "format": "csv",
        "description": "Port scan sweep followed by unauthorized sudo execution",
        "content": """timestamp,source_ip,destination_ip,user_identity,event_type,action,status,details
2026-11-27T08:20:00Z,91.240.118.172,10.0.0.25,,PORT_SCAN,TCP_SYN_SWEEP,BLOCKED,"{""scanned_ports"": [21, 22, 80, 443, 3389, 8080], ""flags"": ""SYN""}"
2026-11-27T08:22:15Z,192.168.1.189,10.0.0.25,contractor_jake,PRIVILEGE_ESCALATION,SUDO_EXEC,FAILURE,"{""command"": ""sudo su - root"", ""terminal"": ""pts/1""}"
2026-11-27T08:25:00Z,192.168.1.189,194.26.29.99,contractor_jake,C2_BEACON,DNS_TUNNEL_QUERY,BLOCKED,"{""domain"": ""tunnel-stage-verify.top"", ""query_type"": ""TXT""}"
"""
    },
    "multi_ip_access": {
        "filename": "multi_ip_account_access.json",
        "format": "json",
        "description": "User 'sarah.lead' accessed concurrently from 3 distinct global IPs (HQ, London, Sydney) within 5 minutes",
        "content": """[
  {
    "timestamp": "2026-11-27T09:00:00Z",
    "source_ip": "192.168.1.101",
    "destination_ip": "10.0.0.5",
    "user_identity": "sarah.lead",
    "event_type": "AUTH_SUCCESS",
    "action": "LOGIN_SSO",
    "status": "SUCCESS",
    "details": {"geo": "US-East", "client": "Chrome/131"}
  },
  {
    "timestamp": "2026-11-27T09:02:15Z",
    "source_ip": "185.199.108.153",
    "destination_ip": "10.0.0.5",
    "user_identity": "sarah.lead",
    "event_type": "AUTH_SUCCESS",
    "action": "LOGIN_WEB",
    "status": "SUCCESS",
    "details": {"geo": "GB-London", "client": "Firefox/132"}
  },
  {
    "timestamp": "2026-11-27T09:04:40Z",
    "source_ip": "203.0.113.195",
    "destination_ip": "10.0.0.5",
    "user_identity": "sarah.lead",
    "event_type": "AUTH_FAILED",
    "action": "API_AUTH",
    "status": "FAILURE",
    "details": {"geo": "AU-Sydney", "reason": "bad_token"}
  }
]"""
    },
    "activity_spike": {
        "filename": "telemetry_activity_spike.csv",
        "format": "csv",
        "description": "Sudden volume surge of 12 rapid automated requests from external host 194.26.29.11 in 20 seconds",
        "content": """timestamp,source_ip,destination_ip,user_identity,event_type,action,status,details
2026-11-27T09:10:00Z,194.26.29.11,10.0.0.10,guest_user,API_REQUEST,ENDPOINT_PROBE,SUCCESS,"{""path"": ""/api/v1/auth""}"
2026-11-27T09:10:01Z,194.26.29.11,10.0.0.10,guest_user,API_REQUEST,ENDPOINT_PROBE,SUCCESS,"{""path"": ""/api/v1/users""}"
2026-11-27T09:10:02Z,194.26.29.11,10.0.0.10,guest_user,API_REQUEST,ENDPOINT_PROBE,SUCCESS,"{""path"": ""/api/v1/admin""}"
2026-11-27T09:10:03Z,194.26.29.11,10.0.0.10,guest_user,API_REQUEST,ENDPOINT_PROBE,FAILURE,"{""path"": ""/api/v1/keys""}"
2026-11-27T09:10:04Z,194.26.29.11,10.0.0.10,guest_user,API_REQUEST,ENDPOINT_PROBE,FAILURE,"{""path"": ""/api/v1/config""}"
2026-11-27T09:10:05Z,194.26.29.11,10.0.0.10,guest_user,API_REQUEST,ENDPOINT_PROBE,FAILURE,"{""path"": ""/api/v1/secrets""}"
2026-11-27T09:10:06Z,194.26.29.11,10.0.0.10,guest_user,API_REQUEST,ENDPOINT_PROBE,BLOCKED,"{""path"": ""/api/v1/tokens""}"
2026-11-27T09:10:07Z,194.26.29.11,10.0.0.10,guest_user,API_REQUEST,ENDPOINT_PROBE,BLOCKED,"{""path"": ""/api/v1/certs""}"
2026-11-27T09:10:08Z,194.26.29.11,10.0.0.10,guest_user,API_REQUEST,ENDPOINT_PROBE,BLOCKED,"{""path"": ""/api/v1/db""}"
2026-11-27T09:10:09Z,194.26.29.11,10.0.0.10,guest_user,API_REQUEST,ENDPOINT_PROBE,BLOCKED,"{""path"": ""/api/v1/backup""}"
2026-11-27T09:10:10Z,194.26.29.11,10.0.0.10,guest_user,API_REQUEST,ENDPOINT_PROBE,BLOCKED,"{""path"": ""/api/v1/export""}"
2026-11-27T09:10:12Z,194.26.29.11,10.0.0.10,guest_user,API_REQUEST,ENDPOINT_PROBE,BLOCKED,"{""path"": ""/api/v1/upload""}"
"""
    },
    "enterprise_audit": {
        "filename": "enterprise_daily_audit.json",
        "format": "json",
        "description": "Realistic enterprise authentication log with normal engineering logins and single anomaly",
        "content": """[
  {
    "timestamp": "2026-11-27T07:45:00Z",
    "source_ip": "192.168.1.101",
    "destination_ip": "10.0.0.5",
    "user_identity": "sarah.lead",
    "event_type": "AUTH_SUCCESS",
    "action": "LOGIN_SSO",
    "status": "SUCCESS",
    "details": {"mfa_method": "FIDO2_WEBAUTHN", "device": "MacBook-Air-M3"}
  },
  {
    "timestamp": "2026-11-27T07:50:00Z",
    "source_ip": "192.168.1.115",
    "destination_ip": "10.0.0.8",
    "user_identity": "alex.analyst",
    "event_type": "AUTH_SUCCESS",
    "action": "SSH_LOGIN",
    "status": "SUCCESS",
    "details": {"key_fingerprint": "SHA256:d8c23...", "port": 22}
  },
  {
    "timestamp": "2026-11-27T07:52:10Z",
    "source_ip": "192.168.1.140",
    "destination_ip": "10.0.0.20",
    "user_identity": "app-daemon",
    "event_type": "API_ACCESS",
    "action": "TOKEN_REFRESH",
    "status": "SUCCESS",
    "details": {"scope": "metrics:read"}
  },
  {
    "timestamp": "2026-11-27T07:55:00Z",
    "source_ip": "185.220.101.45",
    "destination_ip": "10.0.0.5",
    "user_identity": "root",
    "event_type": "AUTH_FAILED",
    "action": "SSH_LOGIN",
    "status": "FAILURE",
    "details": {"port": 22, "failure_reason": "key_rejected"}
  }
]"""
    }
}
