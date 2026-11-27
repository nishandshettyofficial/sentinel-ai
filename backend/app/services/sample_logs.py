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
    }
}
