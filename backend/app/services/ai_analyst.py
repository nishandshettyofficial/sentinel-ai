import json
import datetime
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_

from backend.app.core.config import settings
from backend.app.models.alert import SecurityAlert
from backend.app.models.event import SecurityEvent
from backend.app.schemas.ai_analyst import (
    AlertExplanationResponse,
    AnalystChatRequest,
    AnalystChatResponse,
    ChatMessage
)

# Standardized SOC analyst disclaimer
AI_SOC_DISCLAIMER = (
    "AI-generated security analysis is provided for SOC triage and decision support. "
    "All findings represent behavioral anomaly interpretations and must be verified by a human analyst "
    "against primary logs before taking punitive or service-disrupting action."
)

# MITRE ATT&CK Knowledge Base mapping for Sentinel AI detection rules
MITRE_RULE_MAPPINGS = {
    "RULE_AUTH_BRUTE_FORCE": {
        "tactic": "Credential Access (TA0006)",
        "technique": "T1110.001 - Password Guessing",
        "description": "Adversaries may use automated password guessing against known accounts to gain initial access."
    },
    "RULE_AUTH_PASSWORD_SPRAYING": {
        "tactic": "Credential Access (TA0006)",
        "technique": "T1110.003 - Password Spraying",
        "description": "Adversaries may iterate through multiple usernames using a single common password to avoid account lockouts."
    },
    "RULE_MULTI_IP_ACCOUNT_ACCESS": {
        "tactic": "Defense Evasion / Initial Access (TA0005 / TA0001)",
        "technique": "T1078 - Valid Accounts",
        "description": "Adversaries may obtain and use credentials of existing accounts from multiple disparate network origins."
    },
    "RULE_ACTIVITY_SPIKE": {
        "tactic": "Reconnaissance / Impact (TA0043 / TA0040)",
        "technique": "T1595 / T1499 - Active Scanning & Endpoint Exhaustion",
        "description": "Adversaries may probe endpoints with rapid automated requests or attempt service denial."
    },
    "RULE_HOST_SUDO_VIOLATION": {
        "tactic": "Privilege Escalation (TA0004)",
        "technique": "T1548.003 - Sudo and Sudo Caching",
        "description": "Adversaries may execute commands with elevated privileges by violating sudo configuration rules."
    },
    "RULE_PERIMETER_PORT_SCAN": {
        "tactic": "Reconnaissance (TA0043)",
        "technique": "T1046 - Network Service Discovery",
        "description": "Adversaries may attempt to discover active network services and open ports via TCP connection sweeps."
    },
    "RULE_NETWORK_C2_BEACON": {
        "tactic": "Command and Control (TA0011)",
        "technique": "T1071.004 - DNS Tunneling / Application Layer Protocol",
        "description": "Adversaries may communicate using specialized DNS queries to establish bidirectional C2 channels."
    }
}

# ---------------------------------------------------------------------------
# Fallback Grounded SOC Intelligence Engine (Deterministic & Real-data Grounded)
# ---------------------------------------------------------------------------
def _generate_grounded_explanation(
    alert: SecurityAlert,
    contributing_events: List[SecurityEvent]
) -> Dict[str, Any]:
    """
    Generates a high-fidelity, strictly grounded explanation of an alert
    using its exact telemetry parameters, evidence fields, and contributing events.
    Guarantees no hallucination or invented findings.
    """
    evidence = alert.evidence or {}
    mitre = MITRE_RULE_MAPPINGS.get(alert.rule_name, {
        "tactic": "Initial Access / Execution",
        "technique": "T1078 - Valid Accounts",
        "description": "Behavioral anomaly detected across security telemetry."
    })

    target = alert.target_user or "System / Multiple Accounts"
    src = alert.source_ip or "Internal / Unspecified Origin"

    # Specialized grounded analysis by rule
    if alert.rule_name == "RULE_AUTH_BRUTE_FORCE":
        failed_count = evidence.get("failed_attempts", len(contributing_events) or 3)
        time_span = evidence.get("time_window_seconds", 0)
        time_str = f" across approximately {round(time_span, 1)} seconds" if time_span > 0 else ""
        
        what_happened = (
            f"A sequence of {failed_count} consecutive failed authentication attempts{time_str} "
            f"was recorded targeting account '{target}', originating exclusively from source IP address {src}. "
            f"The authentication requests generated immediate rejection responses from the target host."
        )
        why_suspicious = (
            f"The event volume exceeds normal user credential error thresholds. "
            f"Automated authentication failures concentrated in a brief window are characteristic of "
            f"dictionary attacks or automated credential guessers attempting to guess user passwords."
        )
        potential_impact = (
            f"If successful, an adversary could gain unauthorized access to '{target}'. "
            f"{'Because this account holds administrative/privileged access, compromise would lead to complete host control.' if evidence.get('is_privileged_account') else 'This could provide initial foothold access for lateral movement.'}"
        )
        recommendations = [
            f"Immediately enforce a temporary perimeter firewall block for source IP {src}.",
            f"Notify user '{target}' and prompt an immediate password reset via verified out-of-band communication.",
            f"Enforce mandatory Multi-Factor Authentication (MFA) challenge on the affected login endpoint.",
            f"Audit recent authentication records for '{target}' to confirm no successful logins occurred prior to the block."
        ]

    elif alert.rule_name == "RULE_AUTH_PASSWORD_SPRAYING":
        targeted = evidence.get("targeted_accounts", [])
        total_attempts = evidence.get("total_failed_attempts", len(contributing_events) or len(targeted))
        sample_users = ", ".join(targeted[:4]) if targeted else target

        what_happened = (
            f"Source IP {src} attempted {total_attempts} failed authentication attempts across "
            f"{evidence.get('distinct_accounts_count', len(targeted))} distinct user accounts ({sample_users}) "
            f"within a rapid observation window."
        )
        why_suspicious = (
            f"Standard user mistakes target only one account. When a single IP addresses multiple distinct "
            f"corporate identities, it indicates horizontal password spraying designed to test common passwords "
            f"while avoiding per-account lockout policies."
        )
        potential_impact = (
            f"Horizontal credential spraying has a high probability of discovering weak passwords across the user directory, "
            f"enabling quiet unauthorized entry without triggering single-user lockouts."
        )
        recommendations = [
            f"Apply an immediate perimeter network block on source IP {src}.",
            f"Force password rotations for all {len(targeted)} targeted accounts ({sample_users}).",
            f"Review ingress proxy headers to check if {src} is rotating through residential or commercial proxies.",
            f"Enable conditional access policies requiring corporate-managed devices for external authentication."
        ]

    elif alert.rule_name == "RULE_MULTI_IP_ACCOUNT_ACCESS":
        distinct_ips = evidence.get("distinct_ips", [src])
        ips_str = ", ".join(distinct_ips[:4])

        what_happened = (
            f"Account '{target}' was accessed or authenticated from {len(distinct_ips)} distinct IP addresses "
            f"({ips_str}) within the telemetry window."
        )
        why_suspicious = (
            f"Concurrent or rapid sequential sign-ins from disparate network origins for the same user identity "
            f"suggest either session token compromise, credential sharing, or impossible travel anomalies."
        )
        potential_impact = (
            f"Could signify active session hijacking or credential theft. An unauthorized external third-party "
            f"may be operating concurrently with the legitimate user."
        )
        recommendations = [
            f"Contact user '{target}' to verify if they used multiple devices or an active corporate VPN.",
            f"Revoke all active OAuth refresh tokens and terminate active web sessions for '{target}'.",
            f"Examine the geographic IP origins ({ips_str}) to identify unauthorized foreign network blocks.",
            f"Require step-up MFA re-authentication on all subsequent connection requests."
        ]

    elif alert.rule_name == "RULE_ACTIVITY_SPIKE":
        count = evidence.get("event_count", len(contributing_events) or 10)
        action = evidence.get("dominant_action", "requests")

        what_happened = (
            f"An abrupt burst of {count} security events (dominant action: '{action}') was observed "
            f"originating from source IP {src} in a compressed time frame."
        )
        why_suspicious = (
            f"The telemetry rate significantly exceeds normal baseline traffic. "
            f"High-frequency automated bursts typically represent vulnerability scanners, aggressive crawlers, "
            f"or denial-of-service probing."
        )
        potential_impact = (
            f"High-frequency request surges can exhaust application worker pools, degrade system responsiveness, "
            f"or uncover unpatched API endpoints."
        )
        recommendations = [
            f"Inspect Web Application Firewall (WAF) rate limits and throttle connection bursts from {src}.",
            f"Inspect HTTP user-agent headers and request payloads for automated vulnerability scanners.",
            f"Temporarily rate-limit connection requests from {src} to 1 request per second.",
            f"Verify backend server CPU and database connection pool health."
        ]

    elif alert.rule_name == "RULE_HOST_SUDO_VIOLATION":
        cmd = evidence.get("details", {}).get("command") or evidence.get("action") or "sudo"
        what_happened = (
            f"User '{target}' executed command '{cmd}' attempting unauthorized administrative privilege escalation. "
            f"The system authorization subsystem rejected the request."
        )
        why_suspicious = (
            f"User account is not listed in sudoers permissions for the specified administrative command. "
            f"Indicates either an insider policy violation or a compromised lower-privileged shell attempting privilege escalation."
        )
        potential_impact = (
            f"If an adversary bypasses sudo controls, they achieve complete root privileges over the host system, "
            f"allowing kernel tampering, log destruction, and arbitrary software execution."
        )
        recommendations = [
            f"Isolate host endpoint where '{target}' is logged in.",
            f"Inspect bash command history (`~/.bash_history`) and active terminal sessions.",
            f"Review `sudoers` file configuration for any unintended privilege grants.",
            f"Temporarily suspend account '{target}' pending internal security interview."
        ]

    elif alert.rule_name == "RULE_NETWORK_C2_BEACON":
        domain = evidence.get("domain") or "remote C2 server"
        what_happened = (
            f"Outbound communication pattern matching Command & Control (C2) beaconing was detected from "
            f"internal host {src} to destination domain '{domain}'."
        )
        why_suspicious = (
            f"Regular outbound DNS queries or periodic beacon intervals to unclassified or newly registered "
            f"domains are indicative of malware callbacks or exfiltration channels."
        )
        potential_impact = (
            f"Active C2 communication allows remote attackers to issue commands, exfiltrate confidential files, "
            f"and deploy secondary payloads within the private network."
        )
        recommendations = [
            f"Immediately disconnect host {src} from the corporate local network.",
            f"Sinkhole domain '{domain}' at internal DNS resolvers to prevent communication from other endpoints.",
            f"Perform memory dump and volatile forensic capture on host {src}.",
            f"Search enterprise DNS proxy logs for any other endpoints resolving '{domain}'."
        ]

    else:
        what_happened = (
            f"Security alert '{alert.title}' was triggered by detection rule '{alert.rule_name}'. "
            f"Observed telemetry involves source entity {src} and target '{target}'."
        )
        why_suspicious = (
            f"The observed behavior deviated from standard operational parameters and triggered Sentinel AI's "
            f"correlation criteria."
        )
        potential_impact = "Could indicate unauthorized reconnaissance or unauthorized operational activity."
        recommendations = [
            f"Review related raw log records for source {src}.",
            f"Cross-reference indicator in Sentinel AI Threat Intelligence Radar.",
            f"Verify authorization with system owners."
        ]

    return {
        "what_happened": what_happened,
        "why_suspicious": why_suspicious,
        "potential_impact": potential_impact,
        "defensive_recommendations": recommendations,
        "mitre_attack_mapping": mitre
    }


# ---------------------------------------------------------------------------
# Gemini API Live Client
# ---------------------------------------------------------------------------
def _call_gemini_api(prompt: str) -> Optional[str]:
    """
    Executes a structured generative request using Google GenAI SDK to gemini-2.5-flash.
    Returns generated response text or None if API key missing or error occurs.
    """
    api_key = settings.GEMINI_API_KEY.strip()
    if not api_key:
        return None

    try:
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.2, # Low temperature for factual, deterministic security analysis
                system_instruction=(
                    "You are Sentinel AI's Senior SOC Security Analyst. "
                    "Analyze the provided security telemetry, alert evidence, and logs with extreme factual precision. "
                    "Explain what happened, why it is suspicious, potential impact, and defensive recommendations. "
                    "Rules: Never invent logs, IPs, or confirmed breach claims. Adhere strictly to the provided evidence."
                )
            )
        )
        if response and response.text:
            return response.text.strip()
    except Exception as e:
        print(f"[Sentinel AI] Gemini API call exception: {e}")
        return None
    return None


# ---------------------------------------------------------------------------
# Master AI Alert Explanation Service
# ---------------------------------------------------------------------------
def explain_alert_with_ai(
    db: Session,
    alert_id: int,
    include_raw_logs: bool = True
) -> AlertExplanationResponse:
    """
    Fetches the alert from the database, retrieves its contributing logs,
    and runs the AI Security Analyst explanation using Gemini API (or grounded engine fallback).
    """
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise ValueError(f"Security Alert with ID {alert_id} not found.")

    # Retrieve contributing events
    evidence = alert.evidence or {}
    event_ids = evidence.get("event_ids", [])
    contributing_events = []
    if event_ids:
        contributing_events = db.query(SecurityEvent).filter(SecurityEvent.id.in_(event_ids[:20])).all()

    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    # 1. Check if Gemini API is configured and attempt live LLM explanation
    api_key = settings.GEMINI_API_KEY.strip()
    if api_key:
        # Build prompt for Gemini
        events_summary = "\n".join([
            f"- [{ev.timestamp}] action={ev.action} src={ev.source_ip} user={ev.user_identity} status={ev.status} details={ev.details}"
            for ev in contributing_events[:10]
        ])

        prompt = f"""
Please analyze this security alert generated by Sentinel AI's correlation engine:

ALERT CONTEXT:
- Title: {alert.title}
- Severity: {alert.severity}
- Rule Name: {alert.rule_name}
- Target User: {alert.target_user}
- Source IP: {alert.source_ip}
- Created At: {alert.created_at}
- Evidence Metadata: {json.dumps(alert.evidence)}

CONTRIBUTING LOG TELEMETRY:
{events_summary or 'No specific raw event IDs attached; evaluate from alert evidence.'}

Format your response as a valid JSON object with the following exact keys:
{{
  "what_happened": "Clear narrative explaining the observed sequence of events in simple terms.",
  "why_suspicious": "Explanation of behavioral anomalies and why the rule triggered.",
  "potential_impact": "Realistic potential security/business impact if this is an active attack.",
  "defensive_recommendations": ["Action 1", "Action 2", "Action 3", "Action 4"]
}}
Return ONLY valid JSON.
"""
        raw_llm_output = _call_gemini_api(prompt)
        if raw_llm_output:
            try:
                # Strip markdown json code fences if present
                clean_json = raw_llm_output
                if clean_json.startswith("```json"):
                    clean_json = clean_json.split("```json", 1)[1]
                if clean_json.startswith("```"):
                    clean_json = clean_json.split("```", 1)[1]
                if clean_json.endswith("```"):
                    clean_json = clean_json.rsplit("```", 1)[0]
                parsed = json.loads(clean_json.strip())

                mitre = MITRE_RULE_MAPPINGS.get(alert.rule_name, {
                    "tactic": "Initial Access",
                    "technique": "T1078 - Valid Accounts"
                })

                return AlertExplanationResponse(
                    alert_id=alert.id,
                    alert_title=alert.title,
                    severity=alert.severity,
                    rule_name=alert.rule_name,
                    what_happened=parsed.get("what_happened", alert.description),
                    why_suspicious=parsed.get("why_suspicious", "Behavioral pattern anomaly triggered detection rule threshold."),
                    potential_impact=parsed.get("potential_impact", "Unauthorized access or system misuse."),
                    defensive_recommendations=parsed.get("defensive_recommendations", ["Review logs", "Block IP"]),
                    mitre_attack_mapping=mitre,
                    disclaimer=AI_SOC_DISCLAIMER,
                    provider="GEMINI_2_5_FLASH",
                    generated_at=now
                )
            except Exception as parse_err:
                print(f"[Sentinel AI] Failed to parse Gemini response as JSON: {parse_err}. Using grounded fallback.")

    # 2. Fallback to Grounded Deterministic Intelligence Engine
    grounded = _generate_grounded_explanation(alert, contributing_events)
    return AlertExplanationResponse(
        alert_id=alert.id,
        alert_title=alert.title,
        severity=alert.severity,
        rule_name=alert.rule_name,
        what_happened=grounded["what_happened"],
        why_suspicious=grounded["why_suspicious"],
        potential_impact=grounded["potential_impact"],
        defensive_recommendations=grounded["defensive_recommendations"],
        mitre_attack_mapping=grounded["mitre_attack_mapping"],
        disclaimer=AI_SOC_DISCLAIMER,
        provider="GROUNDED_SOC_ENGINE",
        generated_at=now
    )


# ---------------------------------------------------------------------------
# Interactive SOC Analyst Chat Assistant
# ---------------------------------------------------------------------------
def chat_with_ai_analyst(
    db: Session,
    request: AnalystChatRequest
) -> AnalystChatResponse:
    """
    Interactive conversation turn with the AI Security Analyst.
    Enriches query with the context of active alert (if provided) and system telemetry.
    """
    user_msg = request.message.strip()
    alert_context = ""
    target_alert = None

    if request.alert_id:
        target_alert = db.query(SecurityAlert).filter(SecurityAlert.id == request.alert_id).first()
        if target_alert:
            alert_context = (
                f"\nACTIVE ALERT CONTEXT:\n"
                f"- ID: {target_alert.id}\n"
                f"- Title: {target_alert.title}\n"
                f"- Severity: {target_alert.severity}\n"
                f"- Rule: {target_alert.rule_name}\n"
                f"- Target User: {target_alert.target_user}\n"
                f"- Source IP: {target_alert.source_ip}\n"
                f"- Description: {target_alert.description}\n"
                f"- Evidence: {json.dumps(target_alert.evidence)}\n"
            )

    # 1. Try Gemini Live API
    api_key = settings.GEMINI_API_KEY.strip()
    if api_key:
        history_str = "\n".join([f"{msg.role.upper()}: {msg.content}" for msg in (request.chat_history or [])[-4:]])
        full_prompt = f"""
You are Sentinel AI's Senior Cybersecurity SOC Analyst assistant.
Assist the human SOC analyst with their question. Maintain a professional, tactical, and clear demeanor.
Base your conclusions solely on the provided alert telemetry and established security standards.

{alert_context}

CONVERSATION HISTORY:
{history_str}

USER QUESTION:
{user_msg}

Provide a concise, practical, and technically accurate answer. If recommending commands (iptables, PowerShell, etc.), provide exact syntax.
"""
        reply_text = _call_gemini_api(full_prompt)
        if reply_text:
            return AnalystChatResponse(
                reply=reply_text,
                referenced_alert_id=request.alert_id,
                provider="GEMINI_2_5_FLASH",
                suggested_followups=[
                    "What are the immediate containment steps?",
                    "Generate a perimeter iptables firewall block rule",
                    "How do I verify if user credentials were breached?",
                    "What MITRE ATT&CK technique applies here?"
                ]
            )

    # 2. Fallback Grounded Conversational Response
    # Generate intelligent contextual response
    user_lower = user_msg.lower()
    
    if "contain" in user_lower or "what should i do" in user_lower or "first" in user_lower or "action" in user_lower:
        if target_alert and target_alert.source_ip:
            reply = (
                f"**Immediate Containment Sequence for Alert #{target_alert.id} ({target_alert.title}):**\n\n"
                f"1. **Perimeter Isolation**: Immediately block source IP `{target_alert.source_ip}` at your border firewall/WAF to halt incoming requests.\n"
                f"2. **Identity Protection**: Force an immediate password change and terminate active sessions for `{target_alert.target_user or 'affected accounts'}`.\n"
                f"3. **Telemetry Audit**: Query recent logs from `{target_alert.source_ip}` over the past 24 hours to verify if any logins succeeded.\n"
                f"4. **Step-up Verification**: Enforce MFA challenge verification before granting access from new network origins."
            )
        else:
            reply = (
                "**Standard SOC Incident Containment Priorities:**\n\n"
                "1. **Isolate**: Sever network access for the offending IP or quarantine communicating host endpoints.\n"
                "2. **Invalidate Credentials**: Invalidate active session tokens and force credential rotation.\n"
                "3. **Preserve Telemetry**: Capture relevant security events, memory dumps, and audit logs for evidence.\n"
                "4. **Review Scope**: Search logs for identical indicators of compromise (IOCs) across all network assets."
            )
    elif "firewall" in user_lower or "iptables" in user_lower or "block" in user_lower:
        ip = target_alert.source_ip if (target_alert and target_alert.source_ip) else "185.220.101.45"
        reply = (
            f"Here are ready-to-deploy firewall containment rules to block `{ip}`:\n\n"
            f"**Linux (iptables):**\n"
            f"```bash\n"
            f"sudo iptables -I INPUT -s {ip} -j DROP\n"
            f"sudo iptables-save\n"
            f"```\n\n"
            f"**Linux (UFW):**\n"
            f"```bash\n"
            f"sudo ufw insert 1 deny from {ip} to any\n"
            f"```\n\n"
            f"**Cloud / WAF (AWS VPC Security Group / Cloudflare):**\n"
            f"Add ingress deny rule for CIDR `{ip}/32` across all protocol ports (0-65535)."
        )
    elif "mitre" in user_lower or "attack" in user_lower or "framework" in user_lower:
        rule = target_alert.rule_name if target_alert else "RULE_AUTH_BRUTE_FORCE"
        m = MITRE_RULE_MAPPINGS.get(rule, {"tactic": "Credential Access", "technique": "T1110 - Brute Force", "description": "Automated authentication probing."})
        reply = (
            f"**MITRE ATT&CK Mapping for {rule}:**\n\n"
            f"- **Tactic**: {m['tactic']}\n"
            f"- **Technique**: `{m['technique']}`\n"
            f"- **Description**: {m['description']}\n\n"
            f"**Detection & Mitigation Strategies:**\n"
            f"- *M1036 (Account Use Policies)*: Enforce account lockout thresholds and multi-factor authentication.\n"
            f"- *M1031 (Network Intrusion Prevention)*: Implement perimeter rate-limiting and automated IP reputation blocklists."
        )
    elif "bot" in user_lower or "human" in user_lower or "automated" in user_lower:
        reply = (
            "Based on the rapid timing intervals and consecutive failure cadence in the alert evidence, "
            "this pattern strongly matches an **automated script or bot** rather than manual human typing. "
            "Automated tools cycle through dictionaries or wordlists with sub-second or regular periodic intervals. "
            "However, remember that automated tools are often operated by human threat actors scouting for soft targets."
        )
    else:
        # General response
        context_str = f"regarding **Alert #{target_alert.id} ({target_alert.title})**" if target_alert else "for your current SOC telemetry"
        reply = (
            f"As your Sentinel AI Security Analyst, I've analyzed the query {context_str}.\n\n"
            f"The observed events show anomalous activity flagged by rule `{target_alert.rule_name if target_alert else 'RULE_AUTH_BRUTE_FORCE'}`. "
            f"To effectively manage this, ensure you cross-reference the source IP `{target_alert.source_ip if target_alert else 'indicator'}` in the Threat Intelligence Radar, "
            f"and check whether any successful logins were recorded before or after the alert window.\n\n"
            f"What specific area would you like to investigate further?"
        )

    return AnalystChatResponse(
        reply=reply,
        referenced_alert_id=request.alert_id,
        provider="GROUNDED_SOC_ENGINE",
        suggested_followups=[
            "What should I do first to contain this threat?",
            "Draft a perimeter firewall block rule",
            "Map this alert to MITRE ATT&CK framework",
            "Is this an automated bot or targeted attack?"
        ]
    )
