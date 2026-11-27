import csv
import io
import json
import datetime
from typing import List, Dict, Any, Tuple
from dateutil import parser as date_parser

def parse_timestamp(val: Any) -> datetime.datetime:
    if not val:
        return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    if isinstance(val, (int, float)):
        # Handle unix timestamp in seconds or milliseconds
        if val > 1e11:
            val = val / 1000.0
        return datetime.datetime.fromtimestamp(val, tz=datetime.timezone.utc).replace(tzinfo=None)
    try:
        dt = date_parser.parse(str(val))
        if dt.tzinfo:
            dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

def normalize_event_dict(raw: Dict[str, Any]) -> Dict[str, Any]:
    # Extract timestamp
    ts_field = raw.get("timestamp") or raw.get("time") or raw.get("@timestamp") or raw.get("datetime")
    timestamp = parse_timestamp(ts_field)

    # Extract source IP
    source_ip = (
        raw.get("source_ip") or raw.get("src_ip") or raw.get("ip") or 
        raw.get("client_ip") or raw.get("remote_addr") or "0.0.0.0"
    ).strip()

    # Destination IP
    dest_ip = raw.get("destination_ip") or raw.get("dst_ip") or raw.get("server_ip") or raw.get("host_ip")
    if dest_ip:
        dest_ip = str(dest_ip).strip()

    # User identity
    user = (
        raw.get("user_identity") or raw.get("username") or raw.get("user") or 
        raw.get("account") or raw.get("login")
    )
    if user:
        user = str(user).strip()

    # Event Type
    event_type = (
        raw.get("event_type") or raw.get("type") or raw.get("category") or 
        raw.get("event") or "SECURITY_EVENT"
    ).strip().upper()

    # Action
    action = (
        raw.get("action") or raw.get("operation") or raw.get("method") or "ACCESS"
    ).strip().upper()

    # Status
    status = (
        raw.get("status") or raw.get("result") or raw.get("outcome") or "SUCCESS"
    ).strip().upper()
    if status in ["FAIL", "FAILED", "ERR", "ERROR", "DENIED", "REJECTED"]:
        status = "FAILURE"
    elif status in ["OK", "SUCCESSFUL", "PERMITTED", "ALLOW", "ALLOWED"]:
        status = "SUCCESS"
    elif status in ["BLOCK", "DROPPED", "MITIGATED"]:
        status = "BLOCKED"

    # Details
    details = raw.get("details")
    if details and isinstance(details, str):
        try:
            details = json.loads(details)
        except Exception:
            details = {"raw_details": details}
    elif not details:
        # Preserve other unrecognized keys in details
        known = {
            "timestamp", "time", "@timestamp", "datetime",
            "source_ip", "src_ip", "ip", "client_ip", "remote_addr",
            "destination_ip", "dst_ip", "server_ip", "host_ip",
            "user_identity", "username", "user", "account", "login",
            "event_type", "type", "category", "event",
            "action", "operation", "method", "status", "result", "outcome", "details"
        }
        details = {k: v for k, v in raw.items() if k not in known}

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "user_identity": user,
        "event_type": event_type,
        "action": action,
        "status": status,
        "details": details or {},
        "raw_log": json.dumps(raw)
    }

def parse_csv_content(content: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    parsed = []
    errors = []
    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames:
        return [], ["Invalid or empty CSV: Missing header row."]

    for idx, row in enumerate(reader, start=1):
        try:
            normalized = normalize_event_dict(row)
            parsed.append(normalized)
        except Exception as e:
            errors.append(f"Line {idx}: {str(e)}")

    return parsed, errors

def parse_json_content(content: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    parsed = []
    errors = []
    content_clean = content.strip()
    if not content_clean:
        return [], ["Empty JSON content."]

    # Try parsing as standard JSON array or object
    if content_clean.startswith("[") or content_clean.startswith("{"):
        try:
            data = json.loads(content_clean)
            if isinstance(data, dict):
                data = [data]
            for idx, item in enumerate(data, start=1):
                try:
                    if isinstance(item, dict):
                        parsed.append(normalize_event_dict(item))
                    else:
                        errors.append(f"Item {idx} is not a valid JSON object.")
                except Exception as e:
                    errors.append(f"Item {idx}: {str(e)}")
            return parsed, errors
        except json.JSONDecodeError:
            # Fallback to line-by-line NDJSON
            pass

    # Process as Newline-Delimited JSON (NDJSON)
    for idx, line in enumerate(content_clean.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
            if isinstance(item, dict):
                parsed.append(normalize_event_dict(item))
            else:
                errors.append(f"Line {idx}: JSON value is not an object.")
        except Exception as e:
            errors.append(f"Line {idx}: {str(e)}")

    return parsed, errors
