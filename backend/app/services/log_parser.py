import csv
import io
import json
import datetime
from typing import List, Dict, Any, Tuple
from dateutil import parser as date_parser
from backend.app.core.errors import SentinelException

MAX_LOG_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

def validate_raw_log_content(content: str):
    if not content or not content.strip():
        raise SentinelException(
            message="Uploaded log file is empty. Provide a valid CSV or JSON audit trail.",
            code="EMPTY_LOG_FILE",
            status_code=400
        )
    if "\x00" in content:
        raise SentinelException(
            message="Binary or non-text files are not supported as security audit logs.",
            code="INVALID_FILE_FORMAT",
            status_code=400
        )

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
    ts_field = raw.get("timestamp") or raw.get("time") or raw.get("@timestamp") or raw.get("datetime") or raw.get("date")
    timestamp = parse_timestamp(ts_field)

    # Extract source IP
    source_ip = (
        raw.get("source_ip") or raw.get("src_ip") or raw.get("ip") or 
        raw.get("client_ip") or raw.get("remote_addr") or raw.get("src") or "0.0.0.0"
    )
    source_ip = str(source_ip).strip()

    # Destination IP
    dest_ip = raw.get("destination_ip") or raw.get("dst_ip") or raw.get("server_ip") or raw.get("host_ip") or raw.get("dst")
    if dest_ip:
        dest_ip = str(dest_ip).strip()

    # User identity
    user = (
        raw.get("user_identity") or raw.get("username") or raw.get("user") or 
        raw.get("account") or raw.get("login") or raw.get("target_user")
    )
    if user:
        user = str(user).strip()

    # Event Type
    event_type = (
        raw.get("event_type") or raw.get("type") or raw.get("category") or 
        raw.get("event") or raw.get("event_id") or "SECURITY_EVENT"
    )
    event_type = str(event_type).strip().upper()

    # Action
    action = (
        raw.get("action") or raw.get("operation") or raw.get("method") or "ACCESS"
    )
    action = str(action).strip().upper()

    # Status
    status = (
        raw.get("status") or raw.get("result") or raw.get("outcome") or raw.get("verdict") or "SUCCESS"
    )
    status = str(status).strip().upper()
    if status in ["FAIL", "FAILED", "ERR", "ERROR", "DENIED", "REJECTED", "401", "403"]:
        status = "FAILURE"
    elif status in ["OK", "SUCCESSFUL", "PERMITTED", "ALLOW", "ALLOWED", "200"]:
        status = "SUCCESS"
    elif status in ["BLOCK", "BLOCKED", "DROPPED", "MITIGATED", "QUARANTINED"]:
        status = "BLOCKED"

    # Details
    details = raw.get("details")
    if details and isinstance(details, str):
        try:
            details = json.loads(details)
        except Exception:
            details = {"raw_details": details}
    elif not details:
        known = {
            "timestamp", "time", "@timestamp", "datetime", "date",
            "source_ip", "src_ip", "ip", "client_ip", "remote_addr", "src",
            "destination_ip", "dst_ip", "server_ip", "host_ip", "dst",
            "user_identity", "username", "user", "account", "login", "target_user",
            "event_type", "type", "category", "event", "event_id",
            "action", "operation", "method", "status", "result", "outcome", "verdict", "details"
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
    validate_raw_log_content(content)
    parsed = []
    errors = []

    # Check for valid CSV delimiter
    first_line = content.strip().splitlines()[0]
    if "," not in first_line and "\t" not in first_line and ";" not in first_line:
        raise SentinelException(
            message="Invalid CSV format: Missing valid column delimiters (comma, semicolon, or tab).",
            code="INVALID_CSV_DELIMITER",
            status_code=400
        )

    try:
        reader = csv.DictReader(io.StringIO(content))
        if not reader.fieldnames:
            raise SentinelException(
                message="Invalid CSV: Header row could not be extracted.",
                code="INVALID_CSV_HEADER",
                status_code=400
            )

        for idx, row in enumerate(reader, start=1):
            try:
                # Discard empty rows
                if not any(row.values()):
                    continue
                normalized = normalize_event_dict(row)
                parsed.append(normalized)
            except Exception as e:
                errors.append(f"Line {idx}: {str(e)}")

    except SentinelException:
        raise
    except Exception as e:
        raise SentinelException(
            message=f"Failed to parse CSV log content: {str(e)}",
            code="MALFORMED_CSV",
            status_code=400
        )

    if not parsed:
        raise SentinelException(
            message="No valid security log records could be parsed from the provided CSV file.",
            code="NO_PARSED_RECORDS",
            status_code=400
        )

    return parsed, errors

def parse_json_content(content: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    validate_raw_log_content(content)
    parsed = []
    errors = []
    content_clean = content.strip()

    # Try standard JSON parsing first
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
                        errors.append(f"Item #{idx} is not a valid JSON dictionary.")
                except Exception as e:
                    errors.append(f"Item #{idx}: {str(e)}")

            if not parsed and errors:
                raise SentinelException(
                    message=f"JSON parsing error: {errors[0]}",
                    code="MALFORMED_JSON_ITEM",
                    status_code=400
                )
            return parsed, errors
        except json.JSONDecodeError as jde:
            # If not a standard array/object, try NDJSON line-by-line fallback
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
        except json.JSONDecodeError as jde:
            errors.append(f"Line {idx}: Invalid JSON syntax - {jde.msg}")

    if not parsed:
        raise SentinelException(
            message="Provided file is not valid JSON or NDJSON security log data.",
            code="MALFORMED_JSON",
            status_code=400
        )

    return parsed, errors
