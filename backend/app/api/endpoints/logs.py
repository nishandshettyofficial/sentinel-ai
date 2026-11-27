import datetime
import io
import csv
import json
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Query, Response, status
from fastapi.responses import PlainTextResponse, StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc
from typing import List, Optional

from backend.app.core.database import get_db
from backend.app.core.errors import SentinelException
from backend.app.models.event import SecurityEvent
from backend.app.schemas.log import (
    LogUploadResponse,
    RawLogIngestRequest,
    PaginatedLogRecords,
    SampleLogMetadata
)
from backend.app.schemas.dashboard import RecentActivityItem
from backend.app.services.log_parser import (
    parse_csv_content,
    parse_json_content,
    MAX_LOG_FILE_SIZE_BYTES
)
from backend.app.services.detection_engine import analyze_events_and_detect_threats
from backend.app.services.sample_logs import SAMPLE_LOGS

router = APIRouter()

def process_and_store_events(
    db: Session,
    parsed_dicts: list,
    filename: str,
    errors: list
) -> LogUploadResponse:
    stored_events: List[SecurityEvent] = []

    for item in parsed_dicts:
        try:
            event = SecurityEvent(
                timestamp=item["timestamp"],
                source_ip=item["source_ip"],
                destination_ip=item["destination_ip"],
                user_identity=item["user_identity"],
                event_type=item["event_type"],
                action=item["action"],
                status=item["status"],
                details=item["details"],
                raw_log=item["raw_log"]
            )
            db.add(event)
            stored_events.append(event)
        except Exception as e:
            errors.append(f"Failed to store event: {str(e)}")

    if stored_events:
        db.commit()
        for ev in stored_events:
            db.refresh(ev)

    # Run Detection Engine on newly stored events
    new_alerts = analyze_events_and_detect_threats(db, stored_events)

    return LogUploadResponse(
        filename=filename,
        records_parsed=len(parsed_dicts),
        records_stored=len(stored_events),
        errors=errors[:10],
        alerts_detected=len(new_alerts),
        alerts=new_alerts
    )

@router.post("/upload", response_model=LogUploadResponse, summary="Upload CSV or JSON Security Log File")
async def upload_log_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # Enforce file size limit
    contents_bytes = await file.read()
    if len(contents_bytes) > MAX_LOG_FILE_SIZE_BYTES:
        raise SentinelException(
            message=f"File exceeds maximum allowed upload size of {MAX_LOG_FILE_SIZE_BYTES // (1024 * 1024)}MB.",
            code="FILE_TOO_LARGE",
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
        )

    if not contents_bytes:
        raise SentinelException(
            message="Uploaded file is empty (0 bytes).",
            code="EMPTY_FILE",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    try:
        content_str = contents_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content_str = contents_bytes.decode("latin-1")
        except Exception:
            raise SentinelException(
                message="File encoding not recognized. Please upload UTF-8 or ASCII text.",
                code="INVALID_ENCODING",
                status_code=status.HTTP_400_BAD_REQUEST
            )

    filename = file.filename or "uploaded_log"
    lower_name = filename.lower()

    if lower_name.endswith(".csv"):
        parsed_records, errors = parse_csv_content(content_str)
    elif lower_name.endswith(".json") or lower_name.endswith(".ndjson"):
        parsed_records, errors = parse_json_content(content_str)
    else:
        # Auto-detect JSON or CSV
        stripped = content_str.strip()
        if stripped.startswith("{") or stripped.startswith("["):
            parsed_records, errors = parse_json_content(content_str)
        else:
            parsed_records, errors = parse_csv_content(content_str)

    return process_and_store_events(db, parsed_records, filename, errors)

@router.post("/raw", response_model=LogUploadResponse, summary="Ingest Raw Log Text Payload")
def ingest_raw_logs(
    payload: RawLogIngestRequest,
    db: Session = Depends(get_db)
):
    if not payload.content or not payload.content.strip():
        raise SentinelException(
            message="Payload content cannot be empty.",
            code="EMPTY_CONTENT",
            status_code=400
        )

    if payload.format.lower() == "csv":
        parsed_records, errors = parse_csv_content(payload.content)
    elif payload.format.lower() == "json":
        parsed_records, errors = parse_json_content(payload.content)
    else:
        raise SentinelException(
            message="Supported formats: 'csv' or 'json'",
            code="UNSUPPORTED_FORMAT",
            status_code=400
        )

    return process_and_store_events(db, parsed_records, payload.filename or "raw_logs", errors)

@router.get("/samples", response_model=List[SampleLogMetadata], summary="List Available Sample Security Logs")
def list_sample_logs():
    return [
        SampleLogMetadata(
            key=k,
            filename=v["filename"],
            format=v["format"],
            description=v["description"]
        )
        for k, v in SAMPLE_LOGS.items()
    ]

@router.get("/sample/{sample_key}/download", summary="Download Sample Log File for Testing")
def download_sample_log(sample_key: str):
    if sample_key not in SAMPLE_LOGS:
        raise SentinelException(
            message=f"Sample log '{sample_key}' not found.",
            code="SAMPLE_NOT_FOUND",
            status_code=404
        )
    sample = SAMPLE_LOGS[sample_key]
    media_type = "text/csv" if sample["format"] == "csv" else "application/json"
    return Response(
        content=sample["content"],
        media_type=media_type,
        headers={"Content-Disposition": f"attachment; filename={sample['filename']}"}
    )

@router.post("/sample/{sample_key}", response_model=LogUploadResponse, summary="Ingest Sample Security Log Directly")
def ingest_sample_log(
    sample_key: str,
    db: Session = Depends(get_db)
):
    if sample_key not in SAMPLE_LOGS:
        raise SentinelException(
            message=f"Sample log '{sample_key}' not found.",
            code="SAMPLE_NOT_FOUND",
            status_code=404
        )

    sample = SAMPLE_LOGS[sample_key]
    if sample["format"] == "csv":
        parsed_records, errors = parse_csv_content(sample["content"])
    else:
        parsed_records, errors = parse_json_content(sample["content"])

    return process_and_store_events(db, parsed_records, sample["filename"], errors)

@router.get("/records", response_model=PaginatedLogRecords, summary="Query & Filter Parsed Security Log Records")
def get_log_records(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    event_type: Optional[str] = None,
    status: Optional[str] = None,
    time_range: Optional[str] = None, # '1h', '6h', '24h', '7d'
    db: Session = Depends(get_db)
):
    query = db.query(SecurityEvent)

    # Search filter
    if search:
        search_filter = f"%{search.strip()}%"
        query = query.filter(
            or_(
                SecurityEvent.source_ip.ilike(search_filter),
                SecurityEvent.destination_ip.ilike(search_filter),
                SecurityEvent.user_identity.ilike(search_filter),
                SecurityEvent.action.ilike(search_filter),
                SecurityEvent.event_type.ilike(search_filter)
            )
        )

    # Event Type filter
    if event_type and event_type != "ALL":
        query = query.filter(SecurityEvent.event_type == event_type)

    # Status filter
    if status and status != "ALL":
        query = query.filter(SecurityEvent.status == status)

    # Time range filter
    if time_range and time_range != "ALL":
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        if time_range == "1h":
            cutoff = now - datetime.timedelta(hours=1)
        elif time_range == "6h":
            cutoff = now - datetime.timedelta(hours=6)
        elif time_range == "24h":
            cutoff = now - datetime.timedelta(hours=24)
        elif time_range == "7d":
            cutoff = now - datetime.timedelta(days=7)
        else:
            cutoff = None

        if cutoff:
            query = query.filter(SecurityEvent.timestamp >= cutoff)

    total = query.count()
    events = (
        query.order_by(desc(SecurityEvent.timestamp))
        .offset((page - 1) * limit)
        .limit(limit)
        .all()
    )

    items = []
    for ev in events:
        severity = "LOW"
        if ev.status == "BLOCKED" or ev.event_type in ["C2_BEACON", "PORT_SCAN"]:
            severity = "HIGH"
        elif ev.event_type in ["PRIVILEGE_ESCALATION", "AUTH_FAILED"]:
            severity = "CRITICAL" if ev.status == "BLOCKED" or ev.user_identity in ["root", "admin"] else "MEDIUM"
        elif ev.status == "SUCCESS":
            severity = "LOW"

        items.append(
            RecentActivityItem(
                id=ev.id,
                timestamp=ev.timestamp,
                event_type=ev.event_type,
                action=ev.action,
                source_ip=ev.source_ip,
                destination_ip=ev.destination_ip,
                user_identity=ev.user_identity,
                status=ev.status,
                severity=severity,
                details=ev.details
            )
        )

    total_pages = (total + limit - 1) // limit if total > 0 else 1

    return PaginatedLogRecords(
        total=total,
        page=page,
        page_size=limit,
        total_pages=total_pages,
        items=items
    )

@router.get("/export", summary="Export Filtered Security Log Records (CSV or JSON)")
def export_log_records(
    format: str = Query("csv", pattern="^(csv|json)$"),
    search: Optional[str] = None,
    event_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(500, ge=1, le=5000),
    db: Session = Depends(get_db)
):
    query = db.query(SecurityEvent)
    if search:
        search_filter = f"%{search.strip()}%"
        query = query.filter(
            or_(
                SecurityEvent.source_ip.ilike(search_filter),
                SecurityEvent.user_identity.ilike(search_filter),
                SecurityEvent.action.ilike(search_filter),
                SecurityEvent.event_type.ilike(search_filter)
            )
        )
    if event_type and event_type != "ALL":
        query = query.filter(SecurityEvent.event_type == event_type)
    if status and status != "ALL":
        query = query.filter(SecurityEvent.status == status)

    events = query.order_by(desc(SecurityEvent.timestamp)).limit(limit).all()

    if format == "json":
        data = [
            {
                "id": ev.id,
                "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                "source_ip": ev.source_ip,
                "destination_ip": ev.destination_ip,
                "user_identity": ev.user_identity,
                "event_type": ev.event_type,
                "action": ev.action,
                "status": ev.status,
                "details": ev.details
            }
            for ev in events
        ]
        return Response(
            content=json.dumps(data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=sentinel_logs_export.json"}
        )

    # CSV Export
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "timestamp", "source_ip", "destination_ip", "user_identity", "event_type", "action", "status", "details"])
    for ev in events:
        writer.writerow([
            ev.id,
            ev.timestamp.isoformat() if ev.timestamp else "",
            ev.source_ip,
            ev.destination_ip or "",
            ev.user_identity or "",
            ev.event_type,
            ev.action,
            ev.status,
            json.dumps(ev.details or {})
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sentinel_logs_export.csv"}
    )
