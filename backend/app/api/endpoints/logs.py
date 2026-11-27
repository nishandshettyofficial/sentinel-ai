from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc
from typing import List, Optional

from backend.app.core.database import get_db
from backend.app.models.event import SecurityEvent
from backend.app.schemas.log import (
    LogUploadResponse,
    RawLogIngestRequest,
    PaginatedLogRecords,
    SampleLogMetadata
)
from backend.app.schemas.dashboard import RecentActivityItem
from backend.app.services.log_parser import parse_csv_content, parse_json_content
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

@router.post("/upload", response_model=LogUploadResponse)
async def upload_log_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    contents_bytes = await file.read()
    try:
        content_str = contents_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content_str = contents_bytes.decode("latin-1")

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

@router.post("/raw", response_model=LogUploadResponse)
def ingest_raw_logs(
    payload: RawLogIngestRequest,
    db: Session = Depends(get_db)
):
    if payload.format.lower() == "csv":
        parsed_records, errors = parse_csv_content(payload.content)
    elif payload.format.lower() == "json":
        parsed_records, errors = parse_json_content(payload.content)
    else:
        raise HTTPException(status_code=400, detail="Supported formats: 'csv' or 'json'")

    return process_and_store_events(db, parsed_records, payload.filename or "raw_logs", errors)

@router.get("/samples", response_model=List[SampleLogMetadata])
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

@router.post("/sample/{sample_key}", response_model=LogUploadResponse)
def ingest_sample_log(
    sample_key: str,
    db: Session = Depends(get_db)
):
    if sample_key not in SAMPLE_LOGS:
        raise HTTPException(status_code=404, detail=f"Sample log '{sample_key}' not found.")

    sample = SAMPLE_LOGS[sample_key]
    if sample["format"] == "csv":
        parsed_records, errors = parse_csv_content(sample["content"])
    else:
        parsed_records, errors = parse_json_content(sample["content"])

    return process_and_store_events(db, parsed_records, sample["filename"], errors)

@router.get("/records", response_model=PaginatedLogRecords)
def get_log_records(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    event_type: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(SecurityEvent)

    if search:
        search_filter = f"%{search}%"
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
