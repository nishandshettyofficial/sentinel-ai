from typing import Optional, List
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_
from backend.app.core.database import get_db
from backend.app.core.errors import SentinelException
from backend.app.models.alert import SecurityAlert
from backend.app.schemas.dashboard import AlertItem
from backend.app.schemas.alert import AlertStatusUpdateRequest, PaginatedAlertsResponse

router = APIRouter()

VALID_STATUSES = {"NEW", "INVESTIGATING", "RESOLVED", "DISMISSED"}

@router.get("", response_model=PaginatedAlertsResponse, summary="Query and Filter Security Alerts")
def get_alerts(
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Items per page"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    status: Optional[str] = Query(None, description="Filter by status: NEW, INVESTIGATING, RESOLVED, DISMISSED"),
    rule_name: Optional[str] = Query(None, description="Filter by detection rule name"),
    search: Optional[str] = Query(None, description="Free text search on title, description, IP, or user"),
    db: Session = Depends(get_db)
):
    query = db.query(SecurityAlert)

    if severity and severity.upper() != "ALL":
        query = query.filter(SecurityAlert.severity == severity.upper())

    if status and status.upper() != "ALL":
        query = query.filter(SecurityAlert.status == status.upper())

    if rule_name and rule_name.upper() != "ALL":
        query = query.filter(SecurityAlert.rule_name == rule_name)

    if search:
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                SecurityAlert.title.ilike(term),
                SecurityAlert.description.ilike(term),
                SecurityAlert.source_ip.ilike(term),
                SecurityAlert.target_user.ilike(term),
                SecurityAlert.rule_name.ilike(term)
            )
        )

    total = query.count()
    total_pages = max(1, (total + limit - 1) // limit)
    offset = (page - 1) * limit
    alerts = query.order_by(SecurityAlert.created_at.desc()).offset(offset).limit(limit).all()

    return PaginatedAlertsResponse(
        total=total,
        page=page,
        limit=limit,
        total_pages=total_pages,
        items=alerts
    )

@router.get("/{alert_id}", response_model=AlertItem, summary="Get Full Forensic Alert Details")
def get_alert_by_id(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise SentinelException(
            message=f"Security alert with ID {alert_id} not found.",
            code="ALERT_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND
        )
    return alert

@router.patch("/{alert_id}/status", response_model=AlertItem, summary="Update Alert Triage Status")
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdateRequest,
    db: Session = Depends(get_db)
):
    target_status = payload.status.upper().strip()
    if target_status not in VALID_STATUSES:
        raise SentinelException(
            message=f"Invalid alert status '{payload.status}'. Allowed values: {', '.join(sorted(VALID_STATUSES))}",
            code="INVALID_STATUS",
            status_code=status.HTTP_400_BAD_REQUEST
        )

    alert = db.query(SecurityAlert).filter(SecurityAlert.id == alert_id).first()
    if not alert:
        raise SentinelException(
            message=f"Security alert with ID {alert_id} not found.",
            code="ALERT_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND
        )

    alert.status = target_status
    db.commit()
    db.refresh(alert)
    return alert
