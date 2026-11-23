from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Dict, Any
from backend.app.core.database import get_db
from backend.app.schemas.dashboard import DashboardSummary, TrendPoint, AlertItem
from backend.app.services.dashboard_service import (
    get_dashboard_summary,
    get_dashboard_trends,
    get_recent_activity,
    get_recent_alerts
)

router = APIRouter()

@router.get("/summary", response_model=DashboardSummary)
def read_dashboard_summary(db: Session = Depends(get_db)):
    return get_dashboard_summary(db)

@router.get("/trends", response_model=List[TrendPoint])
def read_dashboard_trends(db: Session = Depends(get_db)):
    return get_dashboard_trends(db)

@router.get("/recent-activity")
def read_recent_activity(limit: int = 10, db: Session = Depends(get_db)):
    return get_recent_activity(db, limit=limit)

@router.get("/alerts", response_model=List[AlertItem])
def read_recent_alerts(limit: int = 6, db: Session = Depends(get_db)):
    return get_recent_alerts(db, limit=limit)
