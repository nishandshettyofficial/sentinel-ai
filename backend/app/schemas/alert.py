from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from backend.app.schemas.dashboard import AlertItem

class AlertStatusUpdateRequest(BaseModel):
    status: str # NEW, INVESTIGATING, RESOLVED, DISMISSED

class PaginatedAlertsResponse(BaseModel):
    total: int
    page: int
    limit: int
    total_pages: int
    items: List[AlertItem]
