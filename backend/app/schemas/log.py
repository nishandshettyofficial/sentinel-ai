from typing import List, Dict, Any, Optional
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from backend.app.schemas.dashboard import AlertItem, RecentActivityItem

class LogUploadResponse(BaseModel):
    filename: str
    records_parsed: int
    records_stored: int
    errors: List[str]
    alerts_detected: int
    alerts: List[AlertItem]

class RawLogIngestRequest(BaseModel):
    format: str # 'csv' or 'json'
    content: str
    filename: Optional[str] = "raw_ingest_log"

class PaginatedLogRecords(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[RecentActivityItem]

class SampleLogMetadata(BaseModel):
    key: str
    filename: str
    format: str
    description: str
