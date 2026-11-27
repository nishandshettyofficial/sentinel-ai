from fastapi import APIRouter
from backend.app.api.endpoints import health, dashboard, logs, alerts, threat_intel

api_router = APIRouter()
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(logs.router, prefix="/logs", tags=["logs"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["alerts"])
api_router.include_router(threat_intel.router, prefix="/threat-intel", tags=["threat-intel"])
