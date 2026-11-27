from fastapi import APIRouter
from backend.app.api.endpoints import dashboard, logs

api_router = APIRouter()
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(logs.router, prefix="/logs", tags=["logs"])
