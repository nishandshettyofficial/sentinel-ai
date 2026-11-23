from fastapi import APIRouter
from backend.app.api.endpoints import dashboard

api_router = APIRouter()
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
