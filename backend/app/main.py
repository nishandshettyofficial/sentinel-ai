import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.core.config import settings
from backend.app.core.database import engine, Base, SessionLocal
from backend.app.services.seed_service import seed_initial_security_data
from backend.app.api.api import api_router

# Create database tables
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: seed initial telemetry
    db = SessionLocal()
    try:
        seed_initial_security_data(db)
    finally:
        db.close()
    yield

app = FastAPI(
    title=settings.APP_NAME,
    description="Autonomous Cybersecurity Monitoring and Threat Detection Platform (Mini SOC)",
    version="1.0.0",
    lifespan=lifespan
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root and health check
@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "Sentinel AI SOC Engine",
        "version": "1.0.0",
        "docs_url": "/docs"
    }

@app.get("/health")
def read_health():
    return {
        "status": "healthy",
        "subsystems": {
            "database": "connected",
            "detection_engine": "active",
            "telemetry_stream": "online"
        }
    }

# Include API router
app.include_router(api_router, prefix="/api/v1")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
