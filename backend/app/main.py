import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.core.database import engine, Base, SessionLocal
from backend.app.core.middleware import SecurityTelemetryMiddleware
from backend.app.core.errors import (
    SentinelException,
    sentinel_exception_handler,
    http_exception_handler,
    validation_exception_handler,
    generic_exception_handler
)
from backend.app.services.seed_service import seed_initial_security_data
from backend.app.api.api import api_router
from backend.app.api.endpoints.health import basic_health

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

# Create database tables
Base.metadata.create_all(bind=engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: seed initial telemetry if empty
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
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# 1. Custom Exception Handlers
app.add_exception_handler(SentinelException, sentinel_exception_handler)
app.add_exception_handler(StarletteHTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# 2. Telemetry and Latency Middleware
app.add_middleware(SecurityTelemetryMiddleware)

# 3. CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Process-Time"]
)

# 4. Top-level Root & Health Endpoints
@app.get("/", summary="Root Status Endpoint")
def read_root():
    return {
        "status": "online",
        "service": "Sentinel AI SOC Engine",
        "version": "1.0.0",
        "documentation": "/docs",
        "health_endpoint": "/health"
    }

@app.get("/health", summary="Basic Health Check Endpoint")
def read_health():
    return basic_health()

# 5. Include API v1 Router
app.include_router(api_router, prefix="/api/v1")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
