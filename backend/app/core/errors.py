import datetime
import uuid
from typing import List, Dict, Any, Optional
from fastapi import Request, status
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from pydantic import BaseModel

class ErrorDetail(BaseModel):
    field: Optional[str] = None
    message: str

class ErrorPayload(BaseModel):
    code: str
    message: str
    details: Optional[List[Dict[str, Any]]] = None

class ErrorResponse(BaseModel):
    error: ErrorPayload
    timestamp: str
    request_id: Optional[str] = None

class SentinelException(Exception):
    def __init__(self, message: str, code: str = "SECURITY_PLATFORM_ERROR", status_code: int = 400, details: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code
        self.details = details or []

class ResourceNotFoundException(SentinelException):
    def __init__(self, resource_type: str, identifier: Any):
        super().__init__(
            message=f"{resource_type} with ID '{identifier}' not found.",
            code="RESOURCE_NOT_FOUND",
            status_code=status.HTTP_404_NOT_FOUND
        )

def get_request_id(request: Request) -> str:
    return getattr(request.state, "request_id", str(uuid.uuid4()))

def create_error_response(code: str, message: str, status_code: int, details: Optional[List[Dict[str, Any]]] = None, request: Optional[Request] = None) -> JSONResponse:
    req_id = get_request_id(request) if request else str(uuid.uuid4())
    payload = {
        "error": {
            "code": code,
            "message": message,
            "details": details or []
        },
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "request_id": req_id
    }
    return JSONResponse(status_code=status_code, content=payload)

async def sentinel_exception_handler(request: Request, exc: SentinelException) -> JSONResponse:
    return create_error_response(
        code=exc.code,
        message=exc.message,
        status_code=exc.status_code,
        details=exc.details,
        request=request
    )

async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code_map = {
        400: "BAD_REQUEST",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        409: "CONFLICT",
        429: "TOO_MANY_REQUESTS",
        500: "INTERNAL_SERVER_ERROR",
        503: "SERVICE_UNAVAILABLE"
    }
    code = code_map.get(exc.status_code, f"HTTP_{exc.status_code}")
    return create_error_response(
        code=code,
        message=str(exc.detail),
        status_code=exc.status_code,
        request=request
    )

async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    formatted_errors = []
    for err in exc.errors():
        field_path = ".".join(str(p) for p in err.get("loc", []))
        formatted_errors.append({
            "field": field_path,
            "message": err.get("msg", "Validation error"),
            "type": err.get("type", "value_error")
        })
    return create_error_response(
        code="VALIDATION_ERROR",
        message="Request validation failed. Review the details field.",
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        details=formatted_errors,
        request=request
    )

async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    import logging
    logging.getLogger("sentinel.security").error(f"Unhandled exception on {request.url.path}: {exc}", exc_info=True)
    return create_error_response(
        code="INTERNAL_SERVER_ERROR",
        message="An unexpected system error occurred within the security platform.",
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        request=request
    )
