import time
import uuid
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("sentinel.telemetry")

class SecurityTelemetryMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # Request correlation ID
        request_id = request.headers.get("X-Request-ID") or f"req-{uuid.uuid4().hex[:12]}"
        request.state.request_id = request_id

        start_time = time.perf_counter()
        response = await call_next(request)
        process_time_ms = (time.perf_counter() - start_time) * 1000

        # Inject telemetry headers
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{process_time_ms:.2f}ms"

        # Structured SOC access log
        if not request.url.path.startswith("/docs") and not request.url.path.startswith("/openapi"):
            logger.info(
                f"[SOC-ACCESS] {request.method} {request.url.path} "
                f"status={response.status_code} latency={process_time_ms:.2f}ms req_id={request_id}"
            )

        return response
