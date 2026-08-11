import time
from collections import defaultdict, deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from urllib3 import request

from backend.app.security_state import is_ip_blocked


# ============================================================
# API SECURITY ENFORCEMENT
# ============================================================

REQUEST_LIMIT = 30
WINDOW_SECONDS = 60


request_history = defaultdict(deque)


class SecurityEnforcementMiddleware(
    BaseHTTPMiddleware
):

    async def dispatch(
        self,
        request: Request,
        call_next
    ):

        client_ip = (
            request.client.host
            if request.client
            else "unknown"
        )

        current_time = time.time()

        # ====================================================
        # AI-DRIVEN IP BLOCK CHECK
        # ====================================================

        if is_ip_blocked(client_ip):

            return JSONResponse(
                status_code=403,
                content={
                    "status": "blocked",

                    "error":
                        "Request blocked by AI security system",

                    "reason":
                        "Critical API security threat detected",

                    "client_ip":
                        client_ip
                }
            )

        # ====================================================
        # ROLLING REQUEST WINDOW
        # ====================================================

        history = request_history[client_ip]

        while (
            history
            and
            current_time - history[0]
            > WINDOW_SECONDS
        ):
            history.popleft()

        history.append(current_time)

        # Security analysis endpoints must remain accessible
        # even when the monitored API is rate limited.
        if request.url.path.startswith("/api/security/"):
           return await call_next(request)

        request_count = len(history)

        # ====================================================
        # RATE LIMITING
        # ====================================================

        if request_count > REQUEST_LIMIT:

            return JSONResponse(
                status_code=429,
                content={
                    "status": "rate_limited",

                    "error":
                        "Rate limit exceeded",

                    "requests_in_last_60_seconds":
                        request_count,

                    "limit":
                        REQUEST_LIMIT,

                    "client_ip":
                        client_ip
                }
            )

        # ====================================================
        # NORMAL REQUEST
        # ====================================================

        response = await call_next(request)

        return response