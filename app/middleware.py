import time
from datetime import datetime

from starlette.middleware.base import BaseHTTPMiddleware

from backend.app.database import SessionLocal
from backend.app.models import SecurityEvent


class SecurityMonitoringMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request, call_next):

        start_time = time.perf_counter()

        client_ip = (
            request.client.host
            if request.client
            else "unknown"
        )

        method = request.method
        endpoint = request.url.path

        user_agent = request.headers.get(
            "user-agent",
            "unknown"
        )

        # Process request
        response = await call_next(request)

        # Calculate response time
        duration = time.perf_counter() - start_time

        # Create database session
        db = SessionLocal()

        try:

            event = SecurityEvent(
                timestamp=datetime.utcnow(),
                method=method,
                endpoint=endpoint,
                status_code=response.status_code,
                response_time_ms=round(
                    duration * 1000,
                    2
                ),
                client_ip=client_ip,
                user_agent=user_agent
            )

            db.add(event)
            db.commit()

        except Exception as e:

            db.rollback()

            print(
                f"Security event logging error: {e}"
            )

        finally:

            db.close()

        return response