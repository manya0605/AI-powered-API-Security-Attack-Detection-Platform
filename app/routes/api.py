from collections import Counter

from fastapi import APIRouter, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.models import SecurityEvent
from backend.app.security import decode_access_token

from ml.detector import detect_latest_behavior


router = APIRouter(
    prefix="/api",
    tags=["Protected API"]
)

security = HTTPBearer()


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    payload = decode_access_token(token)

    if not payload:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=401,
            detail="Invalid or expired access token"
        )

    username = payload.get("sub")

    if not username:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=401,
            detail="Invalid token payload"
        )

    return username


@router.get("/profile")
def profile(username: str = Depends(get_current_user)):
    return {
        "message": "Authenticated API request successful",
        "username": username,
        "security_status": "authenticated"
    }


@router.get("/data")
def protected_data(username: str = Depends(get_current_user)):
    return {
        "message": "Protected data accessed successfully",
        "user": username,
        "data": {
            "account_status": "active",
            "access_level": "standard"
        }
    }


@router.get("/security/summary")
def security_summary(
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user)
):

    events = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.timestamp.desc())
        .all()
    )

    total_requests = len(events)

    successful_requests = sum(
        1 for event in events
        if 200 <= event.status_code < 300
    )

    failed_requests = sum(
        1 for event in events
        if event.status_code >= 400
    )

    unique_ips = len(
        set(event.client_ip for event in events)
    )

    endpoint_counts = Counter(
        event.endpoint
        for event in events
    )

    ip_counts = Counter(
        event.client_ip
        for event in events
    )

    average_response_time = (
        sum(event.response_time_ms for event in events)
        / total_requests
        if total_requests > 0
        else 0
    )

    return {
        "requested_by": username,
        "total_requests": total_requests,
        "successful_requests": successful_requests,
        "failed_requests": failed_requests,
        "unique_ips": unique_ips,
        "average_response_time_ms": round(
            average_response_time,
            2
        ),
        "top_endpoints": endpoint_counts.most_common(10),
        "top_ips": ip_counts.most_common(10)
    }

@router.get("/security/detect")
def detect_security_threat(
    db: Session = Depends(get_db),
    username: str = Depends(get_current_user)
):
    result = detect_latest_behavior()

    return {
        "requested_by": username,
        "ai_security_analysis": result
    }