from datetime import datetime

from sqlalchemy import Column, Integer, String, Float, DateTime

from backend.app.database import Base


class SecurityEvent(Base):

    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    method = Column(String, nullable=False)

    endpoint = Column(String, nullable=False)

    status_code = Column(Integer, nullable=False)

    response_time_ms = Column(Float, nullable=False)

    client_ip = Column(String, nullable=False)

    user_agent = Column(String, nullable=True)

    username = Column(String, nullable=True)

    # ML-related fields — populated later
    risk_score = Column(Float, nullable=True)

    attack_type = Column(String, nullable=True)

    is_anomaly = Column(Integer, default=0)