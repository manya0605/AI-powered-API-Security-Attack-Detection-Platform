from fastapi import FastAPI

from backend.app.database import Base, engine
from backend.app.middleware import SecurityMonitoringMiddleware
from backend.app.routes.auth import router as auth_router
from backend.app.routes.api import router as api_router
from backend.app import models
from backend.app.security_middleware import (
    SecurityEnforcementMiddleware
)

# Create database tables
Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="AI API Security & Attack Detection Platform",
    description="AI-powered API security monitoring and attack detection system",
    version="1.0.0"
)


app.add_middleware(
    SecurityEnforcementMiddleware
)


# Security monitoring middleware
app.add_middleware(SecurityMonitoringMiddleware)


# API routes
app.include_router(auth_router)
app.include_router(api_router)


@app.get("/")
def root():
    return {
        "message": "AI API Security Platform is running",
        "status": "healthy"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "api-security-platform"
    }