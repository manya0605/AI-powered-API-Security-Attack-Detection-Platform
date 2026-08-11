from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.app.security import (
    hash_password,
    verify_password,
    create_access_token
)


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"]
)


# Temporary in-memory user store.
# We'll replace this with a database shortly.
users = {}


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/register")
def register(request: RegisterRequest):

    if request.username in users:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    users[request.username] = {
        "username": request.username,
        "password_hash": hash_password(request.password)
    }

    return {
        "message": "User registered successfully",
        "username": request.username
    }


@router.post("/login")
def login(request: LoginRequest):

    user = users.get(request.username)

    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    if not verify_password(
        request.password,
        user["password_hash"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    token = create_access_token(
        {
            "sub": request.username
        }
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }