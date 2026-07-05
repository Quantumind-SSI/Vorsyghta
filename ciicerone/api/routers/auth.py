"""Authentication router for Ciicerone API.

Provides /auth/token (login) and /auth/register endpoints.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from ciicerone.security.rbac import (
    create_access_token,
    get_password_hash,
    verify_password,
    Role,
    CurrentUser,
    get_current_user,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

# In-memory user store for pilot (replace with DB in production)
_users: dict[str, dict] = {}


class RegisterRequest(BaseModel):
    email: str
    password: str
    tenant_id: str = "default"
    role: str = "analyst"


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    tenant_id: str


@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register(request: RegisterRequest):
    """Register a new user (pilot use only — replace with proper IdP in production)."""
    if request.email in _users:
        raise HTTPException(status_code=400, detail="User already exists")
    user_id = f"user_{len(_users) + 1}"
    _users[request.email] = {
        "user_id": user_id,
        "email": request.email,
        "hashed_password": get_password_hash(request.password),
        "tenant_id": request.tenant_id,
        "role": request.role,
    }
    logger.info("Registered user: %s (role=%s, tenant=%s)", request.email, request.role, request.tenant_id)
    return {"message": "User registered", "user_id": user_id}


@router.post("/token", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Issue a JWT access token."""
    user = _users.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(
        user_id=user["user_id"],
        tenant_id=user["tenant_id"],
        role=user["role"],
    )
    return TokenResponse(access_token=token, role=user["role"], tenant_id=user["tenant_id"])


@router.get("/me", response_model=CurrentUser)
async def get_me(current_user: CurrentUser = Depends(get_current_user)):
    """Return the current authenticated user."""
    return current_user
