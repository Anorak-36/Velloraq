"""Authentication API routes for browser and API clients."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from velloraq.backend.schemas.api import LoginRequest, TokenResponse, UserCreate, UserRead
from velloraq.backend.auth.dependencies import get_current_user
from velloraq.backend.auth.security import create_access_token
from velloraq.backend.core.config import get_settings
from velloraq.backend.database.session import get_db
from velloraq.backend.models.entities import User
from velloraq.backend.services.user_service import authenticate_user, create_user

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)) -> User:
    """Create a user account when open registration is enabled."""

    return create_user(db, payload)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)) -> TokenResponse:
    """Authenticate a user and set a same-origin HttpOnly session cookie.

    The JSON bearer token keeps API automation simple, while the cookie lets the
    dashboard load protected HTML reports in sandboxed iframes without exposing
    tokens in URLs.
    """

    user = authenticate_user(db, payload.email, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    token = create_access_token(user.id, user.role)
    settings = get_settings()
    response.set_cookie(
        key="velloraq_access_token",
        value=token,
        httponly=True,
        secure=settings.is_production,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )
    response.delete_cookie("slssec_access_token", path="/")
    return TokenResponse(access_token=token, user=UserRead.model_validate(user))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(response: Response) -> Response:
    """Clear both current and legacy session cookies."""

    response.delete_cookie("velloraq_access_token", path="/")
    response.delete_cookie("slssec_access_token", path="/")
    return response


@router.get("/me", response_model=UserRead)
def me(current_user: User = Depends(get_current_user)) -> User:
    """Return the authenticated user profile."""

    return current_user
