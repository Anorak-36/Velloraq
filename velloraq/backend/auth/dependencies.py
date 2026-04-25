"""Authentication dependencies shared by protected API routes."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import uuid

import jwt
from fastapi import Cookie, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from velloraq.backend.auth.security import decode_access_token
from velloraq.backend.database.session import get_db
from velloraq.backend.models.entities import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)


def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    cookie_token: str | None = Cookie(default=None, alias="velloraq_access_token"),
    legacy_cookie_token: str | None = Cookie(default=None, alias="slssec_access_token"),
    db: Session = Depends(get_db),
) -> User:
    """Resolve the current active user from a bearer token or secure cookie."""

    selected_token = token or cookie_token or legacy_cookie_token
    if not selected_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(selected_token)
        subject = payload.get("sub")
        user_id = uuid.UUID(str(subject))
    except (jwt.PyJWTError, ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    user = db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User is inactive or no longer exists",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require the authenticated user to hold the admin role."""

    if current_user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required")
    return current_user
