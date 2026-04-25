"""User registration and authentication business logic."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from velloraq.backend.schemas.api import UserCreate
from velloraq.backend.auth.security import hash_password, verify_password
from velloraq.backend.core.config import get_settings
from velloraq.backend.models.entities import User


def create_user(db: Session, payload: UserCreate, role: str = "user") -> User:
    """Create a user after enforcing registration policy and uniqueness."""

    settings = get_settings()
    if not settings.create_open_registration and role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Registration is disabled")
    existing = db.execute(select(User).where(User.email == payload.email)).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")
    user = User(email=payload.email, password_hash=hash_password(payload.password), role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def authenticate_user(db: Session, email: str, password: str) -> User | None:
    """Validate user credentials without revealing which part failed."""

    user = db.execute(select(User).where(User.email == email.lower())).scalar_one_or_none()
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user
