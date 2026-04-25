"""Database engine and session factory for the SaaS backend."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from velloraq.backend.core.config import get_settings


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM entities."""

    pass


settings = get_settings()
engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    """Yield a request-scoped SQLAlchemy session for FastAPI dependencies."""

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
