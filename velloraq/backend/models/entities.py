"""SQLAlchemy ORM entities for the Velloraq SaaS backend."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON, TypeDecorator

from velloraq.backend.database.session import Base


class PortableJSON(TypeDecorator):
    """Use PostgreSQL JSONB in production and portable JSON in tests."""

    impl = JSON
    cache_ok = True

    def load_dialect_impl(self, dialect):
        """Select JSONB on PostgreSQL while keeping SQLite tests simple."""

        if dialect.name == "postgresql":
            return dialect.type_descriptor(JSONB())
        return dialect.type_descriptor(JSON())


def utcnow() -> datetime:
    """Return a timezone-aware UTC timestamp for persisted rows."""

    return datetime.now(timezone.utc)


class User(Base):
    """Authenticated SaaS user with role and ownership relationships."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="user")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    projects: Mapped[list["Project"]] = relationship(back_populates="owner")
    scans: Mapped[list["Scan"]] = relationship(back_populates="owner")


class Project(Base):
    """Logical grouping for scans and reusable scan defaults."""

    __tablename__ = "projects"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    default_config: Mapped[dict] = mapped_column(PortableJSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    owner: Mapped[User] = relationship(back_populates="projects")
    scans: Mapped[list["Scan"]] = relationship(back_populates="project")

    __table_args__ = (Index("ix_projects_owner_name", "owner_id", "name"),)


class Scan(Base):
    """Queued or completed security scan owned by a user."""

    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False, default="source")
    config: Mapped[dict] = mapped_column(PortableJSON, default=dict, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text)
    webhook_url: Mapped[str | None] = mapped_column(String(2048))
    queued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    owner: Mapped[User] = relationship(back_populates="scans")
    project: Mapped[Project | None] = relationship(back_populates="scans")
    result: Mapped["Result | None"] = relationship(back_populates="scan", uselist=False)

    __table_args__ = (
        Index("ix_scans_owner_created", "owner_id", "created_at"),
        Index("ix_scans_status_queued", "status", "queued_at"),
    )


class Result(Base):
    """Persisted scanner output and rendered report artifacts for one scan."""

    __tablename__ = "results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), unique=True, index=True
    )
    summary: Mapped[dict] = mapped_column(PortableJSON, default=dict, nullable=False)
    findings: Mapped[list] = mapped_column(PortableJSON, default=list, nullable=False)
    warnings: Mapped[list] = mapped_column(PortableJSON, default=list, nullable=False)
    raw_result: Mapped[dict] = mapped_column(PortableJSON, default=dict, nullable=False)
    html_report: Mapped[str | None] = mapped_column(Text)
    siem_jsonl: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)

    scan: Mapped[Scan] = relationship(back_populates="result")
