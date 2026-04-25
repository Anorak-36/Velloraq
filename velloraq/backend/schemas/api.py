"""Pydantic request and response schemas for the public REST API."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Provider = Literal["all", "aws", "azure", "gcp", "source"]
Severity = Literal["Low", "Medium", "High", "Critical"]
ScanStatus = Literal["queued", "running", "succeeded", "failed", "cancelled"]


class UserCreate(BaseModel):
    """UserCreate component used by Velloraq. """
    email: str = Field(..., min_length=5, max_length=320)
    password: str = Field(..., min_length=12, max_length=72)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        """Execute the normalize_email operation for this module."""
        if "@" not in value:
            raise ValueError("A valid email address is required")
        return value.strip().lower()


class UserRead(BaseModel):
    """UserRead component used by Velloraq. """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    role: str
    is_active: bool
    created_at: datetime


class LoginRequest(BaseModel):
    """LoginRequest component used by Velloraq. """
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        """Execute the normalize_email operation for this module."""
        return value.strip().lower()


class TokenResponse(BaseModel):
    """TokenResponse component used by Velloraq. """
    access_token: str
    token_type: str = "bearer"
    user: UserRead


class ProjectCreate(BaseModel):
    """ProjectCreate component used by Velloraq. """
    name: str = Field(..., min_length=1, max_length=160)
    description: str | None = Field(None, max_length=2000)
    default_config: dict[str, Any] = Field(default_factory=dict)


class ProjectRead(BaseModel):
    """ProjectRead component used by Velloraq. """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    description: str | None
    default_config: dict[str, Any]
    created_at: datetime


class ScanCreate(BaseModel):
    """ScanCreate component used by Velloraq. """
    project_id: uuid.UUID | None = None
    providers: list[Provider] = Field(default_factory=lambda: ["source"], max_length=5)
    regions: list[str] = Field(default_factory=list, max_length=50)
    aws_profile: str | None = Field(None, max_length=128)
    azure_subscriptions: list[str] = Field(default_factory=list, max_length=100)
    gcp_projects: list[str] = Field(default_factory=list, max_length=100)
    source_paths: list[str] = Field(default_factory=list, max_length=100)
    dependency_manifests: list[str] = Field(default_factory=list, max_length=100)
    enabled_rules: list[str] = Field(default_factory=list, max_length=200)
    disabled_rules: list[str] = Field(default_factory=list, max_length=200)
    min_severity: Severity | None = None
    exclude_resources: list[str] = Field(default_factory=list, max_length=500)
    enable_nvd: bool = False
    include_inventory: bool = False
    webhook_url: str | None = Field(None, max_length=2048)

    @field_validator("providers")
    @classmethod
    def providers_must_be_unique(cls, value: list[str]) -> list[str]:
        """Execute the providers_must_be_unique operation for this module."""
        deduped = list(dict.fromkeys(value))
        if not deduped:
            raise ValueError("At least one provider is required")
        return deduped

    @field_validator("webhook_url")
    @classmethod
    def validate_webhook_url(cls, value: str | None) -> str | None:
        """Execute the validate_webhook_url operation for this module."""
        if value is None:
            return None
        if not value.startswith(("https://", "http://")):
            raise ValueError("Webhook URL must start with http:// or https://")
        return value


class ScanRead(BaseModel):
    """ScanRead component used by Velloraq. """
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID | None
    status: str
    provider: str
    config: dict[str, Any]
    error_message: str | None
    queued_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class ResultRead(BaseModel):
    """ResultRead component used by Velloraq. """
    scan_id: uuid.UUID
    summary: dict[str, Any]
    findings: list[dict[str, Any]]
    warnings: list[dict[str, Any]]
    raw_result: dict[str, Any] | None = None


class HealthResponse(BaseModel):
    """HealthResponse component used by Velloraq. """
    status: str
    app: str
    environment: str
