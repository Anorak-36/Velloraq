"""System health and admin-only configuration routes."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

from fastapi import APIRouter, Depends

from velloraq.backend.schemas.api import HealthResponse
from velloraq.backend.auth.dependencies import require_admin
from velloraq.backend.core.config import get_settings, settings_snapshot
from velloraq.backend.models.entities import User

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Return a lightweight health check for load balancers and Compose."""

    settings = get_settings()
    return HealthResponse(status="ok", app=settings.app_name, environment=settings.app_env)


@router.get("/admin/settings")
def settings_endpoint(_admin: User = Depends(require_admin)):
    """Return a redacted settings snapshot for administrators."""

    return settings_snapshot()
