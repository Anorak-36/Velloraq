"""Project management routes."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from velloraq.backend.schemas.api import ProjectCreate, ProjectRead
from velloraq.backend.auth.dependencies import get_current_user
from velloraq.backend.database.session import get_db
from velloraq.backend.models.entities import Project, User
from velloraq.backend.services.project_service import create_project, list_projects

router = APIRouter(prefix="/projects", tags=["projects"])


@router.post("", response_model=ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project_endpoint(
    payload: ProjectCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Project:
    """Create a project for grouping scans and default configuration."""

    return create_project(db, current_user, payload)


@router.get("", response_model=list[ProjectRead])
def list_projects_endpoint(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Project]:
    """List projects visible to the authenticated user."""

    return list_projects(db, current_user)
