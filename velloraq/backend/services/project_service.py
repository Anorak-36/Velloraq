"""Project service functions for grouping scans and reusable defaults."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from velloraq.backend.schemas.api import ProjectCreate
from velloraq.backend.models.entities import Project, User


def create_project(db: Session, owner: User, payload: ProjectCreate) -> Project:
    """Create a project owned by the authenticated user."""

    project = Project(
        owner_id=owner.id,
        name=payload.name,
        description=payload.description,
        default_config=payload.default_config,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


def list_projects(db: Session, owner: User) -> list[Project]:
    """List projects visible to the user or all projects for admins."""

    query = select(Project)
    if owner.role != "admin":
        query = query.where(Project.owner_id == owner.id)
    return list(db.execute(query.order_by(Project.created_at.desc())).scalars())


def get_project_for_user(db: Session, project_id: uuid.UUID, owner: User) -> Project:
    """Fetch a project while preventing cross-tenant access."""

    project = db.get(Project, project_id)
    if not project or (owner.role != "admin" and project.owner_id != owner.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project
