"""Report retrieval service with authorization checks.

Report HTML may contain data derived from scanned assets, so routes call this
service to centralize ownership checks and missing-report behavior before any
browser-renderable content is returned.
"""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import uuid

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from velloraq.backend.models.entities import User


def get_html_report_for_user(db: Session, scan_id: uuid.UUID, owner: User) -> str:
    """Return a stored HTML report for the owner or an admin user."""

    from velloraq.backend.models.entities import Scan

    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    if owner.role != "admin" and scan.owner_id != owner.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Report access denied")
    if not scan.result or not scan.result.html_report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not available")
    return scan.result.html_report
