"""Business logic for scan lifecycle management.

The API layer queues scans only; this service owns validation, database state
transitions, report persistence, and optional completion webhooks. That split
keeps HTTP routes thin and makes worker execution reusable from tests.
"""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from velloraq.backend.schemas.api import ScanCreate
from velloraq.backend.core.config import Settings, get_settings
from velloraq.backend.models.entities import Project, Result, Scan, User
from velloraq.backend.scanner.adapter import run_scan_from_config
from velloraq.reports.html_reporter import render_html


TERMINAL_STATUSES = {"succeeded", "failed", "cancelled"}


def create_scan(db: Session, owner: User, payload: ScanCreate) -> Scan:
    """Create a queued scan owned by the authenticated user."""

    settings = get_settings()
    project = _project_for_payload(db, owner, payload.project_id)
    config = _build_config(project, payload, settings)
    scan = Scan(
        owner_id=owner.id,
        project_id=project.id if project else None,
        provider=",".join(config["providers"]),
        config=config,
        webhook_url=payload.webhook_url,
        status="queued",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def list_scans(db: Session, owner: User, limit: int = 50, offset: int = 0) -> list[Scan]:
    """List scans, scoped to the owner unless the caller is an admin."""

    query = select(Scan)
    if owner.role != "admin":
        query = query.where(Scan.owner_id == owner.id)
    return list(
        db.execute(query.order_by(Scan.created_at.desc()).offset(offset).limit(limit)).scalars()
    )


def get_scan_for_user(db: Session, scan_id: uuid.UUID, owner: User) -> Scan:
    """Fetch a scan by ID and hide other users' scans behind a 404."""

    scan = db.get(Scan, scan_id)
    if not scan or (owner.role != "admin" and scan.owner_id != owner.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


def get_result_for_user(db: Session, scan_id: uuid.UUID, owner: User) -> Result:
    """Return completed results after scan ownership has been verified."""

    scan = get_scan_for_user(db, scan_id, owner)
    if scan.status not in TERMINAL_STATUSES:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Scan is not complete")
    if not scan.result:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Results not found")
    return scan.result


def claim_next_scan(db: Session) -> Scan | None:
    """Atomically claim the oldest queued scan for a worker process."""

    query = (
        select(Scan)
        .where(Scan.status == "queued")
        .order_by(Scan.queued_at.asc())
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    scan = db.execute(query).scalar_one_or_none()
    if not scan:
        return None
    scan.status = "running"
    scan.started_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(scan)
    return scan


def execute_scan(db: Session, scan: Scan) -> Scan:
    """Run the scanner, persist all report formats, and update scan status."""

    try:
        scan_result = run_scan_from_config(scan.config)
        raw_result = scan_result.to_dict()
        result = Result(
            scan_id=scan.id,
            summary=raw_result.get("summary", {}),
            findings=raw_result.get("findings", []),
            warnings=raw_result.get("warnings", []),
            raw_result=raw_result,
            html_report=render_html(scan_result),
            siem_jsonl=_render_siem_jsonl(raw_result),
        )
        db.add(result)
        scan.status = "succeeded"
        scan.completed_at = datetime.now(timezone.utc)
        scan.error_message = None
        db.commit()
        db.refresh(scan)
        _notify_webhook(scan, result)
        return scan
    except Exception as exc:
        scan.status = "failed"
        scan.error_message = _safe_error(exc)
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(scan)
        _notify_webhook(scan, None)
        return scan


def _project_for_payload(db: Session, owner: User, project_id: uuid.UUID | None) -> Project | None:
    """Internal helper used to keep the module implementation focused."""
    if project_id is None:
        return None
    project = db.get(Project, project_id)
    if not project or (owner.role != "admin" and project.owner_id != owner.id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")
    return project


def _build_config(project: Project | None, payload: ScanCreate, settings: Settings) -> dict[str, Any]:
    """Internal helper used to keep the module implementation focused."""
    config: dict[str, Any] = dict(project.default_config) if project else {}
    request_config = payload.model_dump(exclude={"project_id", "webhook_url"})
    request_config["source_paths"] = _validate_paths(request_config["source_paths"], settings)
    request_config["dependency_manifests"] = _validate_paths(
        request_config["dependency_manifests"], settings
    )
    config.update({key: value for key, value in request_config.items() if value not in (None, [])})
    config.setdefault("providers", ["source"])
    config["include_inventory"] = bool(config.get("include_inventory", False))
    config["enable_nvd"] = bool(config.get("enable_nvd", False))
    return config


def _validate_paths(paths: list[str], settings: Settings) -> list[str]:
    """Internal helper used to keep the module implementation focused."""
    validated: list[str] = []
    for item in paths:
        resolved = Path(item).resolve()
        if not _is_under_allowed_root(resolved, settings.allowed_source_roots):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Path is outside allowed source roots: {item}",
            )
        validated.append(str(resolved))
    return validated


def _is_under_allowed_root(path: Path, roots: list[Path]) -> bool:
    """Internal helper used to keep the module implementation focused."""
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _render_siem_jsonl(raw_result: dict[str, Any]) -> str:
    """Internal helper used to keep the module implementation focused."""
    lines = []
    timestamp = raw_result.get("started_at")
    for finding in raw_result.get("findings", []):
        event = {
            "@timestamp": timestamp,
            "event": {
                "kind": "alert",
                "category": ["configuration", "vulnerability"],
                "severity": finding.get("severity"),
                "provider": "velloraq",
                "dataset": "serverless.security",
            },
            "cloud": {
                "provider": finding.get("provider"),
                "region": finding.get("region"),
                "account": {"id": finding.get("account_id")},
                "project": {"id": finding.get("project_id")},
            },
            "rule": {
                "id": finding.get("rule_id"),
                "name": finding.get("title"),
                "category": finding.get("category"),
                "reference": finding.get("standard_refs", []),
            },
            "resource": {
                "id": finding.get("resource_id"),
                "name": finding.get("resource_name"),
                "type": finding.get("service"),
            },
            "message": finding.get("description"),
            "recommendation": finding.get("recommendation"),
            "velloraq": finding,
        }
        lines.append(json.dumps(event, sort_keys=True))
    return "\n".join(lines) + ("\n" if lines else "")


def _notify_webhook(scan: Scan, result: Result | None) -> None:
    """Send an optional completion webhook without leaking scan internals."""

    settings = get_settings()
    if not settings.enable_webhooks or not scan.webhook_url:
        return
    if not _webhook_url_is_safe(scan.webhook_url):
        return
    payload = {
        "scan_id": str(scan.id),
        "status": scan.status,
        "summary": result.summary if result else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
    }
    request = Request(
        scan.webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "velloraq-saas/0.1"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=settings.webhook_timeout_seconds):
            return
    except Exception:
        return


def _webhook_url_is_safe(value: str) -> bool:
    """Internal helper used to keep the module implementation focused."""
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    hostname = parsed.hostname.lower()
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return False
    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for address in addresses:
        ip = address[4][0]
        if ip.startswith(("10.", "127.", "169.254.", "192.168.")):
            return False
        if ip.startswith("172."):
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return False
    return True


def _safe_error(exc: Exception) -> str:
    """Internal helper used to keep the module implementation focused."""
    message = str(exc) or exc.__class__.__name__
    return message[:2000]
