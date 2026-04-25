"""Scan management and report delivery routes.

Routes expose canonical plural REST paths under ``/scans`` while retaining the
former singular ``/scan`` paths as hidden compatibility aliases.
"""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from sqlalchemy.orm import Session

from velloraq.backend.schemas.api import ResultRead, ScanCreate, ScanRead
from velloraq.backend.auth.dependencies import get_current_user
from velloraq.backend.database.session import get_db
from velloraq.backend.models.entities import Scan, User
from velloraq.backend.services.report_service import get_html_report_for_user
from velloraq.backend.services.scan_service import create_scan, get_result_for_user, get_scan_for_user, list_scans

router = APIRouter(tags=["scans"])


@router.post("/scans", response_model=ScanRead, status_code=202)
@router.post("/scan", response_model=ScanRead, status_code=202, include_in_schema=False)
def trigger_scan(
    payload: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    """Queue a read-only scan for asynchronous worker execution."""

    return create_scan(db, current_user, payload)


@router.get("/scans/{scan_id}", response_model=ScanRead)
@router.get("/scan/{scan_id}", response_model=ScanRead, include_in_schema=False)
def get_scan(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    """Return scan metadata after enforcing user ownership."""

    return get_scan_for_user(db, scan_id, current_user)


@router.get("/scans/{scan_id}/results", response_model=ResultRead)
@router.get("/scan/{scan_id}/results", response_model=ResultRead, include_in_schema=False)
def get_scan_results(
    scan_id: uuid.UUID,
    include_raw: bool = Query(default=False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ResultRead:
    """Return normalized findings and optionally the raw scanner payload."""

    result = get_result_for_user(db, scan_id, current_user)
    return ResultRead(
        scan_id=result.scan_id,
        summary=result.summary,
        findings=result.findings,
        warnings=result.warnings,
        raw_result=result.raw_result if include_raw else None,
    )


@router.get("/scans/{scan_id}/export/{export_format}")
@router.get("/scan/{scan_id}/export/{export_format}", include_in_schema=False)
def export_scan_results(
    scan_id: uuid.UUID,
    export_format: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Export completed scan results in JSON, HTML, or SIEM JSONL format."""

    result = get_result_for_user(db, scan_id, current_user)
    if export_format == "json":
        return JSONResponse(result.raw_result)
    if export_format == "html":
        if not result.html_report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not available")
        return _html_report_response(result.html_report)
    if export_format in {"siem", "jsonl"}:
        return PlainTextResponse(result.siem_jsonl or "", media_type="application/x-ndjson")
    return JSONResponse({"detail": "Unsupported export format"}, status_code=400)


@router.get("/scans/{scan_id}/report", response_class=HTMLResponse)
@router.get("/scans/{scan_id}/report/html", response_class=HTMLResponse)
@router.get("/scan/{scan_id}/report/html", response_class=HTMLResponse, include_in_schema=False)
def view_html_report(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    """Serve an authenticated HTML report with browser-safe response headers."""

    return _html_report_response(get_html_report_for_user(db, scan_id, current_user))


@router.get("/scans/{scan_id}/report/download")
@router.get("/scan/{scan_id}/report/download", include_in_schema=False)
def download_html_report(
    scan_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Response:
    """Return the authenticated HTML report as a downloadable attachment."""

    return _html_report_response(
        get_html_report_for_user(db, scan_id, current_user),
        extra_headers={"Content-Disposition": f'attachment; filename="report_{scan_id}.html"'},
    )


@router.get("/scans", response_model=list[ScanRead])
def list_scans_endpoint(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Scan]:
    """List scans visible to the current user."""

    return list_scans(db, current_user, limit=limit, offset=offset)


def _html_report_response(
    html_report: str, extra_headers: dict[str, str] | None = None
) -> Response:
    """Return report HTML with headers that keep active content isolated."""

    headers = {
        "X-Content-Type-Options": "nosniff",
        "Cache-Control": "private, no-store",
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors 'self'",
    }
    headers.update(extra_headers or {})
    return Response(content=html_report, media_type="text/html; charset=utf-8", headers=headers)
