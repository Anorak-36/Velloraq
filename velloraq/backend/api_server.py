"""FastAPI application factory for the Velloraq SaaS backend."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from velloraq.backend.api.routes_auth import router as auth_router
from velloraq.backend.api.routes_projects import router as projects_router
from velloraq.backend.api.routes_scans import router as scans_router
from velloraq.backend.api.routes_system import router as system_router
from velloraq.backend.auth.security import hash_password
from velloraq.backend.core.config import get_settings
from velloraq.backend.core.rate_limit import InMemoryRateLimitMiddleware
from velloraq.backend.database.migrate import run_migrations
from velloraq.backend.database.session import SessionLocal
from velloraq.backend.models.entities import User


FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


def create_app() -> FastAPI:
    """Create and configure the API server, middleware, routes, and dashboard."""

    settings = get_settings()
    app = FastAPI(title=settings.app_name, version="0.1.0-alpha")
    app.add_middleware(InMemoryRateLimitMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )
    app.include_router(system_router)
    app.include_router(auth_router)
    app.include_router(projects_router)
    app.include_router(scans_router)

    @app.middleware("http")
    async def reject_cross_site_cookie_writes(request: Request, call_next):
        """Block unsafe cross-site writes when browsers send session cookies."""

        if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = request.headers.get("origin")
            cookie_header = request.headers.get("cookie", "")
            uses_session_cookie = "velloraq_access_token=" in cookie_header
            if origin and uses_session_cookie and origin not in settings.allowed_origins:
                from starlette.responses import JSONResponse

                return JSONResponse({"detail": "Cross-site request denied"}, status_code=403)
        return await call_next(request)

    if FRONTEND_DIR.exists():
        app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

        @app.get("/", include_in_schema=False)
        def dashboard_index():
            """Serve the bundled single-page dashboard."""

            return FileResponse(FRONTEND_DIR / "index.html")

    @app.on_event("startup")
    def on_startup() -> None:
        """Initialize schema and optional first admin before serving traffic."""

        run_migrations()
        _ensure_first_admin()

    return app


def _ensure_first_admin() -> None:
    """Create or promote the configured bootstrap admin account."""

    settings = get_settings()
    if not settings.first_admin_email or not settings.first_admin_password:
        return
    with SessionLocal() as db:
        existing = db.execute(
            select(User).where(User.email == settings.first_admin_email.lower())
        ).scalar_one_or_none()
        if existing:
            if existing.role != "admin":
                existing.role = "admin"
                db.commit()
            return
        user = User(
            email=settings.first_admin_email.lower(),
            password_hash=hash_password(settings.first_admin_password),
            role="admin",
        )
        db.add(user)
        db.commit()


app = create_app()
