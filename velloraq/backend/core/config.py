"""Runtime configuration for the Velloraq SaaS backend.

The settings layer intentionally reads from environment variables only. This
keeps Docker, CI, and self-hosted deployments deterministic while avoiding
hardcoded secrets in source control. ``VELLORAQ_*`` names are canonical; the
former ``SLSSEC_*`` names are accepted as a migration aid.
"""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import os
import secrets
from functools import lru_cache
from pathlib import Path
from typing import Any


def _load_dotenv(path: Path) -> None:
    """Internal helper used to keep the module implementation focused."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'\"")
        os.environ.setdefault(key, value)


_load_dotenv(Path(".env"))


class Settings:
    """Validated runtime settings loaded from environment variables."""

    app_name: str
    app_env: str
    database_url: str
    jwt_secret_key: str
    jwt_algorithm: str
    access_token_expire_minutes: int
    password_bcrypt_rounds: int
    allowed_origins: list[str]
    rate_limit_requests: int
    rate_limit_window_seconds: int
    scan_poll_interval_seconds: int
    scan_worker_batch_size: int
    allowed_source_roots: list[Path]
    reports_dir: Path
    create_open_registration: bool
    first_admin_email: str | None
    first_admin_password: str | None
    webhook_timeout_seconds: int
    enable_webhooks: bool

    def __init__(self) -> None:
        """Load environment-backed settings and validate production safety."""

        self.app_name = _env("VELLORAQ_APP_NAME", "Velloraq")
        self.app_env = _env("VELLORAQ_APP_ENV", "development")
        self.database_url = _env(
            "VELLORAQ_DATABASE_URL",
            "postgresql+pg8000://velloraq:velloraq_dev_password@localhost:5432/velloraq",
        )
        self.jwt_secret_key = _env("VELLORAQ_JWT_SECRET_KEY", "change-me-in-production")
        self.jwt_algorithm = _env("VELLORAQ_JWT_ALGORITHM", "HS256")
        self.access_token_expire_minutes = _env_int("VELLORAQ_ACCESS_TOKEN_EXPIRE_MINUTES", 60)
        self.password_bcrypt_rounds = _env_int("VELLORAQ_PASSWORD_BCRYPT_ROUNDS", 12)
        self.allowed_origins = _env_list("VELLORAQ_ALLOWED_ORIGINS", ["http://localhost:8000"])
        self.rate_limit_requests = _env_int("VELLORAQ_RATE_LIMIT_REQUESTS", 120)
        self.rate_limit_window_seconds = _env_int("VELLORAQ_RATE_LIMIT_WINDOW_SECONDS", 60)
        self.scan_poll_interval_seconds = _env_int("VELLORAQ_SCAN_POLL_INTERVAL_SECONDS", 5)
        self.scan_worker_batch_size = _env_int("VELLORAQ_SCAN_WORKER_BATCH_SIZE", 1)
        self.allowed_source_roots = [
            Path(item).resolve() for item in _env_list("VELLORAQ_ALLOWED_SOURCE_ROOTS", ["."])
        ]
        self.reports_dir = Path(_env("VELLORAQ_REPORTS_DIR", "reports")).resolve()
        open_registration_default = self.app_env.lower() != "production"
        self.create_open_registration = _env_bool(
            "VELLORAQ_OPEN_REGISTRATION", open_registration_default
        )
        self.first_admin_email = _env_optional("VELLORAQ_FIRST_ADMIN_EMAIL")
        self.first_admin_password = _env_optional("VELLORAQ_FIRST_ADMIN_PASSWORD")
        self.webhook_timeout_seconds = _env_int("VELLORAQ_WEBHOOK_TIMEOUT_SECONDS", 10)
        self.enable_webhooks = _env_bool("VELLORAQ_ENABLE_WEBHOOKS", False)
        self._validate()

    def _validate(self) -> None:
        """Enforce production secret hygiene and create report directories."""

        if self.app_env.lower() == "production":
            if _looks_like_placeholder_secret(self.jwt_secret_key):
                raise RuntimeError("Set VELLORAQ_JWT_SECRET_KEY before running in production.")
            if len(self.jwt_secret_key) < 32:
                raise RuntimeError("VELLORAQ_JWT_SECRET_KEY must be at least 32 characters.")
            if "*" in self.allowed_origins:
                raise RuntimeError("VELLORAQ_ALLOWED_ORIGINS cannot contain '*' in production.")
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    @property
    def is_production(self) -> bool:
        """Execute the is_production operation for this module."""
        return self.app_env.lower() == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings for the current process."""

    return Settings()


def generate_secret_key() -> str:
    """Generate a high-entropy secret suitable for JWT signing."""

    return secrets.token_urlsafe(48)


def _env(name: str, default: str) -> str:
    """Internal helper used to keep the module implementation focused."""
    return os.getenv(name) or os.getenv(_legacy_env_name(name), default)


def _env_optional(name: str) -> str | None:
    """Internal helper used to keep the module implementation focused."""
    value = os.getenv(name) or os.getenv(_legacy_env_name(name))
    return value if value else None


def _env_int(name: str, default: int) -> int:
    """Internal helper used to keep the module implementation focused."""
    value = os.getenv(name) or os.getenv(_legacy_env_name(name))
    if value is None:
        return default
    return int(value)


def _env_bool(name: str, default: bool) -> bool:
    """Internal helper used to keep the module implementation focused."""
    value = os.getenv(name) or os.getenv(_legacy_env_name(name))
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str, default: list[str]) -> list[str]:
    """Internal helper used to keep the module implementation focused."""
    value = os.getenv(name) or os.getenv(_legacy_env_name(name))
    if value is None:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


def _legacy_env_name(name: str) -> str:
    """Return the previous environment variable name for migration support."""

    if name.startswith("VELLORAQ_"):
        return "SLSSEC_" + name.removeprefix("VELLORAQ_")
    return name


def _looks_like_placeholder_secret(value: str) -> bool:
    """Reject common sample values before they become production JWT keys."""

    normalized = value.strip().lower()
    placeholder_markers = (
        "change-me",
        "change-this",
        "replace-me",
        "replace-with",
        "example",
        "placeholder",
        "in-production",
    )
    return any(marker in normalized for marker in placeholder_markers)


def settings_snapshot(settings: Settings | None = None) -> dict[str, Any]:
    """Return redacted settings for diagnostics and admin display."""

    active = settings or get_settings()
    return {
        "app_name": active.app_name,
        "app_env": active.app_env,
        "database_url": _mask_database_url(active.database_url),
        "jwt_algorithm": active.jwt_algorithm,
        "access_token_expire_minutes": active.access_token_expire_minutes,
        "allowed_origins": active.allowed_origins,
        "rate_limit_requests": active.rate_limit_requests,
        "rate_limit_window_seconds": active.rate_limit_window_seconds,
        "allowed_source_roots": [str(path) for path in active.allowed_source_roots],
        "reports_dir": str(active.reports_dir),
        "open_registration": active.create_open_registration,
        "enable_webhooks": active.enable_webhooks,
    }


def _mask_database_url(value: str) -> str:
    """Internal helper used to keep the module implementation focused."""
    if "@" not in value or "://" not in value:
        return value
    scheme, rest = value.split("://", 1)
    _, host = rest.rsplit("@", 1)
    return f"{scheme}://***:***@{host}"
