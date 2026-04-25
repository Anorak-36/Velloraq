"""Simple in-memory rate limiter for self-hosted MVP deployments."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import time
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from velloraq.backend.core.config import get_settings


class InMemoryRateLimitMiddleware(BaseHTTPMiddleware):
    """Limit requests per client IP without external infrastructure."""

    def __init__(self, app):
        """Initialize a per-client timestamp bucket store."""

        super().__init__(app)
        self.clients: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Allow or reject a request based on the configured rolling window."""

        settings = get_settings()
        if request.url.path.startswith(("/health", "/static")):
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window_start = now - settings.rate_limit_window_seconds
        bucket = self.clients[client]
        while bucket and bucket[0] < window_start:
            bucket.popleft()
        if len(bucket) >= settings.rate_limit_requests:
            return JSONResponse(
                {"detail": "Rate limit exceeded"},
                status_code=429,
                headers={"Retry-After": str(settings.rate_limit_window_seconds)},
            )
        bucket.append(now)
        return await call_next(request)
