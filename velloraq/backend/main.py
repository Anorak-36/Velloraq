"""Backward-compatible ASGI import path.

New deployments should use ``velloraq.backend.api_server:app``. This module is
kept so existing Docker commands, local scripts, and interview demos that still
reference ``velloraq.backend.main:app`` continue to work.
"""

# SPDX-License-Identifier: MIT
from velloraq.backend.api_server import app, create_app

__all__ = ["app", "create_app"]
