"""Legacy ASGI entrypoint forwarding to Velloraq."""

# SPDX-License-Identifier: MIT
from velloraq.backend.api_server import app, create_app

__all__ = ["app", "create_app"]
