"""Backward-compatible schema imports for older API modules.

Canonical request and response schemas now live in ``velloraq.backend.schemas``
to keep HTTP contracts separate from route handlers.
"""

# SPDX-License-Identifier: MIT
from velloraq.backend.schemas.api import *  # noqa: F403
