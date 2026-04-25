# SPDX-License-Identifier: MIT
"""velloraq.integrations.redaction module for the Velloraq security platform."""

from __future__ import annotations

import re
from typing import Any

from velloraq.rules.helpers import (
    SECRET_VALUE_PATTERNS,
    contains_secret_key,
    looks_like_secret,
)

SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)(secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key|client[_-]?secret)"
    r"(\s*[:=]\s*)(['\"]?)([^'\"\s,;]+)(['\"]?)"
)


def summarize_environment(values: dict[str, Any]) -> dict[str, Any]:
    """Execute the summarize_environment operation for this module."""
    names = sorted(str(key) for key in values.keys())
    suspicious = sorted(
        str(key)
        for key, value in values.items()
        if contains_secret_key(str(key)) or looks_like_secret(value)
    )
    return {
        "environment_variable_count": len(names),
        "environment_variable_names": names,
        "secret_environment_variable_names": suspicious,
    }


def redact_text(value: str) -> str:
    """Execute the redact_text operation for this module."""
    redacted = SENSITIVE_ASSIGNMENT_RE.sub(r"\1\2\3[REDACTED]\5", value)
    for pattern in SECRET_VALUE_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted
