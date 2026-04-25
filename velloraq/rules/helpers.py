# SPDX-License-Identifier: MIT
"""velloraq.rules.helpers module for the Velloraq security platform."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

SECRET_KEY_RE = re.compile(
    r"(secret|password|passwd|pwd|token|api[_-]?key|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)
SECRET_VALUE_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(r"(?i)(xox[baprs]-[0-9A-Za-z-]{10,})"),
    re.compile(r"(?i)(ghp_[0-9A-Za-z]{30,})"),
    re.compile(r"(?i)(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})"),
]


def as_list(value: Any) -> list[Any]:
    """Execute the as_list operation for this module."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def iter_statements(policy_document: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Execute the iter_statements operation for this module."""
    statements = policy_document.get("Statement", [])
    if isinstance(statements, dict):
        yield statements
        return
    if isinstance(statements, list):
        for statement in statements:
            if isinstance(statement, dict):
                yield statement


def value_has_wildcard(value: Any) -> bool:
    """Execute the value_has_wildcard operation for this module."""
    return any(item == "*" or (isinstance(item, str) and item.endswith(":*")) for item in as_list(value))


def contains_secret_key(name: str) -> bool:
    """Execute the contains_secret_key operation for this module."""
    return bool(SECRET_KEY_RE.search(name))


def looks_like_secret(value: Any) -> bool:
    """Execute the looks_like_secret operation for this module."""
    if value is None:
        return False
    text = str(value)
    if len(text) < 12:
        return False
    return any(pattern.search(text) for pattern in SECRET_VALUE_PATTERNS)
