"""Configuration-file helpers for CLI scans.

The parser is deliberately dependency-light: PyYAML is used when available, and
a small read-only subset parser keeps the CLI usable in minimal environments.
Velloraq accepts legacy ``SLSSEC_*`` variables while standardizing on
``VELLORAQ_*`` for new deployments.
"""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Any


def load_config(path: str | None) -> dict[str, Any]:
    """Load YAML configuration from an explicit path, env var, or config.yaml."""

    selected = path or _env_value("VELLORAQ_CONFIG")
    if not selected:
        default = Path("config.yaml")
        if not default.exists():
            return {}
        selected = str(default)
    config_path = Path(selected)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    text = config_path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        loaded = yaml.safe_load(text) or {}
        if not isinstance(loaded, dict):
            raise ValueError("The YAML config root must be an object")
        return loaded
    except ModuleNotFoundError:
        return parse_simple_yaml(text)


def parse_simple_yaml(text: str) -> dict[str, Any]:
    """Parse the small YAML subset needed when PyYAML is unavailable."""

    lines = []
    for raw_line in text.splitlines():
        line = _strip_comment(raw_line).rstrip()
        if not line.strip():
            continue
        lines.append((len(line) - len(line.lstrip(" ")), line.strip()))
    if not lines:
        return {}
    parsed, index = _parse_block(lines, 0, lines[0][0])
    if index != len(lines):
        raise ValueError("Unable to parse config.yaml")
    if not isinstance(parsed, dict):
        raise ValueError("The YAML config root must be an object")
    return parsed


def config_list(config: dict[str, Any], key: str, default: list[str] | None = None) -> list[str]:
    """Read a config value as a list of strings."""

    value = config.get(key, default or [])
    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def config_bool(config: dict[str, Any], key: str, default: bool = False) -> bool:
    """Read a config value as a boolean."""

    value = config.get(key, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def env_list(name: str) -> list[str] | None:
    """Read a comma-separated environment variable as a list."""

    value = _env_value(name)
    if value is None:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def env_bool(name: str) -> bool | None:
    """Read an environment variable as a boolean when it is present."""

    value = _env_value(name)
    if value is None:
        return None
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_value(name: str) -> str | None:
    """Return a canonical environment variable with legacy fallback."""

    return _env_value(name)


def nested(config: dict[str, Any], section: str, key: str, default: Any = None) -> Any:
    """Return a nested section value for legacy config shapes."""

    value = config.get(section)
    if isinstance(value, dict):
        return value.get(key, default)
    return default


def deep_get(config: dict[str, Any], path: str, default: Any = None) -> Any:
    """Read a dotted-path value from a nested config object."""

    current: Any = config
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _parse_block(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[Any, int]:
    """Internal helper used to keep the module implementation focused."""
    if index >= len(lines):
        return {}, index
    is_list = lines[index][1].startswith("- ")
    return _parse_list(lines, index, indent) if is_list else _parse_dict(lines, index, indent)


def _parse_dict(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[dict[str, Any], int]:
    """Internal helper used to keep the module implementation focused."""
    data: dict[str, Any] = {}
    while index < len(lines):
        current_indent, content = lines[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            raise ValueError(f"Unexpected indentation near: {content}")
        if ":" not in content:
            raise ValueError(f"Expected key: value near: {content}")
        key, raw_value = content.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        index += 1
        if raw_value:
            data[key] = _parse_scalar(raw_value)
        elif index < len(lines) and lines[index][0] > current_indent:
            data[key], index = _parse_block(lines, index, lines[index][0])
        else:
            data[key] = None
    return data, index


def _parse_list(lines: list[tuple[int, str]], index: int, indent: int) -> tuple[list[Any], int]:
    """Internal helper used to keep the module implementation focused."""
    data: list[Any] = []
    while index < len(lines):
        current_indent, content = lines[index]
        if current_indent < indent:
            break
        if current_indent > indent:
            raise ValueError(f"Unexpected indentation near: {content}")
        if not content.startswith("- "):
            break
        item = content[2:].strip()
        index += 1
        if item:
            if ":" in item and not item.startswith(("'", '"')):
                key, raw_value = item.split(":", 1)
                data.append({key.strip(): _parse_scalar(raw_value.strip())})
            else:
                data.append(_parse_scalar(item))
        elif index < len(lines) and lines[index][0] > current_indent:
            value, index = _parse_block(lines, index, lines[index][0])
            data.append(value)
        else:
            data.append(None)
    return data, index


def _parse_scalar(value: str) -> Any:
    """Internal helper used to keep the module implementation focused."""
    lower = value.lower()
    if lower in {"null", "none", "~"}:
        return None
    if lower in {"true", "false"}:
        return lower == "true"
    if value.startswith("[") and value.endswith("]"):
        try:
            return ast.literal_eval(value)
        except Exception:
            inner = value[1:-1].strip()
            return [item.strip().strip("'\"") for item in inner.split(",") if item.strip()]
    if value.startswith(("'", '"')) and value.endswith(("'", '"')):
        return value[1:-1]
    return value


def _strip_comment(line: str) -> str:
    """Internal helper used to keep the module implementation focused."""
    in_single = False
    in_double = False
    for index, char in enumerate(line):
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        elif char == "#" and not in_single and not in_double:
            return line[:index]
    return line


def _env_value(name: str) -> str | None:
    """Internal helper used to keep the module implementation focused."""
    value = os.getenv(name)
    if value is not None:
        return value
    if name.startswith("VELLORAQ_"):
        return os.getenv("SLSSEC_" + name.removeprefix("VELLORAQ_"))
    if name.startswith("SLSSEC_"):
        return os.getenv("VELLORAQ_" + name.removeprefix("SLSSEC_")) or os.getenv(name)
    return os.getenv(name)
