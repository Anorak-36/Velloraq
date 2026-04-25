# SPDX-License-Identifier: MIT
"""velloraq.integrations.source module for the Velloraq security platform."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from velloraq.integrations.base import CollectionResult
from velloraq.integrations.redaction import redact_text
from velloraq.scanner.models import Resource, ScanContext, ScanWarning

PYTHON_SUFFIXES = {".py"}
JAVASCRIPT_SUFFIXES = {".js", ".mjs", ".cjs", ".ts"}

JS_PATTERNS = [
    ("code_execution", "eval call", re.compile(r"\beval\s*\("), "High"),
    (
        "command_injection",
        "child_process exec call",
        re.compile(r"\b(child_process\.)?exec\s*\("),
        "High",
    ),
    (
        "insecure_deserialization",
        "node-serialize unserialize call",
        re.compile(r"\bunserialize\s*\("),
        "High",
    ),
]


class SourceCodeScanner:
    """SourceCodeScanner component used by Velloraq. """
    provider = "source"

    def collect(self, context: ScanContext) -> CollectionResult:
        """Execute the collect operation for this module."""
        result = CollectionResult()
        for source_path in context.source_paths:
            path = Path(source_path)
            if not path.exists():
                result.warnings.append(ScanWarning("source", f"Source path not found: {source_path}"))
                continue
            files = [path] if path.is_file() else [item for item in path.rglob("*") if item.is_file()]
            for file_path in files:
                if _is_ignored(file_path):
                    continue
                if file_path.suffix in PYTHON_SUFFIXES:
                    self._scan_python(file_path, result)
                elif file_path.suffix in JAVASCRIPT_SUFFIXES:
                    self._scan_javascript(file_path, result)
        return result

    def _scan_python(self, path: Path, result: CollectionResult) -> None:
        """Internal helper used to keep the module implementation focused."""
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except Exception as exc:
            result.warnings.append(ScanWarning("source", f"Unable to parse Python file {path}", str(exc)))
            return
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            issue = _python_call_issue(node)
            if issue:
                issue_type, title, severity = issue
                result.resources.append(
                    _source_issue(path, node.lineno, issue_type, title, severity, _line_at(text, node.lineno))
                )

    def _scan_javascript(self, path: Path, result: CollectionResult) -> None:
        """Internal helper used to keep the module implementation focused."""
        try:
            text = path.read_text(encoding="utf-8")
        except Exception as exc:
            result.warnings.append(ScanWarning("source", f"Unable to read JavaScript file {path}", str(exc)))
            return
        for line_no, line in enumerate(text.splitlines(), start=1):
            for issue_type, title, pattern, severity in JS_PATTERNS:
                if pattern.search(line):
                    result.resources.append(_source_issue(path, line_no, issue_type, title, severity, line))


def _python_call_issue(node: ast.Call) -> tuple[str, str, str] | None:
    """Internal helper used to keep the module implementation focused."""
    call_name = _call_name(node.func)
    if call_name in {"eval", "exec"}:
        return "code_execution", f"Python {call_name} call", "High"
    if call_name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads"}:
        return "insecure_deserialization", f"{call_name} call", "High"
    if call_name == "yaml.load" and not _has_safe_yaml_loader(node):
        return "insecure_deserialization", "yaml.load without SafeLoader", "High"
    if call_name.startswith("subprocess.") and _keyword_is_true(node, "shell"):
        return "command_injection", f"{call_name} with shell=True", "High"
    if call_name.endswith(".execute") and node.args and isinstance(node.args[0], (ast.BinOp, ast.JoinedStr)):
        return "sql_injection", "SQL execute with string interpolation", "High"
    return None


def _call_name(node: ast.AST) -> str:
    """Internal helper used to keep the module implementation focused."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _has_safe_yaml_loader(node: ast.Call) -> bool:
    """Internal helper used to keep the module implementation focused."""
    for keyword in node.keywords:
        if keyword.arg != "Loader":
            continue
        name = _call_name(keyword.value)
        if name.endswith("SafeLoader") or name.endswith("CSafeLoader"):
            return True
    return False


def _keyword_is_true(node: ast.Call, name: str) -> bool:
    """Internal helper used to keep the module implementation focused."""
    for keyword in node.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant):
            return keyword.value.value is True
    return False


def _source_issue(
    path: Path,
    line: int,
    issue_type: str,
    title: str,
    severity: str,
    code: str,
) -> Resource:
    """Internal helper used to keep the module implementation focused."""
    return Resource(
        provider="source",
        service="code",
        resource_type="source_code_issue",
        resource_id=f"{path}:{line}:{issue_type}",
        name=str(path),
        metadata={
            "file": str(path),
            "line": line,
            "issue_type": issue_type,
            "title": title,
            "severity": severity,
            "code": redact_text(code.strip()[:500]),
        },
    )


def _line_at(text: str, line: int) -> str:
    """Internal helper used to keep the module implementation focused."""
    lines = text.splitlines()
    if 1 <= line <= len(lines):
        return lines[line - 1]
    return ""


def _is_ignored(path: Path) -> bool:
    """Internal helper used to keep the module implementation focused."""
    ignored_parts = {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
    }
    return any(part in ignored_parts for part in path.parts)
