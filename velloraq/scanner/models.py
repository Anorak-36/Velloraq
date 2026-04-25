"""Domain models shared by scanner integrations, rules, and report writers."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class Severity(str, Enum):
    """Severity component used by Velloraq. """
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"
    INFO = "Info"


SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class Evidence:
    """Evidence component used by Velloraq. """
    key: str
    value: Any

    def to_dict(self) -> dict[str, Any]:
        """Execute the to_dict operation for this module."""
        return {"key": self.key, "value": jsonable(self.value)}


@dataclass
class Resource:
    """Resource component used by Velloraq. """
    provider: str
    service: str
    resource_type: str
    resource_id: str
    name: str
    region: str | None = None
    account_id: str | None = None
    project_id: str | None = None
    subscription_id: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Execute the to_dict operation for this module."""
        return {
            "provider": self.provider,
            "service": self.service,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "name": self.name,
            "region": self.region,
            "account_id": self.account_id,
            "project_id": self.project_id,
            "subscription_id": self.subscription_id,
            "tags": jsonable(self.tags),
            "metadata": jsonable(self.metadata),
        }


@dataclass
class Finding:
    """Finding component used by Velloraq. """
    title: str
    provider: str
    service: str
    resource_id: str
    resource_name: str
    severity: Severity
    description: str
    recommendation: str
    rule_id: str
    category: str
    standard_refs: list[str] = field(default_factory=list)
    region: str | None = None
    account_id: str | None = None
    project_id: str | None = None
    subscription_id: str | None = None
    evidence: list[Evidence] = field(default_factory=list)
    finding_id: str = field(default_factory=lambda: str(uuid4()))

    def to_dict(self) -> dict[str, Any]:
        """Execute the to_dict operation for this module."""
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "provider": self.provider,
            "service": self.service,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "severity": self.severity.value,
            "description": self.description,
            "recommendation": self.recommendation,
            "rule_id": self.rule_id,
            "category": self.category,
            "standard_refs": jsonable(self.standard_refs),
            "region": self.region,
            "account_id": self.account_id,
            "project_id": self.project_id,
            "subscription_id": self.subscription_id,
            "evidence": [item.to_dict() for item in self.evidence],
        }


@dataclass
class ScanWarning:
    """ScanWarning component used by Velloraq. """
    provider: str
    message: str
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Execute the to_dict operation for this module."""
        return {"provider": self.provider, "message": self.message, "detail": self.detail}


def jsonable(value: Any) -> Any:
    """Convert SDK objects into report-safe JSON values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [jsonable(item) for item in value]
    if hasattr(value, "as_dict"):
        try:
            return jsonable(value.as_dict())
        except Exception:
            pass
    return str(value)


@dataclass
class ScanContext:
    """ScanContext component used by Velloraq. """
    providers: list[str]
    regions: list[str] = field(default_factory=list)
    aws_profile: str | None = None
    azure_subscriptions: list[str] = field(default_factory=list)
    gcp_projects: list[str] = field(default_factory=list)
    plugin_dirs: list[str] = field(default_factory=list)
    dependency_manifests: list[str] = field(default_factory=list)
    source_paths: list[str] = field(default_factory=list)
    enabled_rules: list[str] = field(default_factory=list)
    disabled_rules: list[str] = field(default_factory=list)
    min_severity: Severity | None = None
    exclude_resources: list[str] = field(default_factory=list)
    enable_nvd: bool = False
    nvd_api_key: str | None = None
    include_resource_inventory: bool = False
    verbose: bool = False
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ScanResult:
    """ScanResult component used by Velloraq. """
    context: ScanContext
    findings: list[Finding] = field(default_factory=list)
    resources: list[Resource] = field(default_factory=list)
    warnings: list[ScanWarning] = field(default_factory=list)
    completed_at: datetime | None = None

    def complete(self) -> None:
        """Execute the complete operation for this module."""
        self.completed_at = datetime.now(timezone.utc)

    def summary(self) -> dict[str, Any]:
        """Execute the summary operation for this module."""
        counts: dict[str, int] = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return {
            "total_findings": len(self.findings),
            "by_severity": counts,
            "resources_scanned": len(self.resources),
            "warnings": len(self.warnings),
        }

    def to_dict(self) -> dict[str, Any]:
        """Execute the to_dict operation for this module."""
        started_at = self.context.started_at.isoformat()
        completed_at = self.completed_at.isoformat() if self.completed_at else None
        findings = sorted(
            self.findings,
            key=lambda item: (SEVERITY_ORDER[item.severity], item.provider, item.service),
            reverse=True,
        )
        payload: dict[str, Any] = {
            "scanner": "velloraq",
            "started_at": started_at,
            "completed_at": completed_at,
            "providers": self.context.providers,
            "regions": self.context.regions,
            "summary": self.summary(),
            "findings": [finding.to_dict() for finding in findings],
            "warnings": [warning.to_dict() for warning in self.warnings],
        }
        if self.context.include_resource_inventory:
            payload["resources"] = [resource.to_dict() for resource in self.resources]
        return payload
