# SPDX-License-Identifier: MIT
"""velloraq.rules.dependencies module for the Velloraq security platform."""

from __future__ import annotations

from collections.abc import Iterable

from velloraq.scanner.models import Evidence, Finding, Resource, Severity
from velloraq.rules.base import Rule


class DependencyVulnerabilityRule(Rule):
    """DependencyVulnerabilityRule component used by Velloraq. """
    rule_id = "DEP-NVD-001"
    title = "Vulnerable dependency detected"
    category = "Dependencies"
    provider = None
    standard_refs = ["OWASP Top 10: A06", "OWASP Serverless Top 10: SAS-6"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.resource_type == "dependency"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        vulnerabilities = resource.metadata.get("vulnerabilities") or []
        for item in vulnerabilities:
            severity = _severity_from_nvd(item.get("severity"))
            yield Finding(
                **self.finding_base(resource),
                severity=severity,
                description=(
                    f"Dependency {resource.name} {resource.metadata.get('version', '')} "
                    f"matches NVD entry {item.get('cve_id')}."
                ),
                recommendation=(
                    "Upgrade to a fixed version, replace the package, or document a temporary "
                    "risk acceptance with compensating controls."
                ),
                evidence=[
                    Evidence("package", resource.name),
                    Evidence("version", resource.metadata.get("version")),
                    Evidence("cve_id", item.get("cve_id")),
                    Evidence("cvss_score", item.get("cvss_score")),
                    Evidence("published", item.get("published")),
                    Evidence("url", item.get("url")),
                ],
            )


def _severity_from_nvd(value: str | None) -> Severity:
    """Internal helper used to keep the module implementation focused."""
    normalized = (value or "").upper()
    if normalized == "CRITICAL":
        return Severity.CRITICAL
    if normalized == "HIGH":
        return Severity.HIGH
    if normalized == "MEDIUM":
        return Severity.MEDIUM
    return Severity.LOW
