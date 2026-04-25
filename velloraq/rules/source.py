# SPDX-License-Identifier: MIT
"""velloraq.rules.source module for the Velloraq security platform."""

from __future__ import annotations

from collections.abc import Iterable

from velloraq.scanner.models import Evidence, Finding, Resource, Severity
from velloraq.rules.base import Rule


class SourceCodeIssueRule(Rule):
    """SourceCodeIssueRule component used by Velloraq. """
    rule_id = "SRC-CODE-001"
    title = "Potential vulnerable code pattern detected"
    category = "Source Code"
    provider = "source"
    standard_refs = ["OWASP Top 10", "OWASP Serverless Top 10: SAS-6"]

    DESCRIPTIONS = {
        "code_execution": "The function source contains dynamic code execution.",
        "command_injection": "The function source contains a command execution pattern that may be injectable.",
        "insecure_deserialization": "The function source contains an unsafe deserialization pattern.",
        "sql_injection": "The function source builds SQL dynamically before execution.",
    }

    RECOMMENDATIONS = {
        "code_execution": "Remove eval/exec patterns and replace them with explicit parsers or allowlisted dispatch.",
        "command_injection": "Avoid shell=True and pass fixed command arguments as arrays with strict input validation.",
        "insecure_deserialization": "Use safe loaders and signed/trusted formats. Never deserialize untrusted input.",
        "sql_injection": "Use parameterized queries and avoid string interpolation for SQL statements.",
    }

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "source" and resource.resource_type == "source_code_issue"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        issue_type = resource.metadata.get("issue_type", "code")
        base = self.finding_base(resource)
        base["title"] = resource.metadata.get("title") or self.title
        yield Finding(
            **base,
            severity=_severity(resource.metadata.get("severity")),
            description=self.DESCRIPTIONS.get(issue_type, self.title),
            recommendation=self.RECOMMENDATIONS.get(
                issue_type,
                "Review the pattern manually and replace it with a safer implementation.",
            ),
            evidence=[
                Evidence("file", resource.metadata.get("file")),
                Evidence("line", resource.metadata.get("line")),
                Evidence("code", resource.metadata.get("code")),
                Evidence("issue_type", issue_type),
            ],
        )


def _severity(value: str | None) -> Severity:
    """Internal helper used to keep the module implementation focused."""
    try:
        return Severity(value or "Medium")
    except ValueError:
        return Severity.MEDIUM
