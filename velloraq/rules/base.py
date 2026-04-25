# SPDX-License-Identifier: MIT
"""velloraq.rules.base module for the Velloraq security platform."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from velloraq.scanner.models import Finding, Resource


class Rule(ABC):
    """Base class for read-only security checks."""

    rule_id: str
    title: str
    category: str
    provider: str | None = None
    standard_refs: list[str] = []

    @abstractmethod
    def applies_to(self, resource: Resource) -> bool:
        """Return True when this rule should inspect the resource."""

    @abstractmethod
    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Yield findings for a resource."""

    def finding_base(self, resource: Resource) -> dict:
        """Execute the finding_base operation for this module."""
        return {
            "title": self.title,
            "provider": resource.provider,
            "service": resource.service,
            "resource_id": resource.resource_id,
            "resource_name": resource.name,
            "rule_id": self.rule_id,
            "category": self.category,
            "standard_refs": self.standard_refs,
            "region": resource.region,
            "account_id": resource.account_id,
            "project_id": resource.project_id,
            "subscription_id": resource.subscription_id,
        }
