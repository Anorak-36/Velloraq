# SPDX-License-Identifier: MIT
"""velloraq.scanner.rule_engine module for the Velloraq security platform."""

from __future__ import annotations

from velloraq.scanner.models import Finding, Resource
from velloraq.rules.base import Rule


class RuleEngine:
    """RuleEngine component used by Velloraq. """
    def __init__(self, rules: list[Rule]) -> None:
        """Internal helper used to keep the module implementation focused."""
        self.rules = rules

    def evaluate(self, resources: list[Resource]) -> list[Finding]:
        """Execute the evaluate operation for this module."""
        findings: list[Finding] = []
        for resource in resources:
            for rule in self.rules:
                if rule.provider is not None and rule.provider != resource.provider:
                    continue
                if not rule.applies_to(resource):
                    continue
                findings.extend(rule.evaluate(resource))
        return findings
