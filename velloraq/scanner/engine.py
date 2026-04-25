"""Provider-agnostic scan orchestration.

The engine coordinates read-only integrations and rule evaluation. It does not
perform persistence or HTTP work, which keeps the same scanning core reusable by
the CLI, SaaS worker, and tests.
"""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import fnmatch

from velloraq.integrations.aws import AwsIntegration
from velloraq.integrations.azure import AzureIntegration
from velloraq.integrations.base import ProviderIntegration
from velloraq.integrations.gcp import GcpIntegration
from velloraq.integrations.nvd import NvdDependencyScanner
from velloraq.integrations.source import SourceCodeScanner
from velloraq.scanner.models import SEVERITY_ORDER, ScanContext, ScanResult
from velloraq.plugins.loader import load_plugin_rules
from velloraq.rules.registry import built_in_rules
from velloraq.scanner.rule_engine import RuleEngine


class ScannerEngine:
    """Run integrations, apply rules, and return a normalized scan result."""

    def __init__(self, context: ScanContext) -> None:
        """Create an engine for a single immutable scan context."""

        self.context = context
        self.integrations = self._build_integrations(context.providers)
        self.rules = self._filter_rules(built_in_rules() + load_plugin_rules(context.plugin_dirs))

    def run(self) -> ScanResult:
        """Collect resources, evaluate rules, apply filters, and complete the scan."""

        result = ScanResult(context=self.context)
        for integration in self.integrations:
            provider_result = integration.collect(self.context)
            result.resources.extend(provider_result.resources)
            result.warnings.extend(provider_result.warnings)

        if self.context.dependency_manifests:
            dep_result = NvdDependencyScanner().collect(self.context)
            result.resources.extend(dep_result.resources)
            result.warnings.extend(dep_result.warnings)

        if self.context.source_paths:
            source_result = SourceCodeScanner().collect(self.context)
            result.resources.extend(source_result.resources)
            result.warnings.extend(source_result.warnings)

        resources = self._filter_resources(result.resources)
        result.resources = resources
        findings = RuleEngine(self.rules).evaluate(resources)
        if self.context.min_severity:
            threshold = self.context.min_severity
            findings = [
                finding
                for finding in findings
                if SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[threshold]
            ]
        result.findings = findings
        result.complete()
        return result

    @staticmethod
    def _build_integrations(providers: list[str]) -> list[ProviderIntegration]:
        """Instantiate provider integrations requested by the scan context."""

        integrations: list[ProviderIntegration] = []
        provider_set = set(providers)
        if "all" in provider_set or "aws" in provider_set:
            integrations.append(AwsIntegration())
        if "all" in provider_set or "azure" in provider_set:
            integrations.append(AzureIntegration())
        if "all" in provider_set or "gcp" in provider_set:
            integrations.append(GcpIntegration())
        return integrations

    def _filter_rules(self, rules: list) -> list:
        """Apply include/exclude rule patterns configured by the user."""

        enabled = self.context.enabled_rules
        disabled = self.context.disabled_rules
        filtered = []
        for rule in rules:
            if enabled and not _matches_any(rule.rule_id, enabled):
                continue
            if disabled and _matches_any(rule.rule_id, disabled):
                continue
            filtered.append(rule)
        return filtered

    def _filter_resources(self, resources: list) -> list:
        """Exclude resources matching user-provided safe-list patterns."""

        patterns = self.context.exclude_resources
        if not patterns:
            return resources
        filtered = []
        for resource in resources:
            candidates = [
                resource.resource_id,
                resource.name,
                resource.provider,
                resource.service,
                resource.resource_type,
            ]
            if any(_matches_any(str(candidate), patterns) for candidate in candidates if candidate):
                continue
            filtered.append(resource)
        return filtered


def _matches_any(value: str, patterns: list[str]) -> bool:
    """Return whether a value matches any glob pattern exactly."""

    return any(fnmatch.fnmatchcase(value, pattern) for pattern in patterns)
