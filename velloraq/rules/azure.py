# SPDX-License-Identifier: MIT
"""velloraq.rules.azure module for the Velloraq security platform."""

from __future__ import annotations

from collections.abc import Iterable

from velloraq.scanner.models import Evidence, Finding, Resource, Severity
from velloraq.rules.base import Rule
from velloraq.rules.helpers import contains_secret_key, looks_like_secret


class AzureFunctionAnonymousHttpRule(Rule):
    """AzureFunctionAnonymousHttpRule component used by Velloraq. """
    rule_id = "AZ-FUNC-001"
    title = "Azure Function HTTP trigger allows anonymous access"
    category = "Functions"
    provider = "azure"
    standard_refs = ["OWASP Serverless Top 10: SAS-7", "CIS Microsoft Azure Foundations"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "azure" and resource.resource_type == "api_route"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        auth_level = str(resource.metadata.get("auth_level", "")).lower()
        if auth_level not in {"anonymous", "anon", "none", ""}:
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.HIGH,
            description="The Azure Function HTTP trigger can be invoked without authentication.",
            recommendation=(
                "Use Function, Admin, EasyAuth, API Management, or Azure AD authorization depending "
                "on exposure requirements. Add rate limits for public endpoints."
            ),
            evidence=[
                Evidence("function_name", resource.metadata.get("function_name")),
                Evidence("route", resource.metadata.get("route")),
                Evidence("auth_level", auth_level or "missing"),
            ],
        )


class AzureFunctionSecretEnvironmentRule(Rule):
    """AzureFunctionSecretEnvironmentRule component used by Velloraq. """
    rule_id = "AZ-FUNC-002"
    title = "Azure Function app setting may expose a secret"
    category = "Secrets"
    provider = "azure"
    standard_refs = ["OWASP Serverless Top 10: SAS-2", "CIS Microsoft Azure Foundations"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "azure" and resource.resource_type == "serverless_function"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        risky_keys = resource.metadata.get("secret_app_setting_names")
        if risky_keys is None:
            settings = resource.metadata.get("app_settings") or {}
            risky_keys = [
                key
                for key, value in settings.items()
                if contains_secret_key(key) or looks_like_secret(value)
            ]
        if not risky_keys:
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.HIGH,
            description="Function app settings contain names or values that look like secrets.",
            recommendation=(
                "Move secrets to Azure Key Vault, use managed identities, and rotate exposed values."
            ),
            evidence=[Evidence("setting_names", sorted(risky_keys))],
        )


class AzureStoragePublicContainerRule(Rule):
    """AzureStoragePublicContainerRule component used by Velloraq. """
    rule_id = "AZ-STOR-001"
    title = "Azure Storage container permits public blob access"
    category = "Storage"
    provider = "azure"
    standard_refs = ["CIS Microsoft Azure Foundations", "OWASP Cloud-Native Application Security"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "azure" and resource.resource_type == "storage_container"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        public_access = str(resource.metadata.get("public_access", "")).lower()
        if public_access not in {"blob", "container"}:
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.CRITICAL,
            description="The storage container permits unauthenticated public access.",
            recommendation=(
                "Disable anonymous blob access unless explicitly required, use private endpoints or "
                "signed URLs, and audit object-level exposure."
            ),
            evidence=[Evidence("public_access", public_access)],
        )


class AzureOverPrivilegedRoleRule(Rule):
    """AzureOverPrivilegedRoleRule component used by Velloraq. """
    rule_id = "AZ-IAM-001"
    title = "Broad Azure role assignment detected"
    category = "IAM"
    provider = "azure"
    standard_refs = ["CIS Microsoft Azure Foundations", "Microsoft Cloud Security Benchmark"]

    BROAD_ROLES = {"Owner", "Contributor", "User Access Administrator"}

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "azure" and resource.resource_type == "iam_binding"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        role_name = resource.metadata.get("role_name")
        if role_name not in self.BROAD_ROLES:
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.HIGH if role_name == "Owner" else Severity.MEDIUM,
            description=(
                "A broad Azure role assignment can grant permissions beyond the needs of a "
                "serverless workload."
            ),
            recommendation=(
                "Replace broad roles with least-privilege custom roles scoped to the smallest "
                "resource group or resource."
            ),
            evidence=[
                Evidence("role_name", role_name),
                Evidence("principal_id", resource.metadata.get("principal_id")),
                Evidence("scope", resource.metadata.get("scope")),
            ],
        )
