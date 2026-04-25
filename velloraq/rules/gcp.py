# SPDX-License-Identifier: MIT
"""velloraq.rules.gcp module for the Velloraq security platform."""

from __future__ import annotations

from collections.abc import Iterable

from velloraq.scanner.models import Evidence, Finding, Resource, Severity
from velloraq.rules.base import Rule
from velloraq.rules.helpers import contains_secret_key, looks_like_secret


PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}


class GcpFunctionPublicInvokerRule(Rule):
    """GcpFunctionPublicInvokerRule component used by Velloraq. """
    rule_id = "GCP-FUNC-001"
    title = "Cloud Function allows unauthenticated invocation"
    category = "Functions"
    provider = "gcp"
    standard_refs = ["OWASP Serverless Top 10: SAS-7", "CIS Google Cloud Platform"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "gcp" and resource.resource_type == "serverless_function"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        public_members = set(resource.metadata.get("public_invokers") or [])
        if not public_members.intersection(PUBLIC_MEMBERS):
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.HIGH,
            description=(
                "The Cloud Function IAM policy grants invocation to all users or all authenticated users."
            ),
            recommendation=(
                "Remove public invoker bindings, require IAM or identity-aware authorization, and "
                "protect public endpoints with API Gateway/Cloud Armor controls."
            ),
            evidence=[Evidence("public_invokers", sorted(public_members))],
        )


class GcpFunctionSecretEnvironmentRule(Rule):
    """GcpFunctionSecretEnvironmentRule component used by Velloraq. """
    rule_id = "GCP-FUNC-002"
    title = "Cloud Function environment variable may expose a secret"
    category = "Secrets"
    provider = "gcp"
    standard_refs = ["OWASP Serverless Top 10: SAS-2", "CIS Google Cloud Platform"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "gcp" and resource.resource_type == "serverless_function"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        risky_keys = resource.metadata.get("secret_environment_variable_names")
        if risky_keys is None:
            env = resource.metadata.get("environment") or {}
            risky_keys = [
                key for key, value in env.items() if contains_secret_key(key) or looks_like_secret(value)
            ]
        if not risky_keys:
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.HIGH,
            description="Cloud Function environment variables contain names or values that look like secrets.",
            recommendation=(
                "Move secrets to Secret Manager, bind access to the runtime service account, "
                "and rotate exposed values."
            ),
            evidence=[Evidence("variable_names", sorted(risky_keys))],
        )


class GcsPublicBucketRule(Rule):
    """GcsPublicBucketRule component used by Velloraq. """
    rule_id = "GCP-GCS-001"
    title = "Cloud Storage bucket is publicly accessible"
    category = "Storage"
    provider = "gcp"
    standard_refs = ["CIS Google Cloud Platform", "OWASP Cloud-Native Application Security"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "gcp" and resource.resource_type == "storage_bucket"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        public_members = set(resource.metadata.get("public_members") or [])
        if not public_members.intersection(PUBLIC_MEMBERS):
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.CRITICAL,
            description="The Cloud Storage bucket IAM policy grants public access.",
            recommendation=(
                "Remove allUsers/allAuthenticatedUsers bindings, enable uniform bucket-level access, "
                "and use signed URLs for temporary sharing."
            ),
            evidence=[Evidence("public_members", sorted(public_members))],
        )


class GcpBroadIamRoleRule(Rule):
    """GcpBroadIamRoleRule component used by Velloraq. """
    rule_id = "GCP-IAM-001"
    title = "Broad GCP IAM role detected"
    category = "IAM"
    provider = "gcp"
    standard_refs = ["CIS Google Cloud Platform", "Google Cloud Security Foundations"]

    BROAD_ROLES = {"roles/owner", "roles/editor"}

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "gcp" and resource.resource_type == "iam_binding"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        role = resource.metadata.get("role")
        if role not in self.BROAD_ROLES:
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.HIGH,
            description="A broad GCP primitive role is assigned in the scanned scope.",
            recommendation=(
                "Replace primitive roles with predefined or custom least-privilege roles, and "
                "scope bindings to the smallest required resource."
            ),
            evidence=[
                Evidence("role", role),
                Evidence("members", resource.metadata.get("members", [])),
            ],
        )
