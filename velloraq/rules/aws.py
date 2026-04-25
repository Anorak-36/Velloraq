# SPDX-License-Identifier: MIT
"""velloraq.rules.aws module for the Velloraq security platform."""

from __future__ import annotations

from collections.abc import Iterable

from velloraq.scanner.models import Evidence, Finding, Resource, Severity
from velloraq.rules.base import Rule
from velloraq.rules.helpers import (
    contains_secret_key,
    iter_statements,
    looks_like_secret,
    value_has_wildcard,
)


class AwsLambdaWildcardPermissionRule(Rule):
    """AwsLambdaWildcardPermissionRule component used by Velloraq. """
    rule_id = "AWS-IAM-001"
    title = "Lambda execution role has wildcard permissions"
    category = "IAM"
    provider = "aws"
    standard_refs = ["CIS AWS Foundations", "OWASP Serverless Top 10: SAS-1"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "aws" and resource.resource_type == "iam_policy"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        policy = resource.metadata.get("policy_document") or {}
        risky_statements: list[dict] = []
        for statement in iter_statements(policy):
            if statement.get("Effect") != "Allow":
                continue
            if value_has_wildcard(statement.get("Action")) or value_has_wildcard(statement.get("Resource")):
                risky_statements.append(
                    {
                        "Sid": statement.get("Sid"),
                        "Action": statement.get("Action"),
                        "Resource": statement.get("Resource"),
                    }
                )
        if not risky_statements:
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.HIGH,
            description=(
                "The Lambda execution role policy allows wildcard actions or resources. "
                "This violates least privilege and can expand impact after code compromise."
            ),
            recommendation=(
                "Replace wildcard actions/resources with explicit API actions and resource ARNs. "
                "Split broad policies by function responsibility and validate with IAM Access Analyzer."
            ),
            evidence=[
                Evidence("policy_name", resource.metadata.get("policy_name")),
                Evidence("role_name", resource.metadata.get("role_name")),
                Evidence("statements", risky_statements),
            ],
        )


class AwsS3PublicBucketRule(Rule):
    """AwsS3PublicBucketRule component used by Velloraq. """
    rule_id = "AWS-S3-001"
    title = "S3 bucket is publicly accessible"
    category = "Storage"
    provider = "aws"
    standard_refs = ["CIS AWS Foundations", "OWASP Cloud-Native Application Security"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "aws" and resource.resource_type == "storage_bucket"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        if not resource.metadata.get("is_public"):
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.CRITICAL,
            description=(
                "The S3 bucket appears public through bucket policy, ACL grants, or missing "
                "public access block controls."
            ),
            recommendation=(
                "Enable S3 Block Public Access, remove public ACL grants, and restrict bucket "
                "policies to trusted principals."
            ),
            evidence=[
                Evidence("public_signals", resource.metadata.get("public_signals", [])),
                Evidence("public_access_block", resource.metadata.get("public_access_block")),
            ],
        )


class AwsApiGatewayUnauthenticatedRule(Rule):
    """AwsApiGatewayUnauthenticatedRule component used by Velloraq. """
    rule_id = "AWS-APIGW-001"
    title = "API Gateway route has no authorization"
    category = "API Gateway"
    provider = "aws"
    standard_refs = ["OWASP API Security Top 10", "OWASP Serverless Top 10: SAS-7"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "aws" and resource.resource_type == "api_route"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        auth_type = str(resource.metadata.get("authorization_type", "")).upper()
        if auth_type not in {"NONE", "OPEN", ""}:
            return
        severity = Severity.HIGH if resource.metadata.get("public_endpoint", True) else Severity.MEDIUM
        yield Finding(
            **self.finding_base(resource),
            severity=severity,
            description=(
                "The API route is reachable without an authorizer, IAM auth, JWT authorizer, "
                "or API key enforcement."
            ),
            recommendation=(
                "Require an authorizer appropriate to the API, enforce least-privilege IAM/JWT "
                "claims, and pair public APIs with throttling and abuse monitoring."
            ),
            evidence=[
                Evidence("method", resource.metadata.get("method")),
                Evidence("path", resource.metadata.get("path")),
                Evidence("authorization_type", auth_type or "missing"),
            ],
        )


class AwsApiGatewayMissingThrottleRule(Rule):
    """AwsApiGatewayMissingThrottleRule component used by Velloraq. """
    rule_id = "AWS-APIGW-002"
    title = "API Gateway route lacks explicit rate limiting"
    category = "API Gateway"
    provider = "aws"
    standard_refs = ["OWASP API Security Top 10: API4", "CIS AWS Foundations"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "aws" and resource.resource_type == "api_route"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        if resource.metadata.get("throttling_configured") is True:
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.MEDIUM,
            description=(
                "No explicit throttling or rate-limiting configuration was found for the API route."
            ),
            recommendation=(
                "Configure stage/method throttling, usage plans where applicable, and upstream "
                "WAF rules for public APIs."
            ),
            evidence=[
                Evidence("method", resource.metadata.get("method")),
                Evidence("path", resource.metadata.get("path")),
                Evidence("stage", resource.metadata.get("stage")),
            ],
        )


class AwsLambdaSecretEnvironmentRule(Rule):
    """AwsLambdaSecretEnvironmentRule component used by Velloraq. """
    rule_id = "AWS-LAMBDA-001"
    title = "Lambda environment variable may expose a secret"
    category = "Secrets"
    provider = "aws"
    standard_refs = ["OWASP Serverless Top 10: SAS-2", "CIS AWS Foundations"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "aws" and resource.resource_type == "serverless_function"

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
            description=(
                "Function environment variables contain names or values that look like secrets. "
                "Environment variables are often copied into logs, snapshots, and support bundles."
            ),
            recommendation=(
                "Move secrets to AWS Secrets Manager or SSM Parameter Store, scope access by role, "
                "and rotate any exposed values."
            ),
            evidence=[Evidence("variable_names", sorted(risky_keys))],
        )


class AwsUnsafeEventTriggerRule(Rule):
    """AwsUnsafeEventTriggerRule component used by Velloraq. """
    rule_id = "AWS-EVENT-001"
    title = "Serverless trigger has a broad or public source"
    category = "Events and Triggers"
    provider = "aws"
    standard_refs = ["OWASP Serverless Top 10: SAS-4"]

    def applies_to(self, resource: Resource) -> bool:
        """Execute the applies_to operation for this module."""
        return resource.provider == "aws" and resource.resource_type == "event_trigger"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        """Execute the evaluate operation for this module."""
        if not resource.metadata.get("broad_source"):
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.MEDIUM,
            description=(
                "The event source accepts events from a broad or weakly constrained source, which "
                "can increase exposure to event injection and unexpected execution paths."
            ),
            recommendation=(
                "Constrain trigger principals, source ARNs, bucket notifications, and event patterns. "
                "Validate event payload schemas before processing."
            ),
            evidence=[Evidence("trigger", resource.metadata)],
        )
