# SPDX-License-Identifier: MIT
"""velloraq.rules.registry module for the Velloraq security platform."""

from __future__ import annotations

from velloraq.rules.aws import (
    AwsApiGatewayMissingThrottleRule,
    AwsApiGatewayUnauthenticatedRule,
    AwsLambdaSecretEnvironmentRule,
    AwsLambdaWildcardPermissionRule,
    AwsS3PublicBucketRule,
    AwsUnsafeEventTriggerRule,
)
from velloraq.rules.azure import (
    AzureFunctionAnonymousHttpRule,
    AzureFunctionSecretEnvironmentRule,
    AzureOverPrivilegedRoleRule,
    AzureStoragePublicContainerRule,
)
from velloraq.rules.base import Rule
from velloraq.rules.dependencies import DependencyVulnerabilityRule
from velloraq.rules.gcp import (
    GcpBroadIamRoleRule,
    GcpFunctionPublicInvokerRule,
    GcpFunctionSecretEnvironmentRule,
    GcsPublicBucketRule,
)
from velloraq.rules.source import SourceCodeIssueRule


def built_in_rules() -> list[Rule]:
    """Execute the built_in_rules operation for this module."""
    return [
        AwsLambdaWildcardPermissionRule(),
        AwsS3PublicBucketRule(),
        AwsApiGatewayUnauthenticatedRule(),
        AwsApiGatewayMissingThrottleRule(),
        AwsLambdaSecretEnvironmentRule(),
        AwsUnsafeEventTriggerRule(),
        AzureFunctionAnonymousHttpRule(),
        AzureFunctionSecretEnvironmentRule(),
        AzureStoragePublicContainerRule(),
        AzureOverPrivilegedRoleRule(),
        GcpFunctionPublicInvokerRule(),
        GcpFunctionSecretEnvironmentRule(),
        GcsPublicBucketRule(),
        GcpBroadIamRoleRule(),
        DependencyVulnerabilityRule(),
        SourceCodeIssueRule(),
    ]
