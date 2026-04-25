# SPDX-License-Identifier: MIT
from __future__ import annotations

from collections.abc import Iterable

from velloraq.scanner.models import Evidence, Finding, Resource, Severity
from velloraq.rules.base import Rule


class AwsLambdaMissingKmsKeyRule(Rule):
    rule_id = "PLUGIN-AWS-LAMBDA-001"
    title = "Lambda function does not use a customer managed KMS key"
    category = "Encryption"
    provider = "aws"
    standard_refs = ["CIS AWS Foundations"]

    def applies_to(self, resource: Resource) -> bool:
        return resource.provider == "aws" and resource.resource_type == "serverless_function"

    def evaluate(self, resource: Resource) -> Iterable[Finding]:
        if resource.metadata.get("kms_key_arn"):
            return
        yield Finding(
            **self.finding_base(resource),
            severity=Severity.LOW,
            description="The Lambda function uses the default AWS-managed key for environment encryption.",
            recommendation="Use a customer managed KMS key when compliance requires customer control over key policy and rotation.",
            evidence=[Evidence("kms_key_arn", resource.metadata.get("kms_key_arn"))],
        )


def register_rules() -> list[Rule]:
    return [AwsLambdaMissingKmsKeyRule()]
