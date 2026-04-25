# SPDX-License-Identifier: MIT
from __future__ import annotations

import unittest

from velloraq.scanner.models import Evidence, Finding, Resource, ScanContext, ScanResult, Severity
from velloraq.core.config_files import parse_simple_yaml
from velloraq.integrations.redaction import redact_text, summarize_environment
from velloraq.reports.html_reporter import render_html
from velloraq.rules.aws import (
    AwsLambdaSecretEnvironmentRule,
    AwsLambdaWildcardPermissionRule,
    AwsS3PublicBucketRule,
)
from velloraq.rules.dependencies import DependencyVulnerabilityRule
from velloraq.rules.source import SourceCodeIssueRule


class RuleTests(unittest.TestCase):
    def test_lambda_wildcard_policy_is_high(self) -> None:
        resource = Resource(
            provider="aws",
            service="iam",
            resource_type="iam_policy",
            resource_id="policy-1",
            name="role/policy",
            metadata={
                "policy_name": "policy",
                "role_name": "role",
                "policy_document": {
                    "Statement": [
                        {"Effect": "Allow", "Action": "s3:*", "Resource": "*"}
                    ]
                },
            },
        )

        findings = list(AwsLambdaWildcardPermissionRule().evaluate(resource))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "High")

    def test_public_s3_bucket_is_critical(self) -> None:
        resource = Resource(
            provider="aws",
            service="s3",
            resource_type="storage_bucket",
            resource_id="arn:aws:s3:::demo",
            name="demo",
            metadata={"is_public": True, "public_signals": ["bucket_policy_public"]},
        )

        findings = list(AwsS3PublicBucketRule().evaluate(resource))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "Critical")

    def test_secret_environment_variable_is_high(self) -> None:
        resource = Resource(
            provider="aws",
            service="lambda",
            resource_type="serverless_function",
            resource_id="fn",
            name="fn",
            metadata={"environment": {"DB_PASSWORD": "super-secret-value"}},
        )

        findings = list(AwsLambdaSecretEnvironmentRule().evaluate(resource))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "High")

    def test_dependency_vulnerability_uses_nvd_severity(self) -> None:
        resource = Resource(
            provider="dependency",
            service="package",
            resource_type="dependency",
            resource_id="requirements.txt:demo==1.0.0",
            name="demo",
            metadata={
                "version": "1.0.0",
                "vulnerabilities": [{"cve_id": "CVE-2099-0001", "severity": "CRITICAL"}],
            },
        )

        findings = list(DependencyVulnerabilityRule().evaluate(resource))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "Critical")

    def test_source_code_issue_maps_to_finding(self) -> None:
        resource = Resource(
            provider="source",
            service="code",
            resource_type="source_code_issue",
            resource_id="handler.py:10:code_execution",
            name="handler.py",
            metadata={
                "file": "handler.py",
                "line": 10,
                "issue_type": "code_execution",
                "title": "Python eval call",
                "severity": "High",
                "code": "eval(event['expr'])",
            },
        )

        findings = list(SourceCodeIssueRule().evaluate(resource))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity.value, "High")

    def test_environment_summary_redacts_values(self) -> None:
        summary = summarize_environment(
            {"DB_PASSWORD": "super-secret-value", "NORMAL_SETTING": "not-sensitive"}
        )

        self.assertEqual(summary["environment_variable_count"], 2)
        self.assertIn("DB_PASSWORD", summary["secret_environment_variable_names"])
        self.assertNotIn("super-secret-value", str(summary))

    def test_simple_yaml_parser_supports_lists_and_nested_profiles(self) -> None:
        config = parse_simple_yaml(
            """
providers:
  - aws
  - source
provider_profiles:
  aws:
    profile: velloraq-readonly
enabled_rules: [AWS-*]
inventory: false
"""
        )

        self.assertEqual(config["providers"], ["aws", "source"])
        self.assertEqual(config["provider_profiles"]["aws"]["profile"], "velloraq-readonly")
        self.assertEqual(config["enabled_rules"], ["AWS-*"])
        self.assertFalse(config["inventory"])

    def test_text_redaction_masks_secret_assignments(self) -> None:
        redacted = redact_text("api_key = 'secret-token-value'")

        self.assertIn("[REDACTED]", redacted)
        self.assertNotIn("secret-token-value", redacted)

    def test_html_report_escapes_dynamic_finding_values(self) -> None:
        result = ScanResult(context=ScanContext(providers=["source"], regions=["<script>region</script>"]))
        result.findings.append(
            Finding(
                title="<script>alert(1)</script>",
                provider="source",
                service="code",
                resource_id="handler.py",
                resource_name="<img src=x onerror=alert(1)>",
                severity=Severity.HIGH,
                description="<script>description()</script>",
                recommendation="<b>fix it</b>",
                rule_id="SRC-<bad>",
                category="Source",
                evidence=[Evidence("path", "<script>evidence()</script>")],
            )
        )
        result.complete()

        report = render_html(result)

        self.assertNotIn("<script>alert(1)</script>", report)
        self.assertNotIn("<img src=x onerror=alert(1)>", report)
        self.assertNotIn("<b>fix it</b>", report)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", report)
        self.assertIn("SRC-&lt;bad&gt;", report)


if __name__ == "__main__":
    unittest.main()
