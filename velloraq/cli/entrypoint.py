"""Console interface for Velloraq.

This module owns user-facing CLI commands and delegates scan execution to the
scanner package. Keeping argument parsing here avoids coupling cloud collection
logic to terminal concerns such as output paths and exit codes.
"""

# SPDX-License-Identifier: MIT
from __future__ import annotations

import argparse
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from velloraq.core.config_files import (
    config_bool,
    config_list,
    deep_get,
    env_bool,
    env_list,
    env_value,
    load_config,
)
from velloraq.reports.local_dashboard import serve_report
from velloraq.scanner.models import SEVERITY_ORDER, ScanContext, Severity
from velloraq.reports.html_reporter import write_html_report
from velloraq.reports.json_reporter import write_json_report
from velloraq.reports.siem import write_siem_jsonl
from velloraq.scanner.engine import ScannerEngine


def main(argv: list[str] | None = None) -> int:
    """Run the Velloraq CLI and return a process exit code."""

    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    if args.command == "dashboard":
        serve_report(args.report, args.host, args.port)
        return 0
    parser.print_help()
    return 1


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level command parser shared by tests and console scripts."""

    parser = argparse.ArgumentParser(
        prog="velloraq",
        description="Read-only scanner for serverless security posture across AWS, Azure and GCP.",
    )
    subcommands = parser.add_subparsers(dest="command")

    scan = subcommands.add_parser("scan", help="Run a read-only serverless security scan")
    scan.add_argument(
        "--config",
        help="Path to config.yaml. Defaults to VELLORAQ_CONFIG or ./config.yaml.",
    )
    scan.add_argument(
        "--provider",
        action="append",
        choices=["all", "aws", "azure", "gcp", "source"],
        default=None,
        help="Provider to scan. Repeatable. Use source for local code/dependency scans. Defaults to all.",
    )
    scan.add_argument(
        "--region",
        action="append",
        default=[],
        help="Cloud region to scan. Repeatable or comma-separated.",
    )
    scan.add_argument("--aws-profile", help="AWS shared config profile name")
    scan.add_argument(
        "--azure-subscription",
        action="append",
        default=[],
        help="Azure subscription ID. Repeatable.",
    )
    scan.add_argument("--gcp-project", action="append", default=[], help="GCP project ID. Repeatable.")
    scan.add_argument(
        "--dependency-manifest",
        action="append",
        default=[],
        help="Pinned Python requirements file to check against NVD.",
    )
    scan.add_argument(
        "--source-path",
        action="append",
        default=[],
        help="Local function source file or directory to scan for vulnerable code patterns.",
    )
    scan.add_argument(
        "--nvd",
        action="store_true",
        default=None,
        help="Query the NVD 2.0 API for dependency CVEs. Network access required.",
    )
    scan.add_argument("--nvd-api-key", help="NVD API key. Also read from NVD_API_KEY.")
    scan.add_argument(
        "--plugin-dir",
        action="append",
        default=[],
        help="Directory or .py file with plugin rules exposing register_rules().",
    )
    scan.add_argument(
        "--format",
        action="append",
        choices=["json", "html", "siem", "all"],
        default=None,
        help="Report format. Repeatable. Defaults to json and html.",
    )
    scan.add_argument("--output", default=None, help="Output directory for reports.")
    scan.add_argument(
        "--inventory",
        action="store_true",
        default=None,
        help="Include normalized resource inventory in JSON output.",
    )
    scan.add_argument(
        "--enable-rule",
        action="append",
        default=[],
        help="Only run matching rule IDs. Supports glob patterns such as AWS-*.",
    )
    scan.add_argument(
        "--disable-rule",
        action="append",
        default=[],
        help="Disable matching rule IDs. Supports glob patterns such as DEP-*.",
    )
    scan.add_argument(
        "--min-severity",
        choices=["Low", "Medium", "High", "Critical"],
        help="Only include findings at or above this severity.",
    )
    scan.add_argument(
        "--exclude-resource",
        action="append",
        default=[],
        help="Exclude matching resource IDs/names/providers/services. Supports glob patterns.",
    )
    scan.add_argument("--verbose", action="store_true", default=None, help="Print resolved scan settings.")
    scan.add_argument(
        "--fail-on",
        choices=["Low", "Medium", "High", "Critical"],
        help="Exit with code 2 if findings at or above this severity exist. Useful for CI.",
    )

    dashboard = subcommands.add_parser("dashboard", help="Serve an existing report locally")
    dashboard.add_argument("--report", required=True, help="HTML or JSON report path")
    dashboard.add_argument("--host", default="127.0.0.1")
    dashboard.add_argument("--port", type=int, default=8765)
    return parser


def run_scan(args: argparse.Namespace) -> int:
    """Execute a read-only scan from CLI arguments and write selected reports."""

    config = load_config(args.config)
    providers = args.provider or env_list("VELLORAQ_PROVIDERS") or config_list(config, "providers", ["all"])
    formats = _formats(
        args.format
        or env_list("VELLORAQ_FORMATS")
        or config_list(config, "formats", ["json", "html"])
    )
    output_dir = Path(args.output or env_value("VELLORAQ_OUTPUT") or config.get("output", "reports"))
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    nvd_enabled = _first_bool(args.nvd, env_bool("VELLORAQ_NVD"), config_bool(config, "nvd", False))
    inventory = _first_bool(
        args.inventory,
        env_bool("VELLORAQ_INVENTORY"),
        config_bool(config, "inventory", False),
    )
    verbose = _first_bool(
        args.verbose, env_bool("VELLORAQ_VERBOSE"), config_bool(config, "verbose", False)
    )
    min_severity_value = (
        args.min_severity
        or env_value("VELLORAQ_MIN_SEVERITY")
        or config.get("min_severity")
        or config.get("severity_threshold")
    )
    fail_on = args.fail_on or env_value("VELLORAQ_FAIL_ON") or config.get("fail_on")

    context = ScanContext(
        providers=providers,
        regions=_configured_list(args.region, "VELLORAQ_REGIONS", config, "regions"),
        aws_profile=(
            args.aws_profile
            or env_value("VELLORAQ_AWS_PROFILE")
            or deep_get(config, "provider_profiles.aws.profile")
            or deep_get(config, "aws.profile")
            or config.get("aws_profile")
        ),
        azure_subscriptions=_configured_list(
            args.azure_subscription,
            "VELLORAQ_AZURE_SUBSCRIPTIONS",
            config,
            "azure_subscriptions",
            "provider_profiles.azure.subscriptions",
            "azure.subscriptions",
        ),
        gcp_projects=_configured_list(
            args.gcp_project,
            "VELLORAQ_GCP_PROJECTS",
            config,
            "gcp_projects",
            "provider_profiles.gcp.projects",
            "gcp.projects",
        ),
        plugin_dirs=_configured_list(args.plugin_dir, "VELLORAQ_PLUGIN_DIRS", config, "plugin_dirs"),
        dependency_manifests=_configured_list(
            args.dependency_manifest,
            "VELLORAQ_DEPENDENCY_MANIFESTS",
            config,
            "dependency_manifests",
        ),
        source_paths=_configured_list(args.source_path, "VELLORAQ_SOURCE_PATHS", config, "source_paths"),
        enabled_rules=_configured_list(args.enable_rule, "VELLORAQ_ENABLE_RULES", config, "enabled_rules"),
        disabled_rules=_configured_list(args.disable_rule, "VELLORAQ_DISABLE_RULES", config, "disabled_rules"),
        min_severity=Severity(min_severity_value) if min_severity_value else None,
        exclude_resources=_configured_list(
            args.exclude_resource,
            "VELLORAQ_EXCLUDE_RESOURCES",
            config,
            "exclude_resources",
        ),
        enable_nvd=nvd_enabled,
        nvd_api_key=args.nvd_api_key or env_value("VELLORAQ_NVD_API_KEY") or os.getenv("NVD_API_KEY"),
        include_resource_inventory=inventory,
        verbose=verbose,
    )
    if context.verbose:
        print("Resolved scan settings:")
        print(f"  providers={context.providers}")
        print(f"  regions={context.regions}")
        print(f"  enabled_rules={context.enabled_rules or ['all']}")
        print(f"  disabled_rules={context.disabled_rules}")
        print(f"  min_severity={context.min_severity.value if context.min_severity else 'all'}")
        print(f"  exclude_resources={context.exclude_resources}")
    result = ScannerEngine(context).run()
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    if "json" in formats:
        path = write_json_report(result, output_dir / f"velloraq-scan-{timestamp}.json")
        shutil.copyfile(path, output_dir / "latest.json")
        written.append(path)
    if "html" in formats:
        path = write_html_report(result, output_dir / f"velloraq-scan-{timestamp}.html")
        shutil.copyfile(path, output_dir / "latest.html")
        written.append(path)
    if "siem" in formats:
        path = write_siem_jsonl(result, output_dir / f"velloraq-scan-{timestamp}.jsonl")
        shutil.copyfile(path, output_dir / "latest.jsonl")
        written.append(path)

    summary = result.summary()
    print(f"Scan completed: {summary['total_findings']} findings across {summary['resources_scanned']} resources")
    print("Severity:", ", ".join(f"{k}={v}" for k, v in summary["by_severity"].items()))
    if result.warnings:
        print(f"Warnings: {len(result.warnings)}")
        for warning in result.warnings[:5]:
            detail = f" ({warning.detail})" if warning.detail else ""
            print(f"  - {warning.provider}: {warning.message}{detail}")
    print("Reports:")
    for path in written:
        print(f"  - {path}")

    if fail_on and _has_findings_at_or_above(result.findings, Severity(fail_on)):
        return 2
    return 0


def _formats(values: list[str] | None) -> set[str]:
    """Normalize requested report formats."""

    selected = set(values or ["json", "html"])
    if "all" in selected:
        return {"json", "html", "siem"}
    return selected


def _split_values(values: list[str]) -> list[str]:
    """Split repeated or comma-separated CLI values into a flat list."""

    output: list[str] = []
    for value in values:
        output.extend(item.strip() for item in value.split(",") if item.strip())
    return output


def _configured_list(
    cli_values: list[str],
    env_name: str,
    config: dict,
    config_key: str,
    *deep_keys: str,
) -> list[str]:
    """Resolve a list setting from CLI, environment, deep config, or config key."""

    if cli_values:
        return _split_values(cli_values)
    env_values = env_list(env_name)
    if env_values is not None:
        return env_values
    for deep_key in deep_keys:
        value = deep_get(config, deep_key)
        if value is not None:
            return _as_list(value)
    return config_list(config, config_key)


def _as_list(value: object) -> list[str]:
    """Coerce scalar or list config values into a list of strings."""

    if value is None:
        return []
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _first_bool(*values: bool | None) -> bool:
    """Return the first explicitly configured boolean value."""

    for value in values:
        if value is not None:
            return value
    return False


def _has_findings_at_or_above(findings: list, threshold: Severity) -> bool:
    """Return whether any finding meets a CI failure threshold."""

    threshold_value = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[finding.severity] >= threshold_value for finding in findings)
