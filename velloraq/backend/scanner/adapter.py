"""Adapter between persisted SaaS scan configuration and scanner domain models."""

# SPDX-License-Identifier: MIT
from __future__ import annotations

from velloraq.scanner.models import ScanContext, Severity
from velloraq.scanner.engine import ScannerEngine


def build_scan_context(config: dict) -> ScanContext:
    """Convert database JSON configuration into a typed scanner context."""

    min_severity = config.get("min_severity")
    return ScanContext(
        providers=config.get("providers") or ["source"],
        regions=config.get("regions") or [],
        aws_profile=config.get("aws_profile"),
        azure_subscriptions=config.get("azure_subscriptions") or [],
        gcp_projects=config.get("gcp_projects") or [],
        plugin_dirs=config.get("plugin_dirs") or [],
        dependency_manifests=config.get("dependency_manifests") or [],
        source_paths=config.get("source_paths") or [],
        enabled_rules=config.get("enabled_rules") or [],
        disabled_rules=config.get("disabled_rules") or [],
        min_severity=Severity(min_severity) if min_severity else None,
        exclude_resources=config.get("exclude_resources") or [],
        enable_nvd=bool(config.get("enable_nvd", False)),
        nvd_api_key=None,
        include_resource_inventory=bool(config.get("include_inventory", False)),
        verbose=bool(config.get("verbose", False)),
    )


def run_scan_from_config(config: dict):
    """Execute the scanner from persisted configuration."""

    context = build_scan_context(config)
    return ScannerEngine(context).run()
