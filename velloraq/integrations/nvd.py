# SPDX-License-Identifier: MIT
"""velloraq.integrations.nvd module for the Velloraq security platform."""

from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from velloraq.integrations.base import CollectionResult
from velloraq.scanner.models import Resource, ScanContext, ScanWarning

REQUIREMENT_RE = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)\s*(?:==|===)\s*([A-Za-z0-9_.!+:-]+)\s*(?:#.*)?$"
)


class NvdDependencyScanner:
    """NvdDependencyScanner component used by Velloraq. """
    provider = "nvd"

    def collect(self, context: ScanContext) -> CollectionResult:
        """Execute the collect operation for this module."""
        result = CollectionResult()
        dependencies = []
        for manifest in context.dependency_manifests:
            dependencies.extend(parse_requirements(manifest, result))

        if dependencies and not context.enable_nvd:
            result.warnings.append(
                ScanWarning(
                    "nvd",
                    "Dependency manifests were parsed but NVD lookups are disabled",
                    "Pass --nvd to query the NVD 2.0 API.",
                )
            )

        for package_name, version, manifest in dependencies:
            vulnerabilities: list[dict[str, Any]] = []
            if context.enable_nvd:
                vulnerabilities = query_nvd(package_name, version, context.nvd_api_key, result)
                time.sleep(0.7 if context.nvd_api_key else 6.1)
            result.resources.append(
                Resource(
                    provider="dependency",
                    service="package",
                    resource_type="dependency",
                    resource_id=f"{manifest}:{package_name}=={version}",
                    name=package_name,
                    metadata={
                        "version": version,
                        "manifest": manifest,
                        "vulnerabilities": vulnerabilities,
                    },
                )
            )
        return result


def parse_requirements(manifest: str, result: CollectionResult) -> list[tuple[str, str, str]]:
    """Execute the parse_requirements operation for this module."""
    path = Path(manifest)
    if not path.exists():
        result.warnings.append(ScanWarning("dependency", f"Manifest not found: {manifest}"))
        return []
    dependencies: list[tuple[str, str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("-"):
            continue
        match = REQUIREMENT_RE.match(stripped)
        if match:
            dependencies.append((match.group(1), match.group(2), str(path)))
        else:
            result.warnings.append(
                ScanWarning(
                    "dependency",
                    f"Skipping unpinned or unsupported requirement: {stripped}",
                    "Pin dependencies with package==version for deterministic NVD lookups.",
                )
            )
    return dependencies


def query_nvd(
    package_name: str,
    version: str,
    api_key: str | None,
    result: CollectionResult,
) -> list[dict[str, Any]]:
    """Execute the query_nvd operation for this module."""
    query = urllib.parse.urlencode({"keywordSearch": f"{package_name} {version}", "resultsPerPage": "10"})
    request = urllib.request.Request(f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}")
    request.add_header("User-Agent", "velloraq/0.1")
    api_key = api_key or os.getenv("NVD_API_KEY")
    if api_key:
        request.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        result.warnings.append(
            ScanWarning("nvd", f"NVD lookup failed for {package_name}=={version}", str(exc))
        )
        return []
    vulnerabilities = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        metrics = cve.get("metrics", {})
        severity, score = _extract_cvss(metrics)
        descriptions = cve.get("descriptions", [])
        summary = next(
            (entry.get("value") for entry in descriptions if entry.get("lang") == "en"),
            "",
        )
        vulnerabilities.append(
            {
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": score,
                "published": cve.get("published"),
                "summary": summary[:500],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
            }
        )
    return vulnerabilities


def _extract_cvss(metrics: dict[str, Any]) -> tuple[str, float | None]:
    """Internal helper used to keep the module implementation focused."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if not values:
            continue
        data = values[0].get("cvssData", {})
        return data.get("baseSeverity") or values[0].get("baseSeverity") or "LOW", data.get("baseScore")
    return "LOW", None
