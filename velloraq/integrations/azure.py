# SPDX-License-Identifier: MIT
"""velloraq.integrations.azure module for the Velloraq security platform."""

from __future__ import annotations

import json
from typing import Any

from velloraq.integrations.base import CollectionResult, ProviderIntegration
from velloraq.integrations.redaction import summarize_environment
from velloraq.scanner.models import Resource, ScanContext, ScanWarning


class AzureIntegration(ProviderIntegration):
    """AzureIntegration component used by Velloraq. """
    provider = "azure"

    def collect(self, context: ScanContext) -> CollectionResult:
        """Execute the collect operation for this module."""
        result = CollectionResult()
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
            from azure.mgmt.resource import SubscriptionClient
            from azure.mgmt.storage import StorageManagementClient
            from azure.mgmt.web import WebSiteManagementClient
        except ModuleNotFoundError:
            result.warnings.append(
                ScanWarning("azure", "Azure SDK packages are not installed", "Install with: pip install .[azure]")
            )
            return result

        try:
            credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
            if context.azure_subscriptions:
                subscriptions = context.azure_subscriptions
            else:
                sub_client = SubscriptionClient(credential)
                subscriptions = [sub.subscription_id for sub in sub_client.subscriptions.list()]
            for subscription_id in subscriptions:
                web_client = WebSiteManagementClient(credential, subscription_id)
                storage_client = StorageManagementClient(credential, subscription_id)
                auth_client = AuthorizationManagementClient(credential, subscription_id)
                self._collect_function_apps(web_client, result, subscription_id)
                self._collect_storage(storage_client, result, subscription_id)
                self._collect_role_assignments(auth_client, result, subscription_id)
        except Exception as exc:
            result.warnings.append(ScanWarning("azure", "Azure collection failed", str(exc)))
        return result

    def _collect_function_apps(
        self, web_client: Any, result: CollectionResult, subscription_id: str
    ) -> None:
        """Internal helper used to keep the module implementation focused."""
        try:
            for app in web_client.web_apps.list():
                kind = (getattr(app, "kind", "") or "").lower()
                if "functionapp" not in kind:
                    continue
                resource_group = _resource_group_from_id(app.id)
                app_settings = self._function_app_settings(web_client, resource_group, app.name)
                app_setting_summary = summarize_environment(app_settings)
                result.resources.append(
                    Resource(
                        provider="azure",
                        service="functions",
                        resource_type="serverless_function",
                        resource_id=app.id,
                        name=app.name,
                        region=getattr(app, "location", None),
                        subscription_id=subscription_id,
                        metadata={
                            "kind": getattr(app, "kind", None),
                            "resource_group": resource_group,
                            "default_host_name": getattr(app, "default_host_name", None),
                            "https_only": getattr(app, "https_only", None),
                            "app_setting_count": app_setting_summary["environment_variable_count"],
                            "app_setting_names": app_setting_summary["environment_variable_names"],
                            "secret_app_setting_names": app_setting_summary[
                                "secret_environment_variable_names"
                            ],
                        },
                    )
                )
                self._collect_http_triggers(
                    web_client, result, app, resource_group, subscription_id
                )
        except Exception as exc:
            result.warnings.append(ScanWarning("azure", "Unable to collect Function Apps", str(exc)))

    @staticmethod
    def _function_app_settings(web_client: Any, resource_group: str, app_name: str) -> dict[str, Any]:
        """Internal helper used to keep the module implementation focused."""
        try:
            settings = web_client.web_apps.list_application_settings(resource_group, app_name)
            return dict(settings.properties or {})
        except Exception:
            return {}

    def _collect_http_triggers(
        self,
        web_client: Any,
        result: CollectionResult,
        app: Any,
        resource_group: str,
        subscription_id: str,
    ) -> None:
        """Internal helper used to keep the module implementation focused."""
        try:
            functions = web_client.web_apps.list_functions(resource_group, app.name)
        except Exception as exc:
            result.warnings.append(
                ScanWarning("azure", f"Unable to list functions for {app.name}", str(exc))
            )
            return
        for function in functions:
            config = _to_dict(getattr(function, "config", None))
            bindings = config.get("bindings") or []
            for binding in bindings:
                if str(binding.get("type", "")).lower() != "httptrigger":
                    continue
                route = binding.get("route") or getattr(function, "name", None)
                result.resources.append(
                    Resource(
                        provider="azure",
                        service="functions",
                        resource_type="api_route",
                        resource_id=f"{getattr(function, 'id', app.id)}/httpTrigger/{route}",
                        name=f"{app.name}/{getattr(function, 'name', route)}",
                        region=getattr(app, "location", None),
                        subscription_id=subscription_id,
                        metadata={
                            "function_app": app.name,
                            "function_name": getattr(function, "name", None),
                            "route": route,
                            "methods": binding.get("methods"),
                            "auth_level": binding.get("authLevel"),
                            "public_endpoint": True,
                            "rate_limiting_configured": False,
                        },
                    )
                )

    def _collect_storage(self, storage_client: Any, result: CollectionResult, subscription_id: str) -> None:
        """Internal helper used to keep the module implementation focused."""
        try:
            for account in storage_client.storage_accounts.list():
                resource_group = _resource_group_from_id(account.id)
                try:
                    containers = storage_client.blob_containers.list(resource_group, account.name)
                except Exception as exc:
                    result.warnings.append(
                        ScanWarning(
                            "azure",
                            f"Unable to list containers for storage account {account.name}",
                            str(exc),
                        )
                    )
                    continue
                for container in containers:
                    result.resources.append(
                        Resource(
                            provider="azure",
                            service="storage",
                            resource_type="storage_container",
                            resource_id=f"{account.id}/blobServices/default/containers/{container.name}",
                            name=f"{account.name}/{container.name}",
                            region=getattr(account, "location", None),
                            subscription_id=subscription_id,
                            metadata={
                                "storage_account": account.name,
                                "public_access": getattr(container, "public_access", None),
                                "allow_blob_public_access": getattr(
                                    account, "allow_blob_public_access", None
                                ),
                            },
                        )
                    )
        except Exception as exc:
            result.warnings.append(ScanWarning("azure", "Unable to collect storage accounts", str(exc)))

    def _collect_role_assignments(
        self, auth_client: Any, result: CollectionResult, subscription_id: str
    ) -> None:
        """Internal helper used to keep the module implementation focused."""
        scope = f"/subscriptions/{subscription_id}"
        try:
            for assignment in auth_client.role_assignments.list_for_scope(scope):
                role_name = self._role_name(auth_client, getattr(assignment, "role_definition_id", None))
                result.resources.append(
                    Resource(
                        provider="azure",
                        service="authorization",
                        resource_type="iam_binding",
                        resource_id=getattr(assignment, "id", ""),
                        name=role_name or getattr(assignment, "name", ""),
                        subscription_id=subscription_id,
                        metadata={
                            "role_name": role_name,
                            "role_definition_id": getattr(assignment, "role_definition_id", None),
                            "principal_id": getattr(assignment, "principal_id", None),
                            "principal_type": getattr(assignment, "principal_type", None),
                            "scope": getattr(assignment, "scope", scope),
                        },
                    )
                )
        except Exception as exc:
            result.warnings.append(ScanWarning("azure", "Unable to collect role assignments", str(exc)))

    @staticmethod
    def _role_name(auth_client: Any, role_definition_id: str | None) -> str | None:
        """Internal helper used to keep the module implementation focused."""
        if not role_definition_id:
            return None
        try:
            definition = auth_client.role_definitions.get_by_id(role_definition_id)
            return getattr(definition, "role_name", None)
        except Exception:
            return role_definition_id.rsplit("/", 1)[-1]


def _resource_group_from_id(resource_id: str | None) -> str:
    """Internal helper used to keep the module implementation focused."""
    if not resource_id:
        return ""
    parts = resource_id.split("/")
    for index, part in enumerate(parts):
        if part.lower() == "resourcegroups" and index + 1 < len(parts):
            return parts[index + 1]
    return ""


def _to_dict(value: Any) -> dict[str, Any]:
    """Internal helper used to keep the module implementation focused."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}
    if hasattr(value, "as_dict"):
        try:
            return value.as_dict()
        except Exception:
            return {}
    return {}
