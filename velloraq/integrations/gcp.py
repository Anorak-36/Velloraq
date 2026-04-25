# SPDX-License-Identifier: MIT
"""velloraq.integrations.gcp module for the Velloraq security platform."""

from __future__ import annotations

from typing import Any

from velloraq.integrations.base import CollectionResult, ProviderIntegration
from velloraq.integrations.redaction import summarize_environment
from velloraq.scanner.models import Resource, ScanContext, ScanWarning


class GcpIntegration(ProviderIntegration):
    """GcpIntegration component used by Velloraq. """
    provider = "gcp"

    def collect(self, context: ScanContext) -> CollectionResult:
        """Execute the collect operation for this module."""
        result = CollectionResult()
        try:
            import google.auth
            from google.cloud import functions_v1, storage
            from googleapiclient import discovery
        except ModuleNotFoundError:
            result.warnings.append(
                ScanWarning("gcp", "Google Cloud SDK packages are not installed", "Install with: pip install .[gcp]")
            )
            return result

        try:
            credentials, default_project = google.auth.default()
            projects = context.gcp_projects or ([default_project] if default_project else [])
            if not projects:
                result.warnings.append(
                    ScanWarning("gcp", "No GCP project configured", "Pass --gcp-project or set application default credentials")
                )
                return result
            regions = context.regions or ["us-central1"]
            for project_id in projects:
                self._collect_functions_v1(functions_v1, result, project_id, regions)
                self._collect_functions_v2(result, project_id, regions)
                self._collect_storage(storage, result, project_id)
                self._collect_project_iam(discovery, credentials, result, project_id)
                self._collect_api_gateways(discovery, credentials, result, project_id, regions)
        except Exception as exc:
            result.warnings.append(ScanWarning("gcp", "GCP collection failed", str(exc)))
        return result

    def _collect_functions_v1(
        self, functions_v1: Any, result: CollectionResult, project_id: str, regions: list[str]
    ) -> None:
        """Internal helper used to keep the module implementation focused."""
        client = functions_v1.CloudFunctionsServiceClient()
        for region in regions:
            parent = f"projects/{project_id}/locations/{region}"
            try:
                for function in client.list_functions(parent=parent):
                    public_invokers = self._function_public_invokers(client, function.name)
                    result.resources.append(
                        Resource(
                            provider="gcp",
                            service="cloudfunctions",
                            resource_type="serverless_function",
                            resource_id=function.name,
                            name=function.name.rsplit("/", 1)[-1],
                            region=region,
                            project_id=project_id,
                            metadata={
                                "generation": "v1",
                                "runtime": getattr(function, "runtime", None),
                                "entry_point": getattr(function, "entry_point", None),
                                "https_trigger": bool(getattr(function, "https_trigger", None)),
                                "service_account_email": getattr(
                                    function, "service_account_email", None
                                ),
                                **summarize_environment(
                                    dict(getattr(function, "environment_variables", {}) or {})
                                ),
                                "public_invokers": public_invokers,
                            },
                        )
                    )
            except Exception as exc:
                result.warnings.append(
                    ScanWarning("gcp", f"Unable to collect Cloud Functions v1 in {region}", str(exc))
                )

    @staticmethod
    def _function_public_invokers(client: Any, function_name: str) -> list[str]:
        """Internal helper used to keep the module implementation focused."""
        try:
            policy = client.get_iam_policy(request={"resource": function_name})
            public_members: list[str] = []
            for binding in policy.bindings:
                if binding.role in {"roles/cloudfunctions.invoker", "roles/run.invoker"}:
                    public_members.extend(
                        member for member in binding.members if member in {"allUsers", "allAuthenticatedUsers"}
                    )
            return sorted(set(public_members))
        except Exception:
            return []

    def _collect_functions_v2(self, result: CollectionResult, project_id: str, regions: list[str]) -> None:
        """Internal helper used to keep the module implementation focused."""
        try:
            from google.cloud import functions_v2
        except ModuleNotFoundError:
            return
        client = functions_v2.FunctionServiceClient()
        for region in regions:
            parent = f"projects/{project_id}/locations/{region}"
            try:
                for function in client.list_functions(parent=parent):
                    public_invokers = self._function_public_invokers(client, function.name)
                    service_config = getattr(function, "service_config", None)
                    env = getattr(service_config, "environment_variables", {}) if service_config else {}
                    result.resources.append(
                        Resource(
                            provider="gcp",
                            service="cloudfunctions",
                            resource_type="serverless_function",
                            resource_id=function.name,
                            name=function.name.rsplit("/", 1)[-1],
                            region=region,
                            project_id=project_id,
                            metadata={
                                "generation": "v2",
                                "runtime": getattr(
                                    getattr(function, "build_config", None), "runtime", None
                                ),
                                "service_account_email": getattr(
                                    service_config, "service_account_email", None
                                )
                                if service_config
                                else None,
                                **summarize_environment(dict(env or {})),
                                "public_invokers": public_invokers,
                            },
                        )
                    )
            except Exception as exc:
                result.warnings.append(
                    ScanWarning("gcp", f"Unable to collect Cloud Functions v2 in {region}", str(exc))
                )

    def _collect_storage(self, storage: Any, result: CollectionResult, project_id: str) -> None:
        """Internal helper used to keep the module implementation focused."""
        try:
            client = storage.Client(project=project_id)
            for bucket in client.list_buckets():
                public_members: list[str] = []
                try:
                    policy = bucket.get_iam_policy(requested_policy_version=3)
                    for binding in policy.bindings:
                        public_members.extend(
                            member
                            for member in binding.get("members", [])
                            if member in {"allUsers", "allAuthenticatedUsers"}
                        )
                except Exception:
                    pass
                result.resources.append(
                    Resource(
                        provider="gcp",
                        service="storage",
                        resource_type="storage_bucket",
                        resource_id=f"gs://{bucket.name}",
                        name=bucket.name,
                        region=getattr(bucket, "location", None),
                        project_id=project_id,
                        metadata={
                            "public_members": sorted(set(public_members)),
                            "uniform_bucket_level_access": getattr(
                                bucket, "iam_configuration", None
                            ).uniform_bucket_level_access_enabled
                            if getattr(bucket, "iam_configuration", None)
                            else None,
                        },
                    )
                )
        except Exception as exc:
            result.warnings.append(ScanWarning("gcp", "Unable to collect Cloud Storage buckets", str(exc)))

    def _collect_project_iam(
        self, discovery: Any, credentials: Any, result: CollectionResult, project_id: str
    ) -> None:
        """Internal helper used to keep the module implementation focused."""
        try:
            service = discovery.build("cloudresourcemanager", "v1", credentials=credentials, cache_discovery=False)
            policy = service.projects().getIamPolicy(resource=project_id, body={}).execute()
            for binding in policy.get("bindings", []):
                result.resources.append(
                    Resource(
                        provider="gcp",
                        service="iam",
                        resource_type="iam_binding",
                        resource_id=f"projects/{project_id}/iam/{binding.get('role')}",
                        name=binding.get("role", ""),
                        project_id=project_id,
                        metadata={
                            "role": binding.get("role"),
                            "members": binding.get("members", []),
                        },
                    )
                )
        except Exception as exc:
            result.warnings.append(ScanWarning("gcp", "Unable to collect project IAM policy", str(exc)))

    def _collect_api_gateways(
        self,
        discovery: Any,
        credentials: Any,
        result: CollectionResult,
        project_id: str,
        regions: list[str],
    ) -> None:
        """Internal helper used to keep the module implementation focused."""
        try:
            service = discovery.build("apigateway", "v1", credentials=credentials, cache_discovery=False)
            for region in regions:
                parent = f"projects/{project_id}/locations/{region}"
                request = service.projects().locations().gateways().list(parent=parent)
                while request is not None:
                    response = request.execute()
                    for gateway in response.get("gateways", []):
                        result.resources.append(
                            Resource(
                                provider="gcp",
                                service="apigateway",
                                resource_type="api_gateway",
                                resource_id=gateway.get("name", ""),
                                name=gateway.get("displayName") or gateway.get("name", ""),
                                region=region,
                                project_id=project_id,
                                metadata={
                                    "api_config": gateway.get("apiConfig"),
                                    "default_hostname": gateway.get("defaultHostname"),
                                    "state": gateway.get("state"),
                                },
                            )
                        )
                    request = service.projects().locations().gateways().list_next(request, response)
        except Exception as exc:
            result.warnings.append(ScanWarning("gcp", "Unable to collect API Gateway resources", str(exc)))
