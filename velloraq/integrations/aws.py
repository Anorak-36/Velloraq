# SPDX-License-Identifier: MIT
"""velloraq.integrations.aws module for the Velloraq security platform."""

from __future__ import annotations

import json
from typing import Any

from velloraq.integrations.base import CollectionResult, ProviderIntegration
from velloraq.integrations.redaction import summarize_environment
from velloraq.scanner.models import Resource, ScanContext, ScanWarning


class AwsIntegration(ProviderIntegration):
    """AwsIntegration component used by Velloraq. """
    provider = "aws"

    def collect(self, context: ScanContext) -> CollectionResult:
        """Execute the collect operation for this module."""
        result = CollectionResult()
        try:
            import boto3
            from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
        except ModuleNotFoundError as exc:
            result.warnings.append(
                ScanWarning("aws", "boto3 is not installed", "Install with: pip install .[aws]")
            )
            return result

        try:
            session_kwargs = {"profile_name": context.aws_profile} if context.aws_profile else {}
            session = boto3.Session(**session_kwargs)
            account_id = self._account_id(session)
            regions = context.regions or [session.region_name or "us-east-1"]
            iam_client = session.client("iam")
            self._collect_s3(session, result, account_id)
            for region in regions:
                self._collect_lambda(session, iam_client, result, region, account_id)
                self._collect_api_gateway_v1(session, result, region, account_id)
                self._collect_api_gateway_v2(session, result, region, account_id)
        except NoCredentialsError as exc:
            result.warnings.append(ScanWarning("aws", "AWS credentials were not available", str(exc)))
        except (BotoCoreError, ClientError) as exc:
            result.warnings.append(ScanWarning("aws", "AWS collection failed", str(exc)))
        return result

    @staticmethod
    def _account_id(session: Any) -> str | None:
        """Internal helper used to keep the module implementation focused."""
        try:
            return session.client("sts").get_caller_identity().get("Account")
        except Exception:
            return None

    def _collect_lambda(
        self,
        session: Any,
        iam_client: Any,
        result: CollectionResult,
        region: str,
        account_id: str | None,
    ) -> None:
        """Internal helper used to keep the module implementation focused."""
        lambda_client = session.client("lambda", region_name=region)
        try:
            paginator = lambda_client.get_paginator("list_functions")
            for page in paginator.paginate():
                for function in page.get("Functions", []):
                    function_name = function["FunctionName"]
                    env = (function.get("Environment") or {}).get("Variables") or {}
                    role_arn = function.get("Role")
                    result.resources.append(
                        Resource(
                            provider="aws",
                            service="lambda",
                            resource_type="serverless_function",
                            resource_id=function.get("FunctionArn", function_name),
                            name=function_name,
                            region=region,
                            account_id=account_id,
                            metadata={
                                "runtime": function.get("Runtime"),
                                "role_arn": role_arn,
                                "handler": function.get("Handler"),
                                "timeout": function.get("Timeout"),
                                "memory_size": function.get("MemorySize"),
                                **summarize_environment(env),
                                "kms_key_arn": function.get("KMSKeyArn"),
                                "vpc_config": function.get("VpcConfig"),
                            },
                        )
                    )
                    if role_arn:
                        self._collect_lambda_role_policies(
                            iam_client, result, role_arn, function_name, region, account_id
                        )
                    self._collect_lambda_triggers(lambda_client, result, function_name, region, account_id)
        except Exception as exc:
            result.warnings.append(
                ScanWarning("aws", f"Unable to collect Lambda resources in {region}", str(exc))
            )

    def _collect_lambda_role_policies(
        self,
        iam_client: Any,
        result: CollectionResult,
        role_arn: str,
        function_name: str,
        region: str,
        account_id: str | None,
    ) -> None:
        """Internal helper used to keep the module implementation focused."""
        role_name = role_arn.rsplit("/", 1)[-1]
        try:
            for page in iam_client.get_paginator("list_attached_role_policies").paginate(
                RoleName=role_name
            ):
                for policy_ref in page.get("AttachedPolicies", []):
                    policy = iam_client.get_policy(PolicyArn=policy_ref["PolicyArn"])["Policy"]
                    version = iam_client.get_policy_version(
                        PolicyArn=policy_ref["PolicyArn"],
                        VersionId=policy["DefaultVersionId"],
                    )
                    document = version["PolicyVersion"]["Document"]
                    result.resources.append(
                        self._policy_resource(
                            policy_ref["PolicyArn"],
                            policy_ref["PolicyName"],
                            role_name,
                            function_name,
                            role_arn,
                            region,
                            account_id,
                            document,
                            "managed",
                        )
                    )
            for page in iam_client.get_paginator("list_role_policies").paginate(RoleName=role_name):
                for policy_name in page.get("PolicyNames", []):
                    policy = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                    result.resources.append(
                        self._policy_resource(
                            f"{role_arn}/{policy_name}",
                            policy_name,
                            role_name,
                            function_name,
                            role_arn,
                            region,
                            account_id,
                            policy.get("PolicyDocument", {}),
                            "inline",
                        )
                    )
        except Exception as exc:
            result.warnings.append(
                ScanWarning(
                    "aws",
                    f"Unable to collect IAM policies for Lambda role {role_name}",
                    str(exc),
                )
            )

    @staticmethod
    def _policy_resource(
        resource_id: str,
        policy_name: str,
        role_name: str,
        function_name: str,
        role_arn: str,
        region: str,
        account_id: str | None,
        policy_document: dict[str, Any],
        source: str,
    ) -> Resource:
        """Internal helper used to keep the module implementation focused."""
        return Resource(
            provider="aws",
            service="iam",
            resource_type="iam_policy",
            resource_id=resource_id,
            name=f"{role_name}/{policy_name}",
            region=region,
            account_id=account_id,
            metadata={
                "policy_name": policy_name,
                "role_name": role_name,
                "role_arn": role_arn,
                "function_name": function_name,
                "policy_document": policy_document,
                "source": source,
            },
        )

    def _collect_lambda_triggers(
        self,
        lambda_client: Any,
        result: CollectionResult,
        function_name: str,
        region: str,
        account_id: str | None,
    ) -> None:
        """Internal helper used to keep the module implementation focused."""
        try:
            for page in lambda_client.get_paginator("list_event_source_mappings").paginate(
                FunctionName=function_name
            ):
                for mapping in page.get("EventSourceMappings", []):
                    source_arn = mapping.get("EventSourceArn")
                    result.resources.append(
                        Resource(
                            provider="aws",
                            service="lambda",
                            resource_type="event_trigger",
                            resource_id=mapping.get("UUID", f"{function_name}/event-source"),
                            name=f"{function_name} event source",
                            region=region,
                            account_id=account_id,
                            metadata={
                                "function_name": function_name,
                                "event_source_arn": source_arn,
                                "state": mapping.get("State"),
                                "broad_source": not bool(source_arn),
                            },
                        )
                    )
            try:
                policy_raw = lambda_client.get_policy(FunctionName=function_name).get("Policy")
            except Exception:
                policy_raw = None
            if policy_raw:
                policy = json.loads(policy_raw)
                for statement in policy.get("Statement", []):
                    principal = statement.get("Principal")
                    source_arn = statement.get("Condition", {}).get("ArnLike", {}).get("AWS:SourceArn")
                    is_public = principal == "*" or principal == {"AWS": "*"}
                    if is_public or not source_arn:
                        result.resources.append(
                            Resource(
                                provider="aws",
                                service="lambda",
                                resource_type="event_trigger",
                                resource_id=f"{function_name}/{statement.get('Sid', 'policy')}",
                                name=f"{function_name} invoke permission",
                                region=region,
                                account_id=account_id,
                                metadata={
                                    "function_name": function_name,
                                    "principal": principal,
                                    "source_arn": source_arn,
                                    "statement": statement,
                                    "broad_source": is_public or not bool(source_arn),
                                },
                            )
                        )
        except Exception as exc:
            result.warnings.append(
                ScanWarning("aws", f"Unable to collect Lambda triggers for {function_name}", str(exc))
            )

    def _collect_api_gateway_v1(
        self,
        session: Any,
        result: CollectionResult,
        region: str,
        account_id: str | None,
    ) -> None:
        """Internal helper used to keep the module implementation focused."""
        client = session.client("apigateway", region_name=region)
        try:
            for api_page in client.get_paginator("get_rest_apis").paginate():
                for api in api_page.get("items", []):
                    api_id = api["id"]
                    throttled = self._api_v1_has_throttling(client, api_id)
                    for resource_page in client.get_paginator("get_resources").paginate(restApiId=api_id):
                        for api_resource in resource_page.get("items", []):
                            path = api_resource.get("path")
                            for method in (api_resource.get("resourceMethods") or {}).keys():
                                try:
                                    method_cfg = client.get_method(
                                        restApiId=api_id,
                                        resourceId=api_resource["id"],
                                        httpMethod=method,
                                    )
                                except Exception:
                                    method_cfg = {}
                                result.resources.append(
                                    Resource(
                                        provider="aws",
                                        service="apigateway",
                                        resource_type="api_route",
                                        resource_id=f"arn:aws:apigateway:{region}::/restapis/{api_id}/resources/{api_resource['id']}/methods/{method}",
                                        name=f"{api.get('name')} {method} {path}",
                                        region=region,
                                        account_id=account_id,
                                        metadata={
                                            "api_id": api_id,
                                            "api_type": "REST",
                                            "method": method,
                                            "path": path,
                                            "authorization_type": method_cfg.get("authorizationType"),
                                            "api_key_required": method_cfg.get("apiKeyRequired"),
                                            "public_endpoint": True,
                                            "throttling_configured": throttled,
                                        },
                                    )
                                )
        except Exception as exc:
            result.warnings.append(
                ScanWarning("aws", f"Unable to collect API Gateway REST APIs in {region}", str(exc))
            )

    @staticmethod
    def _api_v1_has_throttling(client: Any, api_id: str) -> bool:
        """Internal helper used to keep the module implementation focused."""
        try:
            stages = client.get_stages(restApiId=api_id).get("item", [])
            for stage in stages:
                for settings in (stage.get("methodSettings") or {}).values():
                    if settings.get("throttlingBurstLimit") or settings.get("throttlingRateLimit"):
                        return True
        except Exception:
            return False
        return False

    def _collect_api_gateway_v2(
        self,
        session: Any,
        result: CollectionResult,
        region: str,
        account_id: str | None,
    ) -> None:
        """Internal helper used to keep the module implementation focused."""
        client = session.client("apigatewayv2", region_name=region)
        try:
            for api_page in client.get_paginator("get_apis").paginate():
                for api in api_page.get("Items", []):
                    api_id = api["ApiId"]
                    throttled = self._api_v2_has_throttling(client, api_id)
                    for route_page in client.get_paginator("get_routes").paginate(ApiId=api_id):
                        for route in route_page.get("Items", []):
                            route_key = route.get("RouteKey", "$default")
                            result.resources.append(
                                Resource(
                                    provider="aws",
                                    service="apigateway",
                                    resource_type="api_route",
                                    resource_id=f"arn:aws:apigateway:{region}::/apis/{api_id}/routes/{route.get('RouteId')}",
                                    name=f"{api.get('Name')} {route_key}",
                                    region=region,
                                    account_id=account_id,
                                    metadata={
                                        "api_id": api_id,
                                        "api_type": api.get("ProtocolType"),
                                        "method": route_key.split(" ", 1)[0],
                                        "path": route_key.split(" ", 1)[-1],
                                        "authorization_type": route.get("AuthorizationType"),
                                        "public_endpoint": True,
                                        "throttling_configured": throttled,
                                    },
                                )
                            )
        except Exception as exc:
            result.warnings.append(
                ScanWarning("aws", f"Unable to collect API Gateway HTTP/WebSocket APIs in {region}", str(exc))
            )

    @staticmethod
    def _api_v2_has_throttling(client: Any, api_id: str) -> bool:
        """Internal helper used to keep the module implementation focused."""
        try:
            stages = client.get_stages(ApiId=api_id).get("Items", [])
            for stage in stages:
                default_settings = stage.get("DefaultRouteSettings") or {}
                route_settings = stage.get("RouteSettings") or {}
                if default_settings.get("ThrottlingBurstLimit") or default_settings.get("ThrottlingRateLimit"):
                    return True
                for settings in route_settings.values():
                    if settings.get("ThrottlingBurstLimit") or settings.get("ThrottlingRateLimit"):
                        return True
        except Exception:
            return False
        return False

    def _collect_s3(self, session: Any, result: CollectionResult, account_id: str | None) -> None:
        """Internal helper used to keep the module implementation focused."""
        client = session.client("s3")
        try:
            buckets = client.list_buckets().get("Buckets", [])
            for bucket in buckets:
                name = bucket["Name"]
                public_signals: list[str] = []
                public_access_block = None
                region = None
                try:
                    location = client.get_bucket_location(Bucket=name).get("LocationConstraint")
                    region = location or "us-east-1"
                except Exception:
                    pass
                try:
                    public_access_block = client.get_public_access_block(Bucket=name).get(
                        "PublicAccessBlockConfiguration"
                    )
                except Exception:
                    public_access_block = "missing_or_unreadable"
                try:
                    status = client.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {})
                    if status.get("IsPublic"):
                        public_signals.append("bucket_policy_public")
                except Exception:
                    pass
                try:
                    acl = client.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        uri = grantee.get("URI", "")
                        if uri.endswith("/AllUsers") or uri.endswith("/AuthenticatedUsers"):
                            public_signals.append(f"acl_{grant.get('Permission', 'UNKNOWN')}")
                except Exception:
                    pass
                result.resources.append(
                    Resource(
                        provider="aws",
                        service="s3",
                        resource_type="storage_bucket",
                        resource_id=f"arn:aws:s3:::{name}",
                        name=name,
                        region=region,
                        account_id=account_id,
                        metadata={
                            "is_public": bool(public_signals),
                            "public_signals": sorted(set(public_signals)),
                            "public_access_block": public_access_block,
                        },
                    )
                )
        except Exception as exc:
            result.warnings.append(ScanWarning("aws", "Unable to collect S3 buckets", str(exc)))
