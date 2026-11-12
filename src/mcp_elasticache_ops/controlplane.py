"""Control-plane views over the ElastiCache and CloudWatch APIs (boto3, read-only).

Only ``Describe*`` / ``List*`` / ``GetMetricData`` calls are made. If boto3
cannot find credentials, tools return a clear ``unavailable`` payload instead
of raising, so the data-plane tools keep working on their own.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, NoRegionError

from .config import ControlPlaneConfig

# Metrics worth looking at first, per engine family. Units follow CloudWatch.
REDIS_METRICS = [
    "EngineCPUUtilization",
    "CPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "BytesUsedForCache",
    "Evictions",
    "CurrConnections",
    "NewConnections",
    "CacheHitRate",
    "ReplicationLag",
    "NetworkBytesIn",
    "NetworkBytesOut",
    "SwapUsage",
]
MEMCACHED_METRICS = [
    "CPUUtilization",
    "BytesUsedForCacheItems",
    "Evictions",
    "CurrConnections",
    "GetHits",
    "GetMisses",
    "SwapUsage",
]
SERVERLESS_METRICS = [
    "ElastiCacheProcessingUnits",
    "BytesUsedForCache",
    "CurrConnections",
    "CacheHitRate",
    "ThrottledCmds",
]


class ControlPlane:
    def __init__(
        self,
        config: ControlPlaneConfig | None = None,
        session_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.config = config or ControlPlaneConfig.from_env()
        self._session_factory = session_factory
        self._clients: dict[str, Any] = {}

    # ------------------------------------------------------------ plumbing
    def client(self, service: str):
        if service not in self._clients:
            if self._session_factory:
                session = self._session_factory()
            else:
                session = boto3.Session(profile_name=self.config.profile, region_name=self.config.region)
            self._clients[service] = session.client(service, region_name=self.config.region)
        return self._clients[service]

    def _guard(self, fn: Callable[[], dict]) -> dict:
        if not self.config.enabled:
            return {"unavailable": "control plane disabled (ELASTICACHE_CONTROL_PLANE=false)"}
        try:
            return fn()
        except NoCredentialsError:
            return {"unavailable": "no AWS credentials found; control-plane tools are optional"}
        except NoRegionError:
            return {"unavailable": "no AWS region configured (set AWS_REGION)"}
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return {"error": err.get("Code", "ClientError"), "message": err.get("Message", str(exc))}
        except BotoCoreError as exc:
            return {"error": type(exc).__name__, "message": str(exc)}

    def _paginate(self, op: str, key: str, **kwargs) -> list[dict]:
        ec = self.client("elasticache")
        items: list[dict] = []
        marker = None
        while True:
            call = dict(kwargs)
            if marker:
                call["Marker"] = marker
            page = getattr(ec, op)(**call)
            items.extend(page.get(key, []))
            marker = page.get("Marker")
            if not marker:
                return items

    # ---------------------------------------------------------------- tools
    def replication_groups(self, replication_group_id: str | None = None) -> dict:
        def run() -> dict:
            kwargs = {"ReplicationGroupId": replication_group_id} if replication_group_id else {}
            groups = self._paginate("describe_replication_groups", "ReplicationGroups", **kwargs)
            return {"count": len(groups), "replication_groups": [_rg_view(g) for g in groups]}

        return self._guard(run)

    def cache_clusters(self, cache_cluster_id: str | None = None, show_nodes: bool = True) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {"ShowCacheNodeInfo": show_nodes}
            if cache_cluster_id:
                kwargs["CacheClusterId"] = cache_cluster_id
            clusters = self._paginate("describe_cache_clusters", "CacheClusters", **kwargs)
            return {"count": len(clusters), "cache_clusters": [_cluster_view(c) for c in clusters]}

        return self._guard(run)

    def serverless_caches(self) -> dict:
        def run() -> dict:
            ec = self.client("elasticache")
            items, token = [], None
            while True:
                page = ec.describe_serverless_caches(**({"NextToken": token} if token else {}))
                items.extend(page.get("ServerlessCaches", []))
                token = page.get("NextToken")
                if not token:
                    break
            return {"count": len(items), "serverless_caches": _jsonable(items)}

        return self._guard(run)

    def events(self, source_identifier: str | None = None, source_type: str | None = None, hours: int = 24) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {"Duration": max(1, min(int(hours), 14 * 24)) * 60}
            if source_identifier:
                kwargs["SourceIdentifier"] = source_identifier
            if source_type:
                kwargs["SourceType"] = source_type
            events = self._paginate("describe_events", "Events", **kwargs)
            return {"count": len(events), "events": _jsonable(events)}

        return self._guard(run)

    def parameters(self, parameter_group: str, only_modified: bool = True) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {"CacheParameterGroupName": parameter_group}
            if only_modified:
                kwargs["Source"] = "user"
            params = self._paginate("describe_cache_parameters", "Parameters", **kwargs)
            view = [
                {
                    "name": p.get("ParameterName"),
                    "value": p.get("ParameterValue"),
                    "source": p.get("Source"),
                    "modifiable": p.get("IsModifiable"),
                    "change_type": p.get("ChangeType"),
                }
                for p in params
            ]
            return {"parameter_group": parameter_group, "only_modified": only_modified, "parameters": view}

        return self._guard(run)

    def metrics(
        self,
        cache_cluster_id: str,
        metrics: list[str] | None = None,
        minutes: int = 60,
        period_seconds: int = 60,
        node_id: str | None = None,
        serverless: bool = False,
    ) -> dict:
        def run() -> dict:
            names = metrics or (SERVERLESS_METRICS if serverless else REDIS_METRICS)
            dims = (
                [{"Name": "clusterId", "Value": cache_cluster_id}]
                if serverless
                else [{"Name": "CacheClusterId", "Value": cache_cluster_id}]
            )
            if node_id and not serverless:
                dims.append({"Name": "CacheNodeId", "Value": node_id})
            end = dt.datetime.now(dt.UTC)
            start = end - dt.timedelta(minutes=max(1, min(int(minutes), 14 * 24 * 60)))
            stat_for = {"Evictions": "Sum", "NewConnections": "Sum", "ThrottledCmds": "Sum"}
            queries = [
                {
                    "Id": f"m{i}",
                    "Label": name,
                    "MetricStat": {
                        "Metric": {"Namespace": "AWS/ElastiCache", "MetricName": name, "Dimensions": dims},
                        "Period": int(period_seconds),
                        "Stat": stat_for.get(name, "Average"),
                    },
                    "ReturnData": True,
                }
                for i, name in enumerate(names)
            ]
            cw = self.client("cloudwatch")
            out: dict[str, dict] = {}
            token = None
            while True:
                kwargs: dict[str, Any] = {"MetricDataQueries": queries, "StartTime": start, "EndTime": end}
                if token:
                    kwargs["NextToken"] = token
                resp = cw.get_metric_data(**kwargs)
                for res in resp.get("MetricDataResults", []):
                    entry = out.setdefault(res["Label"], {"timestamps": [], "values": []})
                    entry["timestamps"].extend(t.isoformat() for t in res.get("Timestamps", []))
                    entry["values"].extend(res.get("Values", []))
                token = resp.get("NextToken")
                if not token:
                    break
            summary = {}
            for name, series in out.items():
                vals = series["values"]
                summary[name] = (
                    {"points": len(vals), "latest": vals[0], "max": max(vals), "avg": sum(vals) / len(vals)}
                    if vals
                    else {"points": 0}
                )
            return {
                "cache_cluster_id": cache_cluster_id,
                "node_id": node_id,
                "window_minutes": minutes,
                "summary": summary,
                "series": out,
            }

        return self._guard(run)


def _rg_view(g: dict) -> dict:
    return {
        "id": g.get("ReplicationGroupId"),
        "description": g.get("Description"),
        "status": g.get("Status"),
        "engine": g.get("Engine"),
        "cluster_mode": g.get("ClusterMode") or ("enabled" if g.get("ClusterEnabled") else "disabled"),
        "node_type": g.get("CacheNodeType"),
        "multi_az": g.get("MultiAZ"),
        "automatic_failover": g.get("AutomaticFailover"),
        "transit_encryption": g.get("TransitEncryptionEnabled"),
        "at_rest_encryption": g.get("AtRestEncryptionEnabled"),
        "auth_token_enabled": g.get("AuthTokenEnabled"),
        "member_clusters": g.get("MemberClusters", []),
        "configuration_endpoint": _jsonable(g.get("ConfigurationEndpoint")),
        "node_groups": [
            {
                "id": ng.get("NodeGroupId"),
                "status": ng.get("Status"),
                "slots": ng.get("Slots"),
                "primary_endpoint": _jsonable(ng.get("PrimaryEndpoint")),
                "reader_endpoint": _jsonable(ng.get("ReaderEndpoint")),
                "members": [
                    {
                        "cluster_id": m.get("CacheClusterId"),
                        "role": m.get("CurrentRole"),
                        "az": m.get("PreferredAvailabilityZone"),
                    }
                    for m in ng.get("NodeGroupMembers", [])
                ],
            }
            for ng in g.get("NodeGroups", [])
        ],
        "pending_modified_values": _jsonable(g.get("PendingModifiedValues") or {}),
        "snapshot_retention_limit": g.get("SnapshotRetentionLimit"),
    }


def _cluster_view(c: dict) -> dict:
    return {
        "id": c.get("CacheClusterId"),
        "status": c.get("CacheClusterStatus"),
        "engine": c.get("Engine"),
        "engine_version": c.get("EngineVersion"),
        "node_type": c.get("CacheNodeType"),
        "num_nodes": c.get("NumCacheNodes"),
        "replication_group_id": c.get("ReplicationGroupId"),
        "az": c.get("PreferredAvailabilityZone"),
        "parameter_group": (c.get("CacheParameterGroup") or {}).get("CacheParameterGroupName"),
        "parameter_apply_status": (c.get("CacheParameterGroup") or {}).get("ParameterApplyStatus"),
        "maintenance_window": c.get("PreferredMaintenanceWindow"),
        "auto_minor_version_upgrade": c.get("AutoMinorVersionUpgrade"),
        "pending_modified_values": _jsonable(c.get("PendingModifiedValues") or {}),
        "nodes": [
            {
                "id": n.get("CacheNodeId"),
                "status": n.get("CacheNodeStatus"),
                "endpoint": _jsonable(n.get("Endpoint")),
                "az": n.get("CustomerAvailabilityZone"),
            }
            for n in c.get("CacheNodes", [])
        ],
    }


def _jsonable(v: Any) -> Any:
    if isinstance(v, (dt.datetime, dt.date)):
        return v.isoformat()
    if isinstance(v, dict):
        return {k: _jsonable(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_jsonable(x) for x in v]
    return v
