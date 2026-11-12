"""Control-plane views over the ElastiCache and CloudWatch APIs (boto3, read-only).

Only ``Describe*`` / ``List*`` / ``GetMetricData`` calls are made. If boto3
cannot find credentials, tools return a clear ``unavailable`` payload instead
of raising, so the data-plane tools keep working on their own.

Views are findings-first: each payload carries a ``findings`` list of
``{"severity": "critical" | "warning" | "info", "message": ...}`` entries so a
caller can read the verdict before the raw detail.
"""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter, defaultdict
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
    "CurrItems",
    "CacheHitRate",
    "ReplicationLag",
    "ReplicationBytes",
    "NetworkBytesIn",
    "NetworkBytesOut",
    "NetworkBandwidthAllowanceExceeded",
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
SUM_STAT_METRICS = {
    "Evictions",
    "NewConnections",
    "ThrottledCmds",
    "NetworkBandwidthAllowanceExceeded",
    "ElastiCacheProcessingUnits",
}

SWAP_WARN_BYTES = 50 * 1024 * 1024
MAXCLIENTS_DEFAULT = 65_000  # ElastiCache default maxclients
MAX_QUERIES_PER_CALL = 500  # GetMetricData limit
ALLOWED_PREFIXES = ("describe_", "list_", "get_metric_data")

OVERVIEW_WINDOW_MINUTES = 360
OVERVIEW_METRICS = [
    "EngineCPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "ReplicationLag",
    "Evictions",
    "CurrConnections",
    "NewConnections",
]
OVERVIEW_P95 = ("EngineCPUUtilization", "DatabaseMemoryUsagePercentage")
MAX_OVERVIEW_FINDINGS = 30
MAX_OVERVIEW_SHARDS = 50
OUTLIER_RATIO = 1.5
# Ignore outliers below these floors: 3x of almost nothing is still almost nothing.
OUTLIER_FLOORS = {
    "EngineCPUUtilization": 10.0,
    "DatabaseMemoryUsagePercentage": 20.0,
    "Evictions": 1.0,
    "CurrConnections": 50.0,
    "NewConnections": 50.0,
    "ReplicationLag": 1.0,
}
RIGHTSIZE_MEMORY_P95 = 30.0
RIGHTSIZE_CPU_P95 = 20.0

TRIAGE_WINDOW_HOURS = 6
MAX_TRIAGE_FINDINGS = 30
TRIAGE_METRICS = [
    "EngineCPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "Evictions",
    "ReplicationLag",
    "CurrConnections",
]
_TRIAGE_FATAL = {"ReplicationGroupNotFoundFault"}  # nothing useful to report: surface it as the tool error
_PENDING_ACTION_STATUSES = (
    "not-applied",
    "waiting-to-start",
    "in-progress",
    "stopping",
    "stopped",
    "scheduling",
    "scheduled",
)
IMPORTANT_PARAMETERS = {
    "maxmemory-policy",
    "reserved-memory-percent",
    "timeout",
    "appendonly",
    "cluster-enabled",
    "notify-keyspace-events",
    "maxclients",
    "activedefrag",
    "lazyfree-lazy-eviction",
    "tcp-keepalive",
}

# Alarms every production node should have (CloudWatch metric names, AWS/ElastiCache namespace).
RECOMMENDED_ALARMS = [
    "EngineCPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "Evictions",
    "ReplicationLag",
    "CurrConnections",
    "SwapUsage",
]
MEMCACHED_RECOMMENDED_ALARMS = ["CPUUtilization", "Evictions", "CurrConnections", "SwapUsage"]
SERVERLESS_RECOMMENDED_ALARMS = [m for m in RECOMMENDED_ALARMS if m != "ReplicationLag"] + ["ThrottledCmds"]
ALARM_NAMESPACE = "AWS/ElastiCache"

_SEVERITY_ORDER = {"critical": 0, "important": 1, "warning": 2, "medium": 3, "low": 4, "info": 5}


def finding(severity: str, message: str, **extra: Any) -> dict:
    return {"severity": severity, "message": message, **extra}


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f["severity"], 9))


class ControlPlane:
    def __init__(
        self,
        config: ControlPlaneConfig | None = None,
        session_factory: Callable[[], Any] | None = None,
        clock: Callable[[], dt.datetime] | None = None,
    ) -> None:
        self.config = config or ControlPlaneConfig.from_env()
        self._session_factory = session_factory
        self._clock = clock or (lambda: dt.datetime.now(dt.UTC))
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
        if not op.startswith(ALLOWED_PREFIXES):  # belt and braces: never call a write API
            raise ValueError(f"refusing non-read-only API call {op!r}")
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
            versions = self._member_engine_versions() if groups else {}
            ctx = self._engine_context({engine.lower() for engine, _ in versions.values()}, False)
            views = [_rg_view(g, versions.get(g.get("ReplicationGroupId")), ctx) for g in groups]
            findings = [{**f, "resource": v["id"]} for v in views for f in v["findings"]]
            return {
                "count": len(groups),
                "findings": _sorted_findings(findings),
                "replication_groups": views,
            }

        return self._guard(run)

    def _member_engine_versions(self) -> dict[str, tuple[str, str]]:
        """Replication group id -> (engine, engine version); best effort, never fails the tool."""
        try:
            clusters = self._paginate("describe_cache_clusters", "CacheClusters")
        except (BotoCoreError, ClientError):
            return {}
        out: dict[str, tuple[str, str]] = {}
        for c in clusters:
            rg = c.get("ReplicationGroupId")
            if rg and c.get("EngineVersion"):
                out.setdefault(rg, (str(c.get("Engine", "")), str(c["EngineVersion"])))
        return out

    def cache_clusters(self, cache_cluster_id: str | None = None, show_nodes: bool = True) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {"ShowCacheNodeInfo": show_nodes}
            if cache_cluster_id:
                kwargs["CacheClusterId"] = cache_cluster_id
            clusters = self._paginate("describe_cache_clusters", "CacheClusters", **kwargs)
            ctx = self._engine_context({str(c.get("Engine", "")).lower() for c in clusters}, bool(clusters))
            views = [_cluster_view(c, ctx) for c in clusters]
            findings = [{**f, "resource": v["id"]} for v in views for f in v["findings"]]
            return {"count": len(clusters), "findings": _sorted_findings(findings), "cache_clusters": views}

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
            findings = [f for c in items for f in _serverless_cache_findings(c)]
            return {"count": len(items), "findings": _sorted_findings(findings), "serverless_caches": _jsonable(items)}

        return self._guard(run)

    def _alarm_targets(self, replication_group_id: str | None) -> list[dict]:
        """What should be alarmed: replication groups (members), standalone clusters, serverless caches."""
        targets: list[dict] = []
        kwargs = {"ReplicationGroupId": replication_group_id} if replication_group_id else {}
        groups = self._paginate("describe_replication_groups", "ReplicationGroups", **kwargs)
        for g in groups:
            members = [str(m) for m in g.get("MemberClusters", [])]
            targets.append(
                {
                    "id": g.get("ReplicationGroupId"),
                    "kind": "replication-group",
                    "members": members,
                    "metrics": [m for m in RECOMMENDED_ALARMS if m != "ReplicationLag" or len(members) > 1],
                }
            )
        if replication_group_id:
            return targets
        in_group = {m for t in targets for m in t["members"]}
        for c in self._paginate("describe_cache_clusters", "CacheClusters"):
            cid = str(c.get("CacheClusterId"))
            if cid in in_group or c.get("ReplicationGroupId"):
                continue
            memcached = str(c.get("Engine", "")).lower() == "memcached"
            targets.append(
                {
                    "id": cid,
                    "kind": "cache-cluster",
                    "members": [cid],
                    "metrics": [
                        m
                        for m in (MEMCACHED_RECOMMENDED_ALARMS if memcached else RECOMMENDED_ALARMS)
                        if m != "ReplicationLag"
                    ],
                }
            )
        ec = self.client("elasticache")
        token = None
        while True:
            page = ec.describe_serverless_caches(**({"NextToken": token} if token else {}))
            for c in page.get("ServerlessCaches", []):
                sid = str(c.get("ServerlessCacheName"))
                targets.append(
                    {"id": sid, "kind": "serverless", "members": [sid], "metrics": list(SERVERLESS_RECOMMENDED_ALARMS)}
                )
            token = page.get("NextToken")
            if not token:
                return targets

    def _describe_alarms(self) -> list[dict]:
        cw = self.client("cloudwatch")
        out: list[dict] = []
        token = None
        while True:
            page = cw.describe_alarms(AlarmTypes=["MetricAlarm"], **({"NextToken": token} if token else {}))
            out.extend(a for a in page.get("MetricAlarms", []) if a.get("Namespace") == ALARM_NAMESPACE)
            token = page.get("NextToken")
            if not token:
                return out

    def alarms(self, replication_group_id: str | None = None) -> dict:
        """CloudWatch alarm coverage for ElastiCache: findings first, then the alarms and per-target gaps.

        Flags alarms in ALARM, INSUFFICIENT_DATA or with actions disabled, and recommended metrics
        (``RECOMMENDED_ALARMS``, plus ThrottledCmds for Serverless) that no alarm covers per member.
        """

        def run() -> dict:
            targets = self._alarm_targets(replication_group_id)
            notes: list[str] = []
            try:
                found = self._describe_alarms()
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "ClientError")
                return {
                    "partial": True,
                    "count": 0,
                    "targets": [{"id": t["id"], "kind": t["kind"], "members": t["members"]} for t in targets],
                    "alarms": [],
                    "findings": [
                        finding("warning", f"cloudwatch:DescribeAlarms failed ({code}): alarm coverage not checked")
                    ],
                    "notes": ["grant cloudwatch:DescribeAlarms to see alarm state and coverage"],
                }
            ids = {m for t in targets for m in t["members"]} | {str(t["id"]) for t in targets}
            if replication_group_id or targets:
                scoped = []
                for a in found:
                    dims = {d.get("Name"): d.get("Value") for d in a.get("Dimensions", [])}
                    ref = dims.get("CacheClusterId") or dims.get("ReplicationGroupId") or dims.get("clusterId")
                    if ref in ids or not targets:
                        scoped.append((a, dims))
            else:
                scoped = [(a, {d.get("Name"): d.get("Value") for d in a.get("Dimensions", [])}) for a in found]
            findings: list[dict] = []
            views = []
            for a, dims in scoped:
                ref = dims.get("CacheClusterId") or dims.get("ReplicationGroupId") or dims.get("clusterId")
                state = a.get("StateValue")
                name = a.get("AlarmName")
                views.append(
                    {
                        "name": name,
                        "metric": a.get("MetricName"),
                        "resource": ref,
                        "state": state,
                        "actions_enabled": bool(a.get("ActionsEnabled")),
                        "has_actions": bool(a.get("AlarmActions")),
                    }
                )
                if state == "ALARM":
                    reason = str(a.get("StateReason", ""))[:200]
                    findings.append(
                        finding("critical", f"alarm {name} is in ALARM: {reason}", resource=ref, alarm=name)
                    )
                elif state == "INSUFFICIENT_DATA":
                    findings.append(
                        finding(
                            "warning", f"alarm {name} is INSUFFICIENT_DATA: it cannot fire", resource=ref, alarm=name
                        )
                    )
                if not a.get("ActionsEnabled"):
                    findings.append(
                        finding(
                            "warning",
                            f"alarm {name} has actions disabled: it will not notify",
                            resource=ref,
                            alarm=name,
                        )
                    )
            target_views = []
            for t in targets:
                covered: dict[str, set[str]] = defaultdict(set)
                for a, dims in scoped:
                    metric = str(a.get("MetricName"))
                    if dims.get("ReplicationGroupId") == t["id"]:
                        covered[metric].update(t["members"])
                    elif (dims.get("CacheClusterId") or dims.get("clusterId")) in t["members"]:
                        covered[metric].add(str(dims.get("CacheClusterId") or dims.get("clusterId")))
                missing = {}
                for metric in t["metrics"]:
                    gap = [m for m in t["members"] if m not in covered[metric]]
                    if gap:
                        missing[metric] = gap
                        findings.append(
                            finding(
                                "warning",
                                f"no alarm on {metric} for {', '.join(gap)} ({t['kind']} {t['id']})",
                                resource=t["id"],
                                metric=metric,
                                members=gap,
                            )
                        )
                target_views.append(
                    {"id": t["id"], "kind": t["kind"], "members": t["members"], "missing_alarms": missing}
                )
            if not targets and not replication_group_id:
                notes.append("no replication groups, clusters or serverless caches found in this region")
            return {
                "count": len(views),
                "findings": _sorted_findings(findings),
                "targets": target_views,
                "alarms": views,
                **({"notes": notes} if notes else {}),
            }

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

    # ------------------------------------------------------------ snapshots
    def snapshots(
        self,
        replication_group_id: str | None = None,
        cache_cluster_id: str | None = None,
        source: str | None = None,
        stale_hours: int = 36,
    ) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {}
            if replication_group_id:
                kwargs["ReplicationGroupId"] = replication_group_id
            if cache_cluster_id:
                kwargs["CacheClusterId"] = cache_cluster_id
            if source:
                kwargs["SnapshotSource"] = source
            snaps = self._paginate("describe_snapshots", "Snapshots", **kwargs)
            now = self._clock()
            views = [_snapshot_view(s, now) for s in snaps]
            findings = _snapshot_findings(views, now, stale_hours)
            return {"count": len(views), "findings": _sorted_findings(findings), "snapshots": views}

        return self._guard(run)

    # ------------------------------------------------------------ users / ACL
    def users(self, engine: str | None = None) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {"Engine": engine} if engine else {}
            users = self._paginate("describe_users", "Users", **kwargs)
            views = [_user_view(u) for u in users]
            findings = [{**f, "resource": v["id"]} for v in views for f in v["findings"]]
            return {"count": len(views), "findings": _sorted_findings(findings), "users": views}

        return self._guard(run)

    def user_groups(self) -> dict:
        def run() -> dict:
            groups = self._paginate("describe_user_groups", "UserGroups")
            views = []
            findings = []
            for g in groups:
                view = {
                    "id": g.get("UserGroupId"),
                    "status": g.get("Status"),
                    "engine": g.get("Engine"),
                    "user_ids": g.get("UserIds", []),
                    "replication_groups": g.get("ReplicationGroups", []),
                    "serverless_caches": g.get("ServerlessCaches", []),
                    "pending_changes": _jsonable(g.get("PendingChanges") or {}),
                }
                views.append(view)
                if not view["replication_groups"] and not view["serverless_caches"]:
                    findings.append(finding("info", "user group is not attached to any cache", resource=view["id"]))
                if view["status"] not in (None, "active"):
                    findings.append(finding("warning", f"user group status is {view['status']}", resource=view["id"]))
            return {"count": len(views), "findings": _sorted_findings(findings), "user_groups": views}

        return self._guard(run)

    # -------------------------------------------------------- global datastores
    def global_replication_groups(self) -> dict:
        def run() -> dict:
            groups = self._paginate(
                "describe_global_replication_groups", "GlobalReplicationGroups", ShowMemberInfo=True
            )
            views = []
            findings = []
            for g in groups:
                gid = g.get("GlobalReplicationGroupId")
                members = [
                    {
                        "replication_group_id": m.get("ReplicationGroupId"),
                        "region": m.get("ReplicationGroupRegion"),
                        "role": m.get("Role"),
                        "status": m.get("Status"),
                        "automatic_failover": m.get("AutomaticFailover"),
                    }
                    for m in g.get("Members", [])
                ]
                views.append(
                    {
                        "id": gid,
                        "description": g.get("GlobalReplicationGroupDescription"),
                        "status": g.get("Status"),
                        "engine": g.get("Engine"),
                        "engine_version": g.get("EngineVersion"),
                        "node_type": g.get("CacheNodeType"),
                        "cluster_mode": g.get("ClusterEnabled"),
                        "transit_encryption": g.get("TransitEncryptionEnabled"),
                        "at_rest_encryption": g.get("AtRestEncryptionEnabled"),
                        "members": members,
                    }
                )
                if g.get("Status") not in (None, "available"):
                    findings.append(finding("warning", f"global datastore status is {g.get('Status')}", resource=gid))
                if len(members) < 2:
                    findings.append(finding("warning", "global datastore has no secondary region", resource=gid))
                for m in members:
                    if m["status"] not in (None, "associated"):
                        findings.append(
                            finding(
                                "warning",
                                f"member {m['replication_group_id']} ({m['region']}) is {m['status']}",
                                resource=gid,
                            )
                        )
            return {"count": len(views), "findings": _sorted_findings(findings), "global_replication_groups": views}

        return self._guard(run)

    # ---------------------------------------------------------- reserved nodes
    def reserved_nodes(self, expiring_days: int = 60) -> dict:
        def run() -> dict:
            reserved = self._paginate("describe_reserved_cache_nodes", "ReservedCacheNodes")
            clusters = self._paginate("describe_cache_clusters", "CacheClusters")
            now = self._clock()
            views = [_reserved_view(r) for r in reserved]
            active = [v for v in views if v["state"] == "active"]
            running: Counter[tuple[str, str]] = Counter()
            for c in clusters:
                if str(c.get("CacheClusterStatus", "")).lower() in {"deleting", "deleted"}:
                    continue
                running[(str(c.get("CacheNodeType")), str(c.get("Engine", "")).lower())] += int(
                    c.get("NumCacheNodes") or 1
                )
            held: Counter[tuple[str, str]] = Counter()
            for v in active:
                held[(str(v["node_type"]), str(v["product"]).lower())] += int(v["count"] or 0)
            coverage = []
            findings = []
            for key in sorted(set(running) | set(held)):
                node_type, product = key
                run_n, res_n = running[key], held[key]
                row = {
                    "node_type": node_type,
                    "engine": product,
                    "running_nodes": run_n,
                    "reserved_nodes": res_n,
                    "on_demand_nodes": max(0, run_n - res_n),
                    "unused_reservations": max(0, res_n - run_n),
                }
                coverage.append(row)
                if row["on_demand_nodes"]:
                    findings.append(
                        finding(
                            "info",
                            f"{row['on_demand_nodes']} on-demand {node_type} {product} node(s) not covered by a reservation",
                        )
                    )
                if row["unused_reservations"]:
                    findings.append(
                        finding(
                            "warning",
                            f"{row['unused_reservations']} reserved {node_type} {product} node(s) have no running match",
                        )
                    )
            for v in active:
                if v["end_time"] and dt.datetime.fromisoformat(v["end_time"]) - now < dt.timedelta(days=expiring_days):
                    findings.append(finding("warning", f"reservation {v['id']} ends {v['end_time']}", resource=v["id"]))
            return {
                "count": len(views),
                "findings": _sorted_findings(findings),
                "coverage": coverage,
                "reserved_cache_nodes": views,
                "note": (
                    "Matching is by exact node type and engine; size-flexible matching within a family is not "
                    "modelled. Serverless caches cannot be reserved."
                ),
            }

        return self._guard(run)

    # ---------------------------------------------------------- service updates
    def service_updates(self, status: str = "available", soon_days: int = 14) -> dict:
        def run() -> dict:
            updates = self._paginate("describe_service_updates", "ServiceUpdates", ServiceUpdateStatus=[status])
            now = self._clock()
            views = []
            findings = []
            for u in updates:
                apply_by = u.get("ServiceUpdateRecommendedApplyByDate")
                view = {
                    "name": u.get("ServiceUpdateName"),
                    "type": u.get("ServiceUpdateType"),
                    "severity": u.get("ServiceUpdateSeverity"),
                    "status": u.get("ServiceUpdateStatus"),
                    "engine": u.get("Engine"),
                    "engine_version": u.get("EngineVersion"),
                    "release_date": _jsonable(u.get("ServiceUpdateReleaseDate")),
                    "recommended_apply_by": _jsonable(apply_by),
                    "auto_update_after_apply_by": u.get("AutoUpdateAfterRecommendedApplyByDate"),
                    "estimated_update_minutes": u.get("EstimatedUpdateTime"),
                    "description": u.get("ServiceUpdateDescription"),
                }
                views.append(view)
                sev = str(view["severity"] or "low")
                name = view["name"]
                if status == "available":
                    if apply_by and apply_by < now:
                        findings.append(
                            finding("critical", f"{name} ({sev}) is past its recommended apply-by date", resource=name)
                        )
                    elif apply_by and apply_by - now < dt.timedelta(days=soon_days):
                        auto = view["auto_update_after_apply_by"]
                        note = " and will be applied automatically after that date" if auto else ""
                        findings.append(
                            finding(
                                "warning",
                                f"{name} ({sev}) is due by {view['recommended_apply_by']}{note}",
                                resource=name,
                            )
                        )
                    elif sev in {"critical", "important"}:
                        findings.append(finding("warning", f"{sev} service update {name} is pending", resource=name))
                    else:
                        findings.append(finding("info", f"{sev} service update {name} is pending", resource=name))
            views.sort(key=lambda v: _SEVERITY_ORDER.get(str(v["severity"]), 9))
            return {"count": len(views), "findings": _sorted_findings(findings), "service_updates": views}

        return self._guard(run)

    # ----------------------------------------------------------- subnet groups
    def subnet_groups(self) -> dict:
        def run() -> dict:
            groups = self._paginate("describe_cache_subnet_groups", "CacheSubnetGroups")
            views = []
            findings = []
            for g in groups:
                subnets = [
                    {"id": s.get("SubnetIdentifier"), "az": (s.get("SubnetAvailabilityZone") or {}).get("Name")}
                    for s in g.get("Subnets", [])
                ]
                azs = {s["az"] for s in subnets if s["az"]}
                name = g.get("CacheSubnetGroupName")
                views.append({"name": name, "vpc_id": g.get("VpcId"), "subnets": subnets, "azs": sorted(azs)})
                if len(azs) < 2:
                    findings.append(
                        finding("warning", f"subnet group spans {len(azs)} AZ(s); Multi-AZ needs 2+", resource=name)
                    )
            return {"count": len(views), "findings": _sorted_findings(findings), "subnet_groups": views}

        return self._guard(run)

    # -------------------------------------------------------------- metrics
    def metrics(
        self,
        cache_cluster_id: str | None = None,
        metrics: list[str] | None = None,
        minutes: int = 60,
        period_seconds: int = 60,
        node_id: str | None = None,
        serverless: bool = False,
        include_series: bool = False,
        replication_group_id: str | None = None,
    ) -> dict:
        problem = _validate_window(minutes, period_seconds)
        if not cache_cluster_id and not replication_group_id:
            problem = "give cache_cluster_id or replication_group_id"
        if problem:
            return {"error": "InvalidArgument", "message": problem}

        def run() -> dict:
            names = metrics or (SERVERLESS_METRICS if serverless else REDIS_METRICS)
            if replication_group_id and not serverless:
                groups = self._paginate(
                    "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=replication_group_id
                )
                targets = [m for g in groups for m in g.get("MemberClusters", [])]
                if not targets:
                    return {"error": "NoMembers", "message": f"replication group {replication_group_id} has no members"}
            else:
                targets = [str(cache_cluster_id)]
            summary, series, findings = self._collect_metrics(
                targets, names, minutes, period_seconds, node_id, serverless
            )
            limits: dict[str, dict] = {}
            if serverless:
                limits = self._serverless_limits(targets)
                for target in targets:
                    findings += _serverless_limit_findings(target, summary[target], limits.get(target), period_seconds)
            single = len(targets) == 1
            out: dict[str, Any] = {
                "cache_cluster_id": cache_cluster_id,
                "replication_group_id": replication_group_id,
                "targets": targets,
                "node_id": node_id,
                "window_minutes": minutes,
                "period_seconds": period_seconds,
                "findings": _sorted_findings(findings),
                "summary": summary[targets[0]] if single else summary,
            }
            if serverless:
                out["serverless_limits"] = {t: _limits_view(limits.get(t), summary[t], period_seconds) for t in targets}
            if include_series:
                out["series"] = series[targets[0]] if single else series
            return out

        return self._guard(run)

    def _collect_metrics(
        self,
        targets: list[str],
        names: list[str],
        minutes: int,
        period_seconds: int,
        node_id: str | None,
        serverless: bool,
        rightsizing: bool = True,
    ) -> tuple[dict[str, dict[str, dict]], dict[str, dict[str, dict]], list[dict]]:
        """GetMetricData for every target/metric; returns (summary, series, findings) keyed by target."""
        end = self._clock()
        start = end - dt.timedelta(minutes=int(minutes))
        queries, idx = [], 0
        for target in targets:
            if serverless:
                dims = [{"Name": "clusterId", "Value": target}]
            else:
                dims = [{"Name": "CacheClusterId", "Value": target}]
                if node_id:
                    dims.append({"Name": "CacheNodeId", "Value": node_id})
            for name in names:
                queries.append(
                    {
                        "Id": f"m{idx}",
                        "Label": f"{target}|{name}",
                        "MetricStat": {
                            "Metric": {"Namespace": "AWS/ElastiCache", "MetricName": name, "Dimensions": dims},
                            "Period": int(period_seconds),
                            "Stat": "Sum" if name in SUM_STAT_METRICS else "Average",
                        },
                        "ReturnData": True,
                    }
                )
                idx += 1
        cw = self.client("cloudwatch")
        points: dict[str, dict[str, list[tuple[dt.datetime, float]]]] = defaultdict(lambda: defaultdict(list))
        for i in range(0, len(queries), MAX_QUERIES_PER_CALL):
            chunk = queries[i : i + MAX_QUERIES_PER_CALL]
            token = None
            while True:
                kwargs: dict[str, Any] = {"MetricDataQueries": chunk, "StartTime": start, "EndTime": end}
                if token:
                    kwargs["NextToken"] = token
                resp = cw.get_metric_data(**kwargs)
                for res in resp.get("MetricDataResults", []):
                    target, _, name = res["Label"].rpartition("|")
                    points[target][name].extend(zip(res.get("Timestamps", []), res.get("Values", []), strict=False))
                token = resp.get("NextToken")
                if not token:
                    break
        series: dict[str, dict[str, dict]] = {}
        summary: dict[str, dict[str, dict]] = {}
        findings: list[dict] = []
        for target in targets:
            series[target], summary[target] = {}, {}
            for name in names:
                pts = sorted(points[target][name], key=lambda p: p[0])  # CloudWatch default is newest first
                series[target][name] = {
                    "timestamps": [t.isoformat() for t, _ in pts],
                    "values": [v for _, v in pts],
                }
                summary[target][name] = _summarize([v for _, v in pts])
            findings += _metric_findings(target, summary[target])
            if rightsizing and not serverless:
                findings += _rightsizing_findings(target, summary[target], minutes)
            if all(s["points"] == 0 for s in summary[target].values()):
                findings.append(
                    finding("info", "no datapoints returned (check the id, region and time window)", resource=target)
                )
        return summary, series, findings

    def _engine_context(self, engines: set[str], with_parameter_groups: bool) -> dict[str, Any]:
        """Engine versions, their parameter group families and parameter group families, best effort.

        Used only to add findings; any API failure just means fewer findings, never a failed tool.
        """
        versions: dict[str, set[str]] = defaultdict(set)
        family_of: dict[tuple[str, str], str] = {}
        for engine in sorted(e for e in engines if e):
            try:
                items = self._paginate("describe_cache_engine_versions", "CacheEngineVersions", Engine=engine)
            except (BotoCoreError, ClientError):
                continue
            for item in items:
                version = str(item.get("EngineVersion", ""))
                versions[engine].add(version)
                if item.get("CacheParameterGroupFamily"):
                    family_of[(engine, version)] = str(item["CacheParameterGroupFamily"])
        parameter_group_family: dict[str, str] = {}
        if with_parameter_groups:
            try:
                groups = self._paginate("describe_cache_parameter_groups", "CacheParameterGroups")
            except (BotoCoreError, ClientError):
                groups = []
            parameter_group_family = {
                str(g.get("CacheParameterGroupName")): str(g["CacheParameterGroupFamily"])
                for g in groups
                if g.get("CacheParameterGroupFamily")
            }
        return {"versions": versions, "family_of": family_of, "parameter_group_family": parameter_group_family}

    def parameter_drift(self, group_a: str, group_b: str) -> dict:
        """Diff two parameter groups: only parameters whose values differ and that one side modified."""

        def run() -> dict:
            def load(name: str) -> dict[str, dict]:
                params = self._paginate("describe_cache_parameters", "Parameters", CacheParameterGroupName=name)
                return {str(p.get("ParameterName")): p for p in params}

            a, b = load(group_a), load(group_b)
            diffs: list[dict] = []
            default_only = 0
            for name in sorted(set(a) & set(b)):
                va, vb = a[name].get("ParameterValue"), b[name].get("ParameterValue")
                if str(va) == str(vb):
                    continue
                if a[name].get("Source") != "user" and b[name].get("Source") != "user":
                    default_only += 1  # different engine defaults, nobody changed anything
                    continue
                diffs.append(
                    {
                        "parameter": name,
                        "value_a": va,
                        "value_b": vb,
                        "source_a": a[name].get("Source"),
                        "source_b": b[name].get("Source"),
                        "change_type": a[name].get("ChangeType") or b[name].get("ChangeType"),
                    }
                )
            families = self._parameter_group_families([group_a, group_b])
            findings = _drift_findings(group_a, group_b, diffs, families)
            return {
                "group_a": group_a,
                "group_b": group_b,
                "families": families,
                "differences": diffs,
                "difference_count": len(diffs),
                "only_in_a": sorted(set(a) - set(b)),
                "only_in_b": sorted(set(b) - set(a)),
                "ignored_default_only_differences": default_only,
                "findings": _sorted_findings(findings),
            }

        return self._guard(run)

    def _parameter_group_families(self, names: list[str]) -> dict[str, str | None]:
        out: dict[str, str | None] = {}
        for name in names:
            try:
                groups = self._paginate(
                    "describe_cache_parameter_groups", "CacheParameterGroups", CacheParameterGroupName=name
                )
            except (BotoCoreError, ClientError):
                groups = []
            out[name] = groups[0].get("CacheParameterGroupFamily") if groups else None
        return out

    # --------------------------------------------------------------- triage
    def triage(self, replication_group_id: str) -> dict:
        """One-call incident summary for a replication group: worst findings first, per-section status."""

        def run() -> dict:
            now = self._clock()
            members: list[str] = []
            sections: list[dict] = []
            findings: list[dict] = []

            def section(name: str, fn: Callable[[], tuple[str, list[dict]]]) -> None:
                try:
                    summary, found = fn()
                except (NoCredentialsError, NoRegionError):
                    raise
                except ClientError as exc:
                    err = exc.response.get("Error", {})
                    code = err.get("Code", "ClientError")
                    if code in _TRIAGE_FATAL:
                        raise
                    detail = f"{code}: {err.get('Message', exc)}"
                except BotoCoreError as exc:
                    detail = f"{type(exc).__name__}: {exc}"
                else:
                    status = _worst_status(found)
                    sections.append({"section": name, "status": status, "summary": summary})
                    findings.extend(
                        {**f, "section": name, "resource": f.get("resource", replication_group_id)} for f in found
                    )
                    return
                sections.append({"section": name, "status": "unavailable", "summary": detail})
                findings.append(
                    finding("warning", f"{name} unavailable ({detail})", resource=replication_group_id, section=name)
                )

            def rg_section() -> tuple[str, list[dict]]:
                groups = self._paginate(
                    "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=replication_group_id
                )
                if not groups:
                    raise _TriageEmpty(f"replication group {replication_group_id} not found")
                g = groups[0]
                members.extend(g.get("MemberClusters", []))
                found = _triage_rg_findings(g)
                summary = (
                    f"status {g.get('Status')}, multi-az {g.get('MultiAZ')}, failover {g.get('AutomaticFailover')}, "
                    f"{len(members)} member(s), {len(g.get('NodeGroups', []))} shard(s)"
                )
                return summary, found

            def events_section() -> tuple[str, list[dict]]:
                events = self._paginate(
                    "describe_events",
                    "Events",
                    SourceIdentifier=replication_group_id,
                    SourceType="replication-group",
                    Duration=TRIAGE_WINDOW_HOURS * 60,
                )
                found, notable = _triage_event_findings(events)
                return f"{len(events)} event(s) in the last {TRIAGE_WINDOW_HOURS}h, {notable} notable", found

            def metrics_section() -> tuple[str, list[dict]]:
                if not members:
                    raise _TriageEmpty("no member clusters known (replication group section failed)")
                summary, _, found = self._collect_metrics(
                    members, TRIAGE_METRICS, TRIAGE_WINDOW_HOURS * 60, 300, None, False, rightsizing=False
                )
                peaks = _triage_peaks(summary)
                text = ", ".join(f"{k} {v['value']:.4g} on {v['member']}" for k, v in peaks.items())
                return f"peaks over {TRIAGE_WINDOW_HOURS}h: {text or 'no datapoints'}", found

            def updates_section() -> tuple[str, list[dict]]:
                actions = self._paginate(
                    "describe_update_actions",
                    "UpdateActions",
                    ReplicationGroupIds=[replication_group_id],
                    UpdateActionStatus=list(_PENDING_ACTION_STATUSES),
                )
                found = _triage_update_findings(actions, now)
                return f"{len(actions)} pending service update action(s)", found

            def snapshots_section() -> tuple[str, list[dict]]:
                snaps = self._paginate("describe_snapshots", "Snapshots", ReplicationGroupId=replication_group_id)
                views = [_snapshot_view(x, now) for x in snaps]
                ages = [v["age_hours"] for v in views if v["status"] == "available" and v["age_hours"] is not None]
                found = _snapshot_findings(views, now, 36)
                text = f"newest available snapshot {min(ages):.0f}h old" if ages else "no available snapshot"
                return text, found

            section("replication_group", rg_section)
            section("events", events_section)
            section("metrics", metrics_section)
            section("service_updates", updates_section)
            section("snapshots", snapshots_section)
            ordered = _sorted_findings(findings)
            return {
                "replication_group_id": replication_group_id,
                "generated_at": now.isoformat(),
                "window_hours": TRIAGE_WINDOW_HOURS,
                "overall": _worst_status(ordered) if ordered else "ok",
                "sections": sections,
                "findings": ordered[:MAX_TRIAGE_FINDINGS],
                "findings_total": len(ordered),
                "truncated": len(ordered) > MAX_TRIAGE_FINDINGS,
            }

        return self._guard(run)

    # ------------------------------------------------------------- overview
    def cluster_overview(self, replication_group_id: str, minutes: int = OVERVIEW_WINDOW_MINUTES) -> dict:
        """One findings-first call for a replication group: topology joined with per-node CloudWatch signals."""
        problem = _validate_window(minutes, 300)
        if problem:
            return {"error": "InvalidArgument", "message": problem}

        def run() -> dict:
            groups = self._paginate(
                "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=replication_group_id
            )
            if not groups:
                return {"error": "NotFound", "message": f"replication group {replication_group_id} not found"}
            g = groups[0]
            versions = self._member_engine_versions()
            engine_version = versions.get(replication_group_id)
            topology = _overview_topology(g, engine_version)
            findings = _rg_findings(g, engine_version) + _reader_findings(g)
            nodes = {n["cluster_id"]: n for s in topology["shards"] for n in s["nodes"]}
            status, summary, series = "ok", {}, {}
            if nodes:
                try:
                    summary, series, _ = self._collect_metrics(
                        list(nodes), OVERVIEW_METRICS, int(minutes), 300, None, False, rightsizing=False
                    )
                except ClientError as exc:
                    err = exc.response.get("Error", {})
                    status = "partial"
                    findings.append(
                        finding(
                            "warning",
                            f"CloudWatch GetMetricData failed ({err.get('Code', 'ClientError')}): "
                            "topology is shown, per-node signals are missing",
                        )
                    )
            for cid, n in nodes.items():
                n["signals"] = {m: _signal(summary.get(cid, {}).get(m)) for m in OVERVIEW_METRICS}
                n["p95"] = {m: _p95(series.get(cid, {}).get(m, {}).get("values", [])) for m in OVERVIEW_P95}
            if summary:
                findings += _overview_outliers(topology["shards"])
                findings += _overview_rightsizing(topology["shards"], g.get("CacheNodeType"), int(minutes))
            for shard in topology["shards"]:
                shard["worst_memory_pct"] = max(
                    (n["signals"]["DatabaseMemoryUsagePercentage"].get("avg") or 0 for n in shard["nodes"]), default=0
                )
            ordered_shards = sorted(topology["shards"], key=lambda sh: -sh["worst_memory_pct"])
            ordered = _sorted_findings(findings)
            return {
                "replication_group_id": replication_group_id,
                "status": status,
                "window_minutes": int(minutes),
                "overall": _worst_status(ordered) if ordered else "ok",
                "topology": {k: v for k, v in topology.items() if k != "shards"},
                "findings": ordered[:MAX_OVERVIEW_FINDINGS],
                "findings_total": len(ordered),
                "truncated": len(ordered) > MAX_OVERVIEW_FINDINGS,
                "shards": ordered_shards[:MAX_OVERVIEW_SHARDS],
                "shards_total": len(ordered_shards),
            }

        return self._guard(run)

    def _serverless_limits(self, targets: list[str]) -> dict[str, dict]:
        """Configured usage limits per serverless cache; best effort, never fails the metrics call."""
        out: dict[str, dict] = {}
        for target in targets:
            try:
                caches = self._paginate("describe_serverless_caches", "ServerlessCaches", ServerlessCacheName=target)
            except (BotoCoreError, ClientError):
                continue
            if caches:
                out[target] = caches[0].get("CacheUsageLimits") or {}
        return out


def _p95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))]


def _signal(s: dict | None) -> dict:
    if not s or not s.get("points"):
        return {}
    return {"avg": s["avg"], "max": s["max"], "latest": s["latest"], "sum": s["sum"]}


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def _overview_topology(g: dict, engine_version: tuple[str, str] | None) -> dict:
    shards = []
    for ng in g.get("NodeGroups", []):
        nodes = [
            {
                "cluster_id": m.get("CacheClusterId"),
                "role": m.get("CurrentRole") or "unknown",
                "az": m.get("PreferredAvailabilityZone"),
            }
            for m in ng.get("NodeGroupMembers", [])
        ]
        shards.append(
            {
                "shard": ng.get("NodeGroupId"),
                "replicas": sum(1 for n in nodes if n["role"] != "primary"),
                "azs": sorted({n["az"] for n in nodes if n["az"]}),
                "reader_endpoint": bool(ng.get("ReaderEndpoint")),
                "nodes": nodes,
            }
        )
    return {
        "shard_count": len(shards),
        "replicas_per_shard": sorted({s["replicas"] for s in shards}),
        "node_type": g.get("CacheNodeType"),
        "automatic_failover": g.get("AutomaticFailover"),
        "multi_az": g.get("MultiAZ"),
        "cluster_mode": g.get("ClusterMode") or ("enabled" if g.get("ClusterEnabled") else "disabled"),
        "engine": engine_version[0] if engine_version else g.get("Engine"),
        "engine_version": engine_version[1] if engine_version else None,
        "az_spread": sorted({a for s in shards for a in s["azs"]}),
        "shards": shards,
    }


def _prod_like(g: dict) -> bool:
    text = f"{g.get('ReplicationGroupId', '')} {g.get('Description', '')}".lower()
    return bool(re.search(r"prod|prd|live", text)) or g.get("MultiAZ") == "enabled"


def _reader_findings(g: dict) -> list[dict]:
    """Missing reader endpoint or no replica in a prod-like group (a single node has no failover target)."""
    out: list[dict] = []
    if not _prod_like(g):
        return out
    cluster_mode = bool(g.get("ClusterEnabled")) or g.get("ClusterMode") == "enabled"
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        replicas = sum(1 for m in members if m.get("CurrentRole") != "primary")
        shard = ng.get("NodeGroupId")
        if replicas < 1:
            out.append(
                finding(
                    "critical",
                    f"shard {shard}: no replicas in a prod-like group; no failover target and no read scaling",
                    resource=shard,
                )
            )
        elif not ng.get("ReaderEndpoint") and not cluster_mode:
            out.append(
                finding(
                    "warning",
                    f"shard {shard}: replicas exist but no reader endpoint is exposed; reads cannot be balanced",
                    resource=shard,
                )
            )
    return out


def _overview_outliers(shards: list[dict]) -> list[dict]:
    """Nodes whose signal is above 1.5x the median of their peers (same role), worst ratio first."""
    out: list[dict] = []
    for role in ("primary", "replica"):
        peers = [(n, s["shard"]) for s in shards for n in s["nodes"] if (n["role"] == "primary") == (role == "primary")]
        for metric in OVERVIEW_METRICS:
            if metric == "ReplicationLag" and role == "primary":
                continue
            vals = [(n["signals"].get(metric, {}).get("avg"), n["cluster_id"], shard) for n, shard in peers]
            vals = [v for v in vals if v[0] is not None]
            if len(vals) < 3:
                continue
            median = _median([v[0] for v in vals])
            if median <= 0:
                continue
            for value, cid, shard in vals:
                if value > OUTLIER_RATIO * median and value >= OUTLIER_FLOORS[metric]:
                    out.append(
                        finding(
                            "warning",
                            f"{role} {cid} (shard {shard}): {metric} avg {value:.4g} is {value / median:.1f}x the "
                            f"{role} median {median:.4g}; skewed keys or traffic",
                            resource=cid,
                            shard=shard,
                            metric=metric,
                            ratio=round(value / median, 2),
                        )
                    )
    return sorted(out, key=lambda f: -f["ratio"])


def _overview_rightsizing(shards: list[dict], node_type: str | None, minutes: int) -> list[dict]:
    primaries = [n for s in shards for n in s["nodes"] if n["role"] == "primary" and n.get("p95")]
    mem = [n["p95"].get("DatabaseMemoryUsagePercentage") for n in primaries]
    cpu = [n["p95"].get("EngineCPUUtilization") for n in primaries]
    if not primaries or any(v is None for v in mem + cpu):
        return []
    mem_p95, cpu_p95 = max(mem), max(cpu)
    window = f"over {minutes} minutes"
    tiered = bool(node_type and re.match(r"cache\.r\dgd\.", node_type))
    out: list[dict] = []
    if mem_p95 < RIGHTSIZE_MEMORY_P95 and cpu_p95 < RIGHTSIZE_CPU_P95:
        msg = (
            f"right-sizing: worst primary memory p95 {mem_p95:.0f}% and CPU p95 {cpu_p95:.0f}% {window}; "
            "a smaller node type (or fewer shards) would likely carry this load"
        )
        if tiered:
            msg += "; data tiering (r6gd) is already in use, check whether the SSD tier is needed at all"
        out.append(finding("info", msg, category="right-sizing"))
    elif mem_p95 >= 70 and cpu_p95 < RIGHTSIZE_CPU_P95 and not tiered:
        out.append(
            finding(
                "info",
                f"right-sizing: memory-bound (p95 {mem_p95:.0f}%) with idle CPU (p95 {cpu_p95:.0f}%) {window}; "
                "consider data tiering (cache.r6gd) to trade cold-key RAM for SSD instead of more shards",
                category="right-sizing",
            )
        )
    return out


def _validate_window(minutes: Any, period_seconds: Any) -> str | None:
    if not isinstance(minutes, int) or isinstance(minutes, bool) or not 1 <= minutes <= 20160:
        return "minutes must be an integer between 1 and 20160"
    if (
        not isinstance(period_seconds, int)
        or isinstance(period_seconds, bool)
        or not 1 <= period_seconds <= 86400
        or period_seconds % 60
    ):
        return "period_seconds must be a multiple of 60 between 60 and 86400"
    return None


def _summarize(vals: list[float]) -> dict:
    if not vals:
        return {"points": 0}
    return {
        "points": len(vals),
        "latest": vals[-1],
        "min": min(vals),
        "max": max(vals),
        "avg": sum(vals) / len(vals),
        "sum": sum(vals),
    }


def _metric_findings(resource: str, summary: dict[str, dict]) -> list[dict]:
    out: list[dict] = []

    def get(name: str, field: str) -> float | None:
        s = summary.get(name) or {}
        return s.get(field) if s.get("points") else None

    def add(sev: str, msg: str) -> None:
        out.append(finding(sev, msg, resource=resource))

    cpu_max, cpu_avg = get("EngineCPUUtilization", "max"), get("EngineCPUUtilization", "avg")
    if cpu_max is not None and cpu_avg is not None and cpu_max > 80:
        add(
            "critical" if cpu_avg > 80 or cpu_max > 90 else "warning",
            f"EngineCPUUtilization max {cpu_max:.0f}% (avg {cpu_avg:.0f}%) above 80%",
        )
    host_cpu = get("CPUUtilization", "max")
    if host_cpu is not None and host_cpu > 90:
        add("warning", f"host CPUUtilization max {host_cpu:.0f}% above 90%")
    mem = get("DatabaseMemoryUsagePercentage", "max")
    if mem is not None and mem > 80:
        add(
            "critical" if mem > 90 else "warning",
            f"DatabaseMemoryUsagePercentage max {mem:.0f}% above {90 if mem > 90 else 80}%",
        )
    evictions = get("Evictions", "sum")
    if evictions:
        add("warning", f"{evictions:.0f} evictions in the window")
    swap = get("SwapUsage", "max")
    if swap is not None and swap > SWAP_WARN_BYTES:
        add("warning", f"SwapUsage max {swap / 1024 / 1024:.0f} MB above 50 MB")
    lag = get("ReplicationLag", "max")
    if lag is not None and lag > 1:
        add("critical" if lag > 10 else "warning", f"ReplicationLag max {lag:.1f}s")
    conns = get("CurrConnections", "max")
    if conns is not None and conns > 0.8 * MAXCLIENTS_DEFAULT:
        add("warning", f"CurrConnections max {conns:.0f} is over 80% of maxclients ({MAXCLIENTS_DEFAULT})")
    throttled = get("ThrottledCmds", "sum")
    if throttled:
        add("warning", f"{throttled:.0f} throttled commands in the window")
    bw = get("NetworkBandwidthAllowanceExceeded", "sum")
    if bw:
        add(
            "warning",
            f"network bandwidth allowance exceeded {bw:.0f} times (packets shaped); consider a larger node type",
        )
    return out


class _TriageEmpty(BotoCoreError):
    """A triage section has nothing to work with; reported as an unavailable section."""

    fmt = "{detail}"

    def __init__(self, detail: str) -> None:
        super().__init__(detail=detail)


def _worst_status(findings: list[dict]) -> str:
    sevs = {f["severity"] for f in findings}
    if "critical" in sevs:
        return "critical"
    if sevs & {"warning", "important"}:
        return "warning"
    return "ok"


def _triage_rg_findings(g: dict) -> list[dict]:
    out: list[dict] = []
    status = g.get("Status")
    if status in {"create-failed", "incompatible-network", "snapshot-failed"}:
        out.append(finding("critical", f"replication group status is {status}"))
    elif status not in (None, "available"):
        out.append(finding("warning", f"replication group status is {status}"))
    if g.get("AutomaticFailover") not in (None, "enabled"):
        out.append(finding("warning", "automatic failover is not enabled: a primary failure needs manual action"))
    if g.get("MultiAZ") not in (None, "enabled"):
        out.append(finding("warning", "Multi-AZ is not enabled"))
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        if ng.get("Status") not in (None, "available"):
            out.append(finding("warning", f"node group {ng.get('NodeGroupId')} status is {ng.get('Status')}"))
        if len(members) == 1:
            out.append(finding("warning", f"node group {ng.get('NodeGroupId')} has no replica: failover is impossible"))
    if g.get("PendingModifiedValues"):
        out.append(finding("info", "has pending modified values"))
    return out


_CRITICAL_EVENT_WORDS = ("failure", "failed", "unreachable", "unavailable")
_WARNING_EVENT_WORDS = ("failover", "replac", "reboot", "restart", "removed", "recover")


def _triage_event_findings(events: list[dict]) -> tuple[list[dict], int]:
    ranked: list[tuple[int, dt.datetime | None, dict]] = []
    for e in events:
        msg = str(e.get("Message", ""))
        low = msg.lower()
        if any(w in low for w in _CRITICAL_EVENT_WORDS):
            sev = "critical"
        elif any(w in low for w in _WARNING_EVENT_WORDS):
            sev = "warning"
        else:
            continue
        when = e.get("Date")
        stamp = when.isoformat() if isinstance(when, dt.datetime) else when
        ranked.append(
            (
                _SEVERITY_ORDER[sev],
                when if isinstance(when, dt.datetime) else None,
                finding(sev, f"event {stamp}: {msg}", resource=e.get("SourceIdentifier")),
            )
        )
    # worst first, newest first within a severity; keep the section bounded
    ranked.sort(key=lambda t: (t[0], -(t[1].timestamp() if t[1] else 0)))
    return [f for _, _, f in ranked[:5]], len(ranked)


def _triage_peaks(summary: dict[str, dict[str, dict]]) -> dict[str, dict]:
    peaks: dict[str, dict] = {}
    for member, metrics in summary.items():
        for name in TRIAGE_METRICS:
            s = metrics.get(name) or {}
            if not s.get("points"):
                continue
            value = s["sum"] if name == "Evictions" else s["max"]
            if name not in peaks or value > peaks[name]["value"]:
                peaks[name] = {"member": member, "value": value}
    return peaks


def _triage_update_findings(actions: list[dict], now: dt.datetime) -> list[dict]:
    out: list[dict] = []
    for a in actions:
        name = a.get("ServiceUpdateName")
        sev = str(a.get("ServiceUpdateSeverity") or "low")
        apply_by = a.get("ServiceUpdateRecommendedApplyByDate")
        if apply_by and apply_by < now:
            out.append(finding("critical", f"{name} ({sev}) is past its recommended apply-by date", resource=name))
        elif sev in {"critical", "important"}:
            out.append(finding("warning", f"{sev} service update {name} is pending", resource=name))
        else:
            out.append(finding("info", f"{sev} service update {name} is pending", resource=name))
    return out


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version))


def _version_findings(engine: str, version: str, ctx: dict[str, Any] | None, eol: bool) -> list[dict]:
    out: list[dict] = []
    if not version:
        return out
    major = _major_minor(version)[0]
    if eol and engine == "redis" and major <= 6:
        out.append(
            finding(
                "warning",
                f"Redis OSS {version} is end-of-life upstream; plan the move to Valkey, the engine ElastiCache recommends",
            )
        )
    known = (ctx or {}).get("versions", {}).get(engine, set())
    newer = [v for v in known if _major_minor(v)[0] == major and _version_tuple(v) > _version_tuple(version)]
    if newer:
        latest = max(newer, key=_version_tuple)
        out.append(finding("info", f"{engine} {version} is behind the newest {major}.x available here ({latest})"))
    return out


def _cluster_findings(c: dict, ctx: dict[str, Any] | None) -> list[dict]:
    out: list[dict] = []
    engine = str(c.get("Engine") or "").lower()
    version = str(c.get("EngineVersion") or "")
    out += _version_findings(engine, version, ctx, eol=True)
    pg = c.get("CacheParameterGroup") or {}
    pg_name = pg.get("CacheParameterGroupName")
    apply_status = pg.get("ParameterApplyStatus")
    if apply_status == "pending-reboot":
        nodes = pg.get("CacheNodeIdsToReboot") or []
        extra = f" (nodes {', '.join(nodes)})" if nodes else ""
        out.append(
            finding(
                "warning", f"parameter group {pg_name} has changes pending a reboot{extra}; they are not active yet"
            )
        )
    elif apply_status not in (None, "in-sync"):
        out.append(finding("info", f"parameter group {pg_name} apply status is {apply_status}"))
    family = (ctx or {}).get("parameter_group_family", {}).get(str(pg_name))
    expected = (ctx or {}).get("family_of", {}).get((engine, version))
    if family and expected and family != expected:
        out.append(
            finding(
                "warning",
                f"parameter group {pg_name} is family {family} but engine {engine} {version} expects {expected}",
            )
        )
    if not c.get("ReplicationGroupId"):  # replication group members are covered by the group-level findings
        if c.get("TransitEncryptionEnabled") is False:
            out.append(finding("warning", "encryption in transit is disabled"))
        if engine in {"redis", "valkey"} and c.get("AuthTokenEnabled") is False:
            out.append(finding("critical", "no authentication: AUTH token is not enabled on this standalone cluster"))
        if c.get("AutoMinorVersionUpgrade") is False:
            out.append(finding("info", "auto minor version upgrade is off"))
    return out


def _drift_findings(group_a: str, group_b: str, diffs: list[dict], families: dict[str, str | None]) -> list[dict]:
    out: list[dict] = []
    fa, fb = families.get(group_a), families.get(group_b)
    if fa and fb and fa != fb:
        out.append(
            finding("warning", f"parameter groups belong to different families ({fa} vs {fb}); compare with care")
        )
    for d in diffs:
        if d["parameter"] in IMPORTANT_PARAMETERS:
            out.append(
                finding(
                    "warning",
                    f"{d['parameter']} differs: {group_a}={d['value_a']!r}, {group_b}={d['value_b']!r}",
                    resource=d["parameter"],
                )
            )
    if diffs:
        out.append(finding("info", f"{len(diffs)} modified parameter(s) differ between {group_a} and {group_b}"))
    else:
        out.append(finding("info", f"no modified parameter differs between {group_a} and {group_b}"))
    return out


def _serverless_cache_findings(c: dict) -> list[dict]:
    name = c.get("ServerlessCacheName")
    engine = str(c.get("Engine") or "").lower()
    out: list[dict] = []

    def add(sev: str, msg: str) -> None:
        out.append(finding(sev, msg, resource=name))

    if c.get("Status") not in (None, "available"):
        add("warning", f"serverless cache status is {c.get('Status')}")
    limits = c.get("CacheUsageLimits") or {}
    if (limits.get("DataStorage") or {}).get("Maximum") is None:
        add("warning", "no DataStorage maximum: stored data (and its cost) can grow without bound")
    if (limits.get("ECPUPerSecond") or {}).get("Maximum") is None:
        add("warning", "no ECPUPerSecond maximum: a runaway client can drive compute cost without a cap")
    if engine != "memcached":
        if not c.get("DailySnapshotTime") and not c.get("SnapshotRetentionLimit"):
            add("warning", "no daily snapshot configured (DailySnapshotTime and SnapshotRetentionLimit are unset)")
        if not c.get("UserGroupId"):
            add("warning", "no user group attached: access is the open default user")
    return out


_STORAGE_UNIT = {"GB": 1024**3, "TB": 1024**4}


def _limits_view(limits: dict | None, summary: dict[str, dict], period_seconds: int) -> dict:
    limits = limits or {}
    storage_max = (limits.get("DataStorage") or {}).get("Maximum")
    unit = (limits.get("DataStorage") or {}).get("Unit", "GB")
    ecpu_max = (limits.get("ECPUPerSecond") or {}).get("Maximum")
    used = summary.get("BytesUsedForCache") or {}
    ecpu = summary.get("ElastiCacheProcessingUnits") or {}
    view: dict[str, Any] = {
        "data_storage_max": storage_max,
        "data_storage_unit": unit,
        "ecpu_per_second_max": ecpu_max,
        "bytes_used_max": used.get("max") if used.get("points") else None,
        "ecpu_per_second_peak": ecpu["max"] / period_seconds if ecpu.get("points") else None,
    }
    if storage_max and view["bytes_used_max"] is not None:
        view["data_storage_used_pct"] = round(
            100 * view["bytes_used_max"] / (storage_max * _STORAGE_UNIT.get(unit, 1024**3)), 1
        )
    if ecpu_max and view["ecpu_per_second_peak"] is not None:
        view["ecpu_used_pct"] = round(100 * view["ecpu_per_second_peak"] / ecpu_max, 1)
    return view


def _serverless_limit_findings(
    resource: str, summary: dict[str, dict], limits: dict | None, period_seconds: int
) -> list[dict]:
    if not limits:
        return []
    view = _limits_view(limits, summary, period_seconds)
    out: list[dict] = []
    pct = view.get("data_storage_used_pct")
    if pct is not None and pct > 80:
        out.append(
            finding(
                "critical" if pct > 90 else "warning",
                f"BytesUsedForCache peaked at {pct:.0f}% of the DataStorage maximum ({view['data_storage_max']} {view['data_storage_unit']}); writes are rejected at the limit",
                resource=resource,
            )
        )
    pct = view.get("ecpu_used_pct")
    if pct is not None and pct > 80:
        out.append(
            finding(
                "critical" if pct >= 100 else "warning",
                f"ElastiCacheProcessingUnits peaked at {pct:.0f}% of the ECPUPerSecond maximum ({view['ecpu_per_second_max']}); requests are throttled at the limit",
                resource=resource,
            )
        )
    return out


def _rightsizing_findings(resource: str, summary: dict[str, dict], minutes: int) -> list[dict]:
    """Downsize / upsize hints from the whole window; 'sustained' means the maximum stayed on one side."""

    def get(name: str, field: str, min_points: int = 1) -> float | None:
        s = summary.get(name) or {}
        return s.get(field) if s.get("points", 0) >= min_points else None

    out: list[dict] = []
    cpu_max = get("EngineCPUUtilization", "max", 3)
    mem_max = get("DatabaseMemoryUsagePercentage", "max", 3)
    evictions = get("Evictions", "sum") or 0
    window = f"over the {minutes}-minute window"
    if cpu_max is not None and mem_max is not None and cpu_max < 10 and mem_max < 30 and not evictions:
        out.append(
            finding(
                "info",
                f"right-sizing: EngineCPUUtilization max {cpu_max:.0f}% and memory max {mem_max:.0f}% {window}; "
                "a smaller node type (or fewer replicas/shards) would likely carry this load",
                resource=resource,
                category="right-sizing",
            )
        )
    if mem_max is not None and mem_max > 80:
        out.append(
            finding(
                "warning",
                f"right-sizing: memory peaked at {mem_max:.0f}% {window}; move to a larger node type or add shards",
                resource=resource,
                category="right-sizing",
            )
        )
    if evictions:
        out.append(
            finding(
                "warning",
                f"right-sizing: {evictions:.0f} evictions {window}; the dataset does not fit, scale up or out",
                resource=resource,
                category="right-sizing",
            )
        )
    return out


_SIZE_RE = re.compile(r"([\d.]+)\s*(bytes?|[KMGT]B)", re.IGNORECASE)
_UNITS = {"B": 1, "BYTE": 1, "BYTES": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}


def _size_bytes(text: str | None) -> int | None:
    m = _SIZE_RE.fullmatch((text or "").strip())
    return int(float(m.group(1)) * _UNITS[m.group(2).upper()]) if m else None


def _snapshot_view(s: dict, now: dt.datetime) -> dict:
    nodes = s.get("NodeSnapshots", [])
    created = [n["SnapshotCreateTime"] for n in nodes if n.get("SnapshotCreateTime")]
    created_at = max(created) if created else None
    sizes = [_size_bytes(n.get("CacheSize")) for n in nodes]
    source = s.get("SnapshotSource")
    return {
        "name": s.get("SnapshotName"),
        "source_id": s.get("ReplicationGroupId") or s.get("CacheClusterId"),
        "status": s.get("SnapshotStatus"),
        "source": source,
        "automatic": source == "automated",
        "engine": s.get("Engine"),
        "engine_version": s.get("EngineVersion"),
        "node_type": s.get("CacheNodeType"),
        "created_at": created_at.isoformat() if created_at else None,
        "age_hours": round((now - created_at).total_seconds() / 3600, 1) if created_at else None,
        "size_bytes": sum(x for x in sizes if x is not None) if sizes and None not in sizes else None,
        "retention_limit_days": s.get("SnapshotRetentionLimit"),
    }


def _snapshot_findings(views: list[dict], now: dt.datetime, stale_hours: int) -> list[dict]:
    findings: list[dict] = []
    if not views:
        return [finding("info", "no snapshots found for this filter")]
    by_source: dict[str, list[dict]] = defaultdict(list)
    for v in views:
        by_source[str(v["source_id"])].append(v)
        if v["status"] == "failed":
            findings.append(finding("warning", f"snapshot {v['name']} failed", resource=v["source_id"]))
    for src, items in by_source.items():
        auto = [v for v in items if v["automatic"] and v["age_hours"] is not None and v["status"] == "available"]
        if not auto:
            findings.append(
                finding("warning", "no available automatic snapshots (backup retention may be 0)", resource=src)
            )
            continue
        newest = min(v["age_hours"] for v in auto)
        if newest > stale_hours:
            findings.append(
                finding("warning", f"retention gap: newest automatic snapshot is {newest:.0f}h old", resource=src)
            )
    old_manual = [v for v in views if not v["automatic"] and (v["age_hours"] or 0) > 90 * 24]
    if old_manual:
        findings.append(finding("info", f"{len(old_manual)} manual snapshot(s) older than 90 days (storage cost)"))
    return findings


def _user_view(u: dict) -> dict:
    auth = u.get("Authentication") or {}
    access = " ".join(str(u.get("AccessString", "")).split())
    tokens = set(access.split())
    full_keys = bool(tokens & {"~*", "allkeys", "%RW~*"})
    full_cmds = bool(tokens & {"+@all", "allcommands"})
    no_password = auth.get("Type") == "no-password" or "nopass" in tokens
    active = "on" in tokens
    uid = u.get("UserId")
    findings = []
    if full_keys and full_cmds:
        sev = "critical" if no_password and active else "warning"
        findings.append(finding(sev, "access string grants all keys and all commands (~* +@all)", resource=uid))
    if no_password:
        findings.append(finding("critical" if active else "warning", "user has no password", resource=uid))
    return {
        "id": uid,
        "name": u.get("UserName"),
        "status": u.get("Status"),
        "engine": u.get("Engine"),
        "authentication_type": auth.get("Type"),
        "password_count": auth.get("PasswordCount"),
        "access_string": access,
        "user_group_ids": u.get("UserGroupIds", []),
        "minimum_engine_version": u.get("MinimumEngineVersion"),
        "findings": findings,
    }


def _reserved_view(r: dict) -> dict:
    start = r.get("StartTime")
    duration = r.get("Duration")
    end = start + dt.timedelta(seconds=int(duration)) if start and duration else None
    return {
        "id": r.get("ReservedCacheNodeId"),
        "node_type": r.get("CacheNodeType"),
        "product": r.get("ProductDescription"),
        "count": r.get("CacheNodeCount"),
        "state": r.get("State"),
        "offering_type": r.get("OfferingType"),
        "start_time": _jsonable(start),
        "end_time": end.isoformat() if end else None,
    }


def _major_minor(version: str) -> tuple[int, int]:
    nums = [int(x) for x in re.findall(r"\d+", version)[:2]]
    return (nums[0] if nums else 0, nums[1] if len(nums) > 1 else 0)


def _rg_findings(g: dict, engine_version: tuple[str, str] | None, ctx: dict[str, Any] | None = None) -> list[dict]:
    out: list[dict] = []
    if g.get("Status") not in (None, "available"):
        out.append(finding("warning", f"status is {g.get('Status')}"))
    if g.get("MultiAZ") not in (None, "enabled"):
        out.append(finding("warning", "Multi-AZ is not enabled"))
    if g.get("AutomaticFailover") not in (None, "enabled"):
        out.append(finding("warning", "automatic failover is not enabled"))
    if g.get("AtRestEncryptionEnabled") is False:
        out.append(finding("warning", "encryption at rest is disabled"))
    if g.get("TransitEncryptionEnabled") is False:
        out.append(finding("warning", "encryption in transit is disabled"))
    if g.get("AuthTokenEnabled") is False and not g.get("UserGroupIds"):
        out.append(finding("critical", "no authentication: no AUTH token and no RBAC user group"))
    if g.get("AutoMinorVersionUpgrade") is False:
        out.append(finding("info", "auto minor version upgrade is off"))
    if g.get("SnapshotRetentionLimit") == 0:
        out.append(finding("warning", "automatic snapshots are off (SnapshotRetentionLimit is 0)"))
    if engine_version:
        engine, version = engine_version
        if engine.lower() == "redis" and _major_minor(version) < (7, 0):
            out.append(finding("warning", f"Redis OSS {version} is old (< 7.0); plan an upgrade (Valkey or 7.x)"))
        out += _version_findings(engine.lower(), version, ctx, eol=False)
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        azs = {m.get("PreferredAvailabilityZone") for m in members if m.get("PreferredAvailabilityZone")}
        if len(members) > 1 and len(azs) == 1:
            out.append(
                finding(
                    "warning",
                    f"node group {ng.get('NodeGroupId')}: primary and replicas all sit in {next(iter(azs))}; an AZ outage takes the whole shard",
                )
            )
    if g.get("PendingModifiedValues"):
        out.append(finding("info", "has pending modified values"))
    return out


def _rg_view(g: dict, engine_version: tuple[str, str] | None = None, ctx: dict[str, Any] | None = None) -> dict:
    return {
        "id": g.get("ReplicationGroupId"),
        "description": g.get("Description"),
        "status": g.get("Status"),
        "engine": g.get("Engine") or (engine_version[0] if engine_version else None),
        "engine_version": engine_version[1] if engine_version else None,
        "cluster_mode": g.get("ClusterMode") or ("enabled" if g.get("ClusterEnabled") else "disabled"),
        "node_type": g.get("CacheNodeType"),
        "multi_az": g.get("MultiAZ"),
        "automatic_failover": g.get("AutomaticFailover"),
        "transit_encryption": g.get("TransitEncryptionEnabled"),
        "at_rest_encryption": g.get("AtRestEncryptionEnabled"),
        "auth_token_enabled": g.get("AuthTokenEnabled"),
        "auto_minor_version_upgrade": g.get("AutoMinorVersionUpgrade"),
        "member_clusters": g.get("MemberClusters", []),
        "configuration_endpoint": _jsonable(g.get("ConfigurationEndpoint")),
        "findings": _rg_findings(g, engine_version, ctx),
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


def _cluster_view(c: dict, ctx: dict[str, Any] | None = None) -> dict:
    return {
        "findings": _cluster_findings(c, ctx),
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
