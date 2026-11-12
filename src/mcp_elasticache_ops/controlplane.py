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
            views = [_rg_view(g, versions.get(g.get("ReplicationGroupId"))) for g in groups]
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
                if all(s["points"] == 0 for s in summary[target].values()):
                    findings.append(
                        finding(
                            "info", "no datapoints returned (check the id, region and time window)", resource=target
                        )
                    )
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
            if include_series:
                out["series"] = series[targets[0]] if single else series
            return out

        return self._guard(run)


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


def _rg_findings(g: dict, engine_version: tuple[str, str] | None) -> list[dict]:
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
    if g.get("PendingModifiedValues"):
        out.append(finding("info", "has pending modified values"))
    return out


def _rg_view(g: dict, engine_version: tuple[str, str] | None = None) -> dict:
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
        "findings": _rg_findings(g, engine_version),
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
