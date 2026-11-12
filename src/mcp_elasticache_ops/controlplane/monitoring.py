"""CloudWatch metrics, alarms and maintenance views."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
)

from ._shared import (
    _PENDING_ACTION_STATUSES,
    AUTH_FAILURE_METRICS,
    FLEET_DEADLINE_SECONDS,
    MAX_FLEET_FINDINGS,
    MEMCACHED_METRICS,
    NETWORK_ALLOWANCE_METRICS,
    SERVERLESS_METRICS,
    _fleet_deadline_error,
    _fleet_failed,
    _jsonable,
    _limits_view,
    _monotonic,
    _serverless_limit_findings,
    _sorted_findings,
    _validate_window,
    _version_findings,
    finding,
    is_burstable,
)
from .inventory import _InventoryMixin
from .restore import _node_memory_bytes

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
    "GlobalDatastoreReplicationLag",
    "ReplicationBytes",
    "NetworkBytesIn",
    "NetworkBytesOut",
    *NETWORK_ALLOWANCE_METRICS,
    "SwapUsage",
    "FreeableMemory",
    *AUTH_FAILURE_METRICS,
]


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


_DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def _window_minutes(spec: str, weekly: bool) -> list[tuple[int, int]]:
    """Minute-of-week intervals for ``ddd:hh:mm-ddd:hh:mm`` (weekly) or ``hh:mm-hh:mm`` (daily) windows."""
    try:
        start_s, end_s = spec.lower().split("-")

        def point(text: str) -> int:
            parts = text.split(":")
            if len(parts) == 3:
                return _DAYS.index(parts[0]) * 1440 + int(parts[1]) * 60 + int(parts[2])
            return int(parts[0]) * 60 + int(parts[1])

        start, end = point(start_s), point(end_s)
    except (ValueError, IndexError):
        return []
    week = 7 * 1440
    if weekly:
        end = end if end > start else end + week
        return [(start, end), (start - week, end - week)]
    end = end if end > start else end + 1440
    return [(d * 1440 + start, d * 1440 + end) for d in range(-1, 7)]


def _windows_overlap(maintenance: str, snapshot: str) -> bool:
    weekly = _window_minutes(maintenance, True)
    daily = _window_minutes(snapshot, False)
    return any(a < d and c < b for a, b in weekly for c, d in daily)


MEMCACHED_MISS_RATIO_WARN = 0.5  # GetMisses over GetHits+GetMisses above this: the cache is mostly missing
MEMCACHED_MISS_MIN_REQUESTS = 1000  # fewer gets than this in the window say nothing about the ratio
MEMCACHED_MEMORY_WARN = 0.9  # item bytes over this share of the node memory
MEMCACHED_CPU_WARN = 80.0
MEMCACHED_CONN_LIMIT = 65_000  # ElastiCache default max_simultaneous_connections for memcached


def _memcached_findings(target: str, summary: dict[str, dict], node_type: str | None) -> list[dict]:
    """Memcached-only findings (the shared ones cover evictions, swap and host CPU above 90%)."""

    def val(name: str, field: str) -> float | None:
        s = summary.get(name) or {}
        return s.get(field) if s.get("points") else None

    out: list[dict] = []
    cpu = val("CPUUtilization", "max")
    if cpu is not None and cpu > MEMCACHED_CPU_WARN:
        out.append(
            finding(
                "warning",
                f"memcached CPUUtilization max {cpu:.0f}% above {MEMCACHED_CPU_WARN:.0f}% (it is multi-threaded; "
                "this is host CPU, not one core)",
                resource=target,
            )
        )
    conns = val("CurrConnections", "max")
    if conns is not None and conns > 0.8 * MEMCACHED_CONN_LIMIT:
        out.append(
            finding(
                "warning",
                f"memcached CurrConnections max {conns:.0f} is over 80% of the connection limit "
                f"({MEMCACHED_CONN_LIMIT}); new clients are refused at the limit",
                resource=target,
            )
        )
    items, free = val("BytesUsedForCacheItems", "max"), val("FreeableMemory", "min")
    total = _node_memory_bytes(node_type)
    if items is not None and total and items / total > MEMCACHED_MEMORY_WARN:
        out.append(
            finding(
                "warning",
                f"BytesUsedForCacheItems max {items / 1024**2:.0f} MB is {items / total:.0%} of the node memory "
                f"({node_type}); the cache is full and evicts on every new item",
                resource=target,
            )
        )
    elif (
        items is not None
        and free is not None
        and items + free > 0
        and free / (items + free) < 1 - MEMCACHED_MEMORY_WARN
    ):
        out.append(
            finding(
                "warning",
                f"FreeableMemory min {free / 1024**2:.0f} MB is under 10% of item bytes plus free memory; "
                "little headroom left",
                resource=target,
            )
        )
    hits, misses = val("GetHits", "sum"), val("GetMisses", "sum")
    if hits is not None and misses is not None and hits + misses >= MEMCACHED_MISS_MIN_REQUESTS:
        ratio = misses / (hits + misses)
        if ratio > MEMCACHED_MISS_RATIO_WARN:
            out.append(
                finding(
                    "info",
                    f"GetMisses are {ratio:.0%} of gets in the window ({misses:.0f} of {hits + misses:.0f}); "
                    "check TTLs, key naming and whether evictions are dropping hot items",
                    resource=target,
                )
            )
    return out


class _MonitoringMixin(_InventoryMixin):
    def alarms_fan_out(self, replication_group_id: str | None = None, region: str | None = None) -> dict:
        """``alarms`` per region in ELASTICACHE_REGIONS when no group is named (fleet mode).

        Findings and alarms carry their ``region``; a region that fails (AccessDenied, timeout, deadline) is
        listed in ``region_errors`` and never hides the others."""
        targets = self._target_regions(region)
        if replication_group_id or len(targets) == 1:
            return self.in_region(region if replication_group_id else targets[0]).alarms(replication_group_id)
        deadline = _monotonic() + FLEET_DEADLINE_SECONDS
        findings: list[dict] = []
        alarms: list[dict] = []
        tgts: list[dict] = []
        failures: dict[str, dict] = {}
        partial = False
        for target in targets:
            if _monotonic() >= deadline:
                failures[str(target)] = _fleet_deadline_error()
                continue
            result = self.in_region(target).alarms(None)
            if _fleet_failed(result):
                failures[str(target)] = result
                continue
            partial = partial or bool(result.get("partial"))
            findings += [{**f, "region": target} for f in result.get("findings", [])]
            alarms += [{**a, "region": target} for a in result.get("alarms", [])]
            tgts += [{**t, "region": target} for t in result.get("targets", [])]
        ordered = _sorted_findings(findings)
        out: dict[str, Any] = {
            "regions": [str(t) for t in targets],
            "count": len(alarms),
            "findings": ordered[:MAX_FLEET_FINDINGS],
            "findings_total": len(ordered),
            "truncated": len(ordered) > MAX_FLEET_FINDINGS,
            "targets": tgts,
            "alarms": alarms,
        }
        if partial:
            out["partial"] = True
        if failures:
            out["region_errors"] = failures
        return out

    def maintenance_fan_out(self, replication_group_id: str | None = None, region: str | None = None) -> dict:
        """``maintenance`` per region in ELASTICACHE_REGIONS when no group is named (fleet mode).

        Findings carry their ``region``; a failing region lands in ``region_errors`` and never hides the others."""
        targets = self._target_regions(region)
        if replication_group_id or len(targets) == 1:
            return self.in_region(region if replication_group_id else targets[0]).maintenance(replication_group_id)
        deadline = _monotonic() + FLEET_DEADLINE_SECONDS
        findings: list[dict] = []
        pending: list[dict] = []
        windows: list[dict] = []
        failures: dict[str, dict] = {}
        partial = False
        for target in targets:
            if _monotonic() >= deadline:
                failures[str(target)] = _fleet_deadline_error()
                continue
            result = self.in_region(target).maintenance(None)
            if _fleet_failed(result):
                failures[str(target)] = result
                continue
            partial = partial or bool(result.get("partial"))
            findings += [{**f, "region": target} for f in result.get("findings", [])]
            pending += [{**u, "region": target} for u in result.get("pending_updates", [])]
            windows += [{**w, "region": target} for w in result.get("windows", [])]
        ordered = _sorted_findings(findings)
        out: dict[str, Any] = {
            "regions": [str(t) for t in targets],
            "findings": ordered[:MAX_FLEET_FINDINGS],
            "findings_total": len(ordered),
            "truncated": len(ordered) > MAX_FLEET_FINDINGS,
            "pending_updates": pending,
            "windows": windows,
        }
        if partial:
            out["partial"] = True
        if failures:
            out["region_errors"] = failures
        return out

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
                    "metrics": [m for m in RECOMMENDED_ALARMS if m != "ReplicationLag" or len(members) > 1]
                    + (["CPUCreditBalance"] if is_burstable(g.get("CacheNodeType")) else []),
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
                    ]
                    + (["CPUCreditBalance"] if not memcached and is_burstable(c.get("CacheNodeType")) else []),
                }
            )
        for c in self._paginate_token("describe_serverless_caches", "ServerlessCaches"):
            sid = str(c.get("ServerlessCacheName"))
            targets.append(
                {"id": sid, "kind": "serverless", "members": [sid], "metrics": list(SERVERLESS_RECOMMENDED_ALARMS)}
            )
        return targets

    def _describe_alarms(self) -> list[dict]:
        cw = self.client("cloudwatch")
        out: list[dict] = []
        pages = self._pages(
            "describe_alarms",
            lambda t: cw.describe_alarms(AlarmTypes=["MetricAlarm"], **({"NextToken": t} if t else {})),
            "NextToken",
        )
        for page in pages:
            out.extend(a for a in page.get("MetricAlarms", []) if a.get("Namespace") == ALARM_NAMESPACE)
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

    # ------------------------------------------------------------- maintenance
    def maintenance(self, replication_group_id: str | None = None) -> dict:
        """Pending service updates, maintenance and snapshot windows and engine end-of-life in one pass.

        Read-only (DescribeUpdateActions, DescribeServiceUpdates, DescribeCacheClusters). Flags required
        updates past their apply-by date, a maintenance window that overlaps the snapshot window of the same
        node, and engines that are end-of-life. A denied Describe call is reported as ``partial``."""

        def run() -> dict:
            now = self._clock()
            findings: list[dict] = []
            notes: list[str] = []

            def attempt(label: str, call: Callable[[], list[dict]]) -> list[dict] | None:
                try:
                    return call()
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code", "ClientError")
                    findings.append(finding("warning", f"{label} failed ({code}): that part was not checked"))
                    notes.append(f"grant elasticache:{label} to complete this report")
                    return None

            scope = {"ReplicationGroupIds": [replication_group_id]} if replication_group_id else {}
            actions = attempt(
                "DescribeUpdateActions",
                lambda: self._paginate(
                    "describe_update_actions",
                    "UpdateActions",
                    UpdateActionStatus=list(_PENDING_ACTION_STATUSES),
                    **scope,
                ),
            )
            catalog = (
                None
                if replication_group_id
                else attempt(
                    "DescribeServiceUpdates",
                    lambda: self._paginate(
                        "describe_service_updates", "ServiceUpdates", ServiceUpdateStatus=["available"]
                    ),
                )
            )
            clusters = attempt(
                "DescribeCacheClusters",
                lambda: [
                    c
                    for c in self._paginate("describe_cache_clusters", "CacheClusters")
                    if not replication_group_id or c.get("ReplicationGroupId") == replication_group_id
                ],
            )

            pending: dict[str, dict] = {}
            for a in actions or []:
                name = str(a.get("ServiceUpdateName"))
                sev = str(a.get("ServiceUpdateSeverity") or "low")
                apply_by = a.get("ServiceUpdateRecommendedApplyByDate")
                row = pending.setdefault(
                    name,
                    {
                        "name": name,
                        "severity": sev,
                        "type": a.get("ServiceUpdateType"),
                        "recommended_apply_by": _jsonable(apply_by),
                        "overdue": bool(apply_by and apply_by < now),
                        "status": a.get("UpdateActionStatus"),
                        "targets": [],
                    },
                )
                row["targets"].append(a.get("CacheClusterId") or a.get("ReplicationGroupId"))
            for name, row in pending.items():
                n = len(row["targets"])
                if row["overdue"]:
                    findings.append(
                        finding(
                            "critical",
                            f"required update {name} ({row['severity']}) is past its apply-by date "
                            f"{row['recommended_apply_by']} on {n} target(s)",
                            resource=name,
                        )
                    )
                elif row["severity"] in {"critical", "important"}:
                    findings.append(
                        finding(
                            "warning",
                            f"{row['severity']} service update {name} is pending on {n} target(s)",
                            resource=name,
                        )
                    )
            for u in catalog or []:
                name = str(u.get("ServiceUpdateName"))
                apply_by = u.get("ServiceUpdateRecommendedApplyByDate")
                if name in pending or not (apply_by and apply_by < now):
                    continue
                findings.append(
                    finding(
                        "warning",
                        f"service update {name} is available and past its recommended apply-by date "
                        "(no pending action recorded)",
                        resource=name,
                    )
                )

            windows = []
            for c in clusters or []:
                cid = c.get("CacheClusterId")
                maint = c.get("PreferredMaintenanceWindow")
                snap = c.get("SnapshotWindow")
                engine = str(c.get("Engine") or "").lower()
                version = str(c.get("EngineVersion") or "")
                windows.append(
                    {
                        "cluster": cid,
                        "replication_group": c.get("ReplicationGroupId"),
                        "engine": engine,
                        "engine_version": version,
                        "maintenance_window": maint,
                        "snapshot_window": snap,
                    }
                )
                if maint and snap and _windows_overlap(maint, snap):
                    findings.append(
                        finding(
                            "warning",
                            f"{cid}: maintenance window {maint} overlaps snapshot window {snap}; "
                            "move one so maintenance does not run during a backup",
                            resource=cid,
                        )
                    )
                for f in _version_findings(engine, version, None, eol=True):
                    if "end-of-life" in f["message"]:
                        findings.append({**f, "resource": cid})
            ordered = _sorted_findings(findings)
            out: dict[str, Any] = {
                "generated_at": now.isoformat(),
                "pending_updates": sorted(pending.values(), key=lambda r: (not r["overdue"], r["name"])),
                "windows": windows,
                "findings": ordered[:MAX_FLEET_FINDINGS],
                "findings_total": len(ordered),
                "truncated": len(ordered) > MAX_FLEET_FINDINGS,
            }
            if replication_group_id:
                out["replication_group_id"] = replication_group_id
            if notes:
                out["partial"] = True
                out["notes"] = sorted(set(notes))
            return out

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
            engine_note: str | None = None
            node_type: str | None = None
            if metrics:
                names = metrics
            elif serverless:
                names = SERVERLESS_METRICS
            elif cache_cluster_id and not replication_group_id:
                names, engine_note, node_type = self._default_metric_names(str(cache_cluster_id))
            else:
                names = REDIS_METRICS
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
            if engine_note == "memcached":
                for target in targets:
                    findings += _memcached_findings(target, summary[target], node_type)
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
            if engine_note:
                out["engine"] = engine_note
            if serverless:
                out["serverless_limits"] = {t: _limits_view(limits.get(t), summary[t], period_seconds) for t in targets}
            if include_series:
                out["series"] = series[targets[0]] if single else series
            return out

        return self._guard(run)

    def _default_metric_names(self, cluster_id: str) -> tuple[list[str], str | None, str | None]:
        """Default metric list for one cache cluster: the Memcached set when DescribeCacheClusters says memcached.

        Best effort: when the describe call fails the Redis list is used, which is what earlier versions did."""
        try:
            found = self._paginate("describe_cache_clusters", "CacheClusters", CacheClusterId=cluster_id)
        except (BotoCoreError, ClientError):
            return REDIS_METRICS, None, None
        cluster = found[0] if found else {}
        engine = str(cluster.get("Engine") or "").lower() or None
        names = MEMCACHED_METRICS if engine == "memcached" else REDIS_METRICS
        return names, engine, cluster.get("CacheNodeType")

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
