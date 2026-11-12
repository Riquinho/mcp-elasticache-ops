"""Replication groups, clusters, serverless caches, snapshots, global datastores, events and catalogs."""

from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from typing import Any

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
)

from .. import memcached
from ..quirks import parameter_risks, quirks_for
from ..quirks import summary as quirk_summary
from ._core import _CoreMixin
from ._shared import (
    _SEVERITY_ORDER,
    GLOBAL_LAG_METRIC,
    _error_code,
    _error_result,
    _jsonable,
    _serverless_cache_findings,
    _serverless_snapshot_findings,
    _serverless_snapshot_view,
    _snapshot_findings,
    _snapshot_view,
    _sorted_findings,
    finding,
)
from .group_audit import GROUP_AUDIT_MAX_FINDINGS, group_audit_findings
from .inventory_views import (  # noqa: F401
    _EVENTS_CRITICAL_WORDS,
    _EVENTS_WARNING_WORDS,
    EVENT_SOURCE_TYPES,
    GLOBAL_LAG_CRITICAL_SECONDS,
    GLOBAL_LAG_WARN_SECONDS,
    GLOBAL_LAG_WINDOW_MINUTES,
    HEALTHY_GLOBAL_MEMBER_STATUSES,
    MAX_EVENT_FINDINGS,
    MAX_EVENTS_RETURNED,
    MAX_GLOBAL_SECONDARIES,
    _cluster_view,
    _engine_version_views,
    _event_severity,
    _event_stamp,
    _event_time,
    _latest_per_major,
    _log_delivery_view,
    _rg_view,
    _version_key,
)
from .restore import (
    BACKUP_AUDIT_MANUAL_DAYS,
    BACKUP_AUDIT_MAX_FINDINGS,
    BACKUP_AUDIT_STALE_HOURS,
    MAX_RESTORE_SNAPSHOTS,
    RESTORE_STALE_HOURS,
    backup_audit_findings,
    group_restore_findings,
    serverless_restore_findings,
)

MAX_AUDITED_GROUPS = 25  # DescribeCacheParameters calls made by aws_parameter_groups


_READINESS_RANK = {"blocked": 0, "attention": 1, "ready": 2}


def _datastore_readiness(view: dict) -> dict:
    """Failover verdict for one global datastore built from its ``global_replication_groups`` view.

    ``blocked``: a failover to a secondary would lose or stall (not available, no secondary, a secondary not
    associated, or lag above the critical threshold). ``attention``: it would work but land on different hardware
    or with lag above the warning threshold. ``ready`` otherwise. Unread secondaries (no regional data) are not
    counted against them."""
    members = view.get("members", [])
    primary = next((m for m in members if m.get("role") == "PRIMARY"), None)
    secondaries = [m for m in members if m.get("role") == "SECONDARY"]
    blocked: list[str] = []
    attention: list[str] = []
    if view.get("status") not in (None, "available"):
        blocked.append(f"global datastore status is {view.get('status')}")
    if not secondaries:
        blocked.append("no secondary region")
    primary_type, primary_version = view.get("node_type"), view.get("engine_version")
    rows = []
    for m in secondaries:
        label = f"{m.get('replication_group_id')} ({m.get('region')})"
        lag = (m.get("replication_lag") or {}).get("max")
        if m.get("status") not in HEALTHY_GLOBAL_MEMBER_STATUSES | {None}:
            blocked.append(f"{label} is {m.get('status')}")
        if lag is not None and lag > GLOBAL_LAG_CRITICAL_SECONDS:
            blocked.append(f"{label} replication lag {lag:.1f} s is above {GLOBAL_LAG_CRITICAL_SECONDS:g} s")
        elif lag is not None and lag > GLOBAL_LAG_WARN_SECONDS:
            attention.append(f"{label} replication lag {lag:.1f} s is above {GLOBAL_LAG_WARN_SECONDS:g} s")
        if m.get("node_type") and primary_type and m["node_type"] != primary_type:
            attention.append(f"{label} node type {m['node_type']} differs from the primary ({primary_type})")
        if m.get("engine_version") and primary_version and m["engine_version"] != primary_version:
            attention.append(
                f"{label} engine version {m['engine_version']} differs from the primary ({primary_version})"
            )
        rows.append(
            {
                "replication_group_id": m.get("replication_group_id"),
                "region": m.get("region"),
                "status": m.get("status"),
                "node_type": m.get("node_type"),
                "engine_version": m.get("engine_version"),
                "replication_lag_max": lag,
            }
        )
    level = "blocked" if blocked else "attention" if attention else "ready"
    return {
        "id": view.get("id"),
        "primary_region": primary.get("region") if primary else None,
        "status": view.get("status"),
        "engine_version": primary_version,
        "node_type": primary_type,
        "readiness": level,
        "reasons": blocked + attention,
        "secondaries": rows,
    }


class _InventoryMixin(_CoreMixin):
    def replication_groups_fan_out(self, replication_group_id: str | None = None, region: str | None = None) -> dict:
        """``replication_groups`` over every region in ELASTICACHE_REGIONS (or just ``region``).

        A region that does not hold ``replication_group_id`` is skipped quietly; other failures are
        reported per region and never hide the regions that answered."""
        targets = self._target_regions(region)
        if len(targets) == 1:
            return self.in_region(targets[0]).replication_groups(replication_group_id)
        views: list[dict] = []
        findings: list[dict] = []
        failures: dict[str, dict] = {}
        for target in targets:
            result = self.in_region(target).replication_groups(replication_group_id)
            if "replication_groups" not in result:
                if result.get("error") != "ReplicationGroupNotFoundFault":
                    failures[str(target)] = result
                continue
            views.extend({**v, "region": target} for v in result["replication_groups"])
            findings.extend({**f, "region": target} for f in result["findings"])
        out: dict[str, Any] = {
            "regions": [str(t) for t in targets],
            "count": len(views),
            "findings": _sorted_findings(findings),
            "replication_groups": views,
        }
        if failures:
            out["region_errors"] = failures
        return out

    # ---------------------------------------------------------------- tools
    def replication_groups(self, replication_group_id: str | None = None) -> dict:
        def run() -> dict:
            kwargs = {"ReplicationGroupId": replication_group_id} if replication_group_id else {}
            groups = self._paginate("describe_replication_groups", "ReplicationGroups", **kwargs)
            versions = self._member_engine_versions() if groups else {}
            ctx = self._engine_context({engine.lower() for engine, _ in versions.values()}, False)
            views = [_rg_view(g, versions.get(g.get("ReplicationGroupId", "")), ctx) for g in groups]
            findings = [{**f, "resource": v["id"]} for v in views for f in v["findings"]]
            return {
                "count": len(groups),
                "findings": _sorted_findings(findings),
                "replication_groups": views,
            }

        return self._guard(run)

    def _member_clusters(self) -> list[dict]:
        """All cache clusters; best effort, never fails the tool."""
        try:
            return self._paginate("describe_cache_clusters", "CacheClusters")
        except (BotoCoreError, ClientError):
            return []

    def _member_engine_versions(self, clusters: list[dict] | None = None) -> dict[str, tuple[str, str]]:
        """Replication group id -> (engine, engine version); best effort, never fails the tool."""
        out: dict[str, tuple[str, str]] = {}
        for c in self._member_clusters() if clusters is None else clusters:
            rg = c.get("ReplicationGroupId")
            if rg and c.get("EngineVersion"):
                out.setdefault(rg, (str(c.get("Engine", "")), str(c["EngineVersion"])))
        return out

    def _subnet_group_azs(self, clusters: list[dict], replication_group_id: str) -> tuple[str, set[str]] | None:
        """Subnet group name and AZs of a replication group, from the member data already fetched.

        Makes one extra DescribeCacheSubnetGroups call only when a member names its subnet group; best effort."""
        name = next(
            (
                c["CacheSubnetGroupName"]
                for c in clusters
                if c.get("ReplicationGroupId") == replication_group_id and c.get("CacheSubnetGroupName")
            ),
            None,
        )
        if not name:
            return None
        try:
            groups = self._paginate("describe_cache_subnet_groups", "CacheSubnetGroups", CacheSubnetGroupName=name)
        except (BotoCoreError, ClientError):
            return None
        if not groups:
            return None
        return name, {
            az for sn in groups[0].get("Subnets", []) if (az := (sn.get("SubnetAvailabilityZone") or {}).get("Name"))
        }

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

    def memcached_discovery(
        self, cache_cluster_id: str, host: str | None = None, port: int | None = None, timeout: float = 5.0
    ) -> dict:
        """Diff a Memcached cluster's auto-discovery config (``config get cluster``) with DescribeCacheClusters nodes.

        ``host`` defaults to the cluster's configuration endpoint. Findings first; an unreachable endpoint is a
        finding, never an exception."""

        def run() -> dict:
            clusters = self._paginate(
                "describe_cache_clusters", "CacheClusters", CacheClusterId=cache_cluster_id, ShowCacheNodeInfo=True
            )
            cluster = next((c for c in clusters if c.get("CacheClusterId") == cache_cluster_id), None)
            if cluster is None:
                return _error_result("CacheClusterNotFound", f"no cache cluster {cache_cluster_id!r}")
            if str(cluster.get("Engine", "")).lower() != "memcached":
                return _error_result(
                    "NotMemcached", f"{cache_cluster_id} runs {cluster.get('Engine')}: discovery applies to memcached"
                )
            report = memcached.discovery_report(cluster, host, port, timeout)
            aws_nodes = [
                f"{(n.get('Endpoint') or {}).get('Address')}:{(n.get('Endpoint') or {}).get('Port')}"
                for n in cluster.get("CacheNodes", [])
            ]
            return {**report, "aws_nodes": aws_nodes}

        return self._guard(run)

    def serverless_caches(self) -> dict:
        def run() -> dict:
            items = self._paginate_token("describe_serverless_caches", "ServerlessCaches")
            findings = [f for c in items for f in _serverless_cache_findings(c)]
            return {"count": len(items), "findings": _sorted_findings(findings), "serverless_caches": _jsonable(items)}

        return self._guard(run)

    def serverless_snapshots(
        self,
        serverless_cache_name: str | None = None,
        snapshot_type: str | None = None,
        stale_hours: int = 24,
    ) -> dict:
        def run() -> dict:
            kwargs: dict[str, Any] = {}
            if serverless_cache_name:
                kwargs["ServerlessCacheName"] = serverless_cache_name
            if snapshot_type:
                kwargs["SnapshotType"] = snapshot_type
            snaps = self._paginate_token("describe_serverless_cache_snapshots", "ServerlessCacheSnapshots", **kwargs)
            notes: list[str] = []
            caches: list[dict] | None
            try:
                caches = self._paginate_token(
                    "describe_serverless_caches",
                    "ServerlessCaches",
                    **({"ServerlessCacheName": serverless_cache_name} if serverless_cache_name else {}),
                )
            except (BotoCoreError, ClientError) as exc:
                caches = None
                notes.append(
                    f"per-cache retention skipped: DescribeServerlessCaches failed ({_error_code(exc)}); "
                    "only the snapshot list is checked"
                )
            now = self._clock()
            views = [_serverless_snapshot_view(s, now) for s in snaps]
            findings = _serverless_snapshot_findings(views, caches, now, stale_hours)
            retention = [
                {
                    "cache": c.get("ServerlessCacheName"),
                    "retention_limit_days": c.get("SnapshotRetentionLimit"),
                    "daily_snapshot_time": c.get("DailySnapshotTime"),
                }
                for c in caches or []
            ]
            return {
                "count": len(views),
                "findings": _sorted_findings(findings),
                "serverless_snapshots": views,
                "cache_retention": retention,
                **({"partial": True, "notes": notes} if caches is None else {}),
            }

        return self._guard(run)

    def events(self, source_identifier: str | None = None, source_type: str | None = None, hours: int = 24) -> dict:
        """DescribeEvents, findings first: classified events (worst, then newest), counts per source, capped raw list."""
        if source_type and source_type not in EVENT_SOURCE_TYPES:
            return {
                "error": "InvalidArgument",
                "message": f"source_type must be one of: {', '.join(sorted(EVENT_SOURCE_TYPES))}",
            }

        def run() -> dict:
            window = max(1, min(int(hours), 14 * 24))
            kwargs: dict[str, Any] = {"Duration": window * 60}
            if source_identifier:
                kwargs["SourceIdentifier"] = source_identifier
            if source_type:
                kwargs["SourceType"] = source_type
            events = self._paginate("describe_events", "Events", **kwargs)
            events.sort(key=_event_time, reverse=True)
            by_source = Counter(str(e.get("SourceIdentifier") or "unknown") for e in events)
            classified = [(_event_severity(str(e.get("Message", ""))), e) for e in events]
            findings = [
                finding(
                    sev,
                    f"event {_event_stamp(e)}: {e.get('Message', '')}",
                    resource=e.get("SourceIdentifier"),
                    source_type=e.get("SourceType"),
                )
                for sev, e in classified
            ]
            findings = _sorted_findings(findings)  # stable: newest first inside a severity
            return {
                "window_hours": window,
                "count": len(events),
                "findings": findings[:MAX_EVENT_FINDINGS],
                "findings_truncated": len(findings) > MAX_EVENT_FINDINGS,
                "by_severity": dict(Counter(sev for sev, _ in classified)),
                "by_source": dict(by_source.most_common()),
                "events": _jsonable(events[:MAX_EVENTS_RETURNED]),
                "truncated": len(events) > MAX_EVENTS_RETURNED,
            }

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

    def snapshot_restore_readiness(
        self,
        replication_group_id: str | None = None,
        serverless_cache_name: str | None = None,
        stale_hours: int = RESTORE_STALE_HOURS,
    ) -> dict:
        """Can this group or serverless cache be restored from what exists today? Findings first.

        DescribeSnapshots / DescribeServerlessCacheSnapshots plus the group (or cache) for retention, KMS key and
        target node size. Read-only; exactly one of the two ids is required."""
        if bool(replication_group_id) == bool(serverless_cache_name):
            return {
                "error": "InvalidArgument",
                "message": "pass exactly one of replication_group_id or serverless_cache_name",
            }
        if not 1 <= int(stale_hours) <= 24 * 30:
            return {"error": "InvalidArgument", "message": "stale_hours must be between 1 and 720"}

        def run() -> dict:
            now = self._clock()
            if serverless_cache_name:
                caches = self._paginate_token(
                    "describe_serverless_caches", "ServerlessCaches", ServerlessCacheName=serverless_cache_name
                )
                if not caches:
                    return {"error": "NotFound", "message": f"serverless cache {serverless_cache_name} not found"}
                snaps = self._paginate_token(
                    "describe_serverless_cache_snapshots",
                    "ServerlessCacheSnapshots",
                    ServerlessCacheName=serverless_cache_name,
                )
                views = [_serverless_snapshot_view(s, now) for s in snaps]
                findings = serverless_restore_findings(caches[0], snaps, views, stale_hours)
                resource, kind, retention = serverless_cache_name, "serverless", caches[0].get("SnapshotRetentionLimit")
            else:
                groups = self._paginate(
                    "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=replication_group_id
                )
                if not groups:
                    return {"error": "NotFound", "message": f"replication group {replication_group_id} not found"}
                snaps = self._paginate("describe_snapshots", "Snapshots", ReplicationGroupId=replication_group_id)
                members = [c for c in self._member_clusters() if c.get("ReplicationGroupId") == replication_group_id]
                views = [_snapshot_view(s, now) for s in snaps]
                findings = group_restore_findings(groups[0], snaps, views, members, stale_hours)
                resource, kind = str(replication_group_id), "replication-group"
                retention = groups[0].get("SnapshotRetentionLimit")
            ordered = _sorted_findings(findings)
            newest = sorted(views, key=lambda v: v["age_hours"] if v["age_hours"] is not None else 1e9)
            return {
                "resource": resource,
                "kind": kind,
                "retention_limit_days": retention,
                "overall": ordered[0]["severity"] if ordered else "ok",
                "findings": ordered,
                "snapshot_count": len(views),
                "snapshots": newest[:MAX_RESTORE_SNAPSHOTS],
                "snapshots_truncated": len(newest) > MAX_RESTORE_SNAPSHOTS,
            }

        return self._guard(run)

    def backup_audit(
        self, stale_hours: int = BACKUP_AUDIT_STALE_HOURS, manual_days: int = BACKUP_AUDIT_MANUAL_DAYS
    ) -> dict:
        """Snapshot retention and freshness across every group and standalone cluster. Findings first.

        DescribeReplicationGroups, DescribeCacheClusters and DescribeSnapshots (all paginated and bounded);
        a failing DescribeSnapshots degrades to retention-only findings with ``partial``."""
        if not 1 <= int(stale_hours) <= 24 * 30 or not 1 <= int(manual_days) <= 3650:
            return {
                "error": "InvalidArgument",
                "message": "stale_hours must be 1-720 and manual_days 1-3650",
            }

        def run() -> dict:
            now = self._clock()
            groups = self._paginate("describe_replication_groups", "ReplicationGroups")
            clusters = self._paginate("describe_cache_clusters", "CacheClusters")
            sources: dict[str, int | None] = {
                str(g["ReplicationGroupId"]): g.get("SnapshotRetentionLimit") for g in groups
            }
            members: set[str] = set()
            for c in clusters:
                cid = str(c.get("CacheClusterId"))
                if c.get("ReplicationGroupId"):
                    members.add(cid)
                elif str(c.get("Engine", "")).lower() in ("redis", "valkey"):
                    sources[cid] = c.get("SnapshotRetentionLimit")
            for g in groups:
                members.update(str(m) for m in g.get("MemberClusters", []))
            notes: list[str] = []
            try:
                views = [_snapshot_view(s, now) for s in self._paginate("describe_snapshots", "Snapshots")]
            except (BotoCoreError, ClientError) as exc:
                views = []
                notes.append(f"DescribeSnapshots failed ({_error_code(exc)}); only retention was checked")
            if notes:
                found = [
                    finding(
                        "warning",
                        f"{k}: SnapshotRetentionLimit is 0, automatic backups are off",
                        resource=k,
                        category="retention-off",
                    )
                    for k, v in sorted(sources.items())
                    if v == 0
                ]
            else:
                found = backup_audit_findings(sources, views, stale_hours, manual_days, members)
            ordered = _sorted_findings(found)
            return {
                "sources_checked": len(sources),
                "snapshots_checked": len(views),
                "findings": ordered[:BACKUP_AUDIT_MAX_FINDINGS],
                **({"findings_truncated": len(ordered)} if len(ordered) > BACKUP_AUDIT_MAX_FINDINGS else {}),
                **({"partial": True, "notes": notes} if notes else {}),
            }

        return self._guard(run)

    def replication_group_audit(self, replication_group_id: str | None = None) -> dict:
        """HA and configuration posture of every replication group (or one) in a single call. Findings first.

        DescribeReplicationGroups plus DescribeCacheClusters (both paginated); each finding names the tool that
        covers the topic in depth. A failing DescribeCacheClusters degrades to group-level checks with ``partial``."""

        def run() -> dict:
            kwargs = {"ReplicationGroupId": replication_group_id} if replication_group_id else {}
            groups = self._paginate("describe_replication_groups", "ReplicationGroups", **kwargs)
            if replication_group_id and not groups:
                return {"error": "NotFound", "message": f"replication group {replication_group_id} not found"}
            notes: list[str] = []
            try:
                clusters = self._paginate("describe_cache_clusters", "CacheClusters")
            except (BotoCoreError, ClientError) as exc:
                clusters = []
                notes.append(f"DescribeCacheClusters failed ({_error_code(exc)}); node-level checks were skipped")
            by_group: dict[str, list[dict]] = {}
            for c in clusters:
                if c.get("ReplicationGroupId"):
                    by_group.setdefault(str(c["ReplicationGroupId"]), []).append(c)
            found: list[dict] = []
            worst: dict[str, int] = {}
            for g in groups:
                gid = str(g.get("ReplicationGroupId"))
                mine = group_audit_findings(g, by_group.get(gid, []))
                worst[gid] = len(mine)
                found += mine
            ordered = _sorted_findings(found)
            counts: dict[str, int] = {}
            for f in ordered:
                counts[f["severity"]] = counts.get(f["severity"], 0) + 1
            return {
                "summary": {
                    "groups_checked": len(groups),
                    "groups_with_findings": sum(1 for n in worst.values() if n),
                    "severity_counts": counts,
                },
                "findings": ordered[:GROUP_AUDIT_MAX_FINDINGS],
                **({"findings_truncated": len(ordered)} if len(ordered) > GROUP_AUDIT_MAX_FINDINGS else {}),
                **({"partial": True, "notes": notes} if notes else {}),
            }

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
                    if m["status"] not in HEALTHY_GLOBAL_MEMBER_STATUSES | {None}:
                        findings.append(
                            finding(
                                "warning",
                                f"member {m['replication_group_id']} ({m['region']}) is {m['status']}",
                                resource=gid,
                            )
                        )
                findings += self._secondary_readiness(g, members)
            return {"count": len(views), "findings": _sorted_findings(findings), "global_replication_groups": views}

        return self._guard(run)

    def global_datastore_failover_readiness(self) -> dict:
        """Failover readiness per global datastore, from ``global_replication_groups`` (same Describe calls and
        GlobalDatastoreReplicationLag reads). Findings first, then one verdict per datastore, worst first."""

        def run() -> dict:
            base = self.global_replication_groups()
            if "global_replication_groups" not in base:
                return base
            datastores = sorted(
                (_datastore_readiness(v) for v in base["global_replication_groups"]),
                key=lambda d: _READINESS_RANK[d["readiness"]],
            )
            findings = list(base["findings"])
            if not datastores:
                findings.append(finding("info", "no global datastores in this region"))
            return {"count": len(datastores), "findings": _sorted_findings(findings), "datastores": datastores}

        return self._guard(run)

    def _secondary_readiness(self, g: dict, members: list[dict]) -> list[dict]:
        """Failover-readiness findings for the secondary regions of a global datastore.

        Per secondary (at most MAX_GLOBAL_SECONDARIES): its replication group (node type, member nodes), one
        member's engine version and ``GlobalDatastoreReplicationLag`` in the secondary's own region. Each member
        dict gets a ``replication_lag`` summary. Best effort: a region that cannot be read yields an info finding."""
        gid = g.get("GlobalReplicationGroupId")
        out: list[dict] = []
        secondaries = [m for m in members if m["role"] == "SECONDARY" and m["replication_group_id"] and m["region"]]
        if len(secondaries) > MAX_GLOBAL_SECONDARIES:
            out.append(
                finding(
                    "info", f"only the first {MAX_GLOBAL_SECONDARIES} secondary regions were inspected", resource=gid
                )
            )
        for m in secondaries[:MAX_GLOBAL_SECONDARIES]:
            label = f"{m['replication_group_id']} ({m['region']})"
            try:
                regional = self.in_region(m["region"])
                groups = regional._paginate(
                    "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=m["replication_group_id"]
                )
                member_ids = (groups[0].get("MemberClusters") or []) if groups else []
                node_type = groups[0].get("CacheNodeType") if groups else None
                version = None
                if member_ids:
                    clusters = regional._paginate(
                        "describe_cache_clusters", "CacheClusters", CacheClusterId=member_ids[0]
                    )
                    version = clusters[0].get("EngineVersion") if clusters else None
                if member_ids:
                    summary, _, found = regional._collect_metrics(
                        member_ids,
                        [GLOBAL_LAG_METRIC],
                        GLOBAL_LAG_WINDOW_MINUTES,
                        60,
                        None,
                        False,
                        rightsizing=False,
                    )
                    lags = [s[GLOBAL_LAG_METRIC] for s in summary.values() if s[GLOBAL_LAG_METRIC]["points"]]
                    if lags:
                        m["replication_lag"] = max(lags, key=lambda s: s["max"])
                    out += [
                        {**f, "resource": gid, "message": f"secondary {label}: {f['message']}"}
                        for f in found
                        if GLOBAL_LAG_METRIC in f["message"]
                    ]
            except (BotoCoreError, ClientError, ValueError) as exc:
                out.append(
                    finding("info", f"secondary {label} could not be inspected: {_error_code(exc)}", resource=gid)
                )
                continue
            m["node_type"], m["engine_version"] = node_type, version
            if node_type and g.get("CacheNodeType") and node_type != g["CacheNodeType"]:
                out.append(
                    finding(
                        "warning",
                        f"secondary {label} node type {node_type} differs from the primary ({g['CacheNodeType']}); "
                        "a failover could land on a differently sized node",
                        resource=gid,
                    )
                )
            if version and g.get("EngineVersion") and version != g["EngineVersion"]:
                out.append(
                    finding(
                        "warning",
                        f"secondary {label} engine version {version} differs from the primary ({g['EngineVersion']})",
                        resource=gid,
                    )
                )
        return out

    # ------------------------------------------------- engine versions, parameter groups
    def engine_versions(self, engine: str, version_prefix: str | None = None) -> dict:
        def run() -> dict:
            items = self._paginate("describe_cache_engine_versions", "CacheEngineVersions", Engine=engine)
            views = _engine_version_views(items, version_prefix)
            notes: list[str] = []
            targets = _latest_per_major(views, engine)
            findings: list[dict] = []
            if engine == "redis":
                try:
                    valkey = _engine_version_views(
                        self._paginate("describe_cache_engine_versions", "CacheEngineVersions", Engine="valkey"), None
                    )
                except (BotoCoreError, ClientError) as exc:
                    valkey = []
                    notes.append(f"Valkey versions unavailable: {_error_code(exc)}")
                if valkey:
                    newest = valkey[0]
                    targets.append(
                        {**newest, "engine": "valkey", "reason": "latest Valkey; supported upgrade path from Redis OSS"}
                    )
                    findings.append(
                        finding(
                            "info",
                            f"Valkey {newest['version']} (family {newest['family']}) is available as an upgrade target",
                        )
                    )
            for t in targets:
                found = quirks_for(t.get("engine", engine), t.get("version"))
                if found:
                    t["quirks"] = [quirk_summary(q) for q in found]
            return {
                "engine": engine,
                "version_prefix": version_prefix,
                "count": len(views),
                "findings": _sorted_findings(findings),
                "upgrade_targets": targets,
                "versions": views,
                **({"notes": notes} if notes else {}),
            }

        return self._guard(run)

    def parameter_groups(self, audit_settings: bool = True) -> dict:
        """Groups joined with running clusters; with ``audit_settings``, risky ``Source=user`` values of the custom
        groups in use (rules in ``quirks.PARAM_RULES``), at most ``MAX_AUDITED_GROUPS`` groups."""

        def run() -> dict:
            groups = self._paginate("describe_cache_parameter_groups", "CacheParameterGroups")
            notes: list[str] = []
            try:
                clusters = self._paginate("describe_cache_clusters", "CacheClusters")
            except (BotoCoreError, ClientError) as exc:
                clusters = None
                notes.append(f"cluster listing unavailable ({_error_code(exc)}); in-use detection skipped")
            users: dict[str, list[str]] = defaultdict(list)
            running: dict[str, set[tuple[str, str]]] = defaultdict(set)
            for c in clusters or []:
                name = (c.get("CacheParameterGroup") or {}).get("CacheParameterGroupName")
                if name:
                    users[str(name)].append(str(c.get("CacheClusterId")))
                    running[str(name)].add((str(c.get("Engine", "")).lower(), str(c.get("EngineVersion", ""))))
            ctx = self._engine_context({e for pairs in running.values() for e, _ in pairs}, False)
            views, findings = [], []
            for g in groups:
                name = str(g.get("CacheParameterGroupName"))
                family = g.get("CacheParameterGroupFamily")
                custom = not name.startswith("default.")
                members = sorted(users.get(name, []))
                views.append(
                    {
                        "name": name,
                        "family": family,
                        "description": g.get("Description"),
                        "custom": custom,
                        "in_use": bool(members) if clusters is not None else None,
                        "used_by": members,
                    }
                )
                if clusters is not None and custom and not members:
                    findings.append(
                        finding(
                            "info", f"custom parameter group {name} is not used by any cache cluster", resource=name
                        )
                    )
                for engine, version in sorted(running.get(name, ())):
                    expected = ctx["family_of"].get((engine, version))
                    if family and expected and family != expected:
                        findings.append(
                            finding(
                                "warning",
                                f"parameter group {name} is family {family} but {engine} {version} expects {expected}",
                                resource=name,
                            )
                        )
            audited: list[str] = []
            if audit_settings:
                todo = [
                    str(g.get("CacheParameterGroupName"))
                    for g in groups
                    if not str(g.get("CacheParameterGroupName")).startswith("default.")
                    and (clusters is None or users.get(str(g.get("CacheParameterGroupName"))))
                ]
                if len(todo) > MAX_AUDITED_GROUPS:
                    notes.append(f"settings audit covers {MAX_AUDITED_GROUPS} of {len(todo)} custom groups")
                    todo = todo[:MAX_AUDITED_GROUPS]
                family_of_group = {
                    str(g.get("CacheParameterGroupName")): g.get("CacheParameterGroupFamily") for g in groups
                }
                for name in todo:
                    try:
                        params = self._paginate(
                            "describe_cache_parameters", "Parameters", CacheParameterGroupName=name, Source="user"
                        )
                    except (BotoCoreError, ClientError) as exc:
                        notes.append(
                            f"settings audit stopped at {name}: DescribeCacheParameters failed ({_error_code(exc)})"
                        )
                        break
                    audited.append(name)
                    values = {str(p.get("ParameterName")): str(p.get("ParameterValue", "")) for p in params}
                    for risk in parameter_risks(family_of_group[name], values):
                        findings.append(
                            finding(
                                risk.rule.severity,
                                risk.message(name),
                                resource=name,
                                category="parameter-risk",
                                parameter=risk.parameter,
                                value=risk.value,
                                recommended=risk.rule.recommended,
                                rule=risk.rule.key,
                            )
                        )
            return {
                "count": len(views),
                "findings": _sorted_findings(findings),
                "parameter_groups": views,
                **({"settings_audited": audited} if audit_settings else {}),
                **({"partial": True, "notes": notes} if notes else {}),
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
        return {
            "versions": versions,
            "family_of": family_of,
            "parameter_group_family": parameter_group_family,
            "now": self._clock(),
        }
