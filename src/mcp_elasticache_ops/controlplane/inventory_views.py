"""Inventory views: replication group and cluster summaries and engine-version helpers."""

from __future__ import annotations

import datetime as dt
import re
from typing import Any

from ._shared import (
    _CRITICAL_EVENT_WORDS,
    _auth_token_age_days,
    _cluster_findings,
    _jsonable,
    _rg_findings,
)

GLOBAL_LAG_WINDOW_MINUTES = 60


MAX_GLOBAL_SECONDARIES = 6  # secondary regions inspected per global datastore (each costs 3 API calls)


HEALTHY_GLOBAL_MEMBER_STATUSES = frozenset({"associated", "available"})


EVENT_SOURCE_TYPES = frozenset(
    {
        "cache-cluster",
        "cache-parameter-group",
        "cache-security-group",
        "cache-subnet-group",
        "replication-group",
        "serverless-cache",
        "user",
        "user-group",
    }
)


MAX_EVENTS_RETURNED = 100


MAX_EVENT_FINDINGS = 50


# aws_events treats a failover as critical (a primary was lost) and maintenance as a warning.
_EVENTS_CRITICAL_WORDS = (*_CRITICAL_EVENT_WORDS, "not available", "failover")


_EVENTS_WARNING_WORDS = ("replac", "reboot", "restart", "removed", "recover", "maintenance")


def _event_severity(message: str) -> str:
    low = message.lower()
    if any(w in low for w in _EVENTS_CRITICAL_WORDS):
        return "critical"
    if any(w in low for w in _EVENTS_WARNING_WORDS):
        return "warning"
    return "info"


def _event_time(event: dict) -> float:
    when = event.get("Date")
    return when.timestamp() if isinstance(when, dt.datetime) else 0.0


def _event_stamp(event: dict) -> str:
    when = event.get("Date")
    return when.isoformat() if isinstance(when, dt.datetime) else str(when)


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", version))


def _engine_version_views(items: list[dict], prefix: str | None) -> list[dict]:
    views = [
        {
            "version": str(i.get("EngineVersion", "")),
            "family": i.get("CacheParameterGroupFamily"),
            "description": i.get("CacheEngineVersionDescription"),
        }
        for i in items
        if not prefix or str(i.get("EngineVersion", "")).startswith(prefix)
    ]
    return sorted(views, key=lambda v: _version_key(v["version"]), reverse=True)


def _latest_per_major(views: list[dict], engine: str) -> list[dict]:
    """Newest listed version of each major (views are sorted newest first)."""
    seen: set[int] = set()
    out: list[dict] = []
    for v in views:
        key = _version_key(v["version"])
        major = key[0] if key else -1
        if major not in seen:
            seen.add(major)
            out.append({**v, "engine": engine, "reason": f"latest minor in major {major}"})
    return out


def _log_delivery_view(obj: dict) -> list[dict]:
    return [
        {
            "log_type": d.get("LogType"),
            "destination_type": d.get("DestinationType"),
            "log_format": d.get("LogFormat"),
            "status": d.get("Status"),
            "message": d.get("Message"),
        }
        for d in obj.get("LogDeliveryConfigurations") or []
    ]


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
        "transit_encryption_mode": g.get("TransitEncryptionMode"),
        "auth_token_enabled": g.get("AuthTokenEnabled"),
        "auth_token_age_days": _auth_token_age_days(g, ctx),
        "data_tiering": g.get("DataTiering"),
        "network_type": g.get("NetworkType"),
        "ip_discovery": g.get("IpDiscovery"),
        "log_delivery": _log_delivery_view(g),
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
        "transit_encryption_mode": c.get("TransitEncryptionMode"),
        "auth_token_age_days": _auth_token_age_days(c, ctx),
        "network_type": c.get("NetworkType"),
        "ip_discovery": c.get("IpDiscovery"),
        "log_delivery": _log_delivery_view(c),
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
