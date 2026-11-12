"""Cluster overview rules: topology, readers, outliers and rightsizing."""

from __future__ import annotations

import re

from ._shared import (
    finding,
)

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


MAX_FLEET_GROUPS_PER_REGION = 20


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
