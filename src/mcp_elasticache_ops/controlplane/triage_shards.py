"""Shard balance: per-shard metric rules for aws_shard_balance."""

from __future__ import annotations

from ._shared import finding
from .triage_overview import _median

# aws_shard_balance: one GetMetricData call per node-group member, nothing from the data plane.
SHARD_METRICS = [
    "EngineCPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "NetworkBytesIn",
    "NetworkBytesOut",
    "CurrItems",
    "ReplicationLag",
]


SHARD_WINDOW_MINUTES = 60


MAX_SHARD_MEMBERS = 100  # members queried (one call each); primaries first


MAX_HOT_SHARD_FINDINGS = 5


SHARD_HOT_RATIO = 2.0  # hot shard: CPU above this multiple of the median shard ...


SHARD_HOT_CPU = 50.0  # ... and above this absolute EngineCPUUtilization (percent)


SHARD_PINNED_CPU = 90.0  # a primary at or above this ...


SHARD_IDLE_CPU = 20.0  # ... while every other shard stays under this is a hot-key signature


SHARD_MEMORY_RATIO = 1.5


SHARD_MEMORY_POINTS = 20.0  # memory skew needs this many percentage points over the median shard


SHARD_ITEMS_RATIO = 2.0


SHARD_TRAFFIC_RATIO = 3.0


SHARD_LAG_RATIO = 3.0  # a replica whose max ReplicationLag is this multiple of the median replica ...


SHARD_LAG_SECONDS = 1.0  # ... and above this many seconds is a lagging-replica outlier


MAX_LAG_OUTLIERS = 3


# ------------------------------------------------------------------ shard balance


def _shard_layout(g: dict) -> list[dict]:
    """Shards of a replication group as shard/members dicts, the primary first in each member list."""
    out = []
    for ng in g.get("NodeGroups", []):
        found = [(m.get("CacheClusterId"), m.get("CurrentRole")) for m in ng.get("NodeGroupMembers", [])]
        ids = [str(cid) for cid, _ in found if cid]
        primary = next((str(cid) for cid, role in found if cid and role == "primary"), None)
        ordered = ([primary] if primary else []) + [cid for cid in ids if cid != primary]
        out.append({"shard": str(ng.get("NodeGroupId", "")), "members": ordered, "has_primary": primary is not None})
    return out


def _shard_stats(shard: dict, summary: dict[str, dict[str, dict]]) -> dict:
    """One shard's signals, read from its primary (the first member); replicas add the read-side CPU peak."""
    members = shard["members"]
    primary = members[0] if members else None

    def pick(member: str | None, name: str, key: str) -> float | None:
        s = (summary.get(member or "") or {}).get(name) or {}
        return s.get(key) if s.get("points") else None

    replica_cpu = [pick(m, "EngineCPUUtilization", "max") for m in members[1:]]
    replica_lag = {m: pick(m, "ReplicationLag", "max") for m in members[1:]}
    return {
        "shard": shard["shard"],
        "primary": primary if shard["has_primary"] else None,
        "members": members,
        "cpu_avg": pick(primary, "EngineCPUUtilization", "avg"),
        "cpu_p95": pick(primary, "EngineCPUUtilization", "p95"),
        "cpu_max": pick(primary, "EngineCPUUtilization", "max"),
        "memory_avg": pick(primary, "DatabaseMemoryUsagePercentage", "avg"),
        "memory_max": pick(primary, "DatabaseMemoryUsagePercentage", "max"),
        "network_in_avg_bytes": pick(primary, "NetworkBytesIn", "avg"),
        "network_out_avg_bytes": pick(primary, "NetworkBytesOut", "avg"),
        "curr_items": pick(primary, "CurrItems", "latest"),
        "replica_cpu_max": max((v for v in replica_cpu if v is not None), default=None),
        "replica_lag_max": {m: v for m, v in replica_lag.items() if v is not None},
    }


def _shard_balance_findings(stats: list[dict]) -> list[dict]:
    out: list[dict] = []
    label = {x["shard"]: x["primary"] or (x["members"][0] if x["members"] else "?") for x in stats}
    if len(stats) < 2:
        out.append(
            finding(
                "info",
                "single-shard group: skew between shards cannot be assessed; for a hot key on one primary use "
                "node_clients, node_commandstats and node_keyspace_sample",
                category="shard-balance",
            )
        )
        return out
    for x in stats:
        if x["cpu_avg"] is None and x["memory_avg"] is None:
            out.append(finding("info", f"shard {x['shard']}: no datapoints returned for {label[x['shard']]}"))
    cpu = [x for x in stats if x["cpu_avg"] is not None]
    pinned: str | None = None
    if len(cpu) >= 2:
        median = _median([x["cpu_avg"] for x in cpu])
        hottest = max(cpu, key=lambda x: x["cpu_avg"])
        others = [x["cpu_avg"] for x in cpu if x is not hottest]
        if hottest["cpu_avg"] >= SHARD_PINNED_CPU and all(v < SHARD_IDLE_CPU for v in others):
            pinned = hottest["shard"]
            out.append(
                finding(
                    "critical",
                    f"shard {pinned} primary {label[pinned]} is pinned at {hottest['cpu_avg']:.0f}% "
                    f"EngineCPUUtilization (p95 {hottest['cpu_p95']:.0f}%) while the other {len(others)} shard(s) "
                    f"stay under {max(others):.0f}%: the hot-key signature (one key or hash slot), not a capacity "
                    "problem, so more shards will not help. Find the key with node_clients, node_commandstats and "
                    "node_keyspace_sample, then split it or cache it in the client",
                    category="hot-key",
                    shard=pinned,
                )
            )
        hot = [x for x in cpu if x["cpu_avg"] > SHARD_HOT_RATIO * median and x["cpu_avg"] > SHARD_HOT_CPU]
        for x in sorted(hot, key=lambda x: -x["cpu_avg"])[:MAX_HOT_SHARD_FINDINGS]:
            if x["shard"] == pinned:
                continue
            ratio = f"{x['cpu_avg'] / median:.1f}x" if median > 0 else "far above"
            out.append(
                finding(
                    "warning",
                    f"hot shard {x['shard']} ({label[x['shard']]}): EngineCPUUtilization avg {x['cpu_avg']:.0f}% is "
                    f"{ratio} the median shard ({median:.0f}%) and above {SHARD_HOT_CPU:.0f}%",
                    category="hot-shard",
                    shard=x["shard"],
                )
            )
    memory = [x for x in stats if x["memory_avg"] is not None]
    if len(memory) >= 2:
        median = _median([x["memory_avg"] for x in memory])
        for x in sorted(memory, key=lambda x: -x["memory_avg"]):
            value = x["memory_avg"]
            if value >= SHARD_MEMORY_RATIO * median and value - median >= SHARD_MEMORY_POINTS:
                out.append(
                    finding(
                        "critical" if value >= 90 else "warning",
                        f"memory skew: shard {x['shard']} ({label[x['shard']]}) uses {value:.0f}% against a median "
                        f"of {median:.0f}%: uneven key distribution (large keys or hash tags); rebalance slots or "
                        "review the key design before this shard starts evicting",
                        category="memory-skew",
                        shard=x["shard"],
                    )
                )
    items = [x for x in stats if x["curr_items"] is not None]
    if len(items) >= 2:
        median = _median([x["curr_items"] for x in items])
        for x in items:
            if median > 0 and x["curr_items"] > SHARD_ITEMS_RATIO * median:
                out.append(
                    finding(
                        "info",
                        f"shard {x['shard']} holds {x['curr_items']:.0f} items, {x['curr_items'] / median:.1f}x the "
                        f"median shard ({median:.0f}): uneven key counts per shard",
                        category="item-skew",
                        shard=x["shard"],
                    )
                )
    traffic = [
        (x, (x["network_in_avg_bytes"] or 0) + (x["network_out_avg_bytes"] or 0))
        for x in stats
        if x["network_in_avg_bytes"] is not None or x["network_out_avg_bytes"] is not None
    ]
    if len(traffic) >= 2:
        median = _median([t for _, t in traffic])
        for x, total in traffic:
            if median > 0 and total > SHARD_TRAFFIC_RATIO * median:
                out.append(
                    finding(
                        "info",
                        f"shard {x['shard']} moves {total / median:.1f}x the median shard's network bytes: "
                        "traffic is concentrated on one shard",
                        category="traffic-skew",
                        shard=x["shard"],
                    )
                )
    lags = [(m, v) for x in stats for m, v in x["replica_lag_max"].items()]
    if len(lags) >= 2:
        median = _median([v for _, v in lags])
        outliers = [(m, v) for m, v in lags if v > SHARD_LAG_SECONDS and v > SHARD_LAG_RATIO * median]
        for member, value in sorted(outliers, key=lambda mv: -mv[1])[:MAX_LAG_OUTLIERS]:
            out.append(
                finding(
                    "critical" if value > 10 else "warning",
                    f"lagging replica {member}: ReplicationLag max {value:.1f}s against a median of {median:.1f}s "
                    "across replicas; a group average hides it and reads from this replica are stale. Check its "
                    "node load and network, and the primary's output buffer",
                    category="replica-lag-outlier",
                    resource=member,
                )
            )
    return out
