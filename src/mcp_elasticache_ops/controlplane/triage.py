"""Findings-first triage, cluster overview and shard balance, plus the multi-region fan-outs."""

from __future__ import annotations

import datetime as dt
import re
from collections import defaultdict
from collections.abc import Callable
from typing import Any

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
)

from ._shared import (
    _CRITICAL_EVENT_WORDS,
    _PENDING_ACTION_STATUSES,
    _SEVERITY_ORDER,
    FLEET_DEADLINE_SECONDS,
    MAX_FLEET_FINDINGS,
    SERVERLESS_METRICS,
    _credit_findings,
    _error_code,
    _fleet_deadline_error,
    _fleet_failed,
    _limits_view,
    _monotonic,
    _p95,
    _rg_findings,
    _serverless_cache_findings,
    _serverless_limit_findings,
    _serverless_snapshot_findings,
    _serverless_snapshot_view,
    _snapshot_findings,
    _snapshot_view,
    _sorted_findings,
    _validate_window,
    finding,
    is_burstable,
)
from .security import _SecurityMixin

# Burstable (cache.t*) nodes throttle to baseline CPU when the credit balance hits zero; only these
# node types report the credit metrics, so they are requested for them alone.
BURSTABLE_METRICS = ["CPUCreditBalance", "CPUCreditUsage"]


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


# aws_shard_balance: one GetMetricData call per node-group member, nothing from the data plane.
SHARD_METRICS = [
    "EngineCPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "NetworkBytesIn",
    "NetworkBytesOut",
    "CurrItems",
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


# Failover/maintenance events matched against the metric window in the triage tools.
CORRELATION_HOURS = 24


CORRELATION_MINUTES = 30  # metrics are compared this long before and after an event


CORRELATION_LAG_SECONDS = 1.0


CORRELATION_CONN_DROP = 0.5  # CurrConnections falling by this fraction counts as a drop


MAX_CORRELATED_EVENTS = 3


_FAILOVER_EVENT = re.compile(r"failover.*complet|primary.*changed|node.*replaced|replaced.*node", re.IGNORECASE)


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
    "GlobalDatastoreReplicationLag",
    "CurrConnections",
]


_TRIAGE_FATAL = {"ReplicationGroupNotFoundFault"}  # nothing useful to report: surface it as the tool error


SERVERLESS_TRIAGE_FATAL = frozenset({"ServerlessCacheNotFoundFault"})


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


def _az_placement_findings(g: dict, subnet: tuple[str, set[str]] | None) -> list[dict]:
    """Cross-check node AZ placement against Multi-AZ and the subnet group; uses data already fetched."""
    out: list[dict] = []
    multi_az = g.get("MultiAZ") == "enabled"
    all_azs: set[str] = set()
    node_count = 0
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        node_count += len(members)
        all_azs |= {m["PreferredAvailabilityZone"] for m in members if m.get("PreferredAvailabilityZone")}
    if subnet is not None and len(subnet[1]) < 2:
        name, azs = subnet
        out.append(
            finding(
                "warning",
                f"subnet group {name} spans {len(azs)} AZ(s); replicas cannot be placed across AZs",
                resource=name,
            )
        )
    if multi_az and node_count > 1 and len(all_azs) == 1:
        out.append(finding("warning", f"Multi-AZ is enabled but all {node_count} nodes sit in {next(iter(all_azs))}"))
        return out  # per-shard detail would only repeat this
    available = len(subnet[1]) if subnet is not None else len(all_azs)
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        primary = next((m for m in members if m.get("CurrentRole") == "primary"), None)
        shard_azs = {m["PreferredAvailabilityZone"] for m in members if m.get("PreferredAvailabilityZone")}
        if (
            primary is None
            or not primary.get("PreferredAvailabilityZone")
            or len(shard_azs) >= min(len(members), available)
        ):
            continue
        sharing = [
            m.get("CacheClusterId")
            for m in members
            if m is not primary and m.get("PreferredAvailabilityZone") == primary["PreferredAvailabilityZone"]
        ]
        if sharing:
            out.append(
                finding(
                    "warning" if multi_az else "info",
                    f"node group {ng.get('NodeGroupId')}: replica(s) {', '.join(map(str, sharing))} share the "
                    f"primary's AZ {primary['PreferredAvailabilityZone']} although {available} AZ(s) are available",
                    resource=ng.get("NodeGroupId"),
                )
            )
    return out


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
    out += _az_placement_findings(g, None)
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        if ng.get("Status") not in (None, "available"):
            out.append(finding("warning", f"node group {ng.get('NodeGroupId')} status is {ng.get('Status')}"))
        if len(members) == 1:
            out.append(finding("warning", f"node group {ng.get('NodeGroupId')} has no replica: failover is impossible"))
    if g.get("PendingModifiedValues"):
        out.append(finding("info", "has pending modified values"))
    return out


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
    return out


# ------------------------------------------------------------------ failover correlation


def _as_utc(value: Any) -> dt.datetime | None:
    if isinstance(value, str):
        try:
            value = dt.datetime.fromisoformat(value)
        except ValueError:
            return None
    if not isinstance(value, dt.datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def _series_points(series: dict[str, dict[str, dict]], metric: str) -> dict[dt.datetime, list[float]]:
    """Datapoints of one metric across every member, grouped by timestamp."""
    out: dict[dt.datetime, list[float]] = defaultdict(list)
    for per_member in series.values():
        data = per_member.get(metric) or {}
        for ts, value in zip(data.get("timestamps", []), data.get("values", []), strict=False):
            when = _as_utc(ts)
            if when is not None and isinstance(value, (int, float)):
                out[when].append(float(value))
    return out


def _failover_findings(
    events: list[dict],
    now: dt.datetime,
    series: dict[str, dict[str, dict]],
    resource: str,
    metric_hours: int,
) -> list[dict]:
    """Recent failover/maintenance events (last 24h) lined up against ReplicationLag and CurrConnections."""
    horizon = now - dt.timedelta(hours=CORRELATION_HOURS)
    recent: list[tuple[dt.datetime, dict]] = []
    for e in events:
        when = _as_utc(e.get("Date"))
        if when is None or when < horizon or when > now + dt.timedelta(minutes=5):
            continue
        if _FAILOVER_EVENT.search(str(e.get("Message", ""))):
            recent.append((when, e))
    recent.sort(key=lambda t: t[0], reverse=True)
    lag = _series_points(series, "ReplicationLag")
    conns = _series_points(series, "CurrConnections")
    covered_from = now - dt.timedelta(hours=metric_hours)
    after = dt.timedelta(minutes=CORRELATION_MINUTES)
    out: list[dict] = []
    for when, e in recent[:MAX_CORRELATED_EVENTS]:
        age_min = max(0.0, (now - when).total_seconds() / 60)
        stamp = when.isoformat()
        parts: list[str] = []
        lag_peak = max(
            ((max(v), t) for t, v in lag.items() if when <= t <= when + after and max(v) >= CORRELATION_LAG_SECONDS),
            default=None,
        )
        if lag_peak:
            parts.append(
                f"ReplicationLag peaked at {lag_peak[0]:.1f}s {(lag_peak[1] - when).total_seconds() / 60:.0f} min "
                "after the event"
            )
        before = [sum(v) for t, v in conns.items() if when - after <= t < when]
        later = [(sum(v), t) for t, v in conns.items() if when <= t <= when + after]
        if before and later:
            baseline = sum(before) / len(before)
            trough = min(later, key=lambda x: x[0])
            if baseline > 0 and trough[0] <= baseline * (1 - CORRELATION_CONN_DROP):
                parts.append(
                    f"CurrConnections dropped {100 * (1 - trough[0] / baseline):.0f}% (from about {baseline:.0f} to "
                    f"{trough[0]:.0f}) {(trough[1] - when).total_seconds() / 60:.0f} min after the event: "
                    "clients lost their connections and had to reconnect"
                )
        if parts:
            impact = "; ".join(parts)
        elif when < covered_from:
            impact = f"the event predates the {metric_hours}h metric window, so impact cannot be checked here"
        else:
            impact = "no ReplicationLag or CurrConnections impact visible in the metrics"
        recent_window = age_min <= metric_hours * 60
        out.append(
            finding(
                "warning" if recent_window else "info",
                f"recent failover/maintenance: '{str(e.get('Message', '')).strip()}' at {stamp} "
                f"({age_min:.0f} min ago): {impact}",
                resource=e.get("SourceIdentifier") or resource,
                section="events",
                category="failover-correlation",
                event_time=stamp,
            )
        )
    return out


class _TriageMixin(_SecurityMixin):
    def triage_fan_out(self, replication_group_id: str, region: str | None = None) -> dict:
        """``triage`` in the first region of ELASTICACHE_REGIONS that holds the group (or in ``region``)."""
        targets = self._target_regions(region)
        if len(targets) == 1:
            return self.in_region(targets[0]).triage(replication_group_id)
        failures: dict[str, dict] = {}
        for target in targets:
            probe = self.in_region(target).replication_groups(replication_group_id)
            if probe.get("count"):
                return {"region": target, **self.in_region(target).triage(replication_group_id)}
            if "error" in probe and probe["error"] != "ReplicationGroupNotFoundFault":
                failures[str(target)] = probe
        out: dict[str, Any] = {
            "error": "ReplicationGroupNotFoundFault",
            "message": f"replication group {replication_group_id} not found in {', '.join(map(str, targets))}",
        }
        if failures:
            out["region_errors"] = failures
        return out

    def _group_ids(self) -> dict:
        return self._guard(
            lambda: {
                "ids": sorted(
                    str(g.get("ReplicationGroupId"))
                    for g in self._paginate("describe_replication_groups", "ReplicationGroups")
                )
            }
        )

    def cluster_overview_fan_out(
        self, replication_group_id: str | None, minutes: int = OVERVIEW_WINDOW_MINUTES, region: str | None = None
    ) -> dict:
        """``cluster_overview`` for one group, or for every group of every configured region (fleet mode).

        Fleet mode inspects at most MAX_FLEET_GROUPS_PER_REGION groups per region within one shared deadline and
        returns one row per group plus the merged, region-tagged findings."""
        if replication_group_id:
            return self.in_region(region).cluster_overview(replication_group_id, minutes)
        targets = self._target_regions(region)
        deadline = _monotonic() + FLEET_DEADLINE_SECONDS
        findings: list[dict] = []
        rows: list[dict] = []
        failures: dict[str, dict] = {}
        skipped: list[str] = []
        for target in targets:
            plane = self.in_region(target)
            if _monotonic() >= deadline:
                failures[str(target)] = _fleet_deadline_error()
                continue
            listed = plane._group_ids()
            if _fleet_failed(listed):
                failures[str(target)] = listed
                continue
            ids = listed["ids"]
            skipped += [f"{target or 'default'}/{gid}" for gid in ids[MAX_FLEET_GROUPS_PER_REGION:]]
            for gid in ids[:MAX_FLEET_GROUPS_PER_REGION]:
                if _monotonic() >= deadline:
                    skipped.append(f"{target or 'default'}/{gid}")
                    continue
                result = plane.cluster_overview(gid, minutes)
                if _fleet_failed(result):
                    failures[str(target)] = result
                    break  # the same denial or timeout would hit every other group of this region
                rows.append(
                    {
                        "region": target,
                        "replication_group_id": gid,
                        "status": result.get("status"),
                        "overall": result.get("overall"),
                        "findings_total": result.get("findings_total"),
                    }
                )
                findings += [{**f, "region": target, "replication_group_id": gid} for f in result["findings"]]
        ordered = _sorted_findings(findings)
        out: dict[str, Any] = {
            "regions": [str(t) for t in targets],
            "window_minutes": int(minutes),
            "groups": rows,
            "findings": ordered[:MAX_FLEET_FINDINGS],
            "findings_total": len(ordered),
            "truncated": len(ordered) > MAX_FLEET_FINDINGS,
        }
        if skipped:
            out["skipped_groups"] = skipped
        if failures:
            out["region_errors"] = failures
        return out

    # --------------------------------------------------------------- triage
    @staticmethod
    def _section_runner(
        resource: str,
        sections: list[dict],
        findings: list[dict],
        fatal: frozenset[str] | set[str] = _TRIAGE_FATAL,
    ) -> Callable[[str, Callable[[], tuple[str, list[dict]]]], None]:
        """``section(name, fn)``: run one triage section; a failing one is recorded as ``unavailable``."""

        def section(name: str, fn: Callable[[], tuple[str, list[dict]]]) -> None:
            try:
                summary, found = fn()
            except (NoCredentialsError, NoRegionError):
                raise
            except ClientError as exc:
                err = exc.response.get("Error", {})
                code = err.get("Code", "ClientError")
                if code in fatal:
                    raise
                detail = f"{code}: {err.get('Message', exc)}"
            except BotoCoreError as exc:
                detail = f"{type(exc).__name__}: {exc}"
            else:
                status = _worst_status(found)
                sections.append({"section": name, "status": status, "summary": summary})
                findings.extend({**f, "section": name, "resource": f.get("resource", resource)} for f in found)
                return
            sections.append({"section": name, "status": "unavailable", "summary": detail})
            findings.append(finding("warning", f"{name} unavailable ({detail})", resource=resource, section=name))

        return section

    def serverless_triage(self, serverless_cache_name: str) -> dict:
        """One-call incident summary for a serverless cache: configuration, snapshots and limit/throttle signals."""

        def run() -> dict:
            now = self._clock()
            sections: list[dict] = []
            findings: list[dict] = []
            cache_box: list[dict] = []
            series_box: list[dict[str, dict[str, dict]]] = []
            section = self._section_runner(serverless_cache_name, sections, findings, SERVERLESS_TRIAGE_FATAL)

            def cache_section() -> tuple[str, list[dict]]:
                caches = self._paginate_token(
                    "describe_serverless_caches", "ServerlessCaches", ServerlessCacheName=serverless_cache_name
                )
                if not caches:
                    raise ClientError(
                        {
                            "Error": {
                                "Code": "ServerlessCacheNotFoundFault",
                                "Message": f"serverless cache {serverless_cache_name} not found",
                            }
                        },
                        "DescribeServerlessCaches",
                    )
                cache_box.append(caches[0])
                c = caches[0]
                limits = c.get("CacheUsageLimits") or {}
                text = (
                    f"status {c.get('Status')}, engine {c.get('Engine')} {c.get('FullEngineVersion', '')}".strip()
                    + f", data storage max {(limits.get('DataStorage') or {}).get('Maximum')}"
                    + f", ECPU/s max {(limits.get('ECPUPerSecond') or {}).get('Maximum')}"
                )
                return text, _serverless_cache_findings(c)

            def snapshots_section() -> tuple[str, list[dict]]:
                snaps = self._paginate_token(
                    "describe_serverless_cache_snapshots",
                    "ServerlessCacheSnapshots",
                    ServerlessCacheName=serverless_cache_name,
                )
                views = [_serverless_snapshot_view(x, now) for x in snaps]
                found = _serverless_snapshot_findings(views, cache_box or None, now, 36)
                ages = [v["age_hours"] for v in views if v["status"] == "available" and v["age_hours"] is not None]
                text = f"newest available snapshot {min(ages):.0f}h old" if ages else "no available snapshot"
                return text, found

            def limits_section() -> tuple[str, list[dict]]:
                period = 300
                summary, series, found = self._collect_metrics(
                    [serverless_cache_name],
                    SERVERLESS_METRICS,
                    TRIAGE_WINDOW_HOURS * 60,
                    period,
                    None,
                    True,
                    rightsizing=False,
                )
                series_box.append(series)
                metrics = summary[serverless_cache_name]
                limits = cache_box[0].get("CacheUsageLimits") if cache_box else None
                found += _serverless_limit_findings(serverless_cache_name, metrics, limits, period)
                view = _limits_view(limits, metrics, period)
                throttled = (metrics.get("ThrottledCmds") or {}).get("sum") or 0
                parts = [f"{throttled:.0f} throttled command(s)"]
                for key, label in (("ecpu_used_pct", "ECPU peak"), ("data_storage_used_pct", "storage peak")):
                    if view.get(key) is not None:
                        parts.append(f"{label} {view[key]:.0f}% of limit")
                return f"over {TRIAGE_WINDOW_HOURS}h: " + ", ".join(parts), found

            section("cache", cache_section)
            section("snapshots", snapshots_section)
            section("limits", limits_section)
            try:  # one describe_events call for the 24h failover/maintenance correlation
                events = self._paginate(
                    "describe_events",
                    "Events",
                    SourceIdentifier=serverless_cache_name,
                    SourceType="serverless-cache",
                    Duration=CORRELATION_HOURS * 60,
                )
                findings += _failover_findings(
                    events, now, series_box[0] if series_box else {}, serverless_cache_name, TRIAGE_WINDOW_HOURS
                )
            except (ClientError, BotoCoreError) as exc:
                findings.append(
                    finding(
                        "info",
                        f"{CORRELATION_HOURS}h failover/maintenance correlation skipped ({_error_code(exc)})",
                        resource=serverless_cache_name,
                        section="events",
                    )
                )
            tag_view, tag_findings = self._tag_context(
                serverless_cache_name, [cache_box[0].get("ARN")] if cache_box else []
            )
            findings += tag_findings
            ordered = _sorted_findings(findings)
            return {
                "serverless_cache_name": serverless_cache_name,
                **tag_view,
                "generated_at": now.isoformat(),
                "window_hours": TRIAGE_WINDOW_HOURS,
                "overall": _worst_status(ordered) if ordered else "ok",
                "sections": sections,
                "findings": ordered[:MAX_TRIAGE_FINDINGS],
                "findings_total": len(ordered),
                "truncated": len(ordered) > MAX_TRIAGE_FINDINGS,
            }

        return self._guard(run)

    def triage(self, replication_group_id: str) -> dict:
        """One-call incident summary for a replication group: worst findings first, per-section status."""

        def run() -> dict:
            now = self._clock()
            members: list[str] = []
            node_types: list[str | None] = []
            rg_arn: list[str | None] = []
            sections: list[dict] = []
            findings: list[dict] = []

            section = self._section_runner(replication_group_id, sections, findings)
            long_events: list[dict] = []
            series_box: list[dict[str, dict[str, dict]]] = []

            def rg_section() -> tuple[str, list[dict]]:
                groups = self._paginate(
                    "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=replication_group_id
                )
                if not groups:
                    raise _TriageEmpty(f"replication group {replication_group_id} not found")
                g = groups[0]
                rg_arn.append(g.get("ARN"))
                members.extend(g.get("MemberClusters", []))
                node_types.append(g.get("CacheNodeType"))
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
                try:  # one extra call for the 24h failover/maintenance correlation
                    long_events.extend(
                        self._paginate(
                            "describe_events",
                            "Events",
                            SourceIdentifier=replication_group_id,
                            SourceType="replication-group",
                            Duration=CORRELATION_HOURS * 60,
                        )
                    )
                except (ClientError, BotoCoreError) as exc:
                    found.append(
                        finding(
                            "info",
                            f"{CORRELATION_HOURS}h failover/maintenance correlation skipped ({_error_code(exc)})",
                        )
                    )
                return f"{len(events)} event(s) in the last {TRIAGE_WINDOW_HOURS}h, {notable} notable", found

            def metrics_section() -> tuple[str, list[dict]]:
                if not members:
                    raise _TriageEmpty("no member clusters known (replication group section failed)")
                names = TRIAGE_METRICS + (BURSTABLE_METRICS if any(is_burstable(t) for t in node_types) else [])
                summary, series, found = self._collect_metrics(
                    members, names, TRIAGE_WINDOW_HOURS * 60, 300, None, False, rightsizing=False
                )
                series_box.append(series)
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
            tag_view, tag_findings = self._tag_context(replication_group_id, [rg_arn[0]] if rg_arn else [])
            findings += tag_findings
            section("events", events_section)
            section("metrics", metrics_section)
            section("service_updates", updates_section)
            section("snapshots", snapshots_section)
            findings += _failover_findings(
                long_events, now, series_box[0] if series_box else {}, replication_group_id, TRIAGE_WINDOW_HOURS
            )
            ordered = _sorted_findings(findings)
            return {
                "replication_group_id": replication_group_id,
                **tag_view,
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
            member_clusters = self._member_clusters()
            engine_version = self._member_engine_versions(member_clusters).get(replication_group_id)
            topology = _overview_topology(g, engine_version)
            subnet = self._subnet_group_azs(member_clusters, replication_group_id)
            findings = _rg_findings(g, engine_version) + _reader_findings(g) + _az_placement_findings(g, subnet)
            nodes = {n["cluster_id"]: n for s in topology["shards"] for n in s["nodes"]}
            status = "ok"
            summary: dict = {}
            series: dict = {}
            if nodes:
                try:
                    names = OVERVIEW_METRICS + (BURSTABLE_METRICS if is_burstable(g.get("CacheNodeType")) else [])
                    summary, series, _ = self._collect_metrics(
                        list(nodes), names, int(minutes), 300, None, False, rightsizing=False
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
                hinted = False
                for cid in nodes:
                    credit = _credit_findings(cid, summary.get(cid, {}))
                    # one right-sizing hint per group is enough
                    findings += [f for f in credit if not (f.get("category") == "right-sizing" and hinted)]
                    hinted = hinted or bool(credit)
                findings += _overview_outliers(topology["shards"])
                findings += _overview_rightsizing(topology["shards"], g.get("CacheNodeType"), int(minutes))
            for shard in topology["shards"]:
                shard["worst_memory_pct"] = max(
                    (n["signals"]["DatabaseMemoryUsagePercentage"].get("avg") or 0 for n in shard["nodes"]), default=0
                )
            ordered_shards = sorted(topology["shards"], key=lambda sh: -sh["worst_memory_pct"])
            member_arns = [c.get("ARN") for c in member_clusters if c.get("ReplicationGroupId") == replication_group_id]
            tag_view, tag_findings = self._tag_context(replication_group_id, [g.get("ARN"), *member_arns])
            findings += tag_findings
            ordered = _sorted_findings(findings)
            return {
                "replication_group_id": replication_group_id,
                "status": status,
                **tag_view,
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

    def shard_balance(self, replication_group_id: str, minutes: int = SHARD_WINDOW_MINUTES) -> dict:
        """Per-shard skew from CloudWatch alone: one GetMetricData call per node-group member, findings first.

        Never touches the data plane, so it still answers when the endpoint is unreachable."""
        problem = _validate_window(minutes, 300)
        if problem:
            return {"error": "InvalidArgument", "message": problem}

        def run() -> dict:
            groups = self._paginate(
                "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=replication_group_id
            )
            if not groups:
                return {"error": "NotFound", "message": f"replication group {replication_group_id} not found"}
            shards = _shard_layout(groups[0])
            members = [sh["members"][0] for sh in shards if sh["members"]]
            members += [m for sh in shards for m in sh["members"][1:]]
            queried = members[:MAX_SHARD_MEMBERS]
            notes: list[str] = []
            if len(members) > len(queried):
                notes.append(f"metrics cover {len(queried)} of {len(members)} members (primaries first)")
            summary: dict[str, dict[str, dict]] = {}
            status = "ok"
            findings: list[dict] = []
            try:
                for member in queried:
                    one, _, _ = self._collect_metrics(
                        [member], SHARD_METRICS, int(minutes), 300, None, False, rightsizing=False
                    )
                    summary.update(one)
            except ClientError as exc:
                status = "partial"
                findings.append(
                    finding(
                        "warning",
                        f"CloudWatch GetMetricData failed ({_error_code(exc)}): shard skew cannot be computed; "
                        "the layout is shown without metrics",
                    )
                )
            stats = [_shard_stats(sh, summary) for sh in shards]
            if summary:
                findings += _shard_balance_findings(stats)
            ordered = _sorted_findings(findings)
            cpu = [x["cpu_avg"] for x in stats if x["cpu_avg"] is not None]
            memory = [x["memory_avg"] for x in stats if x["memory_avg"] is not None]
            ranked = sorted(stats, key=lambda x: -(x["cpu_avg"] if x["cpu_avg"] is not None else -1.0))
            return {
                "replication_group_id": replication_group_id,
                "status": status,
                "window_minutes": int(minutes),
                "overall": _worst_status(ordered) if ordered else "ok",
                "findings": ordered[:MAX_OVERVIEW_FINDINGS],
                "findings_total": len(ordered),
                "median": {
                    "cpu_avg": _median(cpu) if cpu else None,
                    "memory_avg": _median(memory) if memory else None,
                },
                "shards": ranked[:MAX_OVERVIEW_SHARDS],
                "shards_total": len(ranked),
                **({"notes": notes} if notes else {}),
            }

        return self._guard(run)
