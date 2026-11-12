"""Cost rules: savings, forecast and offering views used by the cost tools."""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter
from typing import Any

from ._shared import (
    _STORAGE_UNIT,
    _jsonable,
    _limits_view,
    _memory_trend,
    _serverless_limit_findings,
    _snapshot_view,
    _version_tuple,
    finding,
    is_burstable,
)

COST_WINDOW_DAYS = 14


COST_METRICS = ["DatabaseMemoryUsagePercentage", "EngineCPUUtilization", "GetTypeCmds"]


COST_SERVERLESS_METRICS = ["ElastiCacheProcessingUnits", "BytesUsedForCache"]

# Serverless bills a minimum amount of stored data even when empty: 100 MB for Valkey, 1 GB for Redis OSS and
# Memcached. Prices differ per region, so the hint reports GB-hours, never dollars.
SERVERLESS_MIN_BILLED_GB = {"valkey": 0.1, "redis": 1.0, "memcached": 1.0}
HOURS_PER_MONTH = 730


FORECAST_CRITICAL_DAYS = 7.0  # projected time to a full cache below this is critical


FORECAST_WARNING_DAYS = 30.0  # ... below this a warning


FORECAST_FULL_PCT = 90.0  # a flat series this high has no headroom either


FORECAST_UNDERUSED_PCT = 30.0  # a stable series whose 14-day peak stays under this is a right-sizing candidate


MAX_FORECAST_TARGETS = 500  # CloudWatch series per resource kind (one GetMetricData batch)


MAX_FORECAST_ROWS = 100  # ranked rows returned per region


# Valkey savings hint: list-price discount versus the Redis OSS engine, as published by AWS. An estimate for
# prioritising, not a quote; actual savings depend on region, node type and reservations.
VALKEY_SAVINGS_NODE_PERCENT = 20


VALKEY_SAVINGS_SERVERLESS_PERCENT = 33


VALKEY_MIN_REDIS_VERSION = (5, 0, 6)  # in-place Redis OSS -> Valkey upgrade needs at least this version


MAX_VALKEY_CANDIDATES = 5  # top candidates (by node count) listed in the valkey summary finding


MAX_COST_GROUPS = 20  # GetMetricData calls per region in aws_cost_overview (one per group)


MIN_COST_POINTS = 24  # hourly points needed before a 14-day peak means anything


OVERSIZED_MEMORY_PEAK = 30.0  # peak DatabaseMemoryUsagePercentage under this: the node type is oversized


OLD_MANUAL_SNAPSHOT_DAYS = 90

IDLE_CPU_PEAK = 5.0  # a group whose peak EngineCPUUtilization stays under this ...
IDLE_MEMORY_PEAK = 10.0  # ... and peak memory under this does almost nothing (idle candidate)
_SIZES = (
    "micro",
    "small",
    "medium",
    "large",
    "xlarge",
    "2xlarge",
    "4xlarge",
    "8xlarge",
    "12xlarge",
    "16xlarge",
    "24xlarge",
)
_NODE_TYPE = re.compile(r"^(cache\.[a-z0-9]+)\.([0-9a-z]+)$")


def smaller_node_type(node_type: Any) -> str | None:
    """The next size down in the same family (half the memory), or None when it is already the smallest.

    Only ``t`` families go below ``large``; the size is a candidate, not an availability guarantee."""
    m = _NODE_TYPE.match(str(node_type or ""))
    if not m or m.group(2) not in _SIZES:
        return None
    i = _SIZES.index(m.group(2))
    floor = _SIZES.index("micro" if m.group(1).startswith("cache.t") else "large")
    return f"{m.group(1)}.{_SIZES[i - 1]}" if i - 1 >= floor else None


MAX_TAG_CALLS = 3  # ListTagsForResource calls per tool call (replication group, then a member cluster)


MAX_TAGS_SHOWN = 25


MAX_TAG_VALUE_CHARS = 120


OWNER_TAG_KEYS = ("owner", "team")


ENVIRONMENT_TAG_KEYS = ("environment", "env")


OFFERING_TERMS = frozenset({1, 3})


MAX_OFFERINGS = 20


_GRAVITON_FAMILY = re.compile(r"^cache\.[a-z]+\d+g")


def _is_graviton(node_type: str | None) -> bool:
    return bool(_GRAVITON_FAMILY.match(str(node_type or "")))


def _reserved_nodes_held(reserved: list[dict]) -> Counter[tuple[str, str]]:
    """Active reserved nodes per (node type, engine)."""
    held: Counter[tuple[str, str]] = Counter()
    for r in reserved:
        v = _reserved_view(r)
        if v["state"] == "active":
            held[(str(v["node_type"]), str(v["product"]).lower())] += int(v["count"] or 0)
    return held


def _cost_group(
    g: dict,
    gid: str,
    members: list[str],
    replicas: list[str],
    metrics: dict[str, dict[str, dict]],
    covered_ids: set[str],
    engine: str,
) -> tuple[dict, list[dict]]:
    """Row and findings for one replication group (see ControlPlane.cost_overview)."""
    node_type = g.get("CacheNodeType")
    nodes = len(members)
    out: list[dict] = []

    def add(sev: str, msg: str, **extra: Any) -> None:
        out.append(finding(sev, msg, resource=gid, category="cost", **extra))

    def peak(name: str) -> float | None:
        values = [
            s["max"]
            for m in members
            if (s := (metrics.get(m) or {}).get(name)) and s.get("points", 0) >= MIN_COST_POINTS
        ]
        return max(values) if values else None

    mem_peak, cpu_peak = peak("DatabaseMemoryUsagePercentage"), peak("EngineCPUUtilization")
    window = f"over {COST_WINDOW_DAYS} days"
    smaller = smaller_node_type(node_type)
    if mem_peak is not None and cpu_peak is not None and mem_peak < IDLE_MEMORY_PEAK and cpu_peak < IDLE_CPU_PEAK:
        add(
            "warning",
            f"{nodes} x {node_type} looks idle: peak memory {mem_peak:.0f}% and peak CPU {cpu_peak:.0f}% {window}; "
            "confirm nothing uses it, then snapshot and delete it" + (f", or shrink to {smaller}" if smaller else ""),
            hint="idle",
            suggested_node_type=smaller,
        )
    elif mem_peak is not None and mem_peak < OVERSIZED_MEMORY_PEAK:
        advice = (
            f"{smaller} (half the memory, peak would be about {mem_peak * 2:.0f}%) would likely carry this dataset"
            if smaller
            else f"{node_type} is already the smallest size of its family: cut replicas or shards instead"
        )
        add(
            "warning" if nodes > 2 else "info",
            f"{nodes} x {node_type}: peak memory {mem_peak:.0f}% {window} (under {OVERSIZED_MEMORY_PEAK:.0f}%); "
            + advice,
            hint="oversized",
            suggested_node_type=smaller,
        )
    idle = [
        m
        for m in replicas
        if (s := (metrics.get(m) or {}).get("GetTypeCmds")) and s.get("points", 0) >= MIN_COST_POINTS and not s["sum"]
    ]
    if idle:
        add(
            "warning",
            f"{len(idle)} replica(s) served no read commands {window} ({', '.join(idle[:5])}): drop them if they "
            "exist only as read capacity (keep one per shard for failover)",
            hint="idle-replicas",
        )
    covered = sum(1 for m in members if m in covered_ids)
    if nodes and not covered:
        add(
            "info",
            f"{nodes} on-demand {node_type} node(s) with no active reservation; steady load is a reserved-node "
            "candidate",
            hint="reserved",
        )
    elif nodes and covered < nodes:
        add(
            "info",
            f"{nodes - covered} of {nodes} {node_type} node(s) are not covered by a reservation",
            hint="reserved",
        )
    if nodes and str(node_type).startswith("cache.") and not _is_graviton(node_type) and not is_burstable(node_type):
        add(
            "info",
            f"{node_type} is not a Graviton family: the g-suffixed equivalent (for example m7g or r7g) is usually "
            "cheaper at equal size",
            hint="graviton",
        )
    row = {
        "id": gid,
        "engine": engine or None,
        "node_type": node_type,
        "shards": len(g.get("NodeGroups", [])),
        "nodes": nodes,
        "replicas": len(replicas),
        "reserved_nodes_covering": covered,
        "peak_memory_percent": round(mem_peak, 1) if mem_peak is not None else None,
        "peak_engine_cpu_percent": round(cpu_peak, 1) if cpu_peak is not None else None,
        "suggested_node_type": smaller if mem_peak is not None and mem_peak < OVERSIZED_MEMORY_PEAK else None,
        "idle_replicas": idle,
        "metrics_checked": bool(metrics),
        "findings_total": len(out),
    }
    return row, out


def _valkey_savings_findings(
    groups: list[dict], clusters: list[dict], caches: list[dict], versions: dict[str, tuple[str, str]]
) -> list[dict]:
    """One info finding: redis-engine resources that could move to Valkey for a list-price discount.

    Only the redis engine qualifies (never memcached or valkey) and only when the version is known and at least
    VALKEY_MIN_REDIS_VERSION; unknown versions are skipped rather than guessed. Uses data already fetched."""
    candidates: list[tuple[str, str, int, int]] = []  # (id, kind, nodes, percent)
    for g in groups:
        gid = str(g.get("ReplicationGroupId"))
        engine, version = versions.get(gid, (str(g.get("Engine") or ""), ""))
        if engine.lower() == "redis" and version and _version_tuple(version) >= VALKEY_MIN_REDIS_VERSION:
            candidates.append((gid, "replication group", len(g.get("MemberClusters", [])), VALKEY_SAVINGS_NODE_PERCENT))
    for c in clusters:
        version = str(c.get("EngineVersion") or "")
        if (
            not c.get("ReplicationGroupId")
            and str(c.get("Engine") or "").lower() == "redis"
            and version
            and _version_tuple(version) >= VALKEY_MIN_REDIS_VERSION
        ):
            candidates.append((str(c.get("CacheClusterId")), "cache cluster", 1, VALKEY_SAVINGS_NODE_PERCENT))
    for sc in caches:
        major = str(sc.get("MajorEngineVersion") or "")
        if str(sc.get("Engine") or "").lower() == "redis" and (not major or _version_tuple(major) >= (5,)):
            candidates.append(
                (str(sc.get("ServerlessCacheName")), "serverless cache", 0, VALKEY_SAVINGS_SERVERLESS_PERCENT)
            )
    if not candidates:
        return []
    top = sorted(candidates, key=lambda c: (-c[2], c[0]))[:MAX_VALKEY_CANDIDATES]
    return [
        finding(
            "info",
            f"{len(candidates)} Redis OSS resource(s) could move to Valkey, which AWS prices lower at list price: about "
            f"{VALKEY_SAVINGS_NODE_PERCENT}% for node-based and {VALKEY_SAVINGS_SERVERLESS_PERCENT}% for serverless. "
            "Assumption: published list-price discount, not a quote; check your region and reservations",
            category="cost",
            hint="valkey-savings",
            candidates_total=len(candidates),
            assumed_savings_percent={
                "node_based": VALKEY_SAVINGS_NODE_PERCENT,
                "serverless": VALKEY_SAVINGS_SERVERLESS_PERCENT,
            },
            top_candidates=[{"id": i, "kind": k, "nodes": n, "assumed_savings_percent": pc} for i, k, n, pc in top],
        )
    ]


def _serverless_billed_floor_gb(c: dict) -> float:
    """Stored GB billed at zero usage: the engine minimum, or the configured DataStorage minimum if larger."""
    engine = str(c.get("Engine") or "").lower()
    floor = SERVERLESS_MIN_BILLED_GB.get(engine, 1.0)
    storage = (c.get("CacheUsageLimits") or {}).get("DataStorage") or {}
    minimum = storage.get("Minimum")
    if minimum:
        floor = max(floor, float(minimum) * _STORAGE_UNIT.get(storage.get("Unit", "GB"), 1024**3) / 1024**3)
    return floor


def _cost_serverless(c: dict, summary: dict[str, dict]) -> tuple[dict, list[dict]]:
    name = str(c.get("ServerlessCacheName"))
    limits = c.get("CacheUsageLimits") or {}
    storage_cap = (limits.get("DataStorage") or {}).get("Maximum")
    ecpu_cap = (limits.get("ECPUPerSecond") or {}).get("Maximum")
    out: list[dict] = []
    missing = [label for label, cap in (("DataStorage", storage_cap), ("ECPUPerSecond", ecpu_cap)) if cap is None]
    if missing:
        out.append(
            finding(
                "warning",
                f"serverless cache is uncapped ({' and '.join(missing)} maximum unset): cost grows with load",
                resource=name,
                category="cost",
                hint="uncapped",
            )
        )
    ecpu = summary.get("ElastiCacheProcessingUnits") or {}
    used = summary.get("BytesUsedForCache") or {}
    out += _serverless_limit_findings(name, summary, c.get("CacheUsageLimits"), 3600)
    view = _limits_view(c.get("CacheUsageLimits"), summary, 3600)
    idle = bool(ecpu.get("points")) and ecpu.get("max") == 0
    if idle:
        floor = _serverless_billed_floor_gb(c)
        out.append(
            finding(
                "warning",
                f"serverless cache had zero ElastiCacheProcessingUnits for {COST_WINDOW_DAYS} days: it is idle but "
                f"still billed for at least {floor:g} GB of stored data (about {floor * HOURS_PER_MONTH:.0f} "
                "GB-hours a month); delete it or take a final snapshot and remove it",
                resource=name,
                category="cost",
                hint="idle",
                billed_floor_gb=floor,
            )
        )
    row = {
        "id": name,
        "engine": c.get("Engine"),
        "data_storage_max": storage_cap,
        "ecpu_per_second_max": ecpu_cap,
        "peak_bytes_used": used.get("max") if used.get("points") else None,
        "peak_ecpu_per_second": round(ecpu["max"] / 3600, 2) if ecpu.get("points") else None,
        "ecpu_p95_pct": view.get("ecpu_p95_pct"),
        "data_storage_p95_pct": view.get("data_storage_p95_pct"),
        "idle": idle,
        "findings_total": len(out),
    }
    return row, out


def _forecast_row(
    rid: str, kind: str, series: dict[str, list[float]], extra: dict[str, Any], what: str = "memory"
) -> tuple[dict, list[dict]]:
    """Rank row and findings for one resource from its per-node memory percentage series.

    The linear estimate is ``_memory_trend``'s (gradual growth only); the node that fills first decides the
    row, because one full shard is enough to start evicting or rejecting writes."""
    trends = {node: _memory_trend(vals, 3600) for node, vals in series.items() if vals}
    latest = max((vals[-1] for vals in series.values() if vals), default=None)
    peak = max((max(vals) for vals in series.values() if vals), default=None)
    row: dict[str, Any] = {"id": rid, "kind": kind, **extra, "current_pct": latest, "peak_pct": peak}
    findings: list[dict] = []
    if latest is None:
        return {**row, "status": "no-data", "days_to_full": None}, findings
    full = {n: t for n, t in trends.items() if t and t.get("hours_to_full") is not None}
    pick = min(full, key=lambda n: full[n]["hours_to_full"]) if full else None
    trend = trends[pick] if pick else next((t for t in trends.values() if t), None)
    if trend is None:
        return {**row, "status": "insufficient-data", "days_to_full": None}, findings
    row["growth"] = {
        "first_quarter_avg_pct": round(trend["first_quarter_avg"], 1),
        "last_quarter_avg_pct": round(trend["last_quarter_avg"], 1),
    }
    if pick is None:
        row.update(status="stable", days_to_full=None)
        if latest >= FORECAST_FULL_PCT:
            findings.append(
                finding(
                    "warning",
                    f"{rid}: {what} at {latest:.0f}% with no growth trend: no headroom for a spike",
                    resource=rid,
                    category="capacity",
                    hint="add memory (larger node type, more shards) before the next traffic increase",
                )
            )
        elif peak is not None and peak < FORECAST_UNDERUSED_PCT:
            row["hint"] = f"peak {peak:.0f}% over the window and no growth: candidate for a smaller node type"
        return row, findings
    days = round(full[pick]["hours_to_full"] / 24, 1)
    row.update(status="growing", days_to_full=days, fastest_node=pick)
    hint = (
        "raise the DataStorage maximum or remove data before then"
        if kind == "serverless"
        else "scale up the node type or add shards (cluster mode) before then; check TTLs with node_keyspace_sample"
    )
    row["hint"] = hint
    if days < FORECAST_WARNING_DAYS:
        findings.append(
            finding(
                "critical" if days < FORECAST_CRITICAL_DAYS else "warning",
                f"{rid}: {what} projected full in about {days:g} days (now {latest:.0f}%, "
                f"{row['growth']['first_quarter_avg_pct']:g}% -> {row['growth']['last_quarter_avg_pct']:g}% "
                f"over {COST_WINDOW_DAYS} days, rough linear estimate)",
                resource=rid,
                category="capacity",
                days_to_full=days,
                hint=hint,
            )
        )
    return row, findings


def _forecast_rank(rows: list[dict]) -> list[dict]:
    """Soonest to full first; resources with no projection follow, fullest first."""
    return sorted(
        rows,
        key=lambda r: (r["days_to_full"] is None, r["days_to_full"] or 0.0, -(r.get("current_pct") or 0.0)),
    )


def _cost_manual_snapshots(snaps: list[dict], now: dt.datetime) -> tuple[dict, list[dict]]:
    views = [v for v in (_snapshot_view(s, now) for s in snaps) if not v["automatic"]]
    old = sorted(
        (v for v in views if v["age_hours"] is not None and v["age_hours"] >= OLD_MANUAL_SNAPSHOT_DAYS * 24),
        key=lambda v: -v["age_hours"],
    )
    size = sum(v["size_bytes"] or 0 for v in old)
    out = []
    if old:
        out.append(
            finding(
                "info",
                f"{len(old)} manual snapshot(s) older than {OLD_MANUAL_SNAPSHOT_DAYS} days"
                + (f" holding {size / 1024**3:.1f} GiB" if size else "")
                + f" (oldest {old[0]['name']}): manual snapshots are billed until deleted",
                category="cost",
                hint="old-snapshots",
            )
        )
    row = {
        "manual_count": len(views),
        "old_count": len(old),
        "old_size_bytes": size or None,
        "oldest": [{"name": v["name"], "age_days": int(v["age_hours"] // 24)} for v in old[:5]],
    }
    return row, out


def _tag_ownership(tags: dict[str, str]) -> dict[str, str]:
    """The owner, team and environment tags (keys matched case-insensitively; ``env`` reported as environment)."""
    out: dict[str, str] = {}
    for key, value in tags.items():
        low = key.strip().lower()
        if low in OWNER_TAG_KEYS and value:
            out.setdefault(low, value[:MAX_TAG_VALUE_CHARS])
        elif low in ENVIRONMENT_TAG_KEYS and value:
            out.setdefault("environment", value[:MAX_TAG_VALUE_CHARS])
    return out


def _offering_view(r: dict) -> dict:
    seconds = int(r.get("Duration") or 0)
    years = round(seconds / (365 * 24 * 3600))
    hourly = float(r.get("UsagePrice") or 0.0) + sum(
        float(c.get("RecurringChargeAmount") or 0.0)
        for c in r.get("RecurringCharges") or []
        if str(c.get("RecurringChargeFrequency", "")).lower() == "hourly"
    )
    fixed = float(r.get("FixedPrice") or 0.0)
    return {
        "id": r.get("ReservedCacheNodesOfferingId"),
        "term_years": years,
        "offering_type": r.get("OfferingType"),
        "fixed_price": fixed,
        "hourly_price": round(hourly, 6),
        "effective_hourly": round(hourly + fixed / (seconds / 3600), 6) if seconds else hourly,
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


# Normalised size units within a node family (as EC2 does): a reservation of N units of a family covers any mix of
# sizes of that family that fits. ElastiCache applies this to Redis OSS and Valkey reservations, not to Memcached.
_SIZE_UNITS = {
    "micro": 0.5,
    "small": 1.0,
    "medium": 2.0,
    "large": 4.0,
    "xlarge": 8.0,
    "2xlarge": 16.0,
    "4xlarge": 32.0,
    "8xlarge": 64.0,
    "12xlarge": 96.0,
    "16xlarge": 128.0,
    "24xlarge": 192.0,
}
SIZE_FLEXIBLE_ENGINES = frozenset({"redis", "valkey"})
EXPIRY_WARNING_DAYS = 30
EXPIRY_INFO_DAYS = 90


def _family_units(node_type: Any) -> tuple[str, float] | None:
    m = _NODE_TYPE.match(str(node_type or ""))
    if not m or m.group(2) not in _SIZE_UNITS:
        return None
    return m.group(1), _SIZE_UNITS[m.group(2)]


def plan_coverage(reserved: list[dict], nodes: list[tuple[str, str, str]]) -> dict[str, Any]:
    """Assign active reservations to running nodes. Shared by aws_reserved_nodes and aws_cost_overview, so the two
    tools always report the same covered node count.

    ``nodes`` is ``(node id, node type, engine)``; an empty engine matches any reservation of that node type.
    Exact node type and engine first, then size flexibility inside a family for Redis OSS / Valkey.
    Returns ``covered`` (node ids), ``size_flexible`` (the subset covered by a different size) and ``reservations``
    (one row per active reservation with the nodes it covers and the nodes it leaves unused)."""
    views = sorted((v for v in map(_reserved_view, reserved) if v["state"] == "active"), key=lambda v: str(v["id"]))
    open_nodes = {nid: (str(nt), str(eng).lower()) for nid, nt, eng in sorted(nodes)}
    covered: set[str] = set()
    flexible: set[str] = set()
    remaining = {str(v["id"]): int(v["count"] or 0) for v in views}
    exact: Counter[str] = Counter()
    for v in views:
        rid, product = str(v["id"]), str(v["product"]).lower()
        for nid, (nt, eng) in list(open_nodes.items()):
            if not remaining[rid]:
                break
            if nt == v["node_type"] and eng in (product, ""):
                covered.add(nid)
                del open_nodes[nid]
                remaining[rid] -= 1
                exact[rid] += 1
    flex: Counter[str] = Counter()
    left: dict[str, int] = dict(remaining)
    for v in views:
        rid, product = str(v["id"]), str(v["product"]).lower()
        res = _family_units(v["node_type"])
        if not res or product not in SIZE_FLEXIBLE_ENGINES or not remaining[rid]:
            continue
        family, unit = res
        budget = remaining[rid] * unit
        pool = sorted(
            (
                (-(u[1]), nid)
                for nid, (nt, eng) in open_nodes.items()
                if eng == product and (u := _family_units(nt)) and u[0] == family
            )
        )
        for neg_units, nid in pool:
            if -neg_units <= budget:
                budget += neg_units
                covered.add(nid)
                flexible.add(nid)
                del open_nodes[nid]
                flex[rid] += 1
        left[rid] = int(budget // unit)
    rows = [
        {
            **v,
            "exact_nodes": exact[str(v["id"])],
            "size_flexible_nodes": flex[str(v["id"])],
            "unused": left[str(v["id"])],
        }
        for v in views
    ]
    return {"covered": covered, "size_flexible": flexible, "reservations": rows}


RESERVED_NOTE = (
    "Matching is by node type and engine, plus size flexibility inside a family for Redis OSS and Valkey "
    "reservations. Serverless caches cannot be reserved. The API exposes no Multi-AZ class and no on-demand price, "
    "so uncovered spend is reported as node-hours per month."
)


def cluster_nodes(clusters: list[dict]) -> list[tuple[str, str, str]]:
    """(node id, node type, engine) for every node of every cluster that is not being deleted."""
    out: list[tuple[str, str, str]] = []
    for c in clusters:
        if str(c.get("CacheClusterStatus", "")).lower() in {"deleting", "deleted"}:
            continue
        cid = str(c.get("CacheClusterId"))
        for i in range(int(c.get("NumCacheNodes") or 1)):
            out.append((f"{cid}#{i}", str(c.get("CacheNodeType")), str(c.get("Engine", "")).lower()))
    return out


def _reserved_finding(severity: str, message: str, resource: str, category: str, next_tool: str, **extra: Any) -> dict:
    return finding(severity, message, resource=resource, category=category, next=next_tool, **extra)


def _mismatch_reason(node_type: str, product: str, running: dict[str, tuple[str, str]]) -> str:
    """Why a reservation covers nothing: same type on another engine, same engine on another size or family."""
    nodes = list(running.values())
    if any(nt == node_type and eng != product for nt, eng in nodes):
        return "engine mismatch: nodes of this type run another engine"
    family = _family_units(node_type)
    if any(eng == product and (u := _family_units(nt)) and family and u[0] == family[0] for nt, eng in nodes):
        return "size mismatch: nodes of this family run and are already covered or not size-flexible"
    if any(eng == product for _, eng in nodes):
        return "node type mismatch: this engine runs on other node types"
    return "no running node of this engine"


def _expiry_findings(r: dict, now: dt.datetime, running: dict[str, tuple[str, str]], unknown: bool) -> list[dict]:
    if not r["end_time"]:
        return []
    days = (dt.datetime.fromisoformat(r["end_time"]) - now).days
    if days >= EXPIRY_INFO_DAYS:
        return []
    still = sum(1 for nt, eng in running.values() if nt == r["node_type"] and eng in (str(r["product"]).lower(), ""))
    tail = (
        f"; {still} {r['node_type']} {r['product']} node(s) still running"
        if still
        else ("" if unknown else "; no matching running nodes")
    )
    when = f"in {days} days" if days >= 0 else f"{-days} days ago"
    return [
        _reserved_finding(
            "warning" if days < EXPIRY_WARNING_DAYS else "info",
            f"reservation {r['id']} ends {r['end_time']} ({when}){tail}",
            str(r["id"]),
            "expiring reservation",
            "aws_reserved_offerings",
            days_left=days,
        )
    ]
