"""Cost, capacity forecast and reserved-capacity views."""

from __future__ import annotations

import datetime as dt
import re
from collections import Counter
from typing import Any

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
)

from ._shared import (
    FLEET_DEADLINE_SECONDS,
    MAX_FLEET_FINDINGS,
    _error_code,
    _fleet_deadline_error,
    _fleet_failed,
    _jsonable,
    _memory_trend,
    _monotonic,
    _snapshot_view,
    _sorted_findings,
    _version_tuple,
    finding,
    is_burstable,
)
from .monitoring import _MonitoringMixin

COST_WINDOW_DAYS = 14


COST_METRICS = ["DatabaseMemoryUsagePercentage", "EngineCPUUtilization", "GetTypeCmds"]


COST_SERVERLESS_METRICS = ["ElastiCacheProcessingUnits", "BytesUsedForCache"]


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
    held: Counter[tuple[str, str]],
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
    if mem_peak is not None and mem_peak < OVERSIZED_MEMORY_PEAK:
        add(
            "warning" if nodes > 2 else "info",
            f"{nodes} x {node_type}: peak memory {mem_peak:.0f}% {window} (under {OVERSIZED_MEMORY_PEAK:.0f}%); "
            "a smaller node type would likely carry this dataset",
            hint="oversized",
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
    reserved_here = (
        held.get((str(node_type), engine), 0)
        if engine
        else sum(n for (nt, _), n in held.items() if nt == str(node_type))
    )
    covered = min(nodes, reserved_here)
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
    row = {
        "id": name,
        "engine": c.get("Engine"),
        "data_storage_max": storage_cap,
        "ecpu_per_second_max": ecpu_cap,
        "peak_bytes_used": used.get("max") if used.get("points") else None,
        "peak_ecpu_per_second": round(ecpu["max"] / 3600, 2) if ecpu.get("points") else None,
        "findings_total": len(out),
    }
    return row, out


def _forecast_row(
    rid: str, kind: str, series: dict[str, list[float]], extra: dict[str, Any]
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
                    f"{rid}: memory at {latest:.0f}% with no growth trend: no headroom for a spike",
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
                f"{rid}: memory projected full in about {days:g} days (now {latest:.0f}%, "
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


class _CostMixin(_MonitoringMixin):
    # ------------------------------------------------------------ cost overview
    def cost_overview_fan_out(self, region: str | None = None) -> dict:
        """``cost_overview`` over every region in ELASTICACHE_REGIONS (or just ``region``), one shared deadline."""
        targets = self._target_regions(region)
        if len(targets) == 1:
            return self.in_region(targets[0]).cost_overview()
        deadline = _monotonic() + FLEET_DEADLINE_SECONDS
        findings: list[dict] = []
        groups: list[dict] = []
        serverless: list[dict] = []
        notes: list[str] = []
        failures: dict[str, dict] = {}
        for target in targets:
            if _monotonic() >= deadline:
                failures[str(target)] = _fleet_deadline_error()
                continue
            result = self.in_region(target).cost_overview(deadline)
            if _fleet_failed(result):
                failures[str(target)] = result
                continue
            findings += [{**f, "region": target} for f in result["findings"]]
            groups += [{**g, "region": target} for g in result["groups"]]
            serverless += [{**s, "region": target} for s in result["serverless"]]
            notes += [f"{target}: {n}" for n in result.get("notes", [])]
        ordered = _sorted_findings(findings)
        out: dict[str, Any] = {
            "regions": [str(t) for t in targets],
            "window_days": COST_WINDOW_DAYS,
            "findings": ordered[:MAX_FLEET_FINDINGS],
            "findings_total": len(ordered),
            "truncated": len(ordered) > MAX_FLEET_FINDINGS,
            "groups": groups,
            "serverless": serverless,
        }
        if notes or failures:
            out["partial"] = True
            out["notes"] = notes
        if failures:
            out["region_errors"] = failures
        return out

    def cost_overview(self, deadline: float | None = None) -> dict:
        """Fleet cost and right-sizing in one call: per replication group and serverless cache.

        Joins node type and count, reserved coverage, 14-day peak memory/CPU and replica read activity, and flags
        oversized nodes, idle replicas, on-demand nodes, non-Graviton families, old manual snapshots and uncapped
        serverless caches. At most MAX_COST_GROUPS groups get a GetMetricData call (one each) and no call is made
        once ``deadline`` (a ``time.monotonic`` value) passes; what was skipped is listed in ``notes``."""

        def run() -> dict:
            now = self._clock()
            notes: list[str] = []
            groups = self._paginate("describe_replication_groups", "ReplicationGroups")
            reserved = self._best_effort(lambda: self._paginate("describe_reserved_cache_nodes", "ReservedCacheNodes"))
            snaps = self._best_effort(
                lambda: self._paginate("describe_snapshots", "Snapshots", SnapshotSource="manual")
            )
            caches = self._best_effort(lambda: self._paginate_token("describe_serverless_caches", "ServerlessCaches"))
            for label, got in (("reservations", reserved), ("manual snapshots", snaps), ("serverless caches", caches)):
                if got is None:
                    notes.append(f"{label} not checked: the Describe call failed")
            held = _reserved_nodes_held(reserved or [])
            clusters = self._member_clusters()
            versions = self._member_engine_versions(clusters)
            rows: list[dict] = []
            findings: list[dict] = []
            for i, g in enumerate(groups):
                gid = str(g.get("ReplicationGroupId"))
                members = [str(m) for m in g.get("MemberClusters", [])]
                replicas = [
                    str(m.get("CacheClusterId"))
                    for ng in g.get("NodeGroups", [])
                    for m in ng.get("NodeGroupMembers", [])
                    if m.get("CurrentRole") == "replica"
                ]
                metrics: dict[str, dict[str, dict]] = {}
                if members and (i >= MAX_COST_GROUPS or (deadline is not None and _monotonic() >= deadline)):
                    notes.append(f"{gid}: no CloudWatch call (limit of {MAX_COST_GROUPS} groups or deadline reached)")
                elif members:
                    metrics = self._cost_metrics(members, False)
                engine = versions.get(gid, (str(g.get("Engine") or ""), ""))[0].lower()
                row, found = _cost_group(g, gid, members, replicas, metrics, held, engine)
                rows.append(row)
                findings += found
            names = [str(c.get("ServerlessCacheName")) for c in (caches or [])][:MAX_COST_GROUPS]
            sl_metrics: dict[str, dict[str, dict]] = {}
            if names and deadline is not None and _monotonic() >= deadline:
                notes.append("serverless metrics skipped: deadline reached")
            elif names:
                sl_metrics = self._cost_metrics(names, True)
            serverless_rows: list[dict] = []
            for c in caches or []:
                row, found = _cost_serverless(c, sl_metrics.get(str(c.get("ServerlessCacheName")), {}))
                serverless_rows.append(row)
                findings += found
            snap_row, snap_found = _cost_manual_snapshots(snaps or [], now)
            findings += snap_found
            findings += _valkey_savings_findings(groups, clusters, caches or [], versions)
            ordered = _sorted_findings(findings)
            out: dict[str, Any] = {
                "window_days": COST_WINDOW_DAYS,
                "findings": ordered[:MAX_FLEET_FINDINGS],
                "findings_total": len(ordered),
                "truncated": len(ordered) > MAX_FLEET_FINDINGS,
                "groups": rows,
                "serverless": serverless_rows,
                "manual_snapshots": snap_row,
            }
            if notes:
                out["partial"] = True
                out["notes"] = notes
            return out

        return self._guard(run)

    # ------------------------------------------------------------ capacity forecast
    def capacity_forecast_fan_out(self, region: str | None = None) -> dict:
        """``capacity_forecast`` over every region in ELASTICACHE_REGIONS (or just ``region``), one shared deadline."""
        targets = self._target_regions(region)
        if len(targets) == 1:
            return self.in_region(targets[0]).capacity_forecast()
        deadline = _monotonic() + FLEET_DEADLINE_SECONDS
        findings: list[dict] = []
        rows: list[dict] = []
        notes: list[str] = []
        failures: dict[str, dict] = {}
        for target in targets:
            if _monotonic() >= deadline:
                failures[str(target)] = _fleet_deadline_error()
                continue
            result = self.in_region(target).capacity_forecast(deadline)
            if _fleet_failed(result):
                failures[str(target)] = result
                continue
            findings += [{**f, "region": target} for f in result["findings"]]
            rows += [{**r, "region": target} for r in result["forecast"]]
            notes += [f"{target}: {n}" for n in result.get("notes", [])]
        ordered = _sorted_findings(findings)
        ranked = _forecast_rank(rows)
        out: dict[str, Any] = {
            "regions": [str(t) for t in targets],
            "window_days": COST_WINDOW_DAYS,
            "findings": ordered[:MAX_FLEET_FINDINGS],
            "findings_total": len(ordered),
            "truncated": len(ordered) > MAX_FLEET_FINDINGS or len(ranked) > MAX_FORECAST_ROWS,
            "forecast": ranked[:MAX_FORECAST_ROWS],
        }
        if notes or failures:
            out["partial"] = True
            out["notes"] = notes
        if failures:
            out["region_errors"] = failures
        return out

    def capacity_forecast(self, deadline: float | None = None) -> dict:
        """Days until memory is full for every replication group, standalone cluster and serverless cache.

        Reads 14 days of hourly DatabaseMemoryUsagePercentage for all node ids in one GetMetricData batch (Serverless:
        BytesUsedForCache against the DataStorage maximum), projects each series with the linear trend used by
        ``aws_metrics`` and ranks the fleet by days to full. Findings first: under 7 days critical, under 30
        warning, each with a right-sizing hint. Memcached has no such metric and is skipped."""

        def run() -> dict:
            notes: list[str] = []
            groups = self._paginate("describe_replication_groups", "ReplicationGroups")
            clusters = self._member_clusters()
            caches = self._best_effort(lambda: self._paginate_token("describe_serverless_caches", "ServerlessCaches"))
            if caches is None:
                notes.append("serverless caches not checked: the Describe call failed")
            members: dict[str, list[str]] = {
                str(g.get("ReplicationGroupId")): [str(m) for m in g.get("MemberClusters", [])] for g in groups
            }
            standalone = [
                c
                for c in clusters
                if not c.get("ReplicationGroupId") and str(c.get("Engine", "")).lower() in ("redis", "valkey")
            ]
            skipped = sum(1 for c in clusters if str(c.get("Engine", "")).lower() == "memcached")
            if skipped:
                notes.append(f"{skipped} memcached cluster(s) skipped: no memory percentage metric")
            ids = list(
                dict.fromkeys(
                    [m for ms in members.values() for m in ms] + [str(c["CacheClusterId"]) for c in standalone]
                )
            )
            if len(ids) > MAX_FORECAST_TARGETS:
                notes.append(f"only the first {MAX_FORECAST_TARGETS} of {len(ids)} nodes were queried")
                ids = ids[:MAX_FORECAST_TARGETS]
            minutes = COST_WINDOW_DAYS * 24 * 60
            series: dict[str, dict[str, dict]] = {}
            if ids:
                _, series, _ = self._collect_metrics(
                    ids, ["DatabaseMemoryUsagePercentage"], minutes, 3600, None, False, rightsizing=False
                )

            def vals(node: str) -> list[float]:
                return list((series.get(node, {}).get("DatabaseMemoryUsagePercentage") or {}).get("values", []))

            rows: list[dict] = []
            findings: list[dict] = []
            for g in groups:
                gid = str(g.get("ReplicationGroupId"))
                nodes = [m for m in members[gid] if m in series]
                row, found = _forecast_row(
                    gid,
                    "replication_group",
                    {m: vals(m) for m in nodes},
                    {"node_type": g.get("CacheNodeType"), "nodes": len(members[gid])},
                )
                rows.append(row)
                findings += found
            for c in standalone:
                cid = str(c["CacheClusterId"])
                if cid in series:
                    row, found = _forecast_row(
                        cid, "cluster", {cid: vals(cid)}, {"node_type": c.get("CacheNodeType"), "nodes": 1}
                    )
                    rows.append(row)
                    findings += found
            names = [str(c.get("ServerlessCacheName")) for c in (caches or [])]
            if len(names) > MAX_FORECAST_TARGETS:
                notes.append(f"only the first {MAX_FORECAST_TARGETS} of {len(names)} serverless caches were queried")
                names = names[:MAX_FORECAST_TARGETS]
            sl_series: dict[str, dict[str, dict]] = {}
            if names and deadline is not None and _monotonic() >= deadline:
                notes.append("serverless caches skipped: deadline reached")
            elif names:
                _, sl_series, _ = self._collect_metrics(
                    names, ["BytesUsedForCache"], minutes, 3600, None, True, rightsizing=False
                )
            for c in caches or []:
                name = str(c.get("ServerlessCacheName"))
                max_gb = ((c.get("CacheUsageLimits") or {}).get("DataStorage") or {}).get("Maximum")
                extra = {"engine": c.get("Engine"), "data_storage_max_gb": max_gb}
                raw = list((sl_series.get(name, {}).get("BytesUsedForCache") or {}).get("values", []))
                if not max_gb:
                    rows.append(
                        {
                            "id": name,
                            "kind": "serverless",
                            **extra,
                            "current_pct": None,
                            "peak_pct": None,
                            "status": "uncapped",
                            "days_to_full": None,
                            "hint": "no DataStorage maximum is set: the cache scales without a ceiling, so there "
                            "is no full point to forecast (set a maximum to cap cost)",
                        }
                    )
                    continue
                pct = [100.0 * v / (float(max_gb) * 1024**3) for v in raw]
                row, found = _forecast_row(name, "serverless", {name: pct}, extra)
                rows.append(row)
                findings += found
            ranked = _forecast_rank(rows)
            ordered = _sorted_findings(findings)
            out: dict[str, Any] = {
                "window_days": COST_WINDOW_DAYS,
                "findings": ordered[:MAX_FLEET_FINDINGS],
                "findings_total": len(ordered),
                "truncated": len(ordered) > MAX_FLEET_FINDINGS or len(ranked) > MAX_FORECAST_ROWS,
                "forecast": ranked[:MAX_FORECAST_ROWS],
            }
            if notes:
                out["partial"] = True
                out["notes"] = notes
            return out

        return self._guard(run)

    def _cost_metrics(self, targets: list[str], serverless: bool) -> dict[str, dict[str, dict]]:
        """One GetMetricData call (hourly points over COST_WINDOW_DAYS); empty when CloudWatch denies it."""
        names = COST_SERVERLESS_METRICS if serverless else COST_METRICS
        try:
            summary, _, _ = self._collect_metrics(
                targets, names, COST_WINDOW_DAYS * 24 * 60, 3600, None, serverless, rightsizing=False
            )
        except (BotoCoreError, ClientError):
            return {}
        return summary

    # ---------------------------------------------------------- reserved nodes
    def reserved_nodes(self, expiring_days: int = 60) -> dict:
        def run() -> dict:
            reserved = self._paginate("describe_reserved_cache_nodes", "ReservedCacheNodes")
            notes = [
                "Matching is by exact node type and engine; size-flexible matching within a family is not "
                "modelled. Serverless caches cannot be reserved."
            ]
            clusters: list[dict] | None
            try:
                clusters = self._paginate("describe_cache_clusters", "CacheClusters")
            except (BotoCoreError, ClientError) as exc:
                clusters = None
                notes.append(
                    f"running-fleet comparison skipped: DescribeCacheClusters failed ({_error_code(exc)}); "
                    "only the reservation list is shown"
                )
            now = self._clock()
            views = [_reserved_view(r) for r in reserved]
            active = [v for v in views if v["state"] == "active"]
            running: Counter[tuple[str, str]] = Counter()
            for c in clusters or []:
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
            for key in sorted(set(running) | set(held)) if clusters is not None else []:
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
                    days = (dt.datetime.fromisoformat(v["end_time"]) - now).days
                    still = running[(str(v["node_type"]), str(v["product"]).lower())]
                    tail = (
                        f"; {still} {v['node_type']} {v['product']} node(s) still running"
                        if still
                        else ""
                        if clusters is None
                        else "; no matching running nodes"
                    )
                    findings.append(
                        finding(
                            "warning",
                            f"reservation {v['id']} ends {v['end_time']} (in {days} days){tail}",
                            resource=v["id"],
                        )
                    )
            return {
                "count": len(views),
                "findings": _sorted_findings(findings),
                "coverage": coverage,
                "reserved_cache_nodes": views,
                "note": notes[0],
                **({"partial": True, "notes": notes[1:]} if clusters is None else {}),
            }

        return self._guard(run)

    def reserved_offerings(self, node_type: str, engine: str) -> dict:
        """Matching 1y/3y offerings plus the number of running nodes no reservation covers. Never purchases."""

        def run() -> dict:
            engine_key = engine.lower()
            raw = self._paginate(
                "describe_reserved_cache_nodes_offerings",
                "ReservedCacheNodesOfferings",
                CacheNodeType=node_type,
                ProductDescription=engine_key,
            )
            offerings = [o for o in (_offering_view(r) for r in raw) if o["term_years"] in OFFERING_TERMS]
            notes: list[str] = []
            uncovered: int | None = None
            try:
                clusters = self._paginate("describe_cache_clusters", "CacheClusters")
                reserved = self._paginate("describe_reserved_cache_nodes", "ReservedCacheNodes")
            except (BotoCoreError, ClientError) as exc:
                notes.append(f"uncovered-node count skipped: listing failed ({_error_code(exc)})")
            else:
                running = sum(
                    int(c.get("NumCacheNodes") or 1)
                    for c in clusters
                    if c.get("CacheNodeType") == node_type
                    and str(c.get("Engine", "")).lower() == engine_key
                    and str(c.get("CacheClusterStatus", "")).lower() not in {"deleting", "deleted"}
                )
                held = sum(
                    int(r.get("CacheNodeCount") or 0)
                    for r in reserved
                    if r.get("State") == "active"
                    and r.get("CacheNodeType") == node_type
                    and str(r.get("ProductDescription", "")).lower() == engine_key
                )
                uncovered = max(0, running - held)
            cheapest = {
                term: min(group, key=lambda o: o["effective_hourly"])
                for term in sorted(OFFERING_TERMS)
                if (group := [o for o in offerings if o["term_years"] == term])
            }
            findings: list[dict] = []
            if not offerings:
                findings.append(finding("info", f"no 1y/3y offerings for {node_type} {engine_key}"))
            elif uncovered:
                for term, o in cheapest.items():
                    findings.append(
                        finding(
                            "info",
                            f"{uncovered} uncovered {node_type} {engine_key} node(s); cheapest {term}y offering "
                            f"{o['id']} ({o['offering_type']}): ${o['fixed_price']:.2f} upfront + "
                            f"${o['hourly_price']:.4f}/h per node",
                            resource=o["id"],
                        )
                    )
            offerings.sort(key=lambda o: (o["term_years"], o["effective_hourly"]))
            return {
                "node_type": node_type,
                "engine": engine_key,
                "uncovered_nodes": uncovered,
                "findings": _sorted_findings(findings),
                "cheapest_per_term": {f"{t}y": o for t, o in cheapest.items()},
                "offerings": offerings[:MAX_OFFERINGS],
                "offerings_total": len(offerings),
                "note": "Prices are per node. This tool never purchases anything.",
                **({"partial": True, "notes": notes} if notes else {}),
            }

        return self._guard(run)

    def _tag_context(self, resource: str, arns: list[str | None]) -> tuple[dict[str, Any], list[dict]]:
        """Tags and ownership for one resource, from at most MAX_TAG_CALLS ListTagsForResource calls.

        The ARNs are tried in order (replication group first, then a member cluster) until one carries an
        owner/team/environment tag. Never fails the tool: an API error becomes ``tags_note`` and no finding."""
        tags: dict[str, str] = {}
        note: str | None = None
        known = [a for a in arns if a][:MAX_TAG_CALLS]
        if not known:
            return {}, []
        ec = self.client("elasticache")
        for arn in known:
            try:
                listed = ec.list_tags_for_resource(ResourceName=arn).get("TagList", [])
            except (BotoCoreError, ClientError) as exc:
                note = f"tags unavailable ({_error_code(exc)}); ownership could not be checked"
                break
            for t in listed:
                tags.setdefault(str(t.get("Key", "")), str(t.get("Value", "")))
            if _tag_ownership(tags):
                break
        out: dict[str, Any] = {}
        if tags:
            out["tags"] = {k: v[:MAX_TAG_VALUE_CHARS] for k, v in list(tags.items())[:MAX_TAGS_SHOWN]}
        ownership = _tag_ownership(tags)
        if ownership:
            out["ownership"] = ownership
        if note:
            out["tags_note"] = note
            return out, []
        if not any(k in ownership for k in (*OWNER_TAG_KEYS, *ENVIRONMENT_TAG_KEYS)):
            return out, [
                finding(
                    "info",
                    "no owner, team or environment tag: on-call cannot tell whom to page; tag the resource",
                    resource=resource,
                    category="ownership",
                )
            ]
        return out, []
