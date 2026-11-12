"""Cost, capacity forecast and reserved-capacity views."""

from __future__ import annotations

from collections import Counter
from typing import Any

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
)

from ._shared import (
    DATA_TIERING_METRIC,
    DATA_TIERING_METRICS,
    FLEET_DEADLINE_SECONDS,
    MAX_FLEET_FINDINGS,
    _error_code,
    _fleet_deadline_error,
    _fleet_failed,
    _monotonic,
    _sorted_findings,
    finding,
    is_data_tiered,
)
from .cost_rules import (  # noqa: F401
    _GRAVITON_FAMILY,
    COST_METRICS,
    COST_SERVERLESS_METRICS,
    COST_WINDOW_DAYS,
    ENVIRONMENT_TAG_KEYS,
    FORECAST_CRITICAL_DAYS,
    FORECAST_FULL_PCT,
    FORECAST_UNDERUSED_PCT,
    FORECAST_WARNING_DAYS,
    HOURS_PER_MONTH,
    MAX_COST_GROUPS,
    MAX_FORECAST_ROWS,
    MAX_FORECAST_TARGETS,
    MAX_OFFERINGS,
    MAX_TAG_CALLS,
    MAX_TAG_VALUE_CHARS,
    MAX_TAGS_SHOWN,
    MAX_VALKEY_CANDIDATES,
    MIN_COST_POINTS,
    OFFERING_TERMS,
    OLD_MANUAL_SNAPSHOT_DAYS,
    OVERSIZED_MEMORY_PEAK,
    OWNER_TAG_KEYS,
    RESERVED_NOTE,
    VALKEY_MIN_REDIS_VERSION,
    VALKEY_SAVINGS_NODE_PERCENT,
    VALKEY_SAVINGS_SERVERLESS_PERCENT,
    _cost_group,
    _cost_manual_snapshots,
    _cost_serverless,
    _expiry_findings,
    _forecast_rank,
    _forecast_row,
    _is_graviton,
    _mismatch_reason,
    _offering_view,
    _reserved_finding,
    _reserved_nodes_held,
    _reserved_view,
    _tag_ownership,
    _valkey_savings_findings,
    cluster_nodes,
    plan_coverage,
)
from .monitoring import _MonitoringMixin


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
            clusters = self._member_clusters()
            versions = self._member_engine_versions(clusters)
            in_groups = {str(m) for g in groups for m in g.get("MemberClusters", [])}
            plan_nodes = [
                (str(m), str(g.get("CacheNodeType")), versions.get(str(g.get("ReplicationGroupId")), ("",))[0].lower())
                for g in groups
                for m in g.get("MemberClusters", [])
            ] + cluster_nodes([c for c in clusters if str(c.get("CacheClusterId")) not in in_groups])
            plan = plan_coverage(reserved or [], plan_nodes)
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
                row, found = _cost_group(g, gid, members, replicas, metrics, plan["covered"], engine)
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
                "reserved_coverage": {
                    "running_nodes": len(plan_nodes),
                    "covered_nodes": len(plan["covered"]),
                },
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
                    ids,
                    ["DatabaseMemoryUsagePercentage"],
                    minutes,
                    3600,
                    None,
                    False,
                    rightsizing=False,
                    extra_names={
                        m: DATA_TIERING_METRICS
                        for g in groups
                        if is_data_tiered(g)
                        for m in members[str(g.get("ReplicationGroupId"))]
                    },
                )

            def vals(node: str, metric: str = "DatabaseMemoryUsagePercentage") -> list[float]:
                return list((series.get(node, {}).get(metric) or {}).get("values", []))

            rows: list[dict] = []
            findings: list[dict] = []
            for g in groups:
                gid = str(g.get("ReplicationGroupId"))
                nodes = [m for m in members[gid] if m in series]
                tiered = is_data_tiered(g) and any(vals(m, DATA_TIERING_METRIC) for m in nodes)
                row, found = _forecast_row(
                    gid,
                    "replication_group",
                    {m: vals(m, DATA_TIERING_METRIC if tiered else "DatabaseMemoryUsagePercentage") for m in nodes},
                    {
                        "node_type": g.get("CacheNodeType"),
                        "nodes": len(members[gid]),
                        **({"metric": DATA_TIERING_METRIC, "data_tiering": True} if tiered else {}),
                    },
                    "capacity (memory plus SSD)" if tiered else "memory",
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
    def reserved_nodes_fan_out(self, region: str | None = None) -> dict:
        """``reserved_nodes`` over every region in ELASTICACHE_REGIONS (at most MAX_REGIONS) or just ``region``."""
        targets = self._target_regions(region)
        if len(targets) == 1:
            return self.in_region(targets[0]).reserved_nodes()
        deadline = _monotonic() + FLEET_DEADLINE_SECONDS
        findings: list[dict] = []
        coverage: list[dict] = []
        reservations: list[dict] = []
        notes: list[str] = []
        failures: dict[str, dict] = {}
        total = Counter[str]()
        for target in targets:
            if _monotonic() >= deadline:
                failures[str(target)] = _fleet_deadline_error()
                continue
            result = self.in_region(target).reserved_nodes()
            if _fleet_failed(result):
                failures[str(target)] = result
                continue
            findings += [{**f, "region": target} for f in result["findings"]]
            coverage += [{**c, "region": target} for c in result["coverage"]]
            reservations += [{**r, "region": target} for r in result["reserved_cache_nodes"]]
            notes += [f"{target}: {n}" for n in result.get("notes", [])]
            total.update({k: v for k, v in result["summary"].items() if isinstance(v, int)})
        ordered = _sorted_findings(findings)
        out: dict[str, Any] = {
            "regions": [str(t) for t in targets],
            "reached": f"{len(targets) - len(failures)}/{len(targets)}",
            "findings": ordered[:MAX_FLEET_FINDINGS],
            "findings_total": len(ordered),
            "truncated": len(ordered) > MAX_FLEET_FINDINGS,
            "summary": dict(total),
            "coverage": coverage,
            "reserved_cache_nodes": reservations,
            "note": RESERVED_NOTE,
        }
        if notes or failures:
            out["partial"] = True
            out["notes"] = notes
        if failures:
            out["region_errors"] = failures
        return out

    def reserved_nodes(self) -> dict:
        """Findings first: expiring reservations (30 / 90 days), reservations matching no running node, running
        nodes no reservation covers and the node-hours per month billed on demand. Uses the same coverage plan as
        aws_cost_overview."""

        def run() -> dict:
            reserved = self._paginate("describe_reserved_cache_nodes", "ReservedCacheNodes")
            notes: list[str] = []
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
            nodes = cluster_nodes(clusters or [])
            plan = plan_coverage(reserved, nodes)
            by_id = {nid: (nt, eng) for nid, nt, eng in nodes}
            running: Counter[tuple[str, str]] = Counter((nt, eng) for nt, eng in by_id.values())
            uncovered: Counter[tuple[str, str]] = Counter(by_id[nid] for nid in by_id if nid not in plan["covered"])
            held: Counter[tuple[str, str]] = Counter()
            unused: Counter[tuple[str, str]] = Counter()
            for r in plan["reservations"]:
                key = (str(r["node_type"]), str(r["product"]).lower())
                held[key] += int(r["count"] or 0)
                unused[key] += r["unused"]
            coverage = []
            findings: list[dict] = []
            for key in sorted(set(running) | set(held)) if clusters is not None else []:
                node_type, product = key
                row: dict[str, Any] = {
                    "node_type": node_type,
                    "engine": product,
                    "running_nodes": running[key],
                    "reserved_nodes": held[key],
                    "on_demand_nodes": uncovered[key],
                    "unused_reservations": unused[key],
                }
                coverage.append(row)
                if row["on_demand_nodes"]:
                    findings.append(
                        _reserved_finding(
                            "info",
                            f"{row['on_demand_nodes']} on-demand {node_type} {product} node(s) not covered by a "
                            "reservation",
                            f"{node_type}/{product}",
                            "uncovered node",
                            "aws_cost_overview",
                            node_hours_per_month=row["on_demand_nodes"] * HOURS_PER_MONTH,
                        )
                    )
                if row["unused_reservations"]:
                    findings.append(
                        _reserved_finding(
                            "warning",
                            f"{row['unused_reservations']} reserved {node_type} {product} node(s) have no running "
                            "match",
                            f"{node_type}/{product}",
                            "unmatched reservation",
                            "aws_cache_clusters",
                            reason=_mismatch_reason(node_type, product, by_id),
                        )
                    )
            for r in plan["reservations"]:
                findings += _expiry_findings(r, now, by_id, clusters is None)
            uncovered_total = sum(uncovered.values())
            summary = {
                "running_nodes": sum(running.values()),
                "covered_nodes": len(plan["covered"]),
                "size_flexible_nodes": len(plan["size_flexible"]),
                "uncovered_nodes": uncovered_total,
                "uncovered_node_hours_per_month": uncovered_total * HOURS_PER_MONTH,
            }
            ordered = _sorted_findings(findings)
            out: dict[str, Any] = {
                "count": len(views),
                "findings": ordered[:MAX_FLEET_FINDINGS],
                "findings_total": len(ordered),
                "truncated": len(ordered) > MAX_FLEET_FINDINGS,
                "summary": summary if clusters is not None else {},
                "coverage": coverage,
                "reserved_cache_nodes": views,
                "note": RESERVED_NOTE,
            }
            if clusters is None:
                out["partial"] = True
                out["notes"] = notes
            return out

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
