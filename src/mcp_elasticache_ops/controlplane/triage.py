"""Findings-first triage, cluster overview and shard balance, plus the multi-region fan-outs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
)

from ._shared import (
    _PENDING_ACTION_STATUSES,
    DATA_TIERING_METRICS,
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
    is_data_tiered,
    log_delivery_findings,
)
from .failover import failover_readiness_findings, reader_endpoint_findings
from .scale import LAG_RISK_SECONDS, _pick
from .security import _SecurityMixin
from .triage_events import (  # noqa: F401
    _FAILOVER_EVENT,
    _WARNING_EVENT_WORDS,
    CORRELATION_CONN_DROP,
    CORRELATION_HOURS,
    CORRELATION_LAG_SECONDS,
    CORRELATION_MINUTES,
    MAX_CORRELATED_EVENTS,
    TRIAGE_METRICS,
    _as_utc,
    _failover_findings,
    _series_points,
    _triage_event_findings,
    _triage_peaks,
    _triage_update_findings,
)
from .triage_overview import (  # noqa: F401
    MAX_FLEET_GROUPS_PER_REGION,
    MAX_OVERVIEW_FINDINGS,
    MAX_OVERVIEW_SHARDS,
    OUTLIER_FLOORS,
    OUTLIER_RATIO,
    OVERVIEW_METRICS,
    OVERVIEW_P95,
    OVERVIEW_WINDOW_MINUTES,
    RIGHTSIZE_CPU_P95,
    RIGHTSIZE_MEMORY_P95,
    _median,
    _overview_outliers,
    _overview_rightsizing,
    _overview_topology,
    _prod_like,
    _reader_findings,
    _signal,
)
from .triage_shards import (  # noqa: F401
    MAX_HOT_SHARD_FINDINGS,
    MAX_SHARD_MEMBERS,
    SHARD_HOT_CPU,
    SHARD_HOT_RATIO,
    SHARD_IDLE_CPU,
    SHARD_ITEMS_RATIO,
    SHARD_MEMORY_POINTS,
    SHARD_MEMORY_RATIO,
    SHARD_METRICS,
    SHARD_PINNED_CPU,
    SHARD_TRAFFIC_RATIO,
    SHARD_WINDOW_MINUTES,
    _shard_balance_findings,
    _shard_layout,
    _shard_stats,
)

# Burstable (cache.t*) nodes throttle to baseline CPU when the credit balance hits zero; only these
# node types report the credit metrics, so they are requested for them alone.
BURSTABLE_METRICS = ["CPUCreditBalance", "CPUCreditUsage"]


TRIAGE_WINDOW_HOURS = 6


MAX_TRIAGE_FINDINGS = 30


_TRIAGE_FATAL = {"ReplicationGroupNotFoundFault"}  # nothing useful to report: surface it as the tool error


SERVERLESS_TRIAGE_FATAL = frozenset({"ServerlessCacheNotFoundFault"})


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
        out.append(
            finding(
                "warning",
                "automatic failover is not enabled: a primary failure needs manual action",
                next="aws_failover_readiness",
            )
        )
    if g.get("MultiAZ") not in (None, "enabled"):
        out.append(finding("warning", "Multi-AZ is not enabled", next="aws_failover_readiness"))
    out += _az_placement_findings(g, None)
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        if ng.get("Status") not in (None, "available"):
            out.append(finding("warning", f"node group {ng.get('NodeGroupId')} status is {ng.get('Status')}"))
        if len(members) == 1:
            out.append(
                finding(
                    "warning",
                    f"node group {ng.get('NodeGroupId')} has no replica: failover is impossible",
                    next="aws_failover_readiness",
                )
            )
    out += log_delivery_findings(g, str(g.get("Engine") or "").lower())
    if g.get("PendingModifiedValues"):
        out.append(finding("info", "has pending modified values"))
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
            tiered: list[str] = []

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
                if is_data_tiered(g):
                    tiered.extend(str(m) for m in g.get("MemberClusters", []))
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
                    members,
                    names,
                    TRIAGE_WINDOW_HOURS * 60,
                    300,
                    None,
                    False,
                    rightsizing=False,
                    extra_names=dict.fromkeys(tiered, DATA_TIERING_METRICS),
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

    def reader_endpoint_audit(self, replication_group_id: str) -> dict:
        """Reader-endpoint use against replica count, findings first.

        DescribeReplicationGroups and DescribeCacheClusters, plus a 1-hour ReplicationLag read from CloudWatch
        (skipped with a note when unavailable); no data-plane connection."""

        def run() -> dict:
            groups = self._paginate(
                "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=replication_group_id
            )
            if not groups:
                return {"error": "NotFound", "message": f"replication group {replication_group_id} not found"}
            g = groups[0]
            notes: list[str] = []
            statuses: dict[str, str] = {}
            try:
                for c in self._paginate("describe_cache_clusters", "CacheClusters"):
                    if c.get("ReplicationGroupId") == replication_group_id and c.get("CacheClusterId"):
                        statuses[str(c["CacheClusterId"])] = str(c.get("CacheClusterStatus"))
            except (BotoCoreError, ClientError) as exc:
                notes.append(f"node states skipped: DescribeCacheClusters failed ({_error_code(exc)})")
            findings, rows = reader_endpoint_findings(g)
            members = [m for ng in g.get("NodeGroups", []) for m in ng.get("NodeGroupMembers", [])]
            down = [
                f"{m['CacheClusterId']} ({statuses[m['CacheClusterId']]})"
                for m in members
                if statuses.get(str(m.get("CacheClusterId")), "available") != "available"
            ]
            if down:
                findings.append(
                    finding(
                        "warning",
                        f"node(s) not available: {', '.join(down[:5])}; reader traffic is already shifted to the "
                        "remaining nodes",
                        resource=replication_group_id,
                        category="replica-state",
                    )
                )
            replicas = [
                str(m["CacheClusterId"])
                for m in members
                if m.get("CurrentRole") != "primary" and m.get("CacheClusterId")
            ][:MAX_SHARD_MEMBERS]
            lag: dict[str, float] = {}
            if replicas:
                try:
                    summary, _, _ = self._collect_metrics(replicas, ["ReplicationLag"], 60, 300, None, False, False)
                    for rep in replicas:
                        v = _pick(summary, rep, "ReplicationLag", "p95")
                        if v is not None:
                            lag[rep] = round(v, 3)
                except (BotoCoreError, ClientError) as exc:
                    notes.append(f"replication lag skipped: GetMetricData failed ({_error_code(exc)})")
            slow = sorted(((k, v) for k, v in lag.items() if v > LAG_RISK_SECONDS), key=lambda kv: -kv[1])
            if slow:
                shown = ", ".join(f"{k} {v:g}s" for k, v in slow[:5])
                findings.append(
                    finding(
                        "warning",
                        f"ReplicationLag p95 above {LAG_RISK_SECONDS:g}s on {len(slow)} replica(s) ({shown}): "
                        "reads from the reader endpoint can be stale",
                        resource=replication_group_id,
                        category="replica-lag",
                    )
                )
            ordered = _sorted_findings(findings)
            clustered = bool(g.get("ClusterEnabled")) or g.get("ClusterMode") == "enabled"
            return {
                "replication_group_id": replication_group_id,
                "status": "partial" if notes else "ok",
                "overall": _worst_status(ordered) if ordered else "ok",
                "cluster_mode": "enabled" if clustered else "disabled",
                "findings": ordered[:MAX_OVERVIEW_FINDINGS],
                "findings_total": len(ordered),
                "replication_lag_p95": lag,
                "shards": rows[:MAX_OVERVIEW_SHARDS],
                "shards_total": len(rows),
                **({"notes": notes} if notes else {}),
            }

        return self._guard(run)

    def failover_readiness(self, replication_group_id: str) -> dict:
        """Would a primary failure be survived? Multi-AZ, replica count and placement per shard, findings first.

        DescribeReplicationGroups and DescribeCacheClusters only; no metrics and no data-plane connection."""

        def run() -> dict:
            groups = self._paginate(
                "describe_replication_groups", "ReplicationGroups", ReplicationGroupId=replication_group_id
            )
            if not groups:
                return {"error": "NotFound", "message": f"replication group {replication_group_id} not found"}
            g = groups[0]
            notes: list[str] = []
            statuses: dict[str, str] = {}
            try:
                for c in self._paginate("describe_cache_clusters", "CacheClusters"):
                    if c.get("ReplicationGroupId") == replication_group_id and c.get("CacheClusterId"):
                        statuses[str(c["CacheClusterId"])] = str(c.get("CacheClusterStatus"))
            except (BotoCoreError, ClientError) as exc:
                notes.append(f"node states skipped: DescribeCacheClusters failed ({_error_code(exc)})")
            findings, shards, risk = failover_readiness_findings(g, statuses, _prod_like(g))
            ordered = _sorted_findings(findings)
            return {
                "replication_group_id": replication_group_id,
                "status": "partial" if notes else "ok",
                "overall": _worst_status(ordered) if ordered else "ok",
                "recovery_risk": risk,
                "findings": ordered[:MAX_OVERVIEW_FINDINGS],
                "findings_total": len(ordered),
                "multi_az": g.get("MultiAZ"),
                "automatic_failover": g.get("AutomaticFailover"),
                "shards": shards[:MAX_OVERVIEW_SHARDS],
                "shards_total": len(shards),
                **({"notes": notes} if notes else {}),
            }

        return self._guard(run)
