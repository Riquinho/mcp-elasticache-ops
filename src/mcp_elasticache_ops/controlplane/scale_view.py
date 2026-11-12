"""aws_scale_readiness: the control-plane view over the scale rules."""

from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from ._shared import _error_code, _sorted_findings, finding
from .scale import (
    CREDIT_METRIC,
    SCALE_PERIOD_SECONDS,
    SCALE_PRIMARY_METRICS,
    SCALE_REPLICA_METRICS,
    SCALE_WINDOW_MINUTES,
    scale_readiness,
)
from .triage import _TriageMixin, _worst_status
from .triage_overview import MAX_OVERVIEW_FINDINGS, MAX_OVERVIEW_SHARDS
from .triage_shards import MAX_SHARD_MEMBERS, _shard_layout


class _ScaleMixin(_TriageMixin):
    def scale_readiness(self, replication_group_id: str) -> dict:
        """Online resharding and node-type change headroom from 7 days of CloudWatch, findings first.

        DescribeReplicationGroups, DescribeCacheClusters and GetMetricData only; no data-plane connection."""

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
            shards = _shard_layout(g)
            primaries = [sh["members"][0] for sh in shards if sh["members"] and sh["has_primary"]]
            replicas = [m for sh in shards for m in sh["members"][1:]]
            if len(primaries) + len(replicas) > MAX_SHARD_MEMBERS:
                replicas = replicas[: max(MAX_SHARD_MEMBERS - len(primaries), 0)]
                notes.append(f"replica lag covers {len(replicas)} replicas only (member cap {MAX_SHARD_MEMBERS})")
            summary: dict[str, dict[str, dict]] = {}
            extra: list[dict] = []
            burstable = str(g.get("CacheNodeType", "")).startswith("cache.t")
            try:
                if primaries:
                    names = SCALE_PRIMARY_METRICS + ([CREDIT_METRIC] if burstable else [])
                    one, _, _ = self._collect_metrics(
                        primaries, names, SCALE_WINDOW_MINUTES, SCALE_PERIOD_SECONDS, None, False, rightsizing=False
                    )
                    summary.update(one)
                if replicas:
                    one, _, _ = self._collect_metrics(
                        replicas,
                        SCALE_REPLICA_METRICS + ([CREDIT_METRIC] if burstable else []),
                        SCALE_WINDOW_MINUTES,
                        SCALE_PERIOD_SECONDS,
                        None,
                        False,
                        rightsizing=False,
                    )
                    summary.update(one)
            except (BotoCoreError, ClientError) as exc:
                notes.append(f"metrics skipped: GetMetricData failed ({_error_code(exc)}); verdicts need metrics")
                extra.append(
                    finding(
                        "warning",
                        f"CloudWatch GetMetricData failed ({_error_code(exc)}): headroom cannot be projected, only "
                        "describe-based checks ran",
                        resource=replication_group_id,
                        category="metrics-unavailable",
                    )
                )
                summary = {}
            findings, scale_in, scale_out, node_change, rows = scale_readiness(g, shards, summary, statuses)
            ordered = _sorted_findings(extra + findings)
            return {
                "replication_group_id": replication_group_id,
                "status": "partial" if notes else "ok",
                "window_days": SCALE_WINDOW_MINUTES // 1440,
                "overall": _worst_status(ordered) if ordered else "ok",
                "node_type": g.get("CacheNodeType"),
                "findings": ordered[:MAX_OVERVIEW_FINDINGS],
                "findings_total": len(ordered),
                "scale_in": scale_in,
                "scale_out": scale_out,
                "node_type_change": node_change,
                "shards": rows[:MAX_OVERVIEW_SHARDS],
                "shards_total": len(rows),
                **({"notes": notes} if notes else {}),
            }

        return self._guard(run)
