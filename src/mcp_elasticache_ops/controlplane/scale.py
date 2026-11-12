"""Scale-readiness rules: online resharding and node-type change headroom, from describe data and 7 days of metrics."""

from __future__ import annotations

from ._shared import CPU_CREDIT_WARN, finding, is_burstable

SCALE_WINDOW_MINUTES = 7 * 24 * 60
SCALE_PERIOD_SECONDS = 3600
SCALE_PRIMARY_METRICS = [
    "DatabaseMemoryUsagePercentage",
    "EngineCPUUtilization",
    "NetworkBandwidthInAllowanceExceeded",
    "NetworkBandwidthOutAllowanceExceeded",
]
SCALE_REPLICA_METRICS = ["ReplicationLag"]
CREDIT_METRIC = "CPUCreditBalance"

SCALE_IN_SAFE_MEMORY = 70.0  # projected peak memory after scale-in at or under this: safe
SCALE_IN_MAX_MEMORY = 85.0  # above this a scale-in would evict or fail: unsafe
SCALE_IN_CPU = 60.0  # projected average EngineCPUUtilization after scale-in above this: tight
SCALE_OUT_MEMORY = 75.0  # peak memory of the fullest shard at or above this advises scale-out
SCALE_OUT_CPU = 65.0  # EngineCPUUtilization p95 of the busiest shard at or above this advises scale-out
LAG_RISK_SECONDS = 1.0  # ReplicationLag p95 above this makes a node-type change (failover) risky
MEMORY_VERY_HIGH = 90.0  # a shard this full has no room for resharding copies or a smaller node type
SKEW_RATIO = 1.5  # fullest shard above this multiple of the mean: scale-out may not help

_NETWORK_EXCEEDED = ("NetworkBandwidthInAllowanceExceeded", "NetworkBandwidthOutAllowanceExceeded")
_HARD_RISKS = {"multi-az-off", "no-replicas", "replica-lag", "modification-in-progress", "burstable-low-credits"}


def _pick(summary: dict, member: str | None, name: str, key: str) -> float | None:
    s = (summary.get(member or "") or {}).get(name) or {}
    return s.get(key) if s.get("points") else None


def _pending(g: dict) -> list[str]:
    values = g.get("PendingModifiedValues") or {}
    names = [k for k, v in values.items() if v not in (None, {}, [])]
    status = str(g.get("Status", "available"))
    if status != "available":
        names.append(f"status {status}")
    return names


def _shard_rows(shards: list[dict], summary: dict) -> list[dict]:
    rows: list[dict] = []
    for sh in shards:
        members = sh["members"]
        primary = members[0] if members and sh["has_primary"] else None
        lag = [_pick(summary, m, "ReplicationLag", "p95") for m in members[1:]]
        rows.append(
            {
                "shard": sh["shard"],
                "primary": primary,
                "replicas": max(len(members) - 1, 0),
                "memory_avg": _pick(summary, primary, "DatabaseMemoryUsagePercentage", "avg"),
                "memory_max": _pick(summary, primary, "DatabaseMemoryUsagePercentage", "max"),
                "cpu_avg": _pick(summary, primary, "EngineCPUUtilization", "avg"),
                "cpu_p95": _pick(summary, primary, "EngineCPUUtilization", "p95"),
                "replication_lag_p95": max((v for v in lag if v is not None), default=None),
                "network_allowance_exceeded": sum(_pick(summary, primary, m, "sum") or 0.0 for m in _NETWORK_EXCEEDED),
            }
        )
    return rows


def _scale_in(rid: str, cluster_mode: bool, rows: list[dict], out: list[dict]) -> dict:
    n = len(rows)
    mem_max = [r["memory_max"] for r in rows if r["memory_max"] is not None]
    mem_avg = [r["memory_avg"] for r in rows if r["memory_avg"] is not None]
    cpu_avg = [r["cpu_avg"] for r in rows if r["cpu_avg"] is not None]
    verdict: dict = {"safe": None, "shards": n, "remaining_shards": None, "projected_memory_pct": None}
    if not cluster_mode:
        verdict["reason"] = "cluster-mode-disabled group: it has one shard, there is nothing to reshard"
        return verdict
    if n < 2:
        verdict.update(safe=False, reason="a single shard cannot shrink further")
        return verdict
    if len(mem_max) < n:
        verdict["reason"] = "memory metrics are missing for some shards: cannot project the post-scale memory"
        return verdict
    remaining = n - 1
    # the removed shard's data lands on the survivors; same node type, so percentages add up like bytes
    projected = sum(mem_max) / remaining
    cpu_proj = sum(cpu_avg) / remaining if len(cpu_avg) == n else None
    verdict.update(remaining_shards=remaining, projected_memory_pct=round(projected, 1))
    if cpu_proj is not None:
        verdict["projected_cpu_pct"] = round(cpu_proj, 1)
    verdict["safe"] = projected <= SCALE_IN_SAFE_MEMORY and (cpu_proj is None or cpu_proj <= SCALE_IN_CPU)
    detail = f"{n} to {remaining} shards puts about {projected:.0f}% of maxmemory on each survivor at the 7-day peak"
    if len(mem_avg) == n:
        detail += f" ({sum(mem_avg) / remaining:.0f}% on average)"
    if projected > SCALE_IN_MAX_MEMORY:
        out.append(
            finding(
                "warning",
                f"scale-in is unsafe: {detail}, above {SCALE_IN_MAX_MEMORY:.0f}%: keys would be evicted or the "
                "reshard would fail",
                resource=rid,
                category="scale-in-unsafe",
            )
        )
    elif projected > SCALE_IN_SAFE_MEMORY:
        out.append(
            finding(
                "warning",
                f"scale-in is tight: {detail}, above the {SCALE_IN_SAFE_MEMORY:.0f}% headroom target "
                "(reserved memory and resharding copy overhead need the rest)",
                resource=rid,
                category="scale-in-tight",
            )
        )
    elif cpu_proj is not None and cpu_proj > SCALE_IN_CPU:
        out.append(
            finding(
                "warning",
                f"scale-in fits in memory ({projected:.0f}%) but the survivors would average about "
                f"{cpu_proj:.0f}% EngineCPUUtilization, above {SCALE_IN_CPU:.0f}%",
                resource=rid,
                category="scale-in-cpu",
            )
        )
    else:
        out.append(finding("info", f"scale-in is safe: {detail}", resource=rid, category="scale-in-safe"))
    return verdict


def _scale_out(rid: str, cluster_mode: bool, rows: list[dict], out: list[dict]) -> dict:
    mem_max = [r["memory_max"] for r in rows if r["memory_max"] is not None]
    cpu_p95 = [r["cpu_p95"] for r in rows if r["cpu_p95"] is not None]
    reasons: list[str] = []
    if mem_max and max(mem_max) >= SCALE_OUT_MEMORY:
        reasons.append(f"fullest shard peaked at {max(mem_max):.0f}% memory")
    if cpu_p95 and max(cpu_p95) >= SCALE_OUT_CPU:
        reasons.append(f"busiest shard EngineCPUUtilization p95 {max(cpu_p95):.0f}%")
    if sum(r["network_allowance_exceeded"] for r in rows) > 0:
        reasons.append("network allowance exceeded (packets queued or dropped)")
    if not reasons:
        return {"advised": False, "reasons": []}
    if not cluster_mode:
        out.append(
            finding(
                "warning",
                f"capacity is tight ({'; '.join(reasons)}) and the group is cluster-mode disabled: it cannot add "
                "shards, so change the node type or migrate to cluster mode",
                resource=rid,
                category="scale-up-needed",
            )
        )
        return {"advised": False, "reasons": reasons}
    skewed = len(mem_max) > 1 and max(mem_max) > SKEW_RATIO * (sum(mem_max) / len(mem_max))
    note = " (memory is skewed across shards: run aws_shard_balance first, more shards may not help)" if skewed else ""
    out.append(
        finding(
            "warning", f"scale-out is advised: {'; '.join(reasons)}{note}", resource=rid, category="scale-out-advised"
        )
    )
    if mem_max and max(mem_max) >= MEMORY_VERY_HIGH:
        out.append(
            finding(
                "warning",
                f"a shard peaked at {max(mem_max):.0f}% memory: online resharding needs free memory on the source "
                "shard while slots are copied, free headroom (TTLs, big keys) before starting",
                resource=rid,
                category="reshard-memory",
            )
        )
    return {"advised": True, "reasons": reasons}


def _node_change(
    g: dict,
    rid: str,
    shards: list[dict],
    rows: list[dict],
    summary: dict,
    pending: list[str],
    statuses: dict[str, str],
    out: list[dict],
) -> dict:
    node_type = str(g.get("CacheNodeType") or "")
    risks: list[str] = []

    def risky(reason: str, category: str, message: str, severity: str = "warning") -> None:
        risks.append(reason)
        out.append(finding(severity, message, resource=rid, category=category))

    if g.get("AutomaticFailover") not in (None, "enabled") or g.get("MultiAZ") not in (None, "enabled"):
        risky(
            "multi-az-off",
            "node-change-multi-az",
            f"node-type change is risky: Multi-AZ is {g.get('MultiAZ')} and automatic failover is "
            f"{g.get('AutomaticFailover')}, so nodes are replaced without a promoted replica serving traffic",
        )
    if rows and all(r["replicas"] == 0 for r in rows):
        risky(
            "no-replicas",
            "node-change-no-replicas",
            "node-type change is risky: no shard has a replica, each primary is unavailable while it is replaced",
        )
    lags = [r["replication_lag_p95"] for r in rows if r["replication_lag_p95"] is not None]
    if lags and max(lags) > LAG_RISK_SECONDS:
        risky(
            "replica-lag",
            "node-change-replica-lag",
            f"node-type change is risky: ReplicationLag p95 reached {max(lags):.1f}s, a replica promoted now could "
            "be behind and lose writes",
        )
    if pending:
        risks.append("modification-in-progress")
    if is_burstable(node_type):
        credits = [
            v for sh in shards for m in sh["members"] if (v := _pick(summary, m, CREDIT_METRIC, "min")) is not None
        ]
        low = bool(credits) and min(credits) < CPU_CREDIT_WARN
        what = (
            f"CPUCreditBalance min {min(credits):.0f} credits, a node-type change or reshard adds CPU load the node "
            "may not have credits for"
            if low
            else "a reshard or node replacement adds CPU load that spends credits; check CPUCreditBalance first"
        )
        risky(
            "burstable-low-credits" if low else "burstable",
            "node-change-burstable",
            f"{node_type} is burstable: {what}",
            "warning" if low else "info",
        )
    mem_max = [r["memory_max"] for r in rows if r["memory_max"] is not None]
    if mem_max and max(mem_max) >= MEMORY_VERY_HIGH:
        risky(
            "memory-high",
            "node-change-memory",
            f"node-type change is risky: a shard peaked at {max(mem_max):.0f}% memory; the replacement node must "
            "load the same data and a smaller target would evict",
        )
    if any(s != "available" for s in statuses.values()):
        risks.append("node-not-available")
    hard = set(risks) & _HARD_RISKS
    return {"risk": "high" if len(hard) >= 2 else "medium" if hard else "low", "reasons": risks}


def scale_readiness(
    g: dict, shards: list[dict], summary: dict[str, dict[str, dict]], statuses: dict[str, str]
) -> tuple[list[dict], dict, dict, dict, list[dict]]:
    """Findings, scale_in / scale_out / node_type_change verdicts and per-shard rows for one replication group.

    ``shards`` is the output of ``_shard_layout``; ``summary`` maps member id to metric summaries; ``statuses`` maps
    CacheClusterId to CacheClusterStatus (empty when DescribeCacheClusters was unavailable)."""
    rid = str(g.get("ReplicationGroupId"))
    cluster_mode = bool(g.get("ClusterEnabled")) or g.get("ClusterMode") == "enabled"
    rows = _shard_rows(shards, summary)
    out: list[dict] = []
    pending = _pending(g)
    if pending:
        out.append(
            finding(
                "warning",
                f"a modification is already in progress or pending ({', '.join(pending[:4])}): wait until the group "
                "is available before resharding or changing the node type",
                resource=rid,
                category="modification-in-progress",
            )
        )
    scale_in = _scale_in(rid, cluster_mode, rows, out)
    scale_out = _scale_out(rid, cluster_mode, rows, out)
    node_change = _node_change(g, rid, shards, rows, summary, pending, statuses, out)
    return out, scale_in, scale_out, node_change, rows
