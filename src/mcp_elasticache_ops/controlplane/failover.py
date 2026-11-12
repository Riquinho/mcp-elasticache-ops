"""Failover-readiness rules for one replication group, from describe data alone."""

from __future__ import annotations

from ._shared import finding


def _listed(names: list[str], limit: int = 5) -> str:
    return ", ".join(names[:limit]) + (f" (+{len(names) - limit} more)" if len(names) > limit else "")


def failover_readiness_findings(g: dict, statuses: dict[str, str], prod: bool) -> tuple[list[dict], list[dict], dict]:
    """Findings, per-shard rows and a recovery-risk estimate for one group, from describe data alone.

    ``statuses`` maps CacheClusterId to CacheClusterStatus (empty when DescribeCacheClusters was unavailable)."""
    rid = str(g.get("ReplicationGroupId"))
    cluster_mode = bool(g.get("ClusterEnabled")) or g.get("ClusterMode") == "enabled"
    rows: list[dict] = []
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        primary = next((m for m in members if m.get("CurrentRole") == "primary"), None)
        replicas = [m for m in members if m is not primary]
        rows.append(
            {
                "shard": str(ng.get("NodeGroupId", "")),
                "primary": primary.get("CacheClusterId") if primary else None,
                "primary_az": primary.get("PreferredAvailabilityZone") if primary else None,
                "replicas": [
                    {
                        "id": m.get("CacheClusterId"),
                        "az": m.get("PreferredAvailabilityZone"),
                        "status": statuses.get(str(m.get("CacheClusterId"))),
                    }
                    for m in replicas
                ],
            }
        )
    out: list[dict] = []
    nodes = sum(1 + len(r["replicas"]) for r in rows)
    if not cluster_mode and nodes == 1:
        out.append(
            finding(
                "critical" if prod else "warning",
                "cluster-mode-disabled group with a single node: any node failure or maintenance restart means "
                "downtime and no failover target exists",
                resource=rid,
                category="single-node",
            )
        )
    else:
        if g.get("AutomaticFailover") not in (None, "enabled"):
            out.append(
                finding(
                    "critical" if prod else "warning",
                    f"automatic failover is {g.get('AutomaticFailover')}: a primary failure is not promoted "
                    "automatically",
                    resource=rid,
                    category="failover-disabled",
                )
            )
        if g.get("MultiAZ") not in (None, "enabled"):
            out.append(
                finding(
                    "warning",
                    f"Multi-AZ is {g.get('MultiAZ')}: replicas may not be placed or promoted across AZs",
                    resource=rid,
                    category="multi-az-disabled",
                )
            )
        bare = [r["shard"] for r in rows if not r["replicas"]]
        if bare:
            out.append(
                finding(
                    "critical",
                    f"{len(bare)} shard(s) have zero replicas ({_listed(bare)}): a primary loss there loses "
                    "availability and, without a snapshot, data",
                    resource=rid,
                    category="no-replicas",
                )
            )
        same_az = [
            r["shard"]
            for r in rows
            if r["replicas"] and r["primary_az"] and all(x["az"] == r["primary_az"] for x in r["replicas"])
        ]
        if same_az:
            out.append(
                finding(
                    "warning",
                    f"all replicas share the primary's AZ in {len(same_az)} shard(s) ({_listed(same_az)}): "
                    "an AZ outage takes the primary and every failover target",
                    resource=rid,
                    category="replicas-same-az",
                )
            )
        counts = {r["shard"]: len(r["replicas"]) for r in rows}
        if len(set(counts.values())) > 1:
            lowest = min(counts.values())
            weak = [s for s, c in counts.items() if c == lowest]
            out.append(
                finding(
                    "warning",
                    f"replica counts differ across shards ({min(counts.values())} to {max(counts.values())}): "
                    f"shard(s) {_listed(weak)} have the fewest failover targets",
                    resource=rid,
                    category="uneven-replicas",
                )
            )
    down = [
        f"{x['id']} ({x['status']})" for r in rows for x in r["replicas"] if x["status"] and x["status"] != "available"
    ]
    if down:
        out.append(
            finding(
                "warning",
                f"replica(s) not available: {_listed(down)}; they cannot take over until available",
                resource=rid,
                category="replica-state",
            )
        )
    sick_primary = [
        f"{r['primary']} ({statuses[r['primary']]})"
        for r in rows
        if r["primary"] in statuses and statuses[str(r["primary"])] != "available"
    ]
    if sick_primary:
        out.append(
            finding(
                "warning",
                f"primary not available: {_listed(sick_primary)}",
                resource=rid,
                category="primary-state",
            )
        )
    severities = {f["severity"] for f in out}
    level = "high" if "critical" in severities else "medium" if "warning" in severities else "low"
    reasons = [str(f["category"]) for f in out if f["severity"] in ("critical", "warning")]
    risk = {"level": level, "reasons": reasons}
    if level != "low":
        out.append(
            finding(
                "info",
                f"recovery risk {level}: "
                + (
                    "a primary loss can mean downtime or data loss; fix the critical findings first"
                    if level == "high"
                    else "failover should work but with reduced margin; see the warnings"
                ),
                resource=rid,
                category="recovery-risk",
            )
        )
    return out, rows, risk
