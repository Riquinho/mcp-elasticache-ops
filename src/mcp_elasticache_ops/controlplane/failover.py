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


def _address(endpoint: dict | None) -> str | None:
    if not endpoint or not endpoint.get("Address"):
        return None
    return f"{endpoint['Address']}:{endpoint.get('Port', '')}".rstrip(":")


def reader_endpoint_findings(g: dict) -> tuple[list[dict], list[dict]]:
    """Reader-endpoint use against replica count for one group, from describe data alone.

    Returns (findings, per-shard rows). Describe data cannot show which endpoint clients use, so the
    "primary endpoint" finding is a pointer to verify, not a verdict; the single-replica and same-AZ findings
    are facts about the layout."""
    rid = str(g.get("ReplicationGroupId"))
    cluster_mode = bool(g.get("ClusterEnabled")) or g.get("ClusterMode") == "enabled"
    rows: list[dict] = []
    for ng in g.get("NodeGroups", []):
        members = ng.get("NodeGroupMembers", [])
        primary = next((m for m in members if m.get("CurrentRole") == "primary"), None)
        replicas = [m for m in members if m is not primary]
        p_az = primary.get("PreferredAvailabilityZone") if primary else None
        rows.append(
            {
                "shard": str(ng.get("NodeGroupId", "")),
                "primary_endpoint": _address(ng.get("PrimaryEndpoint")),
                "reader_endpoint": _address(ng.get("ReaderEndpoint")),
                "replicas": len(replicas),
                "primary_az": p_az,
                "replica_azs": [m.get("PreferredAvailabilityZone") for m in replicas],
                "replicas_in_primary_az": [
                    str(m.get("CacheClusterId"))
                    for m in replicas
                    if p_az and m.get("PreferredAvailabilityZone") == p_az
                ],
            }
        )
    out: list[dict] = []
    with_replicas = [r for r in rows if r["replicas"]]
    if not cluster_mode and with_replicas:
        r = with_replicas[0]
        if not r["reader_endpoint"]:
            out.append(
                finding(
                    "warning",
                    f"{r['replicas']} replica(s) exist but no reader endpoint is exposed: reads cannot reach them "
                    "except by addressing each node",
                    resource=rid,
                    category="no-reader-endpoint",
                )
            )
        else:
            out.append(
                finding(
                    "info",
                    f"{r['replicas']} replica(s) serve reads only through the reader endpoint {r['reader_endpoint']}; "
                    f"clients on the primary endpoint {r['primary_endpoint']} send every read to the primary "
                    "(describe data cannot show which one clients use: check node_clients_summary on a node)",
                    resource=rid,
                    category="primary-endpoint-reads",
                )
            )
    elif cluster_mode and with_replicas:
        out.append(
            finding(
                "info",
                "cluster-mode-enabled group has no reader endpoint: replicas serve reads only when the client "
                "connects with READONLY (read-from-replicas) enabled; otherwise all reads hit the primaries",
                resource=rid,
                category="primary-endpoint-reads",
            )
        )
    single = [r["shard"] for r in with_replicas if r["replicas"] == 1]
    if single:
        out.append(
            finding(
                "warning",
                f"{len(single)} shard(s) have a single replica ({_listed(single)}): if it fails, every read "
                "falls back to the primary until a new replica is available",
                resource=rid,
                category="single-replica",
            )
        )
    same_az = [r["shard"] for r in with_replicas if r["replicas_in_primary_az"]]
    if same_az:
        out.append(
            finding(
                "warning",
                f"replica(s) share the primary's AZ in {len(same_az)} shard(s) ({_listed(same_az)}): reads gain no "
                "AZ isolation and an AZ outage removes primary and replica together",
                resource=rid,
                category="replica-same-az",
            )
        )
    return out, rows
