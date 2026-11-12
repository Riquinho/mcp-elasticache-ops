"""Single-call HA and configuration posture per replication group, from Describe* rows already fetched.

Reuses the shared helpers (log delivery) and points at the tool that covers each topic in depth instead of
repeating it: failover rules live in ``aws_failover_readiness``, backups in ``aws_backup_audit``, security in
``aws_security_audit``. This audit only says which groups need that deeper look."""

from __future__ import annotations

import re
from typing import Any

from ._shared import finding, log_delivery_findings

GROUP_AUDIT_MAX_FINDINGS = 60

# A single-primary (cluster mode disabled) group scales only by moving to a bigger node: from this size up the
# next step is the largest node type, so shard out first.
BIG_NODE_SIZES = ("2xlarge", "4xlarge", "8xlarge", "12xlarge", "16xlarge", "24xlarge")

_SIZE = re.compile(r"^cache\.[a-z0-9]+\.(?P<size>[a-z0-9]+)$")


def _node_groups(g: dict) -> list[dict]:
    return list(g.get("NodeGroups") or [])


def _cluster_mode_on(g: dict) -> bool:
    return g.get("ClusterMode") in ("enabled", "compatible") or bool(g.get("ClusterEnabled"))


def group_audit_findings(g: dict, members: list[dict]) -> list[dict]:
    """Findings for one replication group; ``members`` are its DescribeCacheClusters rows (may be empty)."""
    gid = str(g.get("ReplicationGroupId"))
    out: list[dict] = []

    def add(severity: str, message: str, category: str, next_tool: str | None = None) -> None:
        extra: dict[str, Any] = {"resource": gid, "category": category}
        if next_tool:
            extra["next"] = next_tool
        out.append(finding(severity, f"{gid}: {message}", **extra))

    if g.get("MultiAZ") not in (None, "enabled"):
        add("warning", "Multi-AZ is off; an AZ outage can take the group down", "multi-az", "aws_failover_readiness")
    if g.get("AutomaticFailover") not in (None, "enabled"):
        add(
            "warning",
            "automatic failover is off; a primary failure needs a manual promotion",
            "automatic-failover",
            "aws_failover_readiness",
        )
    groups = _node_groups(g)
    for ng in groups:
        nodes = ng.get("NodeGroupMembers") or []
        shard = ng.get("NodeGroupId") or "0001"
        if len(nodes) == 1:
            add(
                "warning",
                f"shard {shard} has no replica; a node failure loses the data not yet snapshotted and the shard "
                "is down until replaced",
                "zero-replicas",
                "aws_failover_readiness",
            )
        azs = {n.get("PreferredAvailabilityZone") for n in nodes if n.get("PreferredAvailabilityZone")}
        if len(nodes) > 1 and len(azs) == 1:
            add(
                "warning",
                f"shard {shard}: primary and every replica sit in {next(iter(azs))}; one AZ outage takes the shard",
                "single-az",
                "aws_failover_readiness",
            )
    node_type = str(g.get("CacheNodeType") or (members[0].get("CacheNodeType") if members else "") or "")
    size = _SIZE.match(node_type)
    if not _cluster_mode_on(g) and size and size["size"] in BIG_NODE_SIZES:
        add(
            "info",
            f"cluster mode is disabled on {node_type}: the one shard can only grow by a bigger node and a single "
            "main thread serves every key; plan cluster mode before the next resize",
            "cluster-mode-big-node",
            "aws_scale_readiness",
        )
    if g.get("AutoMinorVersionUpgrade") is False:
        add(
            "info",
            "auto minor version upgrade is off; patches need a manual window",
            "auto-minor-upgrade",
            "aws_upgrade_plan",
        )
    if g.get("SnapshotRetentionLimit") == 0:
        add("warning", "no snapshot retention (SnapshotRetentionLimit 0)", "no-snapshots", "aws_backup_audit")
    engine = str(g.get("Engine") or (members[0].get("Engine") if members else "") or "").lower()
    for f in log_delivery_findings(g, engine):
        out.append({**f, "message": f"{gid}: {f['message']}", "resource": gid})
    transit, rest = g.get("TransitEncryptionEnabled"), g.get("AtRestEncryptionEnabled")
    if transit is False and rest is False:
        add("warning", "neither in-transit nor at-rest encryption is enabled", "encryption-mix", "aws_security_audit")
    elif transit is False or rest is False:
        off, on = ("in-transit", "at-rest") if transit is False else ("at-rest", "in-transit")
        add(
            "warning",
            f"encryption is mixed: {on} is on but {off} is off; both are set at creation, so fixing it means a new group",
            "encryption-mix",
            "aws_security_audit",
        )
    types = {str(m.get("NetworkType")) for m in members if m.get("NetworkType")}
    if len(types) > 1:
        add(
            "warning",
            f"members disagree on network type ({', '.join(sorted(types))})",
            "network-type",
            "aws_cache_clusters",
        )
    net = g.get("NetworkType") or (next(iter(types)) if len(types) == 1 else None)
    discovery = g.get("IpDiscovery")
    if net == "ipv6" and discovery and discovery != "ipv6":
        add(
            "warning", f"network type is ipv6 but IP discovery is {discovery}", "network-type", "aws_replication_groups"
        )
    elif net == "ipv4":
        add(
            "info",
            "network type is ipv4 only; clients on IPv6 or dual-stack subnets cannot use it",
            "network-type",
            "aws_replication_groups",
        )
    return out
