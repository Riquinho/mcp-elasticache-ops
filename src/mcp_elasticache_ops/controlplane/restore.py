"""Restore-readiness rules for snapshots of replication groups and serverless caches."""

from __future__ import annotations

from ._shared import _size_bytes, finding

RESTORE_STALE_HOURS = 24  # newest automatic snapshot older than this: backups are not running

MANUAL_BEFORE_UPGRADE_HOURS = 7 * 24  # a manual snapshot at most this old counts as the pre-upgrade backup

RESTORE_SIZE_WARN_RATIO = 0.75  # a restored node keeps about 25% of its memory as reserved-memory headroom

MAX_RESTORE_SNAPSHOTS = 20

_GIB = 1024**3

# Approximate memory (GiB) per node type, from the ElastiCache node-type tables; used only to ask whether a
# snapshot fits a target node. Unknown types are reported, never guessed.
_NODE_MEMORY_GIB: dict[str, float] = {
    **{
        f"cache.{fam}.{size}": gib
        for fam in ("t3", "t4g")
        for size, gib in (("micro", 0.5), ("small", 1.37), ("medium", 3.09))
    },
    **{
        f"cache.{fam}.{size}": gib
        for fam in ("m5", "m6g", "m7g")
        for size, gib in (
            ("large", 6.4),
            ("xlarge", 12.93),
            ("2xlarge", 26.04),
            ("4xlarge", 52.26),
            ("12xlarge", 157.12),
        )
    },
    **{
        f"cache.{fam}.{size}": gib
        for fam in ("r5", "r6g", "r7g")
        for size, gib in (
            ("large", 13.07),
            ("xlarge", 26.32),
            ("2xlarge", 52.82),
            ("4xlarge", 105.81),
            ("12xlarge", 317.77),
        )
    },
}


def _node_memory_bytes(node_type: str | None) -> int | None:
    gib = _NODE_MEMORY_GIB.get(str(node_type or ""))
    return int(gib * _GIB) if gib else None


def _human_bytes(n: float) -> str:
    return f"{n / _GIB:.2f} GiB" if n >= _GIB else f"{n / 1024**2:.0f} MiB"


def _is(status: object, wanted: str) -> bool:
    return str(status).lower() == wanted


def _kms_findings(group_key: str | None, snapshot_keys: dict[str, str | None], resource: str) -> list[dict]:
    """Snapshots encrypted with another key than the group: a restore needs access to that key too."""
    odd = sorted(name for name, key in snapshot_keys.items() if (key or None) != (group_key or None))
    if not odd:
        return []
    listed = ", ".join(odd[:3]) + (f" (+{len(odd) - 3} more)" if len(odd) > 3 else "")
    return [
        finding(
            "warning",
            f"{len(odd)} snapshot(s) use a KMS key different from the group's ({group_key or 'service default'}): "
            f"{listed}; a restore needs kms:Decrypt on that key",
            resource=resource,
            category="kms-mismatch",
        )
    ]


def group_restore_findings(
    g: dict, snaps: list[dict], views: list[dict], members: list[dict], stale_hours: int
) -> list[dict]:
    rid = str(g.get("ReplicationGroupId"))
    out: list[dict] = []
    retention = g.get("SnapshotRetentionLimit")
    pairs = list(zip(snaps, views, strict=True))
    available = [(s, v) for s, v in pairs if _is(v["status"], "available")]
    for _, v in pairs:
        if _is(v["status"], "failed"):
            out.append(finding("warning", f"snapshot {v['name']} is in failed state", resource=rid, category="failed"))
    auto = [v for _, v in available if v["automatic"] and v["age_hours"] is not None]
    if retention == 0:
        out.append(
            finding(
                "critical",
                "automatic backups are disabled (SnapshotRetentionLimit is 0): only manual snapshots can restore "
                "this group",
                resource=rid,
                category="backups-disabled",
            )
        )
    else:
        newest = min((v["age_hours"] for v in auto), default=None)
        if newest is None or newest > stale_hours:
            when = "no available automatic snapshot exists" if newest is None else f"newest is {newest:.0f}h old"
            out.append(
                finding(
                    "warning",
                    f"no automatic snapshot in the last {stale_hours}h ({when})",
                    resource=rid,
                    category="no-recent-snapshot",
                )
            )
        if isinstance(retention, int) and retention > 0:
            past = [v for v in auto if v["age_hours"] > (retention + 1) * 24]
            if past:
                out.append(
                    finding(
                        "warning",
                        f"{len(past)} automatic snapshot(s) are older than the {retention}-day retention window "
                        f"(oldest {max(v['age_hours'] for v in past) / 24:.0f} days): retention is not expiring them",
                        resource=rid,
                        category="beyond-retention",
                    )
                )
    pending = {
        str(c.get("CacheClusterId")): c["PendingModifiedValues"]["EngineVersion"]
        for c in members
        if (c.get("PendingModifiedValues") or {}).get("EngineVersion")
    }
    if pending:
        manual = [
            v
            for _, v in available
            if not v["automatic"] and v["age_hours"] is not None and v["age_hours"] <= MANUAL_BEFORE_UPGRADE_HOURS
        ]
        if not manual:
            first = sorted(pending)
            out.append(
                finding(
                    "warning",
                    f"engine upgrade to {pending[first[0]]} is pending on {', '.join(first[:3])} and there is no "
                    f"manual snapshot from the last {MANUAL_BEFORE_UPGRADE_HOURS // 24} days: an upgrade cannot "
                    "be rolled back",
                    resource=rid,
                    category="no-pre-upgrade-snapshot",
                )
            )
    out += _kms_findings(g.get("KmsKeyId"), {str(s.get("SnapshotName")): s.get("KmsKeyId") for s in snaps}, rid)
    dated = [(s, v) for s, v in available if v["age_hours"] is not None]
    if dated:
        newest_snap, best = min(dated, key=lambda sv: sv[1]["age_hours"])
        node_type = g.get("CacheNodeType")
        capacity = _node_memory_bytes(node_type)
        per_node = max((_size_bytes(n.get("CacheSize")) or 0 for n in newest_snap.get("NodeSnapshots", [])), default=0)
        if capacity is None:
            if node_type:
                out.append(finding("info", f"memory of {node_type} is unknown: restore fit was not checked"))
        elif per_node > capacity:
            out.append(
                finding(
                    "critical",
                    f"snapshot {best['name']} holds {_human_bytes(per_node)} on its largest node but {node_type} has "
                    f"about {_human_bytes(capacity)}: the restore will not fit the target node type",
                    resource=rid,
                    category="restore-size",
                )
            )
        elif per_node > capacity * RESTORE_SIZE_WARN_RATIO:
            out.append(
                finding(
                    "warning",
                    f"snapshot {best['name']} holds {_human_bytes(per_node)} on its largest node, over "
                    f"{RESTORE_SIZE_WARN_RATIO:.0%} of {node_type} ({_human_bytes(capacity)}): little headroom "
                    "after restore",
                    resource=rid,
                    category="restore-size",
                )
            )
    return out


def serverless_restore_findings(cache: dict, snaps: list[dict], views: list[dict], stale_hours: int) -> list[dict]:
    name = str(cache.get("ServerlessCacheName"))
    out: list[dict] = []
    retention = cache.get("SnapshotRetentionLimit")
    for v in views:
        if _is(v["status"], "failed"):
            out.append(finding("warning", f"snapshot {v['name']} is in failed state", resource=name, category="failed"))
    ok = [v for v in views if _is(v["status"], "available") and v["age_hours"] is not None]
    if not retention:
        out.append(
            finding(
                "critical",
                "automatic backups are disabled (SnapshotRetentionLimit is 0 or unset): only manual snapshots can "
                "restore this cache",
                resource=name,
                category="backups-disabled",
            )
        )
    else:
        auto = [v for v in ok if _is(v["type"], "automatic")]
        newest = min((v["age_hours"] for v in auto), default=None)
        if newest is None or newest > stale_hours:
            when = "no available automatic snapshot exists" if newest is None else f"newest is {newest:.0f}h old"
            out.append(
                finding(
                    "warning",
                    f"no automatic snapshot in the last {stale_hours}h ({when})",
                    resource=name,
                    category="no-recent-snapshot",
                )
            )
        past = [v for v in auto if v["age_hours"] > (int(retention) + 1) * 24]
        if past:
            out.append(
                finding(
                    "warning",
                    f"{len(past)} automatic snapshot(s) are older than the {retention}-day retention window",
                    resource=name,
                    category="beyond-retention",
                )
            )
    keys = {str(s.get("ServerlessCacheSnapshotName")): s.get("KmsKeyId") for s in snaps}
    out += _kms_findings(cache.get("KmsKeyId"), keys, name)
    if ok:
        best = min(ok, key=lambda v: v["age_hours"])
        maximum = ((cache.get("CacheUsageLimits") or {}).get("DataStorage") or {}).get("Maximum")
        if maximum and best["size_bytes"] and best["size_bytes"] > maximum * _GIB:
            out.append(
                finding(
                    "critical",
                    f"snapshot {best['name']} holds {_human_bytes(best['size_bytes'])} but the DataStorage maximum "
                    f"is {maximum} GB: the restore will not fit",
                    resource=name,
                    category="restore-size",
                )
            )
    return out
