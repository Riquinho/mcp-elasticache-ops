"""aws_upgrade_plan: engine upgrade pre-flight for one replication group, verdict first.

Everything is read-only (DescribeReplicationGroups, DescribeCacheClusters, DescribeCacheEngineVersions,
DescribeCacheParameterGroups, DescribeUpdateActions, DescribeSnapshots). The rules are pure functions over the
already fetched data so each blocker has a one-case test; a gate that could not be read (for example AccessDenied)
is itself a blocker, because "go" must never rest on data that was not seen."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from ..quirks import parse_version, quirks_for
from ._shared import _PENDING_ACTION_STATUSES, _error_code, _snapshot_view, _sorted_findings, finding
from .cost_rules import VALKEY_MIN_REDIS_VERSION
from .failover import failover_readiness_findings
from .inventory_views import _engine_version_views
from .monitoring import _windows_overlap
from .scale_view import _ScaleMixin
from .triage_overview import _prod_like

UPGRADE_ENGINES = ("redis", "valkey")
SNAPSHOT_MAX_AGE_HOURS = 24
MAX_PLAN_FINDINGS = 40
MAX_FAMILY_GROUPS = 10


def _blocker(category: str, message: str, resource: str) -> dict:
    return finding("critical", message, category=category, resource=resource, blocker=True)


def _fmt(version: tuple[int, ...]) -> str:
    return ".".join(str(p) for p in version)


def path_findings(
    rid: str, source: tuple[str, str], target: tuple[str, str], target_listed: bool
) -> tuple[list[dict], list[dict]]:
    """Blockers and caveats for the move ``source`` -> ``target`` (each an ``(engine, version)`` pair)."""
    blockers: list[dict] = []
    notes: list[dict] = []
    (se, sv), (te, tv) = source, target
    have, want = parse_version(sv), parse_version(tv)
    if not target_listed:
        blockers.append(
            _blocker(
                "target-unavailable",
                f"{te} {tv or '(none)'} is not offered by DescribeCacheEngineVersions in this region; "
                "aws_engine_versions lists the versions you can pick",
                rid,
            )
        )
        return blockers, notes
    if se == "valkey" and te == "redis":
        blockers.append(
            _blocker(
                "no-downgrade-to-redis",
                f"Valkey {sv} cannot be moved back to Redis OSS; stay on Valkey or restore a Redis snapshot into a "
                "new group",
                rid,
            )
        )
    elif se == te and have and want and want <= have:
        blockers.append(
            _blocker(
                "not-an-upgrade",
                f"target {te} {tv} is not newer than the running {sv}; ElastiCache only upgrades the engine version "
                "(a downgrade means a new group restored from a snapshot)",
                rid,
            )
        )
    if se == "redis" and te == "valkey":
        if have and have < VALKEY_MIN_REDIS_VERSION:
            blockers.append(
                _blocker(
                    "valkey-path",
                    f"in-place Redis OSS to Valkey needs Redis {_fmt(VALKEY_MIN_REDIS_VERSION)} or newer, the group "
                    f"runs {sv}; upgrade Redis first",
                    rid,
                )
            )
        notes.append(
            finding(
                "warning",
                "Redis OSS to Valkey changes the parameter group family (redisN to valkeyN): the custom parameter "
                "group must exist in the target family, and the move cannot be reversed in place",
                category="engine-switch",
                resource=rid,
            )
        )
    if have and want and se == te and want[0] > have[0]:
        notes.append(
            finding(
                "info",
                f"major upgrade {sv} to {tv}: the primary of each shard restarts or fails over and clients "
                "reconnect; run it in a low-traffic window and test the client library against the target first",
                category="major-upgrade",
                resource=rid,
            )
        )
    before = {q.quirk for q in quirks_for(se, sv)}
    for q in quirks_for(te, tv):
        if q.quirk not in before:
            notes.append(
                finding("info", f"{q.quirk}; {q.remediation}", category="engine-quirk", resource=rid, quirk=q.key)
            )
    return blockers, notes


def group_caveats(g: dict, rid: str, target: tuple[str, str]) -> list[dict]:
    """Settings an engine upgrade does not change but that interact with it (ACL, TLS, cluster mode)."""
    out: list[dict] = []
    te, tv = target
    if g.get("UserGroupIds"):
        out.append(
            finding(
                "info",
                f"RBAC user group(s) {', '.join(map(str, g['UserGroupIds']))} stay attached; after the upgrade run "
                "aws_security_audit and test each user's ACL rules on the target",
                category="acl",
                resource=rid,
            )
        )
        if g.get("TransitEncryptionEnabled") is False:
            out.append(
                finding(
                    "warning",
                    "RBAC is attached without in-transit encryption; ElastiCache RBAC expects TLS, so confirm the "
                    "clients and the user group before and after the upgrade",
                    category="tls",
                    resource=rid,
                )
            )
    elif parse_version(tv) >= (6,) and g.get("AuthTokenEnabled"):
        out.append(
            finding(
                "info",
                f"AUTH token in use; {te} {tv} supports RBAC users, which are the recommended replacement for the "
                "shared token",
                category="acl",
                resource=rid,
            )
        )
    clustered = bool(g.get("ClusterEnabled"))
    out.append(
        finding(
            "info",
            f"cluster mode stays {'enabled' if clustered else 'disabled'}: an engine upgrade never changes it "
            "(moving between modes means a new group)",
            category="cluster-mode",
            resource=rid,
        )
    )
    if g.get("PendingModifiedValues"):
        out.append(
            finding(
                "warning",
                f"the group already has pending modifications ({', '.join(sorted(g['PendingModifiedValues']))}); "
                "let them finish before queuing an upgrade",
                category="pending-modification",
                resource=rid,
            )
        )
    return out


def parameter_group_findings(
    rid: str, groups: list[dict], members: list[dict], target_family: str
) -> tuple[list[dict], list[dict], dict]:
    """Blockers, notes and a view of the parameter group situation for the target family."""
    names = sorted(
        {
            str((c.get("CacheParameterGroup") or {}).get("CacheParameterGroupName"))
            for c in members
            if (c.get("CacheParameterGroup") or {}).get("CacheParameterGroupName")
        }
    )
    by_name = {str(g.get("CacheParameterGroupName")): g for g in groups}
    current = [{"name": n, "family": (by_name.get(n) or {}).get("CacheParameterGroupFamily")} for n in names]
    custom_stale = [c for c in current if not str(c["name"]).startswith("default.") and c["family"] != target_family]
    in_target = sorted(
        str(g.get("CacheParameterGroupName"))
        for g in groups
        if g.get("CacheParameterGroupFamily") == target_family
        and not str(g.get("CacheParameterGroupName")).startswith("default.")
    )
    view = {
        "current": current,
        "target_family": target_family,
        "target_family_custom_groups": in_target[:MAX_FAMILY_GROUPS],
    }
    blockers: list[dict] = []
    notes: list[dict] = []
    if custom_stale and not in_target:
        stale = ", ".join(f"{c['name']} ({c['family']})" for c in custom_stale)
        blockers.append(
            _blocker(
                "parameter-group-family",
                f"custom parameter group(s) {stale} belong to another family than {target_family} and no custom "
                f"group of family {target_family} exists; create one with the same changed values "
                "(aws_parameter_drift compares two groups) before upgrading",
                rid,
            )
        )
    elif custom_stale:
        notes.append(
            finding(
                "warning",
                f"custom group(s) of family {target_family} exist ({', '.join(in_target[:3])}); pass one of them "
                "with the upgrade, otherwise the engine default group applies and tuned values are lost",
                category="parameter-group-family",
                resource=rid,
            )
        )
    return blockers, notes, view


def snapshot_gate(rid: str, views: list[dict], max_age_hours: int) -> tuple[list[dict], float | None]:
    """A usable (status ``available``) snapshot newer than ``max_age_hours`` must exist before an upgrade."""
    usable = [v for v in views if v.get("status") == "available" and v.get("age_hours") is not None]
    if not usable:
        return [_blocker("no-snapshot", "no completed snapshot exists: take a manual one before upgrading", rid)], None
    age = min(float(v["age_hours"]) for v in usable)
    if age > max_age_hours:
        return [
            _blocker(
                "stale-snapshot",
                f"newest completed snapshot is {age:g} h old (limit {max_age_hours} h): take a manual snapshot "
                "right before the upgrade",
                rid,
            )
        ], age
    return [], age


class _UpgradeMixin(_ScaleMixin):
    def upgrade_plan(
        self,
        replication_group_id: str,
        target_engine: str | None = None,
        target_version: str | None = None,
        snapshot_max_age_hours: int = SNAPSHOT_MAX_AGE_HOURS,
    ) -> dict:
        """Can this group move to ``target_engine`` ``target_version`` now? Verdict (go / no-go) and blockers first.

        Gates: engine path and version availability, parameter group family, group status, failover readiness
        and snapshot freshness; pending service updates and the maintenance window are reported alongside."""
        if target_engine is not None and target_engine not in UPGRADE_ENGINES:
            return {"error": "InvalidArgument", "message": "target_engine must be redis or valkey"}
        if not 1 <= int(snapshot_max_age_hours) <= 24 * 30:
            return {"error": "InvalidArgument", "message": "snapshot_max_age_hours must be between 1 and 720"}
        rid = replication_group_id

        def run() -> dict:
            now = self._clock()
            groups = self._paginate("describe_replication_groups", "ReplicationGroups", ReplicationGroupId=rid)
            if not groups:
                return {"error": "NotFound", "message": f"replication group {rid} not found"}
            g = groups[0]
            blockers: list[dict] = []
            notes: list[dict] = []
            gaps: list[str] = []

            def attempt(label: str, call: Callable[[], Any]) -> Any:
                try:
                    return call()
                except (BotoCoreError, ClientError) as exc:
                    gaps.append(f"{label} ({_error_code(exc)})")
                    blockers.append(
                        _blocker(
                            "unverified",
                            f"{label} failed ({_error_code(exc)}): that gate was not checked, "
                            "so the verdict cannot be go",
                            rid,
                        )
                    )
                    return None

            clusters = attempt(
                "DescribeCacheClusters",
                lambda: [
                    c
                    for c in self._paginate("describe_cache_clusters", "CacheClusters")
                    if c.get("ReplicationGroupId") == rid
                ],
            )
            members = clusters or []
            statuses = {
                str(c["CacheClusterId"]): str(c.get("CacheClusterStatus")) for c in members if c.get("CacheClusterId")
            }
            first = members[0] if members else {}
            engine = str(first.get("Engine") or "redis").lower()
            version = str(first.get("EngineVersion") or "")
            te = target_engine or engine
            if g.get("Status") != "available":
                blockers.append(_blocker("group-status", f"group status is {g.get('Status')}, not available", rid))
            offered = attempt(
                "DescribeCacheEngineVersions",
                lambda: _engine_version_views(
                    self._paginate("describe_cache_engine_versions", "CacheEngineVersions", Engine=te), None
                ),
            )
            chosen: dict | None = None
            tv = str(target_version or "")
            if offered is not None:
                if target_version:
                    chosen = next(
                        (v for v in offered if v["version"] == target_version),
                        next((v for v in offered if v["version"].startswith(f"{target_version}.")), None),
                    )
                else:
                    chosen = offered[0] if offered else None
                tv = chosen["version"] if chosen else tv
                found, more = path_findings(rid, (engine, version), (te, tv), chosen is not None)
                blockers += found
                notes += more
            target_family = str((chosen or {}).get("family") or "")
            if chosen:
                notes += group_caveats(g, rid, (te, tv))
            pgroups = attempt(
                "DescribeCacheParameterGroups",
                lambda: self._paginate("describe_cache_parameter_groups", "CacheParameterGroups"),
            )
            pview: dict = {}
            if pgroups is not None and target_family:
                found, more, pview = parameter_group_findings(rid, pgroups, members, target_family)
                blockers += found
                notes += more
            actions = attempt(
                "DescribeUpdateActions",
                lambda: self._paginate(
                    "describe_update_actions",
                    "UpdateActions",
                    ReplicationGroupIds=[rid],
                    UpdateActionStatus=list(_PENDING_ACTION_STATUSES),
                ),
            )
            pending = sorted({str(a.get("ServiceUpdateName")) for a in actions or []})
            overdue = sorted(
                {
                    str(a.get("ServiceUpdateName"))
                    for a in actions or []
                    if a.get("ServiceUpdateRecommendedApplyByDate") and a["ServiceUpdateRecommendedApplyByDate"] < now
                }
            )
            if pending:
                shown = ", ".join(pending[:3]) + ("..." if len(pending) > 3 else "")
                late = f"; past apply-by: {', '.join(overdue[:3])}" if overdue else ""
                notes.append(
                    finding(
                        "warning",
                        f"{len(pending)} service update(s) pending ({shown}{late}): they share the maintenance "
                        "window and restart nodes too; apply or schedule them together with the upgrade",
                        category="pending-service-update",
                        resource=rid,
                    )
                )
            window = first.get("PreferredMaintenanceWindow")
            snap_window = first.get("SnapshotWindow")
            if window and snap_window and _windows_overlap(str(window), str(snap_window)):
                notes.append(
                    finding(
                        "warning",
                        f"maintenance window {window} overlaps the snapshot window {snap_window}: an upgrade queued "
                        "for the window competes with the backup fork",
                        category="window-overlap",
                        resource=rid,
                    )
                )
            _, _, risk = failover_readiness_findings(g, statuses, _prod_like(g))
            reasons = ", ".join(dict.fromkeys(risk["reasons"])) or "see aws_failover_readiness"
            if risk["level"] == "high":
                blockers.append(
                    _blocker(
                        "failover-readiness",
                        f"failover readiness is high risk ({reasons}): a primary restart during the upgrade means "
                        "downtime; fix it with aws_failover_readiness first",
                        rid,
                    )
                )
            elif risk["level"] == "medium":
                notes.append(
                    finding(
                        "warning",
                        f"failover readiness is medium risk ({reasons}); the upgrade works but with reduced margin",
                        category="failover-readiness",
                        resource=rid,
                    )
                )
            snaps = attempt(
                "DescribeSnapshots", lambda: self._paginate("describe_snapshots", "Snapshots", ReplicationGroupId=rid)
            )
            age: float | None = None
            if snaps is not None:
                gate, age = snapshot_gate(rid, [_snapshot_view(s, now) for s in snaps], int(snapshot_max_age_hours))
                blockers += gate
            ordered = _sorted_findings(blockers + notes)
            return {
                "replication_group_id": rid,
                "verdict": "no-go" if blockers else "go",
                "blockers": [{"category": b["category"], "message": b["message"]} for b in blockers],
                "findings": ordered[:MAX_PLAN_FINDINGS],
                "findings_total": len(ordered),
                "status": "partial" if gaps else "ok",
                "current": {"engine": engine, "version": version},
                "target": {"engine": te, "version": tv or None, "family": target_family or None},
                "parameter_groups": pview,
                "gates": {
                    "failover_risk": risk["level"],
                    "newest_snapshot_age_hours": age,
                    "snapshot_max_age_hours": int(snapshot_max_age_hours),
                    "group_status": g.get("Status"),
                },
                "maintenance": {
                    "window": window,
                    "snapshot_window": snap_window,
                    "pending_service_updates": pending[:10],
                    "overdue_service_updates": overdue[:10],
                },
                **({"notes": [f"not checked: {x}" for x in gaps]} if gaps else {}),
            }

        return self._guard(run)
