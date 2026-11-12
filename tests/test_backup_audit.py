"""aws_backup_audit: one case per finding, plus bounded output and error paths."""

import datetime as dt

import boto3
import pytest
from botocore.stub import Stubber

from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane
from mcp_elasticache_ops.controlplane.restore import BACKUP_AUDIT_MAX_FINDINGS
from tests.test_scale_readiness import NOW, REGION, fake_aws_env  # noqa: F401  (autouse fixture)


def _plane():
    ec = boto3.client("elasticache", region_name=REGION)

    class Session:
        def client(self, service, region_name=None, config=None):
            return ec

    return ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW), ec


def _group(name, retention=7):
    return {"ReplicationGroupId": name, "SnapshotRetentionLimit": retention, "MemberClusters": [f"{name}-001"]}


def _snap(name, source, hours_old, status="available", kind="automated", rg=True, gib=1):
    created = NOW - dt.timedelta(hours=hours_old)
    return {
        "SnapshotName": name,
        ("ReplicationGroupId" if rg else "CacheClusterId"): source,
        "SnapshotStatus": status,
        "SnapshotSource": kind,
        "NodeSnapshots": [{"SnapshotCreateTime": created, "CacheSize": f"{gib * 1024} MB"}],
    }


def _run(groups, snaps, clusters=(), **kw):
    cp, ec = _plane()
    with Stubber(ec) as stub:
        stub.add_response("describe_replication_groups", {"ReplicationGroups": groups})
        stub.add_response("describe_cache_clusters", {"CacheClusters": list(clusters)})
        if isinstance(snaps, Exception):
            stub.add_client_error("describe_snapshots", "AccessDenied")
        else:
            stub.add_response("describe_snapshots", {"Snapshots": snaps})
        out = cp.backup_audit(**kw)
        stub.assert_no_pending_responses()
    return out


def _cats(out):
    return sorted((f["category"], f["resource"]) for f in out["findings"])


def test_healthy_fleet_has_no_findings():
    out = _run([_group("rg")], [_snap("auto-1", "rg", 5)])
    assert out["findings"] == [] and out["sources_checked"] == 1 and out["snapshots_checked"] == 1


def test_retention_zero_is_flagged_and_not_also_reported_stale():
    out = _run([_group("rg", retention=0)], [])
    assert _cats(out) == [("retention-off", "rg")]


def test_no_recent_automatic_snapshot_is_stale_with_age_in_message():
    out = _run([_group("rg")], [_snap("auto-1", "rg", 60)])
    assert _cats(out) == [("stale", "rg")] and "60h old" in out["findings"][0]["message"]


def test_snapshot_exactly_at_window_is_fresh_and_custom_window_applies():
    assert _run([_group("rg")], [_snap("a", "rg", 48)])["findings"] == []
    assert _cats(_run([_group("rg")], [_snap("a", "rg", 10)], stale_hours=6)) == [("stale", "rg")]


def test_group_with_retention_and_no_snapshot_at_all_is_stale():
    out = _run([_group("rg")], [])
    assert _cats(out) == [("stale", "rg")] and "none exists" in out["findings"][0]["message"]


def test_latest_snapshot_failed_is_flagged_even_when_an_older_one_is_fresh():
    snaps = [_snap("old", "rg", 40), _snap("bad", "rg", 2, status="failed")]
    out = _run([_group("rg")], snaps)
    assert _cats(out) == [("latest-failed", "rg")] and "bad" in out["findings"][0]["message"]


def test_old_failed_snapshot_with_newer_success_is_not_flagged():
    snaps = [_snap("bad", "rg", 30, status="failed"), _snap("ok", "rg", 2)]
    assert _run([_group("rg")], snaps)["findings"] == []


def test_old_manual_snapshots_are_aggregated_with_size():
    snaps = [
        _snap("auto", "rg", 2),
        _snap("m1", "rg", 24 * 40, kind="manual", gib=2),
        _snap("m2", "rg", 24 * 90, kind="manual", gib=2),
        _snap("m3", "rg", 24 * 5, kind="manual"),
    ]
    out = _run([_group("rg")], snaps)
    f = out["findings"][0]
    assert _cats(out) == [("manual-old", "rg")] and f["count"] == 2 and "4.00 GiB" in f["message"]
    assert _run([_group("rg")], snaps, manual_days=100)["findings"] == []


def test_snapshots_of_deleted_groups_are_orphans_but_member_cluster_snapshots_are_not():
    snaps = [
        _snap("auto", "rg", 2),
        _snap("final-ghost", "ghost", 24 * 3, kind="manual", gib=1),
        _snap("member", "rg-001", 3, rg=False),
    ]
    out = _run([_group("rg")], snaps)
    assert _cats(out) == [("orphan", "ghost")]
    assert out["findings"][0]["severity"] == "info" and "1.00 GiB" in out["findings"][0]["message"]


def test_orphan_automatic_snapshot_is_a_warning():
    out = _run([], [_snap("auto-x", "gone", 100)])
    assert out["findings"][0]["severity"] == "warning"


def test_standalone_redis_cluster_is_audited_and_memcached_and_group_members_are_not():
    clusters = [
        {"CacheClusterId": "solo", "Engine": "redis", "SnapshotRetentionLimit": 0},
        {"CacheClusterId": "mc", "Engine": "memcached"},
        {"CacheClusterId": "rg-001", "Engine": "redis", "ReplicationGroupId": "rg", "SnapshotRetentionLimit": 0},
    ]
    out = _run([_group("rg")], [_snap("a", "rg", 1)], clusters)
    assert _cats(out) == [("retention-off", "solo")] and out["sources_checked"] == 2


def test_findings_are_severity_ordered_and_bounded():
    groups = [_group(f"g{i:03d}", retention=0) for i in range(BACKUP_AUDIT_MAX_FINDINGS + 5)]
    out = _run(groups + [_group("info-rg")], [_snap("m", "info-rg", 1, kind="manual", rg=True)])
    assert len(out["findings"]) == BACKUP_AUDIT_MAX_FINDINGS
    assert out["findings_truncated"] == BACKUP_AUDIT_MAX_FINDINGS + 5 + 1
    assert {f["severity"] for f in out["findings"]} == {"warning"}


def test_describe_snapshots_denied_degrades_to_retention_only_partial():
    out = _run([_group("a", retention=0), _group("b")], Exception())
    assert out["partial"] is True and "DescribeSnapshots failed (AccessDenied)" in out["notes"][0]
    assert _cats(out) == [("retention-off", "a")]


def test_describe_groups_denied_is_a_structured_error():
    cp, ec = _plane()
    with Stubber(ec) as stub:
        stub.add_client_error("describe_replication_groups", "AccessDenied")
        out = cp.backup_audit()
    assert out["error"] == "AccessDenied"


@pytest.mark.parametrize("kw", [{"stale_hours": 0}, {"stale_hours": 721}, {"manual_days": 0}])
def test_invalid_arguments_are_rejected_without_calls(kw):
    cp, _ = _plane()
    assert cp.backup_audit(**kw)["error"] == "InvalidArgument"


def test_pagination_is_followed_for_snapshots():
    cp, ec = _plane()
    with Stubber(ec) as stub:
        stub.add_response("describe_replication_groups", {"ReplicationGroups": [_group("rg")]})
        stub.add_response("describe_cache_clusters", {"CacheClusters": []})
        stub.add_response("describe_snapshots", {"Snapshots": [_snap("a", "rg", 1)], "Marker": "m1"})
        stub.add_response("describe_snapshots", {"Snapshots": [_snap("g", "ghost", 1, kind="manual")]})
        out = cp.backup_audit()
        stub.assert_no_pending_responses()
    assert out["snapshots_checked"] == 2 and _cats(out) == [("orphan", "ghost")]
