"""Stubber cases for aws_snapshot_restore_readiness and aws_failover_readiness (one case per finding)."""

import datetime as dt

import boto3
import pytest
from botocore.stub import Stubber

from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane

REGION = "us-east-1"
NOW = dt.datetime(2026, 11, 12, 12, 0, tzinfo=dt.UTC)
KEY = "arn:aws:kms:us-east-1:1:key/group"


@pytest.fixture(autouse=True)
def fake_aws_env(monkeypatch, tmp_path):
    for var in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


@pytest.fixture()
def aws():
    ec = boto3.client("elasticache", region_name=REGION)

    class Session:
        def client(self, service, region_name=None, config=None):
            return ec

    cp = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)
    with Stubber(ec) as stub:
        yield cp, stub
        stub.assert_no_pending_responses()


def _ago(hours):
    return NOW - dt.timedelta(hours=hours)


def _snap(name, hours, source="automated", status="available", size="2 GB", kms=KEY, node_type="cache.r6g.large"):
    snap = {
        "SnapshotName": name,
        "ReplicationGroupId": "rg",
        "SnapshotStatus": status,
        "SnapshotSource": source,
        "Engine": "valkey",
        "CacheNodeType": node_type,
        "NodeSnapshots": [{"SnapshotCreateTime": _ago(hours), "CacheSize": size}],
    }
    if kms:
        snap["KmsKeyId"] = kms
    return snap


def _group(retention=7, node_type="cache.r6g.large", kms=KEY):
    g = {
        "ReplicationGroupId": "rg",
        "Status": "available",
        "CacheNodeType": node_type,
        "SnapshotRetentionLimit": retention,
    }
    if kms:
        g["KmsKeyId"] = kms
    return g


def _restore(aws, group, snaps, clusters=()):
    cp, stub = aws
    stub.add_response("describe_replication_groups", {"ReplicationGroups": [group]})
    stub.add_response("describe_snapshots", {"Snapshots": snaps})
    stub.add_response("describe_cache_clusters", {"CacheClusters": list(clusters)})
    return cp.snapshot_restore_readiness("rg")


def _categories(out):
    return {f.get("category") for f in out["findings"]}


def test_snapshot_restore_healthy_group_has_no_findings(aws):
    out = _restore(aws, _group(), [_snap("auto", 5), _snap("man", 30, source="manual")])
    assert out["findings"] == [] and out["overall"] == "ok" and out["snapshot_count"] == 2
    assert out["snapshots"][0]["name"] == "auto"


def test_snapshot_restore_retention_zero_means_backups_disabled(aws):
    out = _restore(aws, _group(retention=0), [_snap("man", 30, source="manual")])
    first = out["findings"][0]
    assert first["severity"] == "critical" and first["category"] == "backups-disabled"
    assert "no-recent-snapshot" not in _categories(out)  # the disabled-backups finding already says it


def test_snapshot_restore_no_automatic_snapshot_in_24h(aws):
    out = _restore(aws, _group(), [_snap("old", 30)])
    f = next(f for f in out["findings"] if f["category"] == "no-recent-snapshot")
    assert f["severity"] == "warning" and "30h old" in f["message"]


def test_snapshot_restore_no_automatic_snapshot_at_all(aws):
    out = _restore(aws, _group(), [])
    f = next(f for f in out["findings"] if f["category"] == "no-recent-snapshot")
    assert "no available automatic snapshot exists" in f["message"]


def test_snapshot_restore_snapshot_older_than_retention_window(aws):
    out = _restore(aws, _group(retention=3), [_snap("fresh", 2), _snap("stale", 24 * 9)])
    f = next(f for f in out["findings"] if f["category"] == "beyond-retention")
    assert "1 automatic snapshot" in f["message"] and "3-day" in f["message"]


def test_snapshot_restore_manual_snapshots_are_not_subject_to_retention(aws):
    out = _restore(aws, _group(retention=3), [_snap("fresh", 2), _snap("pinned", 24 * 90, source="manual")])
    assert "beyond-retention" not in _categories(out)


def test_snapshot_restore_failed_snapshot(aws):
    out = _restore(aws, _group(), [_snap("fresh", 2), _snap("bad", 3, status="failed")])
    f = next(f for f in out["findings"] if f["category"] == "failed")
    assert "bad" in f["message"] and f["severity"] == "warning"


def test_snapshot_restore_pending_engine_upgrade_without_manual_snapshot(aws):
    member = {"CacheClusterId": "rg-001", "ReplicationGroupId": "rg", "PendingModifiedValues": {"EngineVersion": "8.0"}}
    out = _restore(aws, _group(), [_snap("fresh", 2)], [member])
    f = next(f for f in out["findings"] if f["category"] == "no-pre-upgrade-snapshot")
    assert "8.0" in f["message"] and "rg-001" in f["message"]


def test_snapshot_restore_pending_upgrade_with_recent_manual_snapshot_is_fine(aws):
    member = {"CacheClusterId": "rg-001", "ReplicationGroupId": "rg", "PendingModifiedValues": {"EngineVersion": "8.0"}}
    out = _restore(aws, _group(), [_snap("fresh", 2), _snap("pre", 48, source="manual")], [member])
    assert "no-pre-upgrade-snapshot" not in _categories(out)


def test_snapshot_restore_kms_key_differs_from_the_group(aws):
    out = _restore(aws, _group(), [_snap("fresh", 2, kms="arn:aws:kms:us-east-1:1:key/other")])
    f = next(f for f in out["findings"] if f["category"] == "kms-mismatch")
    assert "fresh" in f["message"] and "kms:Decrypt" in f["message"]


def test_snapshot_restore_snapshot_does_not_fit_the_node_type(aws):
    out = _restore(aws, _group(node_type="cache.t3.small"), [_snap("fresh", 2, size="4 GB")])
    f = next(f for f in out["findings"] if f["category"] == "restore-size")
    assert f["severity"] == "critical" and "will not fit" in f["message"]


def test_snapshot_restore_snapshot_leaves_little_headroom(aws):
    out = _restore(aws, _group(node_type="cache.t3.small"), [_snap("fresh", 2, size="1.1 GB")])
    f = next(f for f in out["findings"] if f["category"] == "restore-size")
    assert f["severity"] == "warning" and "headroom" in f["message"]


def test_snapshot_restore_unknown_node_type_is_reported_not_guessed(aws):
    out = _restore(aws, _group(node_type="cache.x99.huge"), [_snap("fresh", 2, size="400 GB")])
    assert "restore-size" not in _categories(out)
    assert any("memory of cache.x99.huge is unknown" in f["message"] for f in out["findings"])


def test_snapshot_restore_findings_are_worst_first(aws):
    out = _restore(
        aws, _group(retention=0, node_type="cache.t3.small"), [_snap("bad", 2, status="failed", size="9 GB")]
    )
    rank = {"critical": 0, "warning": 1, "info": 2}
    assert [rank[f["severity"]] for f in out["findings"]] == sorted(rank[f["severity"]] for f in out["findings"])


def _scache(retention=7, kms=KEY, storage=None):
    c = {"ServerlessCacheName": "sc", "Engine": "valkey", "KmsKeyId": kms}
    if retention:
        c["SnapshotRetentionLimit"] = retention
    if storage:
        c["CacheUsageLimits"] = {"DataStorage": {"Maximum": storage, "Unit": "GB"}}
    return c


def _ssnap(name, hours, kind="automatic", status="available", size="1048576", kms=KEY):
    return {
        "ServerlessCacheSnapshotName": name,
        "SnapshotType": kind,
        "Status": status,
        "CreateTime": _ago(hours),
        "BytesUsedForCache": size,
        "KmsKeyId": kms,
        "ServerlessCacheConfiguration": {"ServerlessCacheName": "sc", "Engine": "valkey"},
    }


def _serverless(aws, cache, snaps):
    cp, stub = aws
    stub.add_response("describe_serverless_caches", {"ServerlessCaches": [cache]})
    stub.add_response("describe_serverless_cache_snapshots", {"ServerlessCacheSnapshots": snaps})
    return cp.snapshot_restore_readiness(serverless_cache_name="sc")


def test_snapshot_restore_serverless_healthy(aws):
    out = _serverless(aws, _scache(), [_ssnap("a", 3)])
    assert out["findings"] == [] and out["kind"] == "serverless"


def test_snapshot_restore_serverless_each_finding(aws):
    out = _serverless(
        aws,
        _scache(retention=2, storage=1),
        [
            _ssnap("old", 24 * 6),
            _ssnap("bad", 3, status="failed"),
            _ssnap("big", 30, size=str(2 * 1024**3), kms="arn:aws:kms:us-east-1:1:key/other"),
        ],
    )
    assert {"no-recent-snapshot", "beyond-retention", "failed", "kms-mismatch", "restore-size"} <= _categories(out)


def test_snapshot_restore_serverless_size_over_storage_maximum(aws):
    out = _serverless(aws, _scache(storage=1), [_ssnap("big", 2, size=str(2 * 1024**3))])
    f = next(f for f in out["findings"] if f["category"] == "restore-size")
    assert f["severity"] == "critical"


def test_snapshot_restore_serverless_backups_disabled(aws):
    out = _serverless(aws, _scache(retention=0), [_ssnap("m", 5, kind="manual")])
    assert out["findings"][0]["category"] == "backups-disabled"


def test_snapshot_restore_arguments_and_not_found(aws):
    cp, stub = aws
    assert cp.snapshot_restore_readiness()["error"] == "InvalidArgument"
    assert cp.snapshot_restore_readiness("a", "b")["error"] == "InvalidArgument"
    assert cp.snapshot_restore_readiness("a", stale_hours=0)["error"] == "InvalidArgument"
    stub.add_response("describe_replication_groups", {"ReplicationGroups": []})
    assert cp.snapshot_restore_readiness("ghost")["error"] == "NotFound"
    stub.add_response("describe_serverless_caches", {"ServerlessCaches": []})
    assert cp.snapshot_restore_readiness(serverless_cache_name="ghost")["error"] == "NotFound"


def test_snapshot_restore_access_denied_is_an_error_dict(aws):
    cp, stub = aws
    stub.add_client_error("describe_replication_groups", "AccessDenied")
    assert cp.snapshot_restore_readiness("rg")["error"] == "AccessDenied"


# ------------------------------------------------------------ failover readiness


def _member(cid, role, az):
    return {"CacheClusterId": cid, "CurrentRole": role, "PreferredAvailabilityZone": az}


def _shard(i, replicas, primary_az="us-east-1a", replica_azs=("us-east-1b", "us-east-1c")):
    members = [_member(f"rg-000{i}-001", "primary", primary_az)]
    members += [_member(f"rg-000{i}-00{n + 2}", "replica", replica_azs[n % len(replica_azs)]) for n in range(replicas)]
    return {"NodeGroupId": f"000{i}", "NodeGroupMembers": members}


def _fo_group(shards, failover="enabled", multi_az="enabled", clustered=True, rid="rg"):
    return {
        "ReplicationGroupId": rid,
        "Status": "available",
        "AutomaticFailover": failover,
        "MultiAZ": multi_az,
        "ClusterEnabled": clustered,
        "NodeGroups": shards,
    }


def _failover(aws, group, statuses=None):
    cp, stub = aws
    stub.add_response("describe_replication_groups", {"ReplicationGroups": [group]})
    clusters = [
        {"CacheClusterId": cid, "ReplicationGroupId": group["ReplicationGroupId"], "CacheClusterStatus": st}
        for cid, st in (statuses or {}).items()
    ]
    clusters.append({"CacheClusterId": "other-001", "ReplicationGroupId": "other", "CacheClusterStatus": "creating"})
    stub.add_response("describe_cache_clusters", {"CacheClusters": clusters})
    return cp.failover_readiness("rg")


def _fo_categories(out):
    return {f.get("category") for f in out["findings"]}


def test_failover_readiness_healthy_group(aws):
    out = _failover(aws, _fo_group([_shard(1, 2), _shard(2, 2)]), {"rg-0001-002": "available"})
    assert out["findings"] == [] and out["overall"] == "ok" and out["recovery_risk"]["level"] == "low"
    assert out["shards_total"] == 2


def test_failover_readiness_failover_and_multi_az_disabled(aws):
    out = _failover(aws, _fo_group([_shard(1, 1)], failover="disabled", multi_az="disabled", clustered=False))
    assert {"failover-disabled", "multi-az-disabled"} <= _fo_categories(out)
    assert out["recovery_risk"]["level"] == "medium"  # not prod-like: warnings only


def test_failover_readiness_zero_replicas_per_shard_is_critical(aws):
    out = _failover(aws, _fo_group([_shard(1, 1), _shard(2, 0), _shard(3, 0)]))
    f = next(f for f in out["findings"] if f["category"] == "no-replicas")
    assert f["severity"] == "critical" and "0002, 0003" in f["message"] and out["recovery_risk"]["level"] == "high"


def test_failover_readiness_replicas_in_the_primary_az(aws):
    shard = _shard(1, 2, replica_azs=("us-east-1a",))
    out = _failover(aws, _fo_group([shard, _shard(2, 2)]))
    f = next(f for f in out["findings"] if f["category"] == "replicas-same-az")
    assert "1 shard(s) (0001)" in f["message"]


def test_failover_readiness_uneven_replica_counts(aws):
    out = _failover(aws, _fo_group([_shard(1, 2), _shard(2, 1), _shard(3, 2)]))
    f = next(f for f in out["findings"] if f["category"] == "uneven-replicas")
    assert "0002" in f["message"] and "1 to 2" in f["message"]


def test_failover_readiness_replica_not_available(aws):
    out = _failover(aws, _fo_group([_shard(1, 2)]), {"rg-0001-002": "modifying", "rg-0001-003": "available"})
    f = next(f for f in out["findings"] if f["category"] == "replica-state")
    assert "rg-0001-002 (modifying)" in f["message"] and "rg-0001-003" not in f["message"]


def test_failover_readiness_primary_not_available(aws):
    out = _failover(aws, _fo_group([_shard(1, 1)]), {"rg-0001-001": "incompatible-network"})
    assert "primary-state" in _fo_categories(out)


def test_failover_readiness_single_node_group_reports_once(aws):
    group = _fo_group([_shard(1, 0)], failover="disabled", multi_az="disabled", clustered=False)
    out = _failover(aws, group)
    assert [f["category"] for f in out["findings"] if f["severity"] != "info"] == ["single-node"]
    assert out["recovery_risk"]["level"] in {"medium", "high"}


def test_failover_readiness_prod_like_group_escalates_failover_disabled(aws):
    out = _failover(aws, _fo_group([_shard(1, 1)], failover="disabled", clustered=False, rid="rg-prod"))
    cp, _ = aws
    f = next(f for f in out["findings"] if f["category"] == "failover-disabled")
    assert f["severity"] == "critical"


def test_failover_readiness_node_state_failure_is_partial(aws):
    cp, stub = aws
    stub.add_response("describe_replication_groups", {"ReplicationGroups": [_fo_group([_shard(1, 1)])]})
    stub.add_client_error("describe_cache_clusters", "AccessDenied")
    out = cp.failover_readiness("rg")
    assert out["status"] == "partial" and "DescribeCacheClusters failed (AccessDenied)" in out["notes"][0]


def test_failover_readiness_not_found_and_denied(aws):
    cp, stub = aws
    stub.add_response("describe_replication_groups", {"ReplicationGroups": []})
    assert cp.failover_readiness("ghost")["error"] == "NotFound"
    stub.add_client_error("describe_replication_groups", "AccessDenied")
    assert cp.failover_readiness("rg")["error"] == "AccessDenied"


# ------------------------------------------------------------ failure modes shared by both readiness tools


def _call_restore(cp):
    return cp.snapshot_restore_readiness("rg")


def _call_restore_serverless(cp):
    return cp.snapshot_restore_readiness(serverless_cache_name="sc")


def _call_failover(cp):
    return cp.failover_readiness("rg")


_FIRST_CALL = [
    (_call_restore, "describe_replication_groups"),
    (_call_restore_serverless, "describe_serverless_caches"),
    (_call_failover, "describe_replication_groups"),
]


@pytest.mark.parametrize("code", ["AccessDenied", "AccessDeniedException", "Throttling", "ThrottlingException"])
@pytest.mark.parametrize(("call", "operation"), _FIRST_CALL)
def test_readiness_tools_turn_aws_errors_into_an_error_dict(aws, call, operation, code):
    cp, stub = aws
    stub.add_client_error(operation, code)
    out = call(cp)
    assert out["error"] == code and "findings" not in out


@pytest.mark.parametrize(("call", "operation"), _FIRST_CALL)
@pytest.mark.parametrize("exc_name", ["ReadTimeoutError", "ConnectTimeoutError", "EndpointConnectionError"])
def test_readiness_tools_turn_timeouts_into_an_error_dict_with_a_hint(call, operation, exc_name):
    import botocore.exceptions as be

    kwargs = {"endpoint_url": "https://x"}
    if exc_name == "EndpointConnectionError":
        exc = be.EndpointConnectionError(**kwargs)
    else:
        exc = getattr(be, exc_name)(**kwargs)

    class Client:
        def __getattr__(self, name):
            def boom(**_kw):
                raise exc

            return boom

    class Session:
        def client(self, service, region_name=None, config=None):
            return Client()

    cp = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)
    out = call(cp)
    assert out["error"] == exc_name and out.get("hint")


def test_snapshot_restore_empty_account_has_no_group_to_inspect(aws):
    cp, stub = aws
    stub.add_response("describe_replication_groups", {"ReplicationGroups": []})
    out = cp.snapshot_restore_readiness("rg")
    assert out["error"] == "NotFound"


def test_snapshot_restore_group_with_no_snapshots_at_all_is_reported(aws):
    out = _restore(aws, _group(), [])
    assert "no-recent-snapshot" in _categories(out)


def test_snapshot_restore_memcached_cluster_id_is_not_found_not_a_crash(aws):
    cp, stub = aws
    stub.add_client_error("describe_replication_groups", "ReplicationGroupNotFoundFault")
    out = cp.snapshot_restore_readiness("memcached-cluster")
    assert out["error"] in {"NotFound", "ReplicationGroupNotFoundFault"}


def test_failover_readiness_memcached_cluster_id_is_not_found_not_a_crash(aws):
    cp, stub = aws
    stub.add_client_error("describe_replication_groups", "ReplicationGroupNotFoundFault")
    out = cp.failover_readiness("memcached-cluster")
    assert out["error"] in {"NotFound", "ReplicationGroupNotFoundFault"}


def test_failover_readiness_empty_account_and_group_without_shards(aws):
    cp, stub = aws
    stub.add_response("describe_replication_groups", {"ReplicationGroups": []})
    assert cp.failover_readiness("rg")["error"] == "NotFound"
    out = _failover(aws, _fo_group([]))
    assert out["shards_total"] == 0 and isinstance(out["findings"], list)


def test_failover_readiness_serverless_name_is_not_a_replication_group(aws):
    cp, stub = aws
    stub.add_response("describe_replication_groups", {"ReplicationGroups": []})
    assert cp.failover_readiness("my-serverless-cache")["error"] == "NotFound"


def test_readiness_outputs_stay_bounded_for_wide_groups(aws):
    out = _failover(aws, _fo_group([_shard(i % 9 + 1, 2) for i in range(60)]))
    assert len(str(out)) < 40_000
