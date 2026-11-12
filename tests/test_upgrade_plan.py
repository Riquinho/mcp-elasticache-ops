"""aws_upgrade_plan: verdict, blockers and caveats, one case per rule, driven through botocore Stubber."""

import datetime as dt

import boto3
import pytest
from botocore.stub import Stubber

from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane
from mcp_elasticache_ops.controlplane.upgrade import parameter_group_findings, path_findings, snapshot_gate

REGION = "us-east-1"
NOW = dt.datetime(2026, 11, 12, 12, 0, tzinfo=dt.UTC)
DEFAULT_GROUPS = [{"CacheParameterGroupName": "default.redis6.x", "CacheParameterGroupFamily": "redis6.x"}]


@pytest.fixture(autouse=True)
def fake_aws_env(monkeypatch, tmp_path):
    for var in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


def _group(**extra):
    g = {
        "ReplicationGroupId": "rg",
        "Status": "available",
        "ClusterEnabled": False,
        "MultiAZ": "enabled",
        "AutomaticFailover": "enabled",
        "NodeGroups": [
            {
                "NodeGroupId": "0001",
                "NodeGroupMembers": [
                    {"CacheClusterId": "rg-001", "CurrentRole": "primary", "PreferredAvailabilityZone": "us-east-1a"},
                    {"CacheClusterId": "rg-002", "CurrentRole": "replica", "PreferredAvailabilityZone": "us-east-1b"},
                ],
            }
        ],
    }
    g.update(extra)
    return g


def _members(version="6.2.6", group="default.redis6.x", window="sun:03:00-sun:04:00", snap="05:00-06:00"):
    return [
        {
            "CacheClusterId": cid,
            "ReplicationGroupId": "rg",
            "CacheClusterStatus": "available",
            "Engine": "redis",
            "EngineVersion": version,
            "CacheParameterGroup": {"CacheParameterGroupName": group},
            "PreferredMaintenanceWindow": window,
            "SnapshotWindow": snap,
        }
        for cid in ("rg-001", "rg-002")
    ]


VERSIONS = {
    "redis": [("7.1", "redis7"), ("6.2", "redis6.x")],
    "valkey": [("8.0", "valkey8"), ("7.2", "valkey7")],
}


def _versions(engine):
    return {
        "CacheEngineVersions": [
            {"Engine": engine, "EngineVersion": v, "CacheParameterGroupFamily": fam} for v, fam in VERSIONS[engine]
        ]
    }


def _snap(hours=3.0, status="available"):
    return {
        "SnapshotName": "s",
        "ReplicationGroupId": "rg",
        "SnapshotStatus": status,
        "SnapshotSource": "automated",
        "NodeSnapshots": [{"SnapshotCreateTime": NOW - dt.timedelta(hours=hours), "CacheSize": "10 GB"}],
    }


def _plane():
    ec = boto3.client("elasticache", region_name=REGION)

    class Session:
        def client(self, service, region_name=None, config=None):
            return ec

    return ec, ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)


def _plan(
    group=None,
    members=None,
    target=("redis", None),
    pgroups=None,
    snaps=None,
    actions=(),
    denied=(),
    plan_kwargs=None,
):
    ec, cp = _plane()
    members = _members() if members is None else members
    replies = [
        ("describe_replication_groups", {"ReplicationGroups": [group or _group()]}),
        ("describe_cache_clusters", {"CacheClusters": members}),
        ("describe_cache_engine_versions", _versions(target[0])),
        ("describe_cache_parameter_groups", {"CacheParameterGroups": DEFAULT_GROUPS if pgroups is None else pgroups}),
        ("describe_update_actions", {"UpdateActions": list(actions)}),
        ("describe_snapshots", {"Snapshots": [_snap()] if snaps is None else snaps}),
    ]
    with Stubber(ec) as stub:
        for op, reply in replies:
            if op in denied:
                stub.add_client_error(op, "AccessDenied")
            else:
                stub.add_response(op, reply)
        out = cp.upgrade_plan("rg", target[0], target[1], **(plan_kwargs or {}))
        stub.assert_no_pending_responses()
    return out


def _cats(out):
    return {b["category"] for b in out["blockers"]}


def test_clean_major_upgrade_is_go_and_verdict_comes_first():
    out = _plan(target=("redis", "7.1"))
    assert out["verdict"] == "go" and out["blockers"] == []
    assert list(out)[:3] == ["replication_group_id", "verdict", "blockers"]
    assert out["target"] == {"engine": "redis", "version": "7.1", "family": "redis7"}
    assert out["gates"]["failover_risk"] == "low" and out["gates"]["newest_snapshot_age_hours"] == 3.0
    assert any(f["category"] == "major-upgrade" for f in out["findings"])


def test_default_target_is_the_newest_version_of_the_engine():
    assert _plan()["target"]["version"] == "7.1"


def test_unknown_target_version_blocks():
    out = _plan(target=("redis", "9.9"))
    assert out["verdict"] == "no-go" and "target-unavailable" in _cats(out)


def test_same_or_lower_version_is_not_an_upgrade():
    out = _plan(members=_members(version="7.1"), target=("redis", "7.1"))
    assert "not-an-upgrade" in _cats(out)


def test_redis_to_valkey_warns_about_family_change():
    out = _plan(target=("valkey", "8.0"))
    assert out["verdict"] == "go"
    switch = next(f for f in out["findings"] if f["category"] == "engine-switch")
    assert switch["severity"] == "warning" and "cannot be reversed" in switch["message"]
    assert any(f.get("quirk") == "valkey-io-threads" for f in out["findings"])


def test_redis_older_than_the_valkey_path_blocks():
    out = _plan(members=_members(version="5.0.0"), target=("valkey", "8.0"))
    assert "valkey-path" in _cats(out)


def test_custom_group_without_a_group_in_the_target_family_blocks():
    pgroups = [{"CacheParameterGroupName": "tuned", "CacheParameterGroupFamily": "redis6.x"}]
    out = _plan(members=_members(group="tuned"), pgroups=pgroups, target=("redis", "7.1"))
    assert "parameter-group-family" in _cats(out)
    assert out["parameter_groups"]["target_family"] == "redis7"


def test_custom_group_with_a_target_family_group_is_a_warning_only():
    pgroups = [
        {"CacheParameterGroupName": "tuned", "CacheParameterGroupFamily": "redis6.x"},
        {"CacheParameterGroupName": "tuned7", "CacheParameterGroupFamily": "redis7"},
    ]
    out = _plan(members=_members(group="tuned"), pgroups=pgroups, target=("redis", "7.1"))
    assert out["verdict"] == "go"
    assert out["parameter_groups"]["target_family_custom_groups"] == ["tuned7"]
    assert any(f["category"] == "parameter-group-family" and f["severity"] == "warning" for f in out["findings"])


def test_group_not_available_blocks():
    assert "group-status" in _cats(_plan(group=_group(Status="modifying"), target=("redis", "7.1")))


def test_high_failover_risk_is_a_gate():
    group = _group(MultiAZ="disabled", AutomaticFailover="disabled", Description="prod cache")
    group["NodeGroups"][0]["NodeGroupMembers"] = group["NodeGroups"][0]["NodeGroupMembers"][:1]
    out = _plan(group=group, members=_members()[:1], target=("redis", "7.1"))
    assert out["verdict"] == "no-go" and "failover-readiness" in _cats(out)
    assert out["gates"]["failover_risk"] == "high"


def test_stale_and_missing_snapshots_block_and_failed_ones_do_not_count():
    assert "stale-snapshot" in _cats(_plan(snaps=[_snap(hours=60)], target=("redis", "7.1")))
    assert "no-snapshot" in _cats(_plan(snaps=[], target=("redis", "7.1")))
    assert "no-snapshot" in _cats(_plan(snaps=[_snap(status="failed")], target=("redis", "7.1")))
    relaxed = _plan(snaps=[_snap(hours=60)], target=("redis", "7.1"), plan_kwargs={"snapshot_max_age_hours": 72})
    assert relaxed["verdict"] == "go"


def test_pending_service_update_and_window_overlap_are_warnings():
    action = {
        "ServiceUpdateName": "elasticache-update-1",
        "ServiceUpdateRecommendedApplyByDate": NOW - dt.timedelta(days=2),
        "UpdateActionStatus": "not-applied",
    }
    out = _plan(members=_members(window="sun:05:30-sun:06:30"), actions=[action], target=("redis", "7.1"))
    cats = {f["category"]: f for f in out["findings"]}
    assert cats["pending-service-update"]["severity"] == "warning"
    assert "past apply-by" in cats["pending-service-update"]["message"]
    assert "window-overlap" in cats
    assert out["verdict"] == "go"
    assert out["maintenance"]["overdue_service_updates"] == ["elasticache-update-1"]


def test_acl_group_without_tls_warns_and_cluster_mode_is_stated():
    out = _plan(group=_group(UserGroupIds=["ug"], TransitEncryptionEnabled=False), target=("redis", "7.1"))
    assert {"acl", "tls", "cluster-mode"} <= {f["category"] for f in out["findings"]}


@pytest.mark.parametrize(
    "op",
    [
        "describe_cache_clusters",
        "describe_cache_engine_versions",
        "describe_cache_parameter_groups",
        "describe_update_actions",
        "describe_snapshots",
    ],
)
def test_a_denied_gate_is_a_blocker_and_the_plan_is_partial(op):
    out = _plan(denied=(op,), target=("redis", "7.1"))
    assert out["verdict"] == "no-go" and out["status"] == "partial"
    assert "unverified" in _cats(out)
    assert any("AccessDenied" in n for n in out["notes"])


def test_access_denied_on_the_group_itself_is_an_error_with_a_hint():
    ec, cp = _plane()
    with Stubber(ec) as stub:
        stub.add_client_error("describe_replication_groups", "AccessDenied")
        out = cp.upgrade_plan("rg")
    assert out["error"] == "AccessDenied" and out["hint"]


def test_missing_group_and_bad_arguments():
    ec, cp = _plane()
    with Stubber(ec) as stub:
        stub.add_response("describe_replication_groups", {"ReplicationGroups": []})
        assert cp.upgrade_plan("rg")["error"] == "NotFound"
    assert cp.upgrade_plan("rg", target_engine="memcached")["error"] == "InvalidArgument"
    assert cp.upgrade_plan("rg", snapshot_max_age_hours=0)["error"] == "InvalidArgument"


def test_valkey_cannot_go_back_to_redis():
    blockers, _ = path_findings("rg", ("valkey", "7.2"), ("redis", "7.1"), True)
    assert [b["category"] for b in blockers] == ["no-downgrade-to-redis"]


def test_rules_are_pure_and_blockers_are_marked():
    blockers, _, view = parameter_group_findings(
        "rg",
        [{"CacheParameterGroupName": "t", "CacheParameterGroupFamily": "redis6.x"}],
        [{"CacheParameterGroup": {"CacheParameterGroupName": "t"}}],
        "valkey8",
    )
    assert blockers and all(b["blocker"] and b["severity"] == "critical" for b in blockers)
    assert view["current"] == [{"name": "t", "family": "redis6.x"}]
    assert snapshot_gate("rg", [], 24)[0][0]["category"] == "no-snapshot"
