"""Stubber-based tests for the control-plane tools added in round 01."""

import datetime as dt

import boto3
import pytest
from botocore.stub import Stubber
from fastmcp import Client
from fastmcp.exceptions import ToolError

from mcp_elasticache_ops import server
from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane

REGION = "us-east-1"
NOW = dt.datetime(2026, 11, 12, 12, 0, tzinfo=dt.UTC)


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
    cw = boto3.client("cloudwatch", region_name=REGION)

    class Session:
        def client(self, service, region_name=None):
            return {"elasticache": ec, "cloudwatch": cw}[service]

    cp = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)
    with Stubber(ec) as ec_stub, Stubber(cw) as cw_stub:
        yield cp, ec_stub, cw_stub
        ec_stub.assert_no_pending_responses()
        cw_stub.assert_no_pending_responses()


def _hours_ago(h):
    return NOW - dt.timedelta(hours=h)


# ----------------------------------------------------------------- snapshots


def _snap(name, source, rg, hours, status="available", size="5 MB"):
    return {
        "SnapshotName": name,
        "ReplicationGroupId": rg,
        "SnapshotStatus": status,
        "SnapshotSource": source,
        "Engine": "valkey",
        "NodeSnapshots": [{"SnapshotCreateTime": _hours_ago(hours), "CacheSize": size}],
    }


def test_snapshots_paginates_and_flags_retention_gap_failed_and_missing_auto(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_snapshots",
        {
            "Snapshots": [_snap("a-1", "automated", "a", 80), _snap("a-bad", "manual", "a", 1, status="failed")],
            "Marker": "m1",
        },
        {},
    )
    ec.add_response(
        "describe_snapshots",
        {"Snapshots": [_snap("b-man", "manual", "b", 24 * 100, size="1 GB")]},
        {"Marker": "m1"},
    )
    out = cp.snapshots()
    assert out["count"] == 3
    msgs = {(f["resource"], f["message"]) for f in out["findings"] if "resource" in f}
    assert ("a", "retention gap: newest automatic snapshot is 80h old") in msgs
    assert ("a", "snapshot a-bad failed") in msgs
    assert ("b", "no available automatic snapshots (backup retention may be 0)") in msgs
    assert any("older than 90 days" in f["message"] for f in out["findings"])
    assert [f["severity"] for f in out["findings"]] == sorted(
        (f["severity"] for f in out["findings"]),
        key=["critical", "important", "warning", "medium", "low", "info"].index,
    )
    by_name = {s["name"]: s for s in out["snapshots"]}
    assert by_name["b-man"]["size_bytes"] == 1024**3 and by_name["b-man"]["automatic"] is False
    assert by_name["a-1"]["age_hours"] == 80.0


def test_snapshots_filters_and_empty(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_snapshots",
        {"Snapshots": []},
        {"ReplicationGroupId": "x", "SnapshotSource": "automated"},
    )
    out = cp.snapshots(replication_group_id="x", source="automated")
    assert out["findings"][0]["message"] == "no snapshots found for this filter"


# --------------------------------------------------------------------- users


def test_users_flags_open_access_and_no_password(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_users",
        {
            "Users": [
                {
                    "UserId": "open",
                    "UserName": "open",
                    "Status": "active",
                    "Engine": "redis",
                    "AccessString": "on ~* +@all",
                    "Authentication": {"Type": "no-password"},
                },
                {
                    "UserId": "scoped",
                    "UserName": "scoped",
                    "Status": "active",
                    "Engine": "redis",
                    "AccessString": "on ~app:* -@all +get",
                    "Authentication": {"Type": "password", "PasswordCount": 1},
                },
                {
                    "UserId": "off",
                    "UserName": "off",
                    "Status": "active",
                    "Engine": "redis",
                    "AccessString": "off ~* +@all",
                    "Authentication": {"Type": "iam"},
                },
            ]
        },
        {"Engine": "redis"},
    )
    out = cp.users(engine="redis")
    flagged = {(f["resource"], f["severity"]) for f in out["findings"]}
    assert ("open", "critical") in flagged
    assert not [f for f in out["findings"] if f["resource"] == "scoped"]
    assert ("off", "warning") in flagged  # all-access but inactive
    assert out["findings"][0]["severity"] == "critical"
    assert all("Password" not in repr(u) for u in out["users"])  # never any secret material


def test_user_groups_findings(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_user_groups",
        {
            "UserGroups": [
                {"UserGroupId": "g1", "Status": "active", "Engine": "redis", "UserIds": ["u"], "ReplicationGroups": []},
                {
                    "UserGroupId": "g2",
                    "Status": "modifying",
                    "Engine": "redis",
                    "UserIds": ["u"],
                    "ReplicationGroups": ["rg"],
                },
            ]
        },
        {},
    )
    out = cp.user_groups()
    msgs = {(f["resource"], f["severity"]) for f in out["findings"]}
    assert msgs == {("g1", "info"), ("g2", "warning")}


# ------------------------------------------------------- global datastores


def test_global_replication_groups(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_global_replication_groups",
        {
            "GlobalReplicationGroups": [
                {
                    "GlobalReplicationGroupId": "g-solo",
                    "Status": "available",
                    "Members": [{"ReplicationGroupId": "a", "ReplicationGroupRegion": "us-east-1", "Role": "PRIMARY"}],
                },
                {
                    "GlobalReplicationGroupId": "g-two",
                    "Status": "modifying",
                    "Members": [
                        {"ReplicationGroupId": "a", "ReplicationGroupRegion": "us-east-1", "Status": "associated"},
                        {"ReplicationGroupId": "b", "ReplicationGroupRegion": "eu-west-1", "Status": "associating"},
                    ],
                },
            ]
        },
        {"ShowMemberInfo": True},
    )
    out = cp.global_replication_groups()
    msgs = [f["message"] for f in out["findings"]]
    assert "global datastore has no secondary region" in msgs
    assert "global datastore status is modifying" in msgs
    assert "member b (eu-west-1) is associating" in msgs
    assert out["global_replication_groups"][1]["members"][1]["region"] == "eu-west-1"


# ------------------------------------------------------------ reserved nodes


def test_reserved_nodes_coverage_and_expiry(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_reserved_cache_nodes",
        {
            "ReservedCacheNodes": [
                {
                    "ReservedCacheNodeId": "r1",
                    "CacheNodeType": "cache.r7g.large",
                    "ProductDescription": "redis",
                    "CacheNodeCount": 3,
                    "State": "active",
                    "StartTime": NOW - dt.timedelta(days=340),
                    "Duration": 365 * 24 * 3600,
                },
                {
                    "ReservedCacheNodeId": "r2",
                    "CacheNodeType": "cache.m7g.large",
                    "ProductDescription": "valkey",
                    "CacheNodeCount": 1,
                    "State": "retired",
                    "StartTime": NOW - dt.timedelta(days=700),
                    "Duration": 365 * 24 * 3600,
                },
            ]
        },
        {},
    )
    ec.add_response(
        "describe_cache_clusters",
        {
            "CacheClusters": [
                {"CacheClusterId": "c1", "CacheNodeType": "cache.r7g.large", "Engine": "redis", "NumCacheNodes": 2},
                {"CacheClusterId": "c2", "CacheNodeType": "cache.m7g.large", "Engine": "valkey", "NumCacheNodes": 1},
                {
                    "CacheClusterId": "c3",
                    "CacheNodeType": "cache.m7g.large",
                    "Engine": "valkey",
                    "CacheClusterStatus": "deleting",
                },
            ]
        },
        {},
    )
    out = cp.reserved_nodes()
    cov = {(c["node_type"], c["engine"]): c for c in out["coverage"]}
    assert cov[("cache.r7g.large", "redis")]["unused_reservations"] == 1
    assert cov[("cache.m7g.large", "valkey")]["on_demand_nodes"] == 1  # retired reservation does not count
    msgs = [f["message"] for f in out["findings"]]
    assert any("1 reserved cache.r7g.large redis node(s) have no running match" in m for m in msgs)
    assert any("reservation r1 ends" in m for m in msgs)
    assert any("1 on-demand cache.m7g.large valkey" in m for m in msgs)


# ----------------------------------------------------------- service updates


def test_service_updates_severity_and_deadlines(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_service_updates",
        {
            "ServiceUpdates": [
                {
                    "ServiceUpdateName": "late",
                    "ServiceUpdateSeverity": "important",
                    "ServiceUpdateRecommendedApplyByDate": NOW - dt.timedelta(days=2),
                },
                {
                    "ServiceUpdateName": "soon",
                    "ServiceUpdateSeverity": "low",
                    "ServiceUpdateRecommendedApplyByDate": NOW + dt.timedelta(days=5),
                    "AutoUpdateAfterRecommendedApplyByDate": True,
                },
                {"ServiceUpdateName": "crit-pending", "ServiceUpdateSeverity": "critical"},
                {"ServiceUpdateName": "meh", "ServiceUpdateSeverity": "medium"},
            ],
            "Marker": "m",
        },
        {"ServiceUpdateStatus": ["available"]},
    )
    ec.add_response(
        "describe_service_updates",
        {"ServiceUpdates": []},
        {"ServiceUpdateStatus": ["available"], "Marker": "m"},
    )
    out = cp.service_updates()
    by = {f["resource"]: f for f in out["findings"]}
    assert by["late"]["severity"] == "critical" and "past its recommended apply-by" in by["late"]["message"]
    assert by["soon"]["severity"] == "warning" and "applied automatically" in by["soon"]["message"]
    assert by["crit-pending"]["severity"] == "warning"
    assert by["meh"]["severity"] == "info"
    assert out["findings"][0]["resource"] == "late"
    assert out["service_updates"][0]["severity"] == "critical"  # views sorted by severity


# ------------------------------------------------------------- subnet groups


def test_subnet_groups_single_az_warning(aws):
    cp, ec, _ = aws
    sub = lambda sid, az: {"SubnetIdentifier": sid, "SubnetAvailabilityZone": {"Name": az}}  # noqa: E731
    ec.add_response(
        "describe_cache_subnet_groups",
        {
            "CacheSubnetGroups": [
                {"CacheSubnetGroupName": "one", "VpcId": "vpc-1", "Subnets": [sub("s1", "us-east-1a")]},
                {
                    "CacheSubnetGroupName": "two",
                    "VpcId": "vpc-1",
                    "Subnets": [sub("s1", "us-east-1a"), sub("s2", "us-east-1b")],
                },
            ]
        },
        {},
    )
    out = cp.subnet_groups()
    assert [f["resource"] for f in out["findings"]] == ["one"]
    assert out["subnet_groups"][1]["azs"] == ["us-east-1a", "us-east-1b"]


# -------------------------------------------------- replication group findings


def test_replication_group_findings_and_engine_version(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_replication_groups",
        {
            "ReplicationGroups": [
                {
                    "ReplicationGroupId": "weak",
                    "Status": "modifying",
                    "MultiAZ": "disabled",
                    "AutomaticFailover": "disabled",
                    "AtRestEncryptionEnabled": False,
                    "TransitEncryptionEnabled": False,
                    "AuthTokenEnabled": False,
                    "SnapshotRetentionLimit": 0,
                    "AutoMinorVersionUpgrade": False,
                },
                {
                    "ReplicationGroupId": "good",
                    "Status": "available",
                    "MultiAZ": "enabled",
                    "AutomaticFailover": "enabled",
                    "AtRestEncryptionEnabled": True,
                    "TransitEncryptionEnabled": True,
                    "AuthTokenEnabled": True,
                },
            ]
        },
        {},
    )
    ec.add_response(
        "describe_cache_clusters",
        {
            "CacheClusters": [
                {
                    "CacheClusterId": "weak-001",
                    "ReplicationGroupId": "weak",
                    "Engine": "redis",
                    "EngineVersion": "6.2.6",
                },
                {
                    "CacheClusterId": "good-001",
                    "ReplicationGroupId": "good",
                    "Engine": "valkey",
                    "EngineVersion": "8.0",
                },
            ]
        },
        {},
    )
    out = cp.replication_groups()
    weak = [f for f in out["findings"] if f["resource"] == "weak"]
    assert not [f for f in out["findings"] if f["resource"] == "good"]
    msgs = " | ".join(f["message"] for f in weak)
    for needle in (
        "Multi-AZ is not enabled",
        "automatic failover is not enabled",
        "encryption at rest is disabled",
        "encryption in transit is disabled",
        "no authentication",
        "automatic snapshots are off",
        "Redis OSS 6.2.6 is old",
    ):
        assert needle in msgs
    assert out["findings"][0]["severity"] == "critical"
    assert out["replication_groups"][0]["engine_version"] == "6.2.6"


# ------------------------------------------------------------------- metrics


def _result(label, points):
    return {
        "Id": "x",
        "Label": label,
        "StatusCode": "Complete",
        "Timestamps": [t for t, _ in points],
        "Values": [v for _, v in points],
    }


def _pts(*values, newest_first=True):
    pts = [(NOW - dt.timedelta(minutes=len(values) - i), v) for i, v in enumerate(values)]
    return list(reversed(pts)) if newest_first else pts


def test_metrics_sorted_series_findings_and_include_series_gate(aws):
    cp, _, cw = aws
    resp = {
        "MetricDataResults": [
            _result("a-001|EngineCPUUtilization", _pts(10, 95, 70)),  # CloudWatch returns newest first
            _result("a-001|Evictions", _pts(1, 2, 0)),
            _result("a-001|SwapUsage", _pts(100 * 1024 * 1024)),
            _result("a-001|ReplicationLag", _pts(12.0)),
            _result("a-001|CurrConnections", _pts(60000)),
            _result("a-001|DatabaseMemoryUsagePercentage", _pts(85)),
        ]
    }
    cw.add_response("get_metric_data", resp, None)
    cw.add_response("get_metric_data", resp, None)
    names = [
        "EngineCPUUtilization",
        "Evictions",
        "SwapUsage",
        "ReplicationLag",
        "CurrConnections",
        "DatabaseMemoryUsagePercentage",
    ]
    out = cp.metrics("a-001", names, minutes=30)
    assert "series" not in out  # token heavy: opt in only
    cpu = out["summary"]["EngineCPUUtilization"]
    assert cpu["latest"] == 70 and cpu["max"] == 95 and cpu["min"] == 10 and cpu["points"] == 3
    msgs = " | ".join(f["message"] for f in out["findings"])
    for needle in (
        "EngineCPUUtilization max 95%",
        "3 evictions in the window",
        "SwapUsage max 100 MB",
        "ReplicationLag max 12.0s",
        "CurrConnections max 60000",
        "DatabaseMemoryUsagePercentage max 85%",
    ):
        assert needle in msgs
    assert out["findings"][0]["severity"] == "critical"
    full = cp.metrics("a-001", names, minutes=30, include_series=True)
    ts = full["series"]["EngineCPUUtilization"]["timestamps"]
    assert ts == sorted(ts)  # ascending regardless of CloudWatch order
    assert full["series"]["EngineCPUUtilization"]["values"] == [10, 95, 70]


def test_metrics_empty_window_emits_info_finding(aws):
    cp, _, cw = aws
    cw.add_response("get_metric_data", {"MetricDataResults": []}, None)
    out = cp.metrics("nope", ["Evictions"], minutes=10)
    assert out["findings"][0]["severity"] == "info"
    assert out["summary"]["Evictions"] == {"points": 0}


def test_metrics_follows_next_token_and_sets_stat(aws):
    cp, _, cw = aws
    cw.add_response(
        "get_metric_data",
        {"MetricDataResults": [_result("a|Evictions", _pts(1, newest_first=False))], "NextToken": "t"},
        None,
    )
    cw.add_response(
        "get_metric_data",
        {"MetricDataResults": [_result("a|Evictions", [(NOW, 4)])]},
        None,
    )
    out = cp.metrics("a", ["Evictions"], minutes=10)
    assert out["summary"]["Evictions"]["points"] == 2 and out["summary"]["Evictions"]["sum"] == 5
    assert any("5 evictions" in f["message"] for f in out["findings"])


def test_metrics_replication_group_fans_out_to_members(aws):
    cp, ec, cw = aws
    ec.add_response(
        "describe_replication_groups",
        {"ReplicationGroups": [{"ReplicationGroupId": "rg", "MemberClusters": ["rg-0001-001", "rg-0001-002"]}]},
        {"ReplicationGroupId": "rg"},
    )
    cw.add_response(
        "get_metric_data",
        {
            "MetricDataResults": [
                _result("rg-0001-001|EngineCPUUtilization", _pts(30)),
                _result("rg-0001-002|EngineCPUUtilization", _pts(99, 99)),
            ]
        },
        None,
    )
    out = cp.metrics(replication_group_id="rg", metrics=["EngineCPUUtilization"], minutes=15, include_series=True)
    assert out["targets"] == ["rg-0001-001", "rg-0001-002"]
    assert set(out["summary"]) == {"rg-0001-001", "rg-0001-002"}
    assert set(out["series"]) == {"rg-0001-001", "rg-0001-002"}
    assert [f["resource"] for f in out["findings"]] == ["rg-0001-002"]


def test_metrics_replication_group_without_members(aws):
    cp, ec, _ = aws
    ec.add_response("describe_replication_groups", {"ReplicationGroups": []}, None)
    assert cp.metrics(replication_group_id="rg", minutes=15)["error"] == "NoMembers"


def test_metrics_chunks_queries_at_500(aws):
    cp, ec, cw = aws
    members = [f"m{i}" for i in range(30)]
    ec.add_response(
        "describe_replication_groups",
        {"ReplicationGroups": [{"ReplicationGroupId": "rg", "MemberClusters": members}]},
        None,
    )
    names = [f"Metric{i}" for i in range(20)]  # 30 x 20 = 600 queries: two calls
    cw.add_response("get_metric_data", {"MetricDataResults": []}, None)
    cw.add_response("get_metric_data", {"MetricDataResults": []}, None)
    out = cp.metrics(replication_group_id="rg", metrics=names, minutes=15)
    assert len(out["targets"]) == 30


@pytest.mark.parametrize(
    "kwargs",
    [
        {"minutes": 0},
        {"minutes": 20161},
        {"minutes": True},
        {"period_seconds": 90},
        {"period_seconds": 0},
        {"period_seconds": 86460},
    ],
)
def test_metrics_rejects_bad_window_without_calling_aws(kwargs):
    cp = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=lambda: pytest.fail("no AWS call"))
    out = cp.metrics("a", **kwargs)
    assert out["error"] == "InvalidArgument"


def test_metrics_requires_a_target():
    cp = ControlPlane(ControlPlaneConfig(region=REGION))
    assert cp.metrics()["error"] == "InvalidArgument"


async def test_aws_metrics_tool_rejects_period_90():
    async with Client(server.mcp) as c:
        with pytest.raises(ToolError):
            await c.call_tool("aws_metrics", {"cache_cluster_id": "a", "period_seconds": 90})


# --------------------------------------------------------- read-only guarantee


class Recorder:
    """Records every API operation name; returns empty pages."""

    def __init__(self):
        self.calls: list[str] = []

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def call(**kwargs):
            self.calls.append(name)
            return {}

        return call


def test_every_tool_only_calls_describe_list_or_get_metric_data():
    rec = Recorder()

    class Session:
        def client(self, service, region_name=None):
            return rec

    cp = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)
    cp.replication_groups()
    cp.cache_clusters()
    cp.serverless_caches()
    cp.events()
    cp.parameters("pg")
    cp.snapshots()
    cp.users()
    cp.user_groups()
    cp.global_replication_groups()
    cp.reserved_nodes()
    cp.service_updates()
    cp.subnet_groups()
    cp.metrics("a", minutes=5)
    cp.metrics(replication_group_id="rg", minutes=5)
    assert len(set(rec.calls)) >= 12
    assert rec.calls, "recorder saw no calls"
    for op in rec.calls:
        assert op.startswith(("describe_", "list_", "get_metric_data")), op


@pytest.mark.parametrize("op", ["modify_replication_group", "delete_snapshot", "create_user", "reboot_cache_cluster"])
def test_paginate_refuses_write_operations(op):
    cp = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=lambda: pytest.fail("must not connect"))
    with pytest.raises(ValueError, match="non-read-only"):
        cp._paginate(op, "Items")
