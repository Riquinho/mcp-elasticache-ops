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
        def client(self, service, region_name=None, config=None):
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
                    "LogDeliveryConfigurations": [
                        {"LogType": "slow-log", "Status": "active"},
                        {"LogType": "engine-log", "Status": "active"},
                    ],
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
        def client(self, service, region_name=None, config=None):
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


# ------------------------------------------------------------------- alarms

ALARM_METRICS = [
    "EngineCPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "Evictions",
    "ReplicationLag",
    "CurrConnections",
    "SwapUsage",
]


def _alarm(metric, cluster, state="OK", actions=True, namespace="AWS/ElastiCache", dim="CacheClusterId"):
    return {
        "AlarmName": f"{cluster}-{metric}",
        "Namespace": namespace,
        "MetricName": metric,
        "Dimensions": [{"Name": dim, "Value": cluster}],
        "StateValue": state,
        "StateReason": f"{metric} crossed the threshold",
        "ActionsEnabled": actions,
        "AlarmActions": ["arn:aws:sns:us-east-1:123456789012:oncall"],
    }


def _rg(members=("rg1-001", "rg1-002")):
    return {"ReplicationGroups": [{"ReplicationGroupId": "rg1", "MemberClusters": list(members)}]}


def test_alarms_full_coverage_has_no_findings(aws):
    cp, ec, cw = aws
    ec.add_response("describe_replication_groups", _rg(), {"ReplicationGroupId": "rg1"})
    cw.add_response(
        "describe_alarms",
        {"MetricAlarms": [_alarm(m, c) for m in ALARM_METRICS for c in ("rg1-001", "rg1-002")]},
        None,
    )
    out = cp.alarms("rg1")
    assert out["count"] == 12
    assert out["findings"] == []
    assert out["targets"][0]["missing_alarms"] == {}


def test_alarms_paginated_filtered_and_flags_state_problems(aws):
    cp, ec, cw = aws
    ec.add_response("describe_replication_groups", _rg(), {"ReplicationGroupId": "rg1"})
    page1 = [_alarm(m, "rg1-001") for m in ALARM_METRICS if m != "DatabaseMemoryUsagePercentage"]
    page1.append(_alarm("CPUUtilization", "other-001"))  # another cluster: ignored
    page1.append(_alarm("EngineCPUUtilization", "rg1-001", namespace="AWS/EC2"))  # other namespace: ignored
    page2 = [_alarm(m, "rg1-002") for m in ALARM_METRICS]
    page2[0] = _alarm("EngineCPUUtilization", "rg1-002", state="ALARM")
    page2[1] = _alarm("DatabaseMemoryUsagePercentage", "rg1-002", state="INSUFFICIENT_DATA")
    page2[2] = _alarm("Evictions", "rg1-002", actions=False)
    cw.add_response("describe_alarms", {"MetricAlarms": page1, "NextToken": "t1"}, None)
    cw.add_response("describe_alarms", {"MetricAlarms": page2}, {"AlarmTypes": ["MetricAlarm"], "NextToken": "t1"})
    out = cp.alarms("rg1")
    assert out["count"] == 11
    msgs = [f["message"] for f in out["findings"]]
    assert out["findings"][0]["severity"] == "critical" and "rg1-002-EngineCPUUtilization is in ALARM" in msgs[0]
    assert any("rg1-002-DatabaseMemoryUsagePercentage is INSUFFICIENT_DATA" in m for m in msgs)
    assert any("rg1-002-Evictions has actions disabled" in m for m in msgs)
    assert any("no alarm on DatabaseMemoryUsagePercentage for rg1-001" in m for m in msgs)
    assert not any("other-001" in m for m in msgs)
    assert out["targets"][0]["missing_alarms"] == {"DatabaseMemoryUsagePercentage": ["rg1-001"]}


def test_alarms_missing_everything(aws):
    cp, ec, cw = aws
    ec.add_response("describe_replication_groups", _rg(), {"ReplicationGroupId": "rg1"})
    cw.add_response("describe_alarms", {"MetricAlarms": []}, None)
    out = cp.alarms("rg1")
    assert out["count"] == 0
    assert set(out["targets"][0]["missing_alarms"]) == set(ALARM_METRICS)
    assert len(out["findings"]) == 6 and all(f["severity"] == "warning" for f in out["findings"])


def test_alarms_single_node_group_does_not_need_replication_lag(aws):
    cp, ec, cw = aws
    ec.add_response("describe_replication_groups", _rg(("rg1-001",)), {"ReplicationGroupId": "rg1"})
    cw.add_response("describe_alarms", {"MetricAlarms": []}, None)
    assert "ReplicationLag" not in cp.alarms("rg1")["targets"][0]["missing_alarms"]


def test_alarms_access_denied_is_partial(aws):
    cp, ec, cw = aws
    ec.add_response("describe_replication_groups", _rg(), {"ReplicationGroupId": "rg1"})
    cw.add_client_error("describe_alarms", service_error_code="AccessDenied")
    out = cp.alarms("rg1")
    assert out["partial"] is True and out["alarms"] == []
    assert out["targets"][0]["id"] == "rg1"
    assert "cloudwatch:DescribeAlarms failed (AccessDenied)" in out["findings"][0]["message"]


def test_alarms_whole_region_covers_clusters_and_serverless(aws):
    cp, ec, cw = aws
    ec.add_response("describe_replication_groups", _rg(), None)
    ec.add_response(
        "describe_cache_clusters",
        {
            "CacheClusters": [
                {"CacheClusterId": "rg1-001", "ReplicationGroupId": "rg1", "Engine": "valkey"},
                {"CacheClusterId": "mc1", "Engine": "memcached"},
            ]
        },
        None,
    )
    ec.add_response("describe_serverless_caches", {"ServerlessCaches": [{"ServerlessCacheName": "sc1"}]}, None)
    cw.add_response(
        "describe_alarms",
        {"MetricAlarms": [_alarm("ThrottledCmds", "sc1", dim="clusterId"), _alarm("Evictions", "mc1")]},
        None,
    )
    out = cp.alarms()
    kinds = {t["id"]: t for t in out["targets"]}
    assert set(kinds) == {"rg1", "mc1", "sc1"}
    assert "ThrottledCmds" not in kinds["sc1"]["missing_alarms"]  # covered through the clusterId dimension
    assert "EngineCPUUtilization" in kinds["sc1"]["missing_alarms"]
    assert "CPUUtilization" in kinds["mc1"]["missing_alarms"] and "Evictions" not in kinds["mc1"]["missing_alarms"]
    assert "EngineCPUUtilization" not in kinds["mc1"]["missing_alarms"]
    assert out["count"] == 2


def test_alarms_replication_group_dimension_covers_all_members(aws):
    cp, ec, cw = aws
    ec.add_response("describe_replication_groups", _rg(), {"ReplicationGroupId": "rg1"})
    cw.add_response(
        "describe_alarms",
        {"MetricAlarms": [_alarm(m, "rg1", dim="ReplicationGroupId") for m in ALARM_METRICS]},
        None,
    )
    assert cp.alarms("rg1")["findings"] == []


def test_alarms_disabled_control_plane():
    cp = ControlPlane(ControlPlaneConfig(region=REGION, enabled=False), session_factory=lambda: pytest.fail("no"))
    assert "unavailable" in cp.alarms()


async def test_aws_alarms_tool_registered_read_only_and_delegates(monkeypatch):
    seen = {}

    class Plane:
        def alarms(self, rg=None):
            seen["rg"] = rg
            return {"count": 0, "findings": [], "targets": [], "alarms": []}

    monkeypatch.setattr(server, "control_plane", lambda: Plane())
    async with Client(server.mcp) as c:
        tool = next(t for t in await c.list_tools() if t.name == "aws_alarms")
        assert tool.annotations.read_only_hint is True
        await c.call_tool("aws_alarms", {"replication_group_id": "rg1"})
    assert seen["rg"] == "rg1"


def test_iam_policy_allows_describe_alarms_and_nothing_else_beyond_describe_list_get():
    import json
    import re
    from pathlib import Path

    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
    block = re.search(r"```json\n(\{\s*\"Version\".*?\})\n```", readme, flags=re.S)
    actions = [a for st in json.loads(block.group(1))["Statement"] for a in st["Action"]]
    assert "cloudwatch:DescribeAlarms" in actions
    assert "cloudwatch:GetMetricData" in actions
    for action in actions:
        assert re.match(r"^(elasticache|cloudwatch):(Describe|List|GetMetricData)", action), action


# ----------------------------------------------------------------- failure modes (every aws_* tool)


def _boto_failures():
    from botocore.exceptions import ClientError, ConnectTimeoutError

    def client_error(code):
        return ClientError({"Error": {"Code": code, "Message": f"{code} for test"}}, "Describe")

    return {
        "AccessDenied": lambda: client_error("AccessDenied"),
        "ThrottlingException": lambda: client_error("ThrottlingException"),
        "ConnectTimeout": lambda: ConnectTimeoutError(endpoint_url="https://elasticache.us-east-1.amazonaws.com"),
    }


class _AlwaysFails:
    """Stands in for a boto3 client: every API call raises the configured exception."""

    def __init__(self, make):
        self._make = make

    def __getattr__(self, name):
        def call(*args, **kwargs):
            raise self._make()

        return call


def _example_args(tool) -> dict:
    props = tool.input_schema.get("properties", {})
    args = {name: props.get(name, {}).get("enum", ["x"])[0] for name in tool.input_schema.get("required", [])}
    if tool.name == "aws_metrics":  # needs one of two optional ids
        args["cache_cluster_id"] = "x"
    return args


def _contains_marker(value) -> bool:
    """A structured failure: an error with a hint, or a partial/unavailable section somewhere in the result."""
    if isinstance(value, dict):
        if "error" in value and "hint" in value:
            return True
        if (
            value.get("partial") is True
            or value.get("status") in {"partial", "error", "unavailable"}
            or "unavailable" in value
        ):
            return True
        return any(_contains_marker(v) for v in value.values())
    if isinstance(value, list):
        return any(_contains_marker(v) for v in value)
    return False


@pytest.mark.parametrize("failure", ["AccessDenied", "ThrottlingException", "ConnectTimeout"])
async def test_every_aws_tool_returns_a_structured_failure_with_a_hint(monkeypatch, failure):
    import json

    make = _boto_failures()[failure]

    class Session:
        def client(self, service, region_name=None, config=None):
            return _AlwaysFails(make)

    plane = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)
    monkeypatch.setattr(server, "control_plane", lambda: plane)
    async with Client(server.mcp) as client:
        tools = [t for t in await client.list_tools() if t.name.startswith("aws_")]
        assert len(tools) >= 19
        for tool in tools:
            result = await client.call_tool(tool.name, _example_args(tool), raise_on_error=False)
            assert not result.is_error, f"{tool.name} raised: {result.content}"
            data = result.structured_content or json.loads(result.content[0].text)
            data = data.get("result", data)
            assert isinstance(data, dict), tool.name
            assert _contains_marker(data), f"{tool.name} gave no structured failure: {str(data)[:300]}"
            assert "Traceback" not in json.dumps(data, default=str), tool.name


@pytest.mark.parametrize("failure", ["AccessDenied", "ThrottlingException", "ConnectTimeout"])
def test_guarded_aws_errors_carry_a_specific_hint(failure):
    class Session:
        def client(self, service, region_name=None, config=None):
            return _AlwaysFails(_boto_failures()[failure])

    plane = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)
    out = plane.replication_groups()
    assert out["error"] and out["message"]
    expected = {"AccessDenied": "IAM", "ThrottlingException": "throttled", "ConnectTimeout": "did not answer"}
    assert expected[failure] in out["hint"]


def test_client_receives_bounded_botocore_config():
    seen: dict = {}

    class Session:
        def client(self, service, region_name=None, config=None):
            seen.update(service=service, region=region_name, config=config)
            return object()

    cp = ControlPlane(
        ControlPlaneConfig(region=REGION, call_timeout=4.0, max_attempts=2),
        session_factory=Session,
    )
    cp.client("elasticache")
    cfg = seen["config"]
    assert seen["region"] == REGION
    assert cfg.connect_timeout == 4.0 and cfg.read_timeout == 4.0
    assert cfg.retries["mode"] == "standard" and cfg.retries["max_attempts"] == 2
    assert cfg.user_agent_extra == "mcp-elasticache-ops"


# ------------------------------------------- log delivery, transit mode, token age


def _hardening_rg(**extra):
    base = {
        "ReplicationGroupId": "hx",
        "Status": "available",
        "Engine": "valkey",
        "MultiAZ": "enabled",
        "AutomaticFailover": "enabled",
        "TransitEncryptionEnabled": True,
        "AuthTokenEnabled": True,
    }
    return {"ReplicationGroups": [{**base, **extra}]}


def _messages(out, severity):
    return [f["message"] for f in out["findings"] if f["severity"] == severity]


def test_rg_without_log_delivery_warns_slow_log_and_infos_engine_log(aws):
    cp, ec, _ = aws
    ec.add_response("describe_replication_groups", _hardening_rg(), {})
    ec.add_response("describe_cache_clusters", {"CacheClusters": []}, {})
    out = cp.replication_groups()
    assert any("slow-log delivery is not enabled" in m for m in _messages(out, "warning"))
    assert any("engine-log delivery is not enabled" in m for m in _messages(out, "info"))
    assert out["replication_groups"][0]["log_delivery"] == []


def test_rg_log_delivery_error_and_only_slow_log_on(aws):
    cp, ec, _ = aws
    logs = [
        {"LogType": "slow-log", "DestinationType": "cloudwatch-logs", "Status": "active"},
        {"LogType": "engine-log", "Status": "error", "Message": "log group missing"},
    ]
    ec.add_response("describe_replication_groups", _hardening_rg(LogDeliveryConfigurations=logs), {})
    ec.add_response("describe_cache_clusters", {"CacheClusters": []}, {})
    out = cp.replication_groups()
    warnings = _messages(out, "warning")
    assert not any("slow-log delivery is not enabled" in m for m in warnings)
    assert any("engine-log delivery status is error: log group missing" in m for m in warnings)
    assert any("engine-log delivery is not enabled" in m for m in _messages(out, "info"))
    assert out["replication_groups"][0]["log_delivery"][0]["destination_type"] == "cloudwatch-logs"


def test_rg_preferred_transit_mode_and_new_view_fields(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_replication_groups",
        _hardening_rg(
            TransitEncryptionMode="preferred",
            DataTiering="enabled",
            NetworkType="dual_stack",
            IpDiscovery="ipv4",
            AuthTokenLastModifiedDate=NOW - dt.timedelta(days=400),
            LogDeliveryConfigurations=[
                {"LogType": "slow-log", "Status": "active"},
                {"LogType": "engine-log", "Status": "active"},
            ],
        ),
        {},
    )
    ec.add_response("describe_cache_clusters", {"CacheClusters": []}, {})
    out = cp.replication_groups()
    assert any("transit encryption mode is 'preferred'" in m for m in _messages(out, "warning"))
    assert any("AUTH token was last rotated 400 days ago" in m for m in _messages(out, "info"))
    view = out["replication_groups"][0]
    assert view["transit_encryption_mode"] == "preferred"
    assert view["data_tiering"] == "enabled"
    assert view["network_type"] == "dual_stack"
    assert view["ip_discovery"] == "ipv4"
    assert view["auth_token_age_days"] == 400


def test_rg_recent_token_required_mode_and_unknown_engine_stay_quiet(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_replication_groups",
        _hardening_rg(
            Engine="memcached",
            TransitEncryptionMode="required",
            AuthTokenLastModifiedDate=NOW - dt.timedelta(days=30),
        ),
        {},
    )
    ec.add_response("describe_cache_clusters", {"CacheClusters": []}, {})
    out = cp.replication_groups()
    assert out["findings"] == []
    assert out["replication_groups"][0]["auth_token_age_days"] == 30


# ------------------------------------------- engine versions and parameter groups


def _ev(version, family, engine="redis", desc=None):
    return {
        "Engine": engine,
        "EngineVersion": version,
        "CacheParameterGroupFamily": family,
        "CacheEngineVersionDescription": desc or f"{engine} {version}",
    }


def test_engine_versions_lists_upgrade_targets_including_latest_valkey(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_cache_engine_versions",
        {
            "CacheEngineVersions": [
                _ev("6.2.6", "redis6.x"),
                _ev("7.0.7", "redis7"),
                _ev("7.1", "redis7"),
                _ev("6.0.5", "redis6.x"),
            ]
        },
        {"Engine": "redis"},
    )
    ec.add_response(
        "describe_cache_engine_versions",
        {"CacheEngineVersions": [_ev("7.2", "valkey7", "valkey"), _ev("8.0", "valkey8", "valkey")]},
        {"Engine": "valkey"},
    )
    out = cp.engine_versions("redis")
    assert [v["version"] for v in out["versions"]] == ["7.1", "7.0.7", "6.2.6", "6.0.5"]
    targets = {(t.get("engine", "valkey"), t["version"]) for t in out["upgrade_targets"]}
    assert ("redis", "7.1") in targets and ("redis", "6.2.6") in targets and ("valkey", "8.0") in targets
    assert any("Valkey 8.0" in f["message"] for f in out["findings"])


def test_engine_versions_prefix_filter_and_valkey_failure_degrades(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_cache_engine_versions",
        {"CacheEngineVersions": [_ev("7.0.7", "redis7"), _ev("6.2.6", "redis6.x")]},
        {"Engine": "redis"},
    )
    ec.add_client_error("describe_cache_engine_versions", service_error_code="AccessDenied", http_status_code=403)
    out = cp.engine_versions("redis", version_prefix="7.")
    assert [v["version"] for v in out["versions"]] == ["7.0.7"]
    assert "AccessDenied" in out["notes"][0]


def test_engine_versions_memcached_has_no_valkey_lookup(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_cache_engine_versions",
        {"CacheEngineVersions": [_ev("1.6.22", "memcached1.6", "memcached")]},
        {"Engine": "memcached"},
    )
    out = cp.engine_versions("memcached")
    assert out["upgrade_targets"][0]["version"] == "1.6.22" and out["findings"] == []


def test_parameter_groups_flags_unused_custom_and_family_mismatch(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_cache_parameter_groups",
        {
            "CacheParameterGroups": [
                {"CacheParameterGroupName": "default.redis7", "CacheParameterGroupFamily": "redis7"},
                {"CacheParameterGroupName": "orphan", "CacheParameterGroupFamily": "redis7"},
                {"CacheParameterGroupName": "stale", "CacheParameterGroupFamily": "redis6.x"},
                {"CacheParameterGroupName": "ok", "CacheParameterGroupFamily": "redis7"},
            ]
        },
        {},
    )
    ec.add_response(
        "describe_cache_clusters",
        {
            "CacheClusters": [
                {
                    "CacheClusterId": "a-001",
                    "Engine": "redis",
                    "EngineVersion": "7.0.7",
                    "CacheParameterGroup": {"CacheParameterGroupName": "stale"},
                },
                {
                    "CacheClusterId": "b-001",
                    "Engine": "redis",
                    "EngineVersion": "7.0.7",
                    "CacheParameterGroup": {"CacheParameterGroupName": "ok"},
                },
            ]
        },
        {},
    )
    ec.add_response(
        "describe_cache_engine_versions", {"CacheEngineVersions": [_ev("7.0.7", "redis7")]}, {"Engine": "redis"}
    )
    out = cp.parameter_groups()
    by_name = {g["name"]: g for g in out["parameter_groups"]}
    assert by_name["ok"]["in_use"] is True and by_name["ok"]["used_by"] == ["b-001"]
    assert by_name["orphan"]["in_use"] is False and by_name["default.redis7"]["custom"] is False
    msgs = {(f["severity"], f["resource"]): f["message"] for f in out["findings"]}
    assert ("info", "orphan") in msgs and "not used" in msgs[("info", "orphan")]
    assert (
        ("warning", "stale") in msgs
        and "redis6.x" in msgs[("warning", "stale")]
        and "redis7" in msgs[("warning", "stale")]
    )
    assert not any(r in ("ok", "default.redis7") for _, r in msgs)
    assert out["findings"][0]["severity"] == "warning"


def test_parameter_groups_without_cluster_listing_skips_unused_findings(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_cache_parameter_groups",
        {"CacheParameterGroups": [{"CacheParameterGroupName": "orphan", "CacheParameterGroupFamily": "redis7"}]},
        {},
    )
    ec.add_client_error("describe_cache_clusters", service_error_code="AccessDenied", http_status_code=403)
    out = cp.parameter_groups()
    assert out["partial"] is True and out["findings"] == []
    assert out["parameter_groups"][0]["in_use"] is None


# ------------------------------------------- reserved nodes vs the running fleet


def _reservation(rid, node_type, product, count, days_left=300):
    return {
        "ReservedCacheNodeId": rid,
        "CacheNodeType": node_type,
        "ProductDescription": product,
        "CacheNodeCount": count,
        "State": "active",
        "StartTime": NOW - dt.timedelta(days=365 - days_left),
        "Duration": 365 * 24 * 3600,
    }


def _cc(cid, node_type, engine, n=1):
    return {"CacheClusterId": cid, "CacheNodeType": node_type, "Engine": engine, "NumCacheNodes": n}


def test_reserved_nodes_fully_covered_fleet_has_no_cost_findings(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_reserved_cache_nodes", {"ReservedCacheNodes": [_reservation("r1", "cache.r6g.large", "redis", 2)]}, {}
    )
    ec.add_response("describe_cache_clusters", {"CacheClusters": [_cc("c1", "cache.r6g.large", "redis", 2)]}, {})
    out = cp.reserved_nodes()
    assert out["findings"] == []
    row = out["coverage"][0]
    assert (row["running_nodes"], row["reserved_nodes"], row["on_demand_nodes"], row["unused_reservations"]) == (
        2,
        2,
        0,
        0,
    )


def test_reserved_nodes_uncovered_and_orphaned_and_wrong_size(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_reserved_cache_nodes",
        {
            "ReservedCacheNodes": [
                _reservation("big", "cache.r6g.xlarge", "redis", 1),
                _reservation("gone", "cache.m6g.large", "valkey", 2),
            ]
        },
        {},
    )
    ec.add_response(
        "describe_cache_clusters",
        {"CacheClusters": [_cc("c1", "cache.r6g.large", "redis", 3), _cc("c2", "cache.r6g.xlarge", "redis", 1)]},
        {},
    )
    out = cp.reserved_nodes()
    by_sev = {(f["severity"], f["message"]) for f in out["findings"]}
    assert (
        "info",
        "3 on-demand cache.r6g.large redis node(s) not covered by a reservation",
    ) in by_sev  # no size flexibility
    assert ("warning", "2 reserved cache.m6g.large valkey node(s) have no running match") in by_sev
    assert not any("xlarge" in m for _, m in by_sev)


def test_reserved_nodes_expiring_with_nodes_still_running(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_reserved_cache_nodes",
        {"ReservedCacheNodes": [_reservation("r1", "cache.r6g.large", "redis", 2, days_left=20)]},
        {},
    )
    ec.add_response("describe_cache_clusters", {"CacheClusters": [_cc("c1", "cache.r6g.large", "redis", 2)]}, {})
    out = cp.reserved_nodes()
    msg = next(f["message"] for f in out["findings"] if f["severity"] == "warning")
    assert (
        "reservation r1 ends" in msg and "in 20 days" in msg and "2 cache.r6g.large redis node(s) still running" in msg
    )


def test_reserved_nodes_cluster_listing_denied_keeps_the_reservations(aws):
    cp, ec, _ = aws
    ec.add_response(
        "describe_reserved_cache_nodes",
        {"ReservedCacheNodes": [_reservation("r1", "cache.r6g.large", "redis", 2, days_left=10)]},
        {},
    )
    ec.add_client_error("describe_cache_clusters", service_error_code="AccessDenied", http_status_code=403)
    out = cp.reserved_nodes()
    assert out["count"] == 1 and out["reserved_cache_nodes"][0]["id"] == "r1"
    assert out["partial"] is True and "AccessDenied" in out["notes"][0]
    assert out["coverage"] == []
    assert any("reservation r1 ends" in f["message"] for f in out["findings"])
    assert not any("on-demand" in f["message"] or "no running match" in f["message"] for f in out["findings"])
