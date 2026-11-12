import datetime as dt

import boto3
import pytest
from botocore.stub import Stubber
from moto import mock_aws

from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def fake_aws_env(monkeypatch, tmp_path):
    # Never touch a real account: fake keys, no shared config files, no IMDS.
    for var in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


@pytest.fixture()
def stubbed():
    ec = boto3.client("elasticache", region_name=REGION)

    class Session:
        def client(self, service, region_name=None, config=None):
            assert service == "elasticache"
            return ec

    cp = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session)
    with Stubber(ec) as stub:
        yield cp, stub
        stub.assert_no_pending_responses()


def _rg(rg_id):
    return {
        "ReplicationGroupId": rg_id,
        "Status": "available",
        "ClusterEnabled": False,
        "MultiAZ": "enabled",
        "AutomaticFailover": "enabled",
        "CacheNodeType": "cache.r7g.large",
        "Engine": "valkey",
        "NodeGroups": [
            {
                "NodeGroupId": "0001",
                "Status": "available",
                "PrimaryEndpoint": {"Address": f"{rg_id}.cache.amazonaws.com", "Port": 6379},
                "NodeGroupMembers": [
                    {"CacheClusterId": f"{rg_id}-001", "CurrentRole": "primary"},
                    {"CacheClusterId": f"{rg_id}-002", "CurrentRole": "replica"},
                ],
            }
        ],
    }


def test_replication_groups_paginates(stubbed):
    cp, stub = stubbed
    stub.add_response("describe_replication_groups", {"ReplicationGroups": [_rg("a")], "Marker": "m1"}, {})
    stub.add_response("describe_replication_groups", {"ReplicationGroups": [_rg("b")]}, {"Marker": "m1"})
    out = cp.replication_groups()
    assert out["count"] == 2
    a = out["replication_groups"][0]
    assert a["cluster_mode"] == "disabled"
    assert a["engine"] == "valkey"
    assert [m["role"] for m in a["node_groups"][0]["members"]] == ["primary", "replica"]


def test_cache_clusters(stubbed):
    cp, stub = stubbed
    stub.add_response(
        "describe_cache_clusters",
        {
            "CacheClusters": [
                {
                    "CacheClusterId": "a-001",
                    "CacheClusterStatus": "available",
                    "Engine": "redis",
                    "EngineVersion": "7.1.0",
                    "CacheParameterGroup": {"CacheParameterGroupName": "pg1", "ParameterApplyStatus": "in-sync"},
                    "CacheNodes": [{"CacheNodeId": "0001", "CacheNodeStatus": "available"}],
                }
            ]
        },
        {"ShowCacheNodeInfo": True, "CacheClusterId": "a-001"},
    )
    c = cp.cache_clusters("a-001")["cache_clusters"][0]
    assert c["parameter_group"] == "pg1"
    assert c["nodes"][0]["id"] == "0001"


def test_events_and_parameters(stubbed):
    cp, stub = stubbed
    when = dt.datetime(2026, 11, 1, 12, 0, tzinfo=dt.UTC)
    stub.add_response(
        "describe_events",
        {"Events": [{"SourceIdentifier": "a-001", "SourceType": "cache-cluster", "Message": "Failover", "Date": when}]},
        {"Duration": 48 * 60, "SourceType": "cache-cluster"},
    )
    stub.add_response(
        "describe_cache_parameters",
        {"Parameters": [{"ParameterName": "maxmemory-policy", "ParameterValue": "allkeys-lfu", "Source": "user"}]},
        {"CacheParameterGroupName": "pg1", "Source": "user"},
    )
    ev = cp.events(source_type="cache-cluster", hours=48)
    assert ev["events"][0]["Date"] == when.isoformat()
    assert cp.parameters("pg1")["parameters"] == [
        {"name": "maxmemory-policy", "value": "allkeys-lfu", "source": "user", "modifiable": None, "change_type": None}
    ]


def test_client_error_is_reported(stubbed):
    cp, stub = stubbed
    stub.add_client_error("describe_replication_groups", "ReplicationGroupNotFoundFault", "not found")
    assert cp.replication_groups("nope") == {"error": "ReplicationGroupNotFoundFault", "message": "not found"}


def test_metrics_with_moto():
    with mock_aws():
        cw = boto3.client("cloudwatch", region_name=REGION)
        now = dt.datetime.now(dt.UTC).replace(second=0, microsecond=0)
        dims = [{"Name": "CacheClusterId", "Value": "a-001"}]
        for i, cpu in enumerate([10.0, 40.0, 25.0]):
            ts = now - dt.timedelta(minutes=5 - i)
            cw.put_metric_data(
                Namespace="AWS/ElastiCache",
                MetricData=[
                    {"MetricName": "EngineCPUUtilization", "Dimensions": dims, "Value": cpu, "Timestamp": ts},
                    {"MetricName": "Evictions", "Dimensions": dims, "Value": 3.0, "Timestamp": ts},
                ],
            )
        cp = ControlPlane(ControlPlaneConfig(region=REGION))
        out = cp.metrics("a-001", ["EngineCPUUtilization", "Evictions", "CurrConnections"], minutes=30)
    s = out["summary"]
    assert s["EngineCPUUtilization"]["points"] == 3
    assert s["EngineCPUUtilization"]["max"] == 40.0
    assert s["Evictions"]["max"] == 3.0
    assert s["CurrConnections"] == {"points": 0}


def test_no_credentials_is_unavailable(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID")
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY")
    cp = ControlPlane(ControlPlaneConfig(region=REGION))
    assert "unavailable" in cp.replication_groups()


def test_disabled():
    cp = ControlPlane(ControlPlaneConfig(region=REGION, enabled=False))
    assert "unavailable" in cp.metrics("a-001")


# ------------------------------------------------------------- round 14: engine default parameters


def _param(name, value, source="system"):
    return {"ParameterName": name, "ParameterValue": value, "Source": source, "IsModifiable": True}


def _diff_stub(stub, actual, defaults, family="redis7"):
    stub.add_response(
        "describe_cache_parameter_groups",
        {"CacheParameterGroups": [{"CacheParameterGroupName": "pg1", "CacheParameterGroupFamily": family}]},
        {"CacheParameterGroupName": "pg1"},
    )
    stub.add_response(
        "describe_engine_default_parameters",
        {"EngineDefaults": {"CacheParameterGroupFamily": family, "Marker": "m1", "Parameters": defaults[:1]}},
        {"CacheParameterGroupFamily": family},
    )
    stub.add_response(
        "describe_engine_default_parameters",
        {"EngineDefaults": {"CacheParameterGroupFamily": family, "Parameters": defaults[1:]}},
        {"CacheParameterGroupFamily": family, "Marker": "m1"},
    )
    stub.add_response("describe_cache_parameters", {"Parameters": actual}, {"CacheParameterGroupName": "pg1"})


DEFAULTS = [
    _param("maxmemory-policy", "volatile-lru"),
    _param("timeout", "0"),
    _param("maxmemory-samples", "3"),
    _param("client-output-buffer-limit-replica-hard-limit", "268435456"),
    _param("tcp-keepalive", "300"),
]


def test_parameters_engine_default_diff_lists_only_non_default_values(stubbed):
    cp, stub = stubbed
    actual = [
        _param("maxmemory-policy", "allkeys-lru", "user"),
        _param("timeout", "0"),
        _param("maxmemory-samples", "3"),
        _param("client-output-buffer-limit-replica-hard-limit", "268435456"),
        _param("tcp-keepalive", "60", "user"),
    ]
    _diff_stub(stub, actual, DEFAULTS)
    out = cp.parameters("pg1", diff_engine_defaults=True)
    assert [(p["name"], p["value"], p["default"]) for p in out["parameters"]] == [
        ("maxmemory-policy", "allkeys-lru", "volatile-lru"),
        ("tcp-keepalive", "60", "300"),
    ]
    assert out["engine_defaults"] == {"family": "redis7", "compared": 5, "non_default": 2}


def test_parameters_flags_risky_settings(stubbed):
    cp, stub = stubbed
    actual = [
        _param("maxmemory-policy", "noeviction", "user"),
        _param("timeout", "0"),
        _param("maxmemory-samples", "1", "user"),
        _param("client-output-buffer-limit-replica-hard-limit", "1024", "user"),
        _param("tcp-keepalive", "300"),
    ]
    _diff_stub(stub, actual, DEFAULTS)
    out = cp.parameters("pg1", diff_engine_defaults=True)
    by_param = {f["parameter"]: f for f in out["findings"]}
    assert set(by_param) == {
        "maxmemory-policy",
        "timeout",
        "maxmemory-samples",
        "client-output-buffer-limit-replica-hard-limit",
    }
    assert (
        by_param["maxmemory-policy"]["severity"] == "warning"
        and "noeviction" in by_param["maxmemory-policy"]["message"]
    )
    assert by_param["timeout"]["severity"] == "info"
    assert "below the engine default (3)" in by_param["maxmemory-samples"]["message"]
    assert "1024 bytes" in by_param["client-output-buffer-limit-replica-hard-limit"]["message"]


def test_parameters_without_diff_still_reports_risky_values(stubbed):
    cp, stub = stubbed
    stub.add_response(
        "describe_cache_parameters",
        {"Parameters": [_param("maxmemory-policy", "noeviction", "user")]},
        {"CacheParameterGroupName": "pg1", "Source": "user"},
    )
    out = cp.parameters("pg1")
    assert [f["parameter"] for f in out["findings"]] == ["maxmemory-policy"]
    assert "engine_defaults" not in out


def test_every_boto3_call_in_controlplane_has_a_matching_action_in_the_readme_policy():
    import ast
    import json
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    readme = (root / "README.md").read_text(encoding="utf-8")
    block = re.search(r"```json\n(\{.*?\})\n```", readme, re.S).group(1)
    actions = {a.split(":", 1)[1] for st in json.loads(block)["Statement"] for a in st["Action"]}
    package = root / "src" / "mcp_elasticache_ops" / "controlplane"
    trees = [ast.parse(f.read_text(encoding="utf-8")) for f in sorted(package.glob("*.py"))]
    names = set()
    for node in (n for tree in trees for n in ast.walk(tree)):
        text = node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None
        text = node.attr if isinstance(node, ast.Attribute) else text
        if text and re.fullmatch(r"(describe|list)_[a-z_]+|get_metric_data", text):
            names.add(text)
    assert "describe_engine_default_parameters" in names and "get_metric_data" in names
    missing = {n for n in names if "".join(p.capitalize() for p in n.split("_")) not in actions}
    assert not missing, f"calls without a README IAM action: {sorted(missing)}"
