"""Round 02: triage, drift, new findings, serverless limits and the read-only invariants."""

from __future__ import annotations

import ast
import datetime as dt
import inspect
import json
import re
import socket
from pathlib import Path

import boto3
import pytest
from botocore.exceptions import ClientError
from fastmcp import Client
from fastmcp.exceptions import ToolError

from mcp_elasticache_ops import controlplane, memcached, server
from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane

REGION = "us-east-1"
NOW = dt.datetime(2026, 11, 12, 12, 0, tzinfo=dt.UTC)
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def fake_aws_env(monkeypatch, tmp_path):
    for var in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


class Fake:
    """Duck-typed boto client: canned responses (or exceptions) per operation, {} for anything else."""

    def __init__(self, responses: dict | None = None):
        self.responses = responses or {}
        self.calls: list[tuple[str, dict]] = []

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)

        def call(**kwargs):
            self.calls.append((name, kwargs))
            r = self.responses.get(name, {})
            if isinstance(r, Exception):
                raise r
            return r(kwargs) if callable(r) else r

        return call


def plane(ec: Fake, cw: Fake | None = None) -> ControlPlane:
    cw = cw or Fake()

    class Session:
        def client(self, service, region_name=None, config=None):
            return {"elasticache": ec, "cloudwatch": cw}[service]

    return ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)


def denied(op: str) -> ClientError:
    return ClientError({"Error": {"Code": "AccessDenied", "Message": "not allowed"}}, op)


def metric_result(values_by_label: dict[str, list[float]]):
    def respond(kwargs):
        out = []
        for q in kwargs["MetricDataQueries"]:
            vals = values_by_label.get(q["Label"], [])
            ts = [NOW - dt.timedelta(minutes=5 * i) for i in range(len(vals))]
            out.append({"Id": q["Id"], "Label": q["Label"], "Timestamps": ts, "Values": vals, "StatusCode": "Complete"})
        return {"MetricDataResults": out}

    return respond


def rg(status="available", multi_az="enabled", failover="enabled", azs=("us-east-1a", "us-east-1b")):
    members = [
        {
            "CacheClusterId": f"prod-00{i + 1}",
            "PreferredAvailabilityZone": az,
            "CurrentRole": "primary" if i == 0 else "replica",
        }
        for i, az in enumerate(azs)
    ]
    return {
        "ReplicationGroupId": "prod",
        "Status": status,
        "MultiAZ": multi_az,
        "AutomaticFailover": failover,
        "MemberClusters": [m["CacheClusterId"] for m in members],
        "NodeGroups": [{"NodeGroupId": "0001", "Status": "available", "NodeGroupMembers": members}],
        "AtRestEncryptionEnabled": True,
        "TransitEncryptionEnabled": True,
        "AuthTokenEnabled": True,
        "SnapshotRetentionLimit": 5,
        "CacheNodeType": "cache.m7g.large",
    }


# ------------------------------------------------------------------ triage


def test_triage_sorts_worst_first_and_builds_status_table():
    ec = Fake(
        {
            "describe_replication_groups": {"ReplicationGroups": [rg(failover="disabled", multi_az="disabled")]},
            "describe_events": {
                "Events": [
                    {
                        "SourceIdentifier": "prod-001",
                        "Message": "Failover from node prod-001 to prod-002 completed",
                        "Date": NOW,
                    },
                    {"SourceIdentifier": "prod-002", "Message": "Cache node unavailable", "Date": NOW},
                    {"SourceIdentifier": "prod-002", "Message": "Cache cluster created", "Date": NOW},
                ]
            },
            "describe_update_actions": {
                "UpdateActions": [
                    {
                        "ServiceUpdateName": "su-1",
                        "ServiceUpdateSeverity": "important",
                        "ServiceUpdateRecommendedApplyByDate": NOW - dt.timedelta(days=2),
                    }
                ]
            },
            "describe_snapshots": {"Snapshots": []},
        }
    )
    cw = Fake(
        {
            "get_metric_data": metric_result(
                {
                    "prod-001|EngineCPUUtilization": [95.0, 90.0, 92.0],
                    "prod-002|EngineCPUUtilization": [10.0, 12.0, 11.0],
                    "prod-001|DatabaseMemoryUsagePercentage": [50.0, 52.0, 51.0],
                }
            )
        }
    )
    out = plane(ec, cw).triage("prod")
    assert [s["section"] for s in out["sections"]] == [
        "replication_group",
        "events",
        "metrics",
        "service_updates",
        "snapshots",
    ]
    assert all(s["status"] != "unavailable" for s in out["sections"])
    sevs = [f["severity"] for f in out["findings"]]
    order = {"critical": 0, "warning": 1, "important": 1, "info": 2}
    assert [order[s] for s in sevs] == sorted(order[s] for s in sevs)
    assert out["overall"] == "critical"
    text = " ".join(f["message"] for f in out["findings"])
    assert "automatic failover" in text and "Multi-AZ" in text and "su-1" in text and "unavailable" in text
    assert {f["section"] for f in out["findings"]} >= {"replication_group", "events", "service_updates"}
    # the metrics section asks the five triage metrics over 6h
    names = {q["MetricStat"]["Metric"]["MetricName"] for q in cw.calls[0][1]["MetricDataQueries"]}
    assert names == set(controlplane.TRIAGE_METRICS)
    assert ec.calls[1][1]["Duration"] == 360


def test_triage_section_failure_becomes_unavailable_and_others_survive():
    ec = Fake(
        {
            "describe_replication_groups": {"ReplicationGroups": [rg()]},
            "describe_events": denied("DescribeEvents"),
            "describe_update_actions": {"UpdateActions": []},
            "describe_snapshots": {
                "Snapshots": [
                    {
                        "SnapshotName": "s",
                        "ReplicationGroupId": "prod",
                        "SnapshotStatus": "available",
                        "SnapshotSource": "automated",
                        "NodeSnapshots": [{"SnapshotCreateTime": NOW - dt.timedelta(hours=2), "CacheSize": "5 MB"}],
                    }
                ]
            },
        }
    )
    out = plane(ec, Fake({"get_metric_data": denied("GetMetricData")})).triage("prod")
    status = {s["section"]: s["status"] for s in out["sections"]}
    assert status["events"] == "unavailable"
    assert status["metrics"] == "unavailable"
    assert status["replication_group"] == "ok"
    assert status["snapshots"] == "ok"
    assert any("events unavailable" in f["message"] for f in out["findings"])
    assert "error" not in out


def test_triage_caps_findings_at_thirty():
    events = [
        {"SourceIdentifier": f"prod-{i}", "Message": f"node {i} failed", "Date": NOW - dt.timedelta(minutes=i)}
        for i in range(50)
    ]
    ec = Fake({"describe_replication_groups": {"ReplicationGroups": [rg()]}, "describe_events": {"Events": events}})
    out = plane(ec).triage("prod")
    assert len(out["findings"]) <= controlplane.MAX_TRIAGE_FINDINGS
    assert out["findings_total"] >= len(out["findings"])
    assert out["truncated"] is (out["findings_total"] > 30)


def test_triage_unknown_group_is_a_tool_error_dict():
    err = ClientError(
        {"Error": {"Code": "ReplicationGroupNotFoundFault", "Message": "nope"}}, "DescribeReplicationGroups"
    )
    out = plane(Fake({"describe_replication_groups": err})).triage("missing")
    assert out["error"] == "ReplicationGroupNotFoundFault"


def test_triage_disabled_control_plane():
    cp = ControlPlane(ControlPlaneConfig(region=REGION, enabled=False))
    assert "unavailable" in cp.triage("x")


# ------------------------------------------------------------------- drift


def _params(**vals):
    return {
        "Parameters": [
            {"ParameterName": k, "ParameterValue": v, "Source": src, "ChangeType": "immediate"}
            for k, (v, src) in vals.items()
        ]
    }


def test_parameter_drift_reports_only_modified_differences():
    by_group = {
        "prod": _params(
            **{"maxmemory-policy": ("allkeys-lru", "user"), "timeout": ("0", "system"), "x-default": ("1", "system")}
        ),
        "stage": _params(
            **{"maxmemory-policy": ("noeviction", "system"), "timeout": ("0", "system"), "x-default": ("2", "system")}
        ),
    }
    by_group["stage"]["Parameters"].append({"ParameterName": "only-b", "ParameterValue": "1", "Source": "system"})

    def params(kw):
        return by_group[kw["CacheParameterGroupName"]]

    def groups(kw):
        fam = "valkey8" if kw["CacheParameterGroupName"] == "prod" else "redis7"
        return {
            "CacheParameterGroups": [
                {"CacheParameterGroupName": kw["CacheParameterGroupName"], "CacheParameterGroupFamily": fam}
            ]
        }

    out = plane(Fake({"describe_cache_parameters": params, "describe_cache_parameter_groups": groups})).parameter_drift(
        "prod", "stage"
    )
    assert [d["parameter"] for d in out["differences"]] == ["maxmemory-policy"]
    assert out["ignored_default_only_differences"] == 1
    assert out["only_in_b"] == ["only-b"] and out["only_in_a"] == []
    msgs = " ".join(f["message"] for f in out["findings"])
    assert "different families" in msgs and "maxmemory-policy differs" in msgs
    assert out["findings"][0]["severity"] == "warning"


def test_parameter_drift_identical_groups():
    p = _params(a=("1", "user"))
    out = plane(Fake({"describe_cache_parameters": p})).parameter_drift("a", "b")
    assert out["difference_count"] == 0
    assert any("no modified parameter differs" in f["message"] for f in out["findings"])


# ------------------------------------------------- cluster and group findings


def _cluster(**over):
    base = {
        "CacheClusterId": "solo",
        "Engine": "redis",
        "EngineVersion": "6.2.6",
        "CacheClusterStatus": "available",
        "CacheNodeType": "cache.t3.small",
        "NumCacheNodes": 1,
        "TransitEncryptionEnabled": False,
        "AuthTokenEnabled": False,
        "AutoMinorVersionUpgrade": False,
        "CacheParameterGroup": {
            "CacheParameterGroupName": "custom",
            "ParameterApplyStatus": "pending-reboot",
            "CacheNodeIdsToReboot": ["0001"],
        },
    }
    base.update(over)
    return base


def test_cache_cluster_findings_cover_new_rules():
    ec = Fake(
        {
            "describe_cache_clusters": {"CacheClusters": [_cluster()]},
            "describe_cache_engine_versions": {
                "CacheEngineVersions": [
                    {"Engine": "redis", "EngineVersion": "6.2.6", "CacheParameterGroupFamily": "redis6.x"},
                    {"Engine": "redis", "EngineVersion": "6.2.14", "CacheParameterGroupFamily": "redis6.x"},
                ]
            },
            "describe_cache_parameter_groups": {
                "CacheParameterGroups": [{"CacheParameterGroupName": "custom", "CacheParameterGroupFamily": "redis7"}]
            },
        }
    )
    out = plane(ec).cache_clusters()
    text = " | ".join(f["message"] for f in out["findings"])
    for needle in (
        "end-of-life",
        "Valkey",
        "behind the newest 6.x",
        "pending a reboot",
        "expects redis6.x",
        "encryption in transit is disabled",
        "no authentication",
        "auto minor version upgrade is off",
    ):
        assert needle in text, needle
    assert out["findings"][0]["severity"] == "critical"
    assert out["cache_clusters"][0]["findings"]


def test_cache_cluster_findings_survive_describe_failures_and_stay_quiet_when_clean():
    clean = _cluster(
        Engine="valkey",
        EngineVersion="8.0",
        TransitEncryptionEnabled=True,
        AuthTokenEnabled=True,
        AutoMinorVersionUpgrade=True,
        LogDeliveryConfigurations=[
            {"LogType": "slow-log", "Status": "active"},
            {"LogType": "engine-log", "Status": "active"},
        ],
        CacheParameterGroup={"CacheParameterGroupName": "default.valkey8", "ParameterApplyStatus": "in-sync"},
    )
    ec = Fake(
        {
            "describe_cache_clusters": {"CacheClusters": [clean]},
            "describe_cache_engine_versions": denied("DescribeCacheEngineVersions"),
            "describe_cache_parameter_groups": denied("DescribeCacheParameterGroups"),
        }
    )
    out = plane(ec).cache_clusters()
    assert out["findings"] == []


def test_replication_group_single_az_and_latest_minor():
    ec = Fake(
        {
            "describe_replication_groups": {"ReplicationGroups": [rg(azs=("us-east-1a", "us-east-1a"))]},
            "describe_cache_clusters": {
                "CacheClusters": [
                    {
                        "CacheClusterId": "prod-001",
                        "ReplicationGroupId": "prod",
                        "Engine": "valkey",
                        "EngineVersion": "7.2",
                    }
                ]
            },
            "describe_cache_engine_versions": {
                "CacheEngineVersions": [
                    {"Engine": "valkey", "EngineVersion": "7.2"},
                    {"Engine": "valkey", "EngineVersion": "7.9"},
                ]
            },
        }
    )
    out = plane(ec).replication_groups()
    text = " | ".join(f["message"] for f in out["findings"])
    assert "all sit in us-east-1a" in text
    assert "behind the newest 7.x" in text


# --------------------------------------------------------------- serverless


def test_serverless_caches_findings():
    bare = {"ServerlessCacheName": "sc1", "Engine": "valkey", "Status": "available"}
    ok = {
        "ServerlessCacheName": "sc2",
        "Engine": "valkey",
        "Status": "available",
        "CacheUsageLimits": {"DataStorage": {"Maximum": 10, "Unit": "GB"}, "ECPUPerSecond": {"Maximum": 5000}},
        "DailySnapshotTime": "03:00",
        "SnapshotRetentionLimit": 7,
        "UserGroupId": "ug",
    }
    out = plane(Fake({"describe_serverless_caches": {"ServerlessCaches": [bare, ok]}})).serverless_caches()
    msgs = [(f["resource"], f["message"]) for f in out["findings"]]
    assert all(r == "sc1" for r, _ in msgs)
    text = " ".join(m for _, m in msgs)
    for needle in ("DataStorage maximum", "ECPUPerSecond maximum", "no daily snapshot", "no user group"):
        assert needle in text, needle


def test_serverless_metrics_limit_findings():
    limits = {"DataStorage": {"Maximum": 1, "Unit": "GB"}, "ECPUPerSecond": {"Maximum": 1000}}
    ec = Fake(
        {
            "describe_serverless_caches": {
                "ServerlessCaches": [{"ServerlessCacheName": "sc", "CacheUsageLimits": limits}]
            }
        }
    )
    cw = Fake(
        {
            "get_metric_data": metric_result(
                {
                    "sc|BytesUsedForCache": [0.95 * 1024**3, 0.5 * 1024**3, 0.4 * 1024**3],
                    "sc|ElastiCacheProcessingUnits": [900 * 60.0, 100.0, 100.0],
                }
            )
        }
    )
    out = plane(ec, cw).metrics(
        "sc", ["BytesUsedForCache", "ElastiCacheProcessingUnits"], minutes=15, period_seconds=60, serverless=True
    )
    text = " | ".join(f["message"] for f in out["findings"])
    assert "DataStorage maximum" in text and "ECPUPerSecond maximum" in text
    assert out["findings"][0]["severity"] == "critical"
    assert out["serverless_limits"]["sc"]["data_storage_used_pct"] == 95.0
    assert out["serverless_limits"]["sc"]["ecpu_used_pct"] == 90.0


def test_serverless_limits_lookup_failure_is_tolerated():
    cw = Fake({"get_metric_data": metric_result({"sc|BytesUsedForCache": [1.0, 2.0, 3.0]})})
    out = plane(Fake({"describe_serverless_caches": denied("DescribeServerlessCaches")}), cw).metrics(
        "sc", ["BytesUsedForCache"], minutes=15, period_seconds=60, serverless=True
    )
    assert "error" not in out and out["findings"] == []


# ------------------------------------------------------------- right-sizing


def _metrics(values):
    cw = Fake({"get_metric_data": metric_result(values)})
    return plane(Fake(), cw).metrics("n1", minutes=60, period_seconds=300)


def test_rightsizing_downsize_hint_on_idle_node():
    out = _metrics(
        {
            "n1|EngineCPUUtilization": [2.0, 3.0, 4.0],
            "n1|DatabaseMemoryUsagePercentage": [10.0, 11.0, 12.0],
            "n1|Evictions": [0.0, 0.0, 0.0],
        }
    )
    hints = [f for f in out["findings"] if f.get("category") == "right-sizing"]
    assert len(hints) == 1 and hints[0]["severity"] == "info" and "smaller node type" in hints[0]["message"]


def test_rightsizing_upsize_hint_on_pressure():
    out = _metrics(
        {
            "n1|EngineCPUUtilization": [50.0, 60.0, 70.0],
            "n1|DatabaseMemoryUsagePercentage": [85.0, 90.0, 92.0],
            "n1|Evictions": [10.0, 20.0, 30.0],
        }
    )
    hints = [f["message"] for f in out["findings"] if f.get("category") == "right-sizing"]
    assert any("larger node type" in h for h in hints) and any("evictions" in h for h in hints)
    assert not any("smaller" in h for h in hints)


def test_rightsizing_needs_enough_points():
    out = _metrics({"n1|EngineCPUUtilization": [1.0], "n1|DatabaseMemoryUsagePercentage": [1.0]})
    assert not [f for f in out["findings"] if f.get("category") == "right-sizing"]


# ------------------------------------------------------------- invariants

READ_PREFIX = re.compile(r"^(Describe|List|GetMetricData)")


def _public_methods(cp: ControlPlane):
    return [
        (n, m)
        for n, m in inspect.getmembers(cp, inspect.ismethod)
        if not n.startswith("_") and n not in ("client", "in_region")
    ]


def _sample_args(method) -> tuple[list, dict]:
    sig = inspect.signature(method)
    args = []
    for p in sig.parameters.values():
        if p.default is inspect.Parameter.empty:
            args.append("x")
    return args, {}


def test_real_botocore_operations_are_all_read_only():
    """Run every public ControlPlane method on real boto3 clients; record the true API operation names."""
    seen: list[str] = []

    class Resp:
        status_code = 200

    def before_call(model, **_kw):
        seen.append(model.name)
        return Resp(), {}

    clients = {s: boto3.client(s, region_name=REGION) for s in ("elasticache", "cloudwatch")}
    for c in clients.values():
        c.meta.events.register("before-call.*.*", before_call)

    class Session:
        def client(self, service, region_name=None, config=None):
            return clients[service]

    cp = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)
    methods = _public_methods(cp)
    assert len(methods) >= 15
    for _name, method in methods:
        args, kwargs = _sample_args(method)
        method(*args, **kwargs)
    cp.metrics(replication_group_id="rg", minutes=5)
    cp.metrics("sc", minutes=5, serverless=True)
    cp.cache_clusters()
    cp.replication_groups()
    assert len(set(seen)) >= 15
    assert all(READ_PREFIX.match(op) for op in seen), sorted(op for op in set(seen) if not READ_PREFIX.match(op))
    assert {"DescribeUpdateActions", "DescribeCacheParameters", "GetMetricData"} <= set(seen)


def test_static_calls_in_controlplane_use_read_only_prefixes():
    tree = ast.parse((ROOT / "src/mcp_elasticache_ops/controlplane.py").read_text(encoding="utf-8"))
    paginated: list[str] = []
    direct: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "_paginate" and node.args:
            a = node.args[0]
            assert isinstance(a, ast.Constant) and isinstance(a.value, str), "_paginate op must be a literal"
            paginated.append(a.value)
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in {"ec", "cw"}:
            direct.append(f.attr)
    assert paginated and direct
    for op in [*paginated, *direct]:
        assert op.startswith(controlplane.ALLOWED_PREFIXES), op


def test_guard_refuses_write_operations():
    cp = plane(Fake())
    with pytest.raises(ValueError, match="non-read-only"):
        cp._paginate("delete_replication_group", "x")
    with pytest.raises(ValueError, match="non-read-only"):
        cp._paginate("modify_cache_cluster", "x")


async def test_every_tool_is_annotated_and_readme_count_matches():
    async with Client(server.mcp) as c:
        tools = await c.list_tools()
    for t in tools:
        assert t.annotations is not None, t.name
        assert t.annotations.read_only_hint is True, t.name
        assert t.annotations.destructive_hint is False, t.name
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    m = re.search(r"All (\d+) tools are annotated", readme)
    assert m and int(m.group(1)) == len(tools)
    documented = set(re.findall(r"^\| `((?:node|aws|memcached)_[a-z_]+)` \|", readme, flags=re.M))
    assert documented == {t.name for t in tools}


def test_iam_policy_in_readme_is_read_only():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    block = re.search(r"```json\n(\{\s*\"Version\".*?\})\n```", readme, flags=re.S)
    assert block, "README must carry a minimal IAM policy"
    policy = json.loads(block.group(1))
    actions = []
    for st in policy["Statement"]:
        assert st["Effect"] == "Allow"
        a = st["Action"]
        actions += [a] if isinstance(a, str) else a
    assert actions
    for action in actions:
        svc, _, op = action.partition(":")
        assert svc in {"elasticache", "cloudwatch"}, action
        assert READ_PREFIX.match(op), action
        assert op != "*", action


# --------------------------------------------------------------- memcached


def test_memcached_query_refuses_anything_but_stats_and_version(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("socket must not be opened")

    monkeypatch.setattr(socket, "create_connection", boom)
    for bad in ("flush_all", "stats\r\nflush_all", "stats settings\r\nflush_all", "set a 0 0 1", "stats cachedump 1 1"):
        with pytest.raises(ValueError):
            memcached._query("h", 11211, bad, 1.0)


@pytest.mark.parametrize(
    "group", ["flush_all", "settings\r\nflush_all", "settings; flush_all", "cachedump 1 1", "reset"]
)
def test_memcached_stats_group_cannot_smuggle_commands(monkeypatch, group):
    sent: list[str] = []
    monkeypatch.setattr(memcached, "_query", lambda host, port, command, timeout: sent.append(command) or [])
    with pytest.raises(ValueError):
        memcached.stats("h", group=group)
    assert sent == []


def test_memcached_only_sends_allowed_commands(monkeypatch):
    sent: list[str] = []
    monkeypatch.setattr(memcached, "_query", lambda host, port, command, timeout: sent.append(command) or [])
    for g in ("", "settings", "slabs", "items", "conns"):
        memcached.stats("h", group=g)
    memcached.summary("h")
    assert set(sent) <= memcached.ALLOWED_COMMANDS
    assert all(c == "version" or c.startswith("stats") for c in sent)


async def test_memcached_tool_rejects_bad_group(monkeypatch):
    monkeypatch.setenv("MEMCACHED_HOST", "127.0.0.1")
    async with Client(server.mcp) as c:
        with pytest.raises(ToolError):
            await c.call_tool("memcached_stats", {"group": "flush_all"})


def test_readme_allowlist_matches_safe_client():
    from mcp_elasticache_ops import safe_client as sc

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    block = readme.split("<!-- allowlist:start -->")[1].split("<!-- allowlist:end -->")[0]
    for name in (*sc.READ_ONLY_COMMANDS, *sc.CONFIG_GET_EXACT, *sc.FORBIDDEN_COMMANDS):
        assert f"`{name}`" in block, name
    for prefix in sc.CONFIG_GET_PREFIXES:
        assert f"`{prefix}*`" in block, prefix


# ----------------------------------------------------------- round 03: aws_cluster_overview


def sharded_rg(shards=3, node_type="cache.r7g.large", reader=True, replicas=1, group_id="prod-cluster"):
    node_groups = []
    for s in range(1, shards + 1):
        members = [
            {
                "CacheClusterId": f"{group_id}-000{s}-00{i + 1}",
                "PreferredAvailabilityZone": ("us-east-1a", "us-east-1b", "us-east-1c")[i % 3],
                "CurrentRole": "primary" if i == 0 else "replica",
            }
            for i in range(replicas + 1)
        ]
        ng = {"NodeGroupId": f"000{s}", "Status": "available", "NodeGroupMembers": members}
        if reader:
            ng["ReaderEndpoint"] = {"Address": f"r{s}.example.com", "Port": 6379}
        node_groups.append(ng)
    members_all = [m["CacheClusterId"] for ng in node_groups for m in ng["NodeGroupMembers"]]
    return {
        "ReplicationGroupId": group_id,
        "Status": "available",
        "MultiAZ": "enabled",
        "AutomaticFailover": "enabled",
        "ClusterEnabled": False,
        "MemberClusters": members_all,
        "NodeGroups": node_groups,
        "AtRestEncryptionEnabled": True,
        "TransitEncryptionEnabled": True,
        "AuthTokenEnabled": True,
        "SnapshotRetentionLimit": 5,
        "CacheNodeType": node_type,
    }


def _overview_plane(group, values, cw_error=None):
    ec = Fake(
        {
            "describe_replication_groups": {"ReplicationGroups": [group]},
            "describe_cache_clusters": {
                "CacheClusters": [
                    {
                        "CacheClusterId": group["MemberClusters"][0],
                        "ReplicationGroupId": group["ReplicationGroupId"],
                        "Engine": "valkey",
                        "EngineVersion": "8.0",
                    }
                ]
            },
        }
    )
    cw = Fake({"get_metric_data": cw_error or metric_result(values)})
    return plane(ec, cw), ec, cw


def _primary_values(group, per_shard_cpu, per_shard_mem, cpu_p=None):
    values = {}
    for ng, cpu, mem in zip(group["NodeGroups"], per_shard_cpu, per_shard_mem, strict=True):
        for m in ng["NodeGroupMembers"]:
            cid = m["CacheClusterId"]
            primary = m["CurrentRole"] == "primary"
            values[f"{cid}|EngineCPUUtilization"] = [cpu if primary else 5.0] * 6
            values[f"{cid}|DatabaseMemoryUsagePercentage"] = [mem] * 6
            values[f"{cid}|ReplicationLag"] = [] if primary else [0.1] * 6
    return values


def test_cluster_overview_flags_a_skewed_shard_worst_first():
    group = sharded_rg(shards=4)
    values = _primary_values(group, [20, 22, 21, 85], [40, 41, 39, 75])
    cp, _, _ = _overview_plane(group, values)
    out = cp.cluster_overview("prod-cluster")
    assert out["status"] == "ok"
    skew = [f for f in out["findings"] if f.get("metric")]
    assert skew and skew[0]["shard"] == "0004" and skew[0]["ratio"] >= 1.5
    assert {f["metric"] for f in skew} >= {"EngineCPUUtilization", "DatabaseMemoryUsagePercentage"}
    assert all("0004" in f["message"] or "-0004-" in f["message"] for f in skew)
    assert out["shards"][0]["shard"] == "0004"  # shards are worst-first by memory
    assert out["topology"]["shard_count"] == 4 and out["topology"]["replicas_per_shard"] == [1]
    assert out["topology"]["az_spread"] == ["us-east-1a", "us-east-1b"]
    assert out["topology"]["engine"] == "valkey"
    sev = [f["severity"] for f in out["findings"]]
    assert sev == sorted(sev, key=lambda s: {"critical": 0, "warning": 2, "info": 5}.get(s, 9))


def test_cluster_overview_balanced_group_has_no_skew_findings():
    group = sharded_rg(shards=3)
    cp, _, _ = _overview_plane(group, _primary_values(group, [40, 42, 41], [50, 52, 51]))
    out = cp.cluster_overview("prod-cluster")
    assert not [f for f in out["findings"] if f.get("metric")]


def test_cluster_overview_rightsizing_hint():
    group = sharded_rg(shards=2)
    cp, _, _ = _overview_plane(group, _primary_values(group, [5, 6], [12, 15]))
    out = cp.cluster_overview("prod-cluster")
    hint = [f for f in out["findings"] if f.get("category") == "right-sizing"]
    assert len(hint) == 1 and "smaller node type" in hint[0]["message"] and hint[0]["severity"] == "info"
    busy = sharded_rg(shards=2)
    cp, _, _ = _overview_plane(busy, _primary_values(busy, [5, 6], [45, 46]))
    assert not [f for f in cp.cluster_overview("prod-cluster")["findings"] if f.get("category") == "right-sizing"]


def test_cluster_overview_data_tiering_hints():
    memory_bound = sharded_rg(shards=2, node_type="cache.r7g.xlarge")
    cp, _, _ = _overview_plane(memory_bound, _primary_values(memory_bound, [8, 9], [82, 85]))
    hint = [f for f in cp.cluster_overview("prod-cluster")["findings"] if f.get("category") == "right-sizing"]
    assert hint and "data tiering" in hint[0]["message"] and "r6gd" in hint[0]["message"]
    tiered = sharded_rg(shards=2, node_type="cache.r6gd.xlarge")
    cp, _, _ = _overview_plane(tiered, _primary_values(tiered, [5, 6], [10, 12]))
    hint = [f for f in cp.cluster_overview("prod-cluster")["findings"] if f.get("category") == "right-sizing"]
    assert hint and "already in use" in hint[0]["message"]


def test_cluster_overview_access_denied_on_metrics_degrades_to_partial():
    group = sharded_rg(shards=2)
    cp, _, cw = _overview_plane(group, {}, cw_error=denied("GetMetricData"))
    out = cp.cluster_overview("prod-cluster")
    assert "error" not in out and out["status"] == "partial"
    assert out["topology"]["shard_count"] == 2 and len(out["shards"]) == 2
    assert any("GetMetricData failed (AccessDenied)" in f["message"] for f in out["findings"])
    assert not [f for f in out["findings"] if f.get("category") == "right-sizing"]
    assert {name for name, _ in cw.calls} == {"get_metric_data"}


def test_cluster_overview_reader_endpoint_and_missing_replica_findings():
    group = sharded_rg(shards=2, reader=False)
    cp, _, _ = _overview_plane(group, {})
    msgs = [f["message"] for f in cp.cluster_overview("prod-cluster")["findings"]]
    assert sum("no reader endpoint" in m for m in msgs) == 2
    lonely = sharded_rg(shards=1, replicas=0)
    cp, _, _ = _overview_plane(lonely, {})
    out = cp.cluster_overview("prod-cluster")
    assert any(f["severity"] == "critical" and "no replicas" in f["message"] for f in out["findings"])
    fine = sharded_rg(shards=1)
    cp, _, _ = _overview_plane(fine, {})
    assert not [f for f in cp.cluster_overview("prod-cluster")["findings"] if "reader" in f["message"]]


def test_cluster_overview_is_bounded_and_unknown_group_is_an_error():
    group = sharded_rg(shards=60, reader=False)
    cp, _, _ = _overview_plane(group, {})
    out = cp.cluster_overview("prod-cluster")
    assert len(out["shards"]) == controlplane.MAX_OVERVIEW_SHARDS and out["shards_total"] == 60
    assert len(out["findings"]) == controlplane.MAX_OVERVIEW_FINDINGS and out["truncated"] is True
    cp, _, _ = _overview_plane(group, {})
    cp.client("elasticache").responses["describe_replication_groups"] = {"ReplicationGroups": []}
    assert cp.cluster_overview("nope")["error"] == "NotFound"
    assert cp.cluster_overview("x", minutes=0)["error"] == "InvalidArgument"


def test_cluster_overview_only_calls_read_only_apis():
    group = sharded_rg(shards=2)
    cp, ec, cw = _overview_plane(group, _primary_values(group, [20, 21], [40, 41]))
    cp.cluster_overview("prod-cluster")
    for name, _ in ec.calls + cw.calls:
        assert name.startswith(("describe_", "list_", "get_metric_data")), name


async def test_cluster_overview_tool_is_registered_and_read_only():
    async with Client(server.mcp) as c:
        tools = {t.name: t for t in await c.list_tools()}
    assert tools["aws_cluster_overview"].annotations.read_only_hint is True


# ------------------------------------------------- global datastore readiness


def _regional_plane(by_region: dict[str, tuple[Fake, Fake]]) -> ControlPlane:
    class Session:
        def client(self, service, region_name=None, config=None):
            ec, cw = by_region[region_name]
            return {"elasticache": ec, "cloudwatch": cw}[service]

    return ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)


def _global(node_type="cache.r6g.large", version="7.1", secondary_status="associated"):
    return {
        "GlobalReplicationGroups": [
            {
                "GlobalReplicationGroupId": "g-1",
                "Status": "available",
                "CacheNodeType": node_type,
                "EngineVersion": version,
                "Members": [
                    {
                        "ReplicationGroupId": "prim",
                        "ReplicationGroupRegion": REGION,
                        "Role": "PRIMARY",
                        "Status": "associated",
                    },
                    {
                        "ReplicationGroupId": "sec",
                        "ReplicationGroupRegion": "eu-west-1",
                        "Role": "SECONDARY",
                        "Status": secondary_status,
                    },
                ],
            }
        ]
    }


def _global_plane(lag_newest_first: list[float], sec_node_type="cache.r6g.large", sec_version="7.1", **global_kwargs):
    primary = Fake({"describe_global_replication_groups": _global(**global_kwargs)})
    secondary_ec = Fake(
        {
            "describe_replication_groups": {
                "ReplicationGroups": [
                    {"ReplicationGroupId": "sec", "CacheNodeType": sec_node_type, "MemberClusters": ["sec-001"]}
                ]
            },
            "describe_cache_clusters": {"CacheClusters": [{"CacheClusterId": "sec-001", "EngineVersion": sec_version}]},
        }
    )
    secondary_cw = Fake({"get_metric_data": metric_result({"sec-001|GlobalDatastoreReplicationLag": lag_newest_first})})
    cp = _regional_plane({REGION: (primary, Fake()), "eu-west-1": (secondary_ec, secondary_cw)})
    return cp, secondary_cw


@pytest.mark.parametrize(("lag", "severity"), [([0.4, 0.2], None), ([3.0, 0.5], "warning"), ([14.0, 2.0], "critical")])
def test_global_datastore_replication_lag_findings(lag, severity):
    cp, cw = _global_plane(lag)
    out = cp.global_replication_groups()
    lag_findings = [f for f in out["findings"] if "GlobalDatastoreReplicationLag" in f["message"]]
    if severity is None:
        assert lag_findings == []
    else:
        assert [f["severity"] for f in lag_findings] == [severity]
        assert "eu-west-1" in lag_findings[0]["message"]
    member = out["global_replication_groups"][0]["members"][1]
    assert member["replication_lag"]["max"] == max(lag)
    query = cw.calls[0][1]["MetricDataQueries"][0]["MetricStat"]
    assert query["Metric"]["MetricName"] == "GlobalDatastoreReplicationLag"
    assert query["Metric"]["Dimensions"] == [{"Name": "CacheClusterId", "Value": "sec-001"}]


def test_global_datastore_flags_mismatched_secondary_node_type_and_engine_version():
    cp, _ = _global_plane([0.1], sec_node_type="cache.r6g.xlarge", sec_version="6.2")
    msgs = [f["message"] for f in cp.global_replication_groups()["findings"]]
    assert any("node type cache.r6g.xlarge differs from the primary (cache.r6g.large)" in m for m in msgs)
    assert any("engine version 6.2 differs from the primary (7.1)" in m for m in msgs)


def test_global_datastore_matching_secondary_has_no_mismatch_finding():
    cp, _ = _global_plane([0.1])
    assert [f for f in cp.global_replication_groups()["findings"] if "differs" in f["message"]] == []


@pytest.mark.parametrize(
    ("status", "flagged"),
    [("associated", False), ("available", False), ("associating", True), ("disassociated", True)],
)
def test_global_datastore_member_status_findings(status, flagged):
    cp, _ = _global_plane([0.1], secondary_status=status)
    msgs = [f["message"] for f in cp.global_replication_groups()["findings"]]
    assert any(f"member sec (eu-west-1) is {status}" in m for m in msgs) is flagged


def test_global_datastore_unreadable_secondary_degrades_to_info():
    primary = Fake({"describe_global_replication_groups": _global()})
    secondary = (Fake({"describe_replication_groups": denied("x")}), Fake())
    cp = _regional_plane({REGION: (primary, Fake()), "eu-west-1": secondary})
    out = cp.global_replication_groups()
    assert any(
        f["severity"] == "info" and "could not be inspected: AccessDenied" in f["message"] for f in out["findings"]
    )


def test_global_lag_metric_is_in_the_default_metric_sets():
    assert "GlobalDatastoreReplicationLag" in controlplane.REDIS_METRICS
    assert "GlobalDatastoreReplicationLag" in controlplane.TRIAGE_METRICS


# --------------------------------------------- sustained vs spike, p95, trend


def _metrics_for(name: str, chronological: list[float], period: int = 300):
    cw = Fake({"get_metric_data": metric_result({f"n-001|{name}": list(reversed(chronological))})})
    return plane(Fake(), cw).metrics("n-001", [name], minutes=len(chronological) * period // 60, period_seconds=period)


def _finding_for(out: dict, needle: str) -> dict:
    return next(f for f in out["findings"] if needle in f["message"])


def test_sustained_cpu_is_critical_and_says_so():
    out = _metrics_for("EngineCPUUtilization", [95.0] * 12)
    f = _finding_for(out, "EngineCPUUtilization")
    assert f["severity"] == "critical" and "sustained (>=50% of points)" in f["message"]
    assert out["summary"]["EngineCPUUtilization"]["fraction_above_threshold"] == 1.0


def test_sustained_boundary_is_half_of_the_points():
    half = _metrics_for("EngineCPUUtilization", [95.0] * 6 + [10.0] * 6)
    assert _finding_for(half, "EngineCPUUtilization")["severity"] == "critical"
    less = _metrics_for("EngineCPUUtilization", [95.0] * 5 + [10.0] * 7)
    assert _finding_for(less, "EngineCPUUtilization")["severity"] == "info"


@pytest.mark.parametrize(
    ("name", "spike"),
    [("EngineCPUUtilization", 95.0), ("DatabaseMemoryUsagePercentage", 95.0), ("CurrConnections", 60000.0)],
)
def test_single_spike_is_downgraded_to_info(name, spike):
    out = _metrics_for(name, [10.0] * 11 + [spike])
    f = _finding_for(out, name)
    assert f["severity"] == "info" and "transient spike: 1 of 12 points" in f["message"]
    paging = [
        x for x in out["findings"] if x["severity"] in ("warning", "critical") and x.get("category") != "right-sizing"
    ]
    assert not paging  # right-sizing hints are a separate, peak-based check


def test_sustained_connections_and_memory_keep_their_severity():
    conns = _metrics_for("CurrConnections", [60000.0] * 10)
    assert _finding_for(conns, "CurrConnections")["severity"] == "warning"
    mem = _metrics_for("DatabaseMemoryUsagePercentage", [92.0] * 10)
    assert _finding_for(mem, "DatabaseMemoryUsagePercentage")["severity"] == "critical"


def test_summary_has_p95():
    out = _metrics_for("EngineCPUUtilization", [float(v) for v in range(1, 21)])
    assert out["summary"]["EngineCPUUtilization"]["p95"] == 20.0
    flat = _metrics_for("EngineCPUUtilization", [5.0] * 10)
    assert flat["summary"]["EngineCPUUtilization"]["p95"] == 5.0


def test_trend_growing_memory_gives_time_to_full_hint():
    series = [40.0 + 2.0 * i for i in range(12)]  # 5 minutes apart, 40% -> 62%
    out = _metrics_for("DatabaseMemoryUsagePercentage", series)
    trend = out["summary"]["DatabaseMemoryUsagePercentage"]["trend"]
    assert trend["first_quarter_avg"] == pytest.approx(42.0) and trend["last_quarter_avg"] == pytest.approx(60.0)
    # 38 points left at 2 points per datapoint: 19 datapoints of 5 minutes
    assert trend["hours_to_full"] == pytest.approx(19 * 5 / 60, abs=0.1)
    f = _finding_for(out, "is growing")
    assert f["severity"] == "warning" and "reached in about" in f["message"]


def test_trend_slow_growth_is_info_and_flat_or_short_series_have_no_hint():
    slow = _metrics_for("DatabaseMemoryUsagePercentage", [30.0 + 0.1 * i for i in range(28)], period=3600)
    assert _finding_for(slow, "is growing")["severity"] == "info"
    flat = _metrics_for("DatabaseMemoryUsagePercentage", [50.0] * 12)
    assert "hours_to_full" not in flat["summary"]["DatabaseMemoryUsagePercentage"].get("trend", {})
    assert not [f for f in flat["findings"] if "growing" in f["message"]]
    short = _metrics_for("DatabaseMemoryUsagePercentage", [10.0, 50.0, 90.0])
    assert "trend" not in short["summary"]["DatabaseMemoryUsagePercentage"]


# ------------------------------------------------------ tags in the triage tools


def test_triage_tags_surface_ownership_and_flag_missing_tags():
    group = {**rg(), "ARN": "arn:rg"}
    tagged = Fake(
        {
            "describe_replication_groups": {"ReplicationGroups": [group]},
            "list_tags_for_resource": {"TagList": [{"Key": "owner", "Value": "cache-team"}]},
        }
    )
    out = plane(tagged).triage("prod")
    assert out["ownership"] == {"owner": "cache-team"} and out["tags"] == {"owner": "cache-team"}
    assert [c for c in tagged.calls if c[0] == "list_tags_for_resource"] == [
        ("list_tags_for_resource", {"ResourceName": "arn:rg"})
    ]

    untagged = Fake(
        {"describe_replication_groups": {"ReplicationGroups": [group]}, "list_tags_for_resource": {"TagList": []}}
    )
    out = plane(untagged).triage("prod")
    assert any(f.get("category") == "ownership" and f["severity"] == "info" for f in out["findings"])


def test_triage_tags_access_denied_is_a_note_not_a_failure():
    group = {**rg(), "ARN": "arn:rg"}
    ec = Fake({"describe_replication_groups": {"ReplicationGroups": [group]}, "list_tags_for_resource": denied("x")})
    out = plane(ec).triage("prod")
    assert "AccessDenied" in out["tags_note"] and "error" not in out
    assert not [f for f in out["findings"] if f.get("category") == "ownership"]


def test_serverless_triage_tags_use_the_cache_arn():
    cache = {"ServerlessCacheName": "sc", "Status": "available", "ARN": "arn:sc"}
    ec = Fake(
        {
            "describe_serverless_caches": {"ServerlessCaches": [cache]},
            "list_tags_for_resource": {"TagList": [{"Key": "Environment", "Value": "staging"}]},
        }
    )
    out = plane(ec).serverless_triage("sc")
    assert out["ownership"] == {"environment": "staging"}
    assert ("list_tags_for_resource", {"ResourceName": "arn:sc"}) in ec.calls


# --------------------------------------------- ENA network allowance metrics


@pytest.mark.parametrize(
    ("metric", "tag"),
    [
        ("NetworkBandwidthInAllowanceExceeded", "in"),
        ("NetworkBandwidthOutAllowanceExceeded", "out"),
        ("NetworkPacketsPerSecondAllowanceExceeded", "pps"),
        ("NetworkConntrackAllowanceExceeded", "conntrack"),
    ],
)
def test_network_allowance_exceeded_warns_naming_the_limit(metric, tag):
    out = _metrics_for(metric, [0.0, 5.0, 0.0, 7.0])
    hits = [f for f in out["findings"] if metric in f["message"]]
    assert len(hits) == 1
    assert hits[0]["severity"] == "warning"
    assert f"({tag})" in hits[0]["message"] and "12 times" in hits[0]["message"]
    assert "larger node type or more shards/replicas" in hits[0]["message"]
    quiet = _metrics_for(metric, [0.0, 0.0, 0.0, 0.0])
    assert not any(metric in f["message"] for f in quiet["findings"])


def test_network_allowance_metrics_use_sum_and_real_names():
    for name in controlplane.NETWORK_ALLOWANCE_METRICS:
        assert name in controlplane.REDIS_METRICS and name in controlplane.SUM_STAT_METRICS
    assert "FreeableMemory" in controlplane.REDIS_METRICS
    assert "FreeableMemory" in controlplane.MEMCACHED_METRICS


# --------------------------------------------- aws_events findings first


def _ev(source, msg, minutes_ago, source_type="replication-group"):
    return {
        "SourceIdentifier": source,
        "SourceType": source_type,
        "Message": msg,
        "Date": NOW - dt.timedelta(minutes=minutes_ago),
    }


def test_events_failover_is_critical_and_listed_before_info():
    ec = Fake(
        {
            "describe_events": {
                "Events": [
                    _ev("rg1", "Snapshot complete for rg1-001", 1),
                    _ev("rg1", "Failover from primary node rg1-001 to replica node rg1-002 completed", 30),
                    _ev("rg1", "Cache node rg1-003 replacement scheduled during maintenance", 20),
                ]
            }
        }
    )
    out = plane(ec).events("rg1", "replication-group", 6)
    assert [f["severity"] for f in out["findings"]] == ["critical", "warning", "info"]
    assert "Failover" in out["findings"][0]["message"]
    assert out["by_severity"] == {"info": 1, "critical": 1, "warning": 1}
    assert out["by_source"] == {"rg1": 3} and out["truncated"] is False
    assert [c[0] for c in ec.calls] == ["describe_events"]
    assert ec.calls[0][1]["Duration"] == 360 and ec.calls[0][1]["SourceType"] == "replication-group"


@pytest.mark.parametrize(
    ("msg", "sev"),
    [
        ("Snapshot failed for node x", "critical"),
        ("Cache cluster not available", "critical"),
        ("Cache node rebooted", "warning"),
        ("Snapshot complete", "info"),
    ],
)
def test_events_classification(msg, sev):
    out = plane(Fake({"describe_events": {"Events": [_ev("c", msg, 5, "cache-cluster")]}})).events()
    assert out["findings"][0]["severity"] == sev


def test_events_caps_the_raw_list_and_counts_every_source():
    events = [_ev("a" if i % 3 else "b", f"Snapshot complete {i}", i) for i in range(300)]
    out = plane(Fake({"describe_events": {"Events": events}})).events()
    assert out["count"] == 300 and len(out["events"]) == 100 and out["truncated"] is True
    assert sum(out["by_source"].values()) == 300 and out["by_source"] == {"a": 200, "b": 100}
    assert out["events"][0]["Message"] == "Snapshot complete 0"  # newest first
    assert len(out["findings"]) <= controlplane.MAX_EVENT_FINDINGS and out["findings_truncated"] is True


def test_events_invalid_source_type_makes_no_boto_call():
    ec = Fake()
    out = plane(ec).events(source_type="bogus")
    assert out["error"] == "InvalidArgument" and "replication-group" in out["message"]
    assert ec.calls == []


@pytest.mark.parametrize(("hours", "minutes"), [(0, 60), (99999, 14 * 24 * 60)])
def test_events_duration_is_clamped(hours, minutes):
    ec = Fake({"describe_events": {"Events": []}})
    plane(ec).events(hours=hours)
    assert ec.calls[0][1]["Duration"] == minutes


# --------------------------------------------- ACL / auth failure signal


@pytest.mark.parametrize("metric", list(controlplane.AUTH_FAILURE_METRICS))
def test_auth_failure_metrics_are_requested_and_summed(metric):
    assert metric in controlplane.REDIS_METRICS and metric in controlplane.SUM_STAT_METRICS
    cw = Fake({"get_metric_data": metric_result({})})
    plane(Fake(), cw).metrics("n-001", minutes=60, period_seconds=300)
    queries = cw.calls[0][1]["MetricDataQueries"]
    stat = {q["MetricStat"]["Metric"]["MetricName"]: q["MetricStat"]["Stat"] for q in queries}
    assert stat[metric] == "Sum"


@pytest.mark.parametrize("metric", list(controlplane.AUTH_FAILURE_METRICS))
def test_sustained_auth_failures_warn_and_point_at_acl_log(metric):
    out = _metrics_for(metric, [3.0] * 8)
    f = _finding_for(out, metric)
    assert f["severity"] == "warning" and "node_acl_log" in f["message"] and "sustained" in f["message"]


def test_transient_auth_failures_are_info_and_zero_is_silent():
    spike = _metrics_for("AuthenticationFailures", [5.0] + [0.0] * 11)
    assert _finding_for(spike, "AuthenticationFailures")["severity"] == "info"
    quiet = _metrics_for("AuthenticationFailures", [0.0] * 12)
    assert not any("AuthenticationFailures" in f["message"] for f in quiet["findings"])


def _user(uid, name, access, auth="password"):
    return {
        "UserId": uid,
        "UserName": name,
        "Status": "active",
        "Engine": "redis",
        "AccessString": access,
        "Authentication": {"Type": auth},
    }


def _ugroup(gid, user_ids, rgs=()):
    return {
        "UserGroupId": gid,
        "Status": "active",
        "Engine": "redis",
        "UserIds": user_ids,
        "ReplicationGroups": list(rgs),
    }


def _users_out(users, groups):
    return plane(Fake({"describe_users": {"Users": users}, "describe_user_groups": {"UserGroups": groups}})).users()


@pytest.mark.parametrize(
    ("user", "expect"),
    [
        (_user("d", "default", "on ~* +@all", "no-password"), True),
        (_user("d", "default", "on ~* +@all"), True),
        (_user("d", "default", "on ~* -@all +get", "no-password"), True),
        (_user("d", "default", "on ~app:* -@all +get"), False),
        (_user("d", "default", "off ~* +@all", "no-password"), False),
        (_user("a", "app", "on ~* +@all", "no-password"), False),
    ],
)
def test_default_user_attached_to_replication_group_is_critical(user, expect):
    out = _users_out([user], [_ugroup("ug", [user["UserId"]], ["rg-prod"])])
    hits = [f for f in out["findings"] if f["message"].startswith("the default user is active")]
    assert bool(hits) is expect
    if expect:
        assert hits[0]["severity"] == "critical" and hits[0]["replication_groups"] == ["rg-prod"]


def test_default_user_not_attached_to_any_cache_is_not_cross_referenced():
    out = _users_out([_user("d", "default", "on ~* +@all", "no-password")], [_ugroup("ug", ["d"])])
    assert not [f for f in out["findings"] if f["message"].startswith("the default user is active")]


@pytest.mark.parametrize(
    ("access", "rg", "expected"),
    [
        ("on ~app:* +@read +@dangerous", "rg-prod", "warning"),
        ("on ~app:* +@read +flushall", "rg-prod", "warning"),
        ("on ~app:* +@read +config|get", "rg-prod", "info"),
        ("on ~app:* +@read +@dangerous -@dangerous", "rg-prod", None),
        ("on ~app:* +@read +@dangerous", "rg-dev", None),
        ("on ~app:* +@read +get", "rg-prod", None),
    ],
)
def test_dangerous_commands_on_prod_like_group(access, rg, expected):
    out = _users_out([_user("app", "app", access)], [_ugroup("ug", ["app"], [rg])])
    hits = [f for f in out["findings"] if "dangerous commands" in f["message"]]
    assert (hits[0]["severity"] if hits else None) == expected


def test_user_group_with_only_the_default_user_warns():
    users = [_user("d", "default", "off"), _user("app", "app", "on ~* +get")]
    groups = [_ugroup("only-default", ["d"], ["rg"]), _ugroup("ok", ["d", "app"], ["rg"])]
    cp = plane(Fake({"describe_users": {"Users": users}, "describe_user_groups": {"UserGroups": groups}}))
    flagged = {f["resource"] for f in cp.user_groups()["findings"] if "no non-default user" in f["message"]}
    assert flagged == {"only-default"}


def test_acl_findings_use_no_new_aws_actions():
    ec = Fake({"describe_users": {"Users": []}, "describe_user_groups": {"UserGroups": []}})
    cp = plane(ec)
    cp.users()
    cp.user_groups()
    assert {c[0] for c in ec.calls} == {"describe_users", "describe_user_groups"}


# --------------------------------------------- region fan-out for alarms and cluster overview


def _fleet_plane(by_region):
    class Session:
        def client(self, service, region_name=None, config=None):
            ec, cw = by_region[region_name]
            return {"elasticache": ec, "cloudwatch": cw}[service]

    cfg = ControlPlaneConfig(region=REGION, regions=tuple(by_region))
    return ControlPlane(cfg, session_factory=Session, clock=lambda: NOW)


def _alarming_region():
    ec = Fake(
        {
            "describe_replication_groups": {
                "ReplicationGroups": [{"ReplicationGroupId": "a1", "MemberClusters": ["a1-001"]}]
            }
        }
    )
    alarm = {
        "AlarmName": "a1-cpu",
        "Namespace": "AWS/ElastiCache",
        "MetricName": "EngineCPUUtilization",
        "StateValue": "ALARM",
        "ActionsEnabled": True,
        "AlarmActions": ["arn:sns"],
        "Dimensions": [{"Name": "CacheClusterId", "Value": "a1-001"}],
    }
    return ec, Fake({"describe_alarms": {"MetricAlarms": [alarm]}})


def test_alarms_fleet_isolates_a_denied_region_and_tags_findings():
    denied_ec = Fake({"describe_replication_groups": denied("DescribeReplicationGroups")})
    cp = _fleet_plane({REGION: _alarming_region(), "eu-west-1": (denied_ec, Fake())})
    out = cp.alarms_fan_out()
    assert out["region_errors"]["eu-west-1"]["error"] == "AccessDenied"
    assert out["findings"] and all(f["region"] == REGION for f in out["findings"])
    assert any(f["severity"] == "critical" and f.get("alarm") == "a1-cpu" for f in out["findings"])
    assert [a["region"] for a in out["alarms"]] == [REGION]


def test_alarms_with_a_group_id_stays_in_one_region():
    ec, cw = _alarming_region()
    other = Fake()
    cp = _fleet_plane({REGION: (ec, cw), "eu-west-1": (other, Fake())})
    out = cp.alarms_fan_out("a1")
    assert "regions" not in out and other.calls == []


def _overview_region(status="modifying"):
    ec = Fake({"describe_replication_groups": {"ReplicationGroups": [rg(status=status)]}})
    return ec, Fake({"get_metric_data": metric_result({})})


def test_cluster_overview_fleet_merges_regions_and_isolates_errors():
    denied_ec = Fake({"describe_replication_groups": denied("DescribeReplicationGroups")})
    cp = _fleet_plane({REGION: _overview_region(), "eu-west-1": (denied_ec, Fake())})
    out = cp.cluster_overview_fan_out(None)
    assert out["region_errors"]["eu-west-1"]["error"] == "AccessDenied"
    assert [g["region"] for g in out["groups"]] == [REGION] and out["groups"][0]["replication_group_id"] == "prod"
    assert out["findings"] and all(
        f["region"] == REGION and f["replication_group_id"] == "prod" for f in out["findings"]
    )


def test_cluster_overview_fleet_merges_findings_from_two_regions_worst_first():
    cp = _fleet_plane({REGION: _overview_region("available"), "eu-west-1": _overview_region("modifying")})
    out = cp.cluster_overview_fan_out(None)
    assert {g["region"] for g in out["groups"]} == {REGION, "eu-west-1"}
    sevs = [f["severity"] for f in out["findings"]]
    assert sevs == sorted(sevs, key=lambda s: controlplane._SEVERITY_ORDER[s])
    assert {f["region"] for f in out["findings"]} <= {REGION, "eu-west-1"}
    assert any(f["region"] == "eu-west-1" for f in out["findings"])


def test_fleet_stops_when_the_shared_deadline_is_used_up(monkeypatch):
    cp = _fleet_plane({REGION: _overview_region(), "eu-west-1": _overview_region()})
    clock = iter([0.0, 0.0, 0.0] + [1000.0] * 50)
    monkeypatch.setattr(controlplane, "_monotonic", lambda: next(clock))
    out = cp.cluster_overview_fan_out(None)
    assert out["region_errors"]["eu-west-1"]["error"] == "DeadlineExceeded"
    assert [g["region"] for g in out["groups"]] == [REGION]
