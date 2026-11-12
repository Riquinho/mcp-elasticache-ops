"""aws_cost_overview right-sizing: idle groups, over-provisioned groups and the smaller node type named."""

from __future__ import annotations

import json

import pytest

from mcp_elasticache_ops.controlplane.cost_rules import smaller_node_type
from tests.test_controlplane_findings import (  # noqa: F401  (fake_aws_env is an autouse fixture)
    Fake,
    _cost_ec,
    _cost_group,
    fake_aws_env,
    metric_result,
    plane,
)


def _fleet(groups: dict[str, str], cpu: float, mem: float):
    """Cost fixture with the given groups ({id: node type}) all at the same flat load."""
    ec = _cost_ec()
    gs = [_cost_group(gid, nt) for gid, nt in groups.items()]
    ec.responses["describe_replication_groups"] = {"ReplicationGroups": gs}
    ec.responses["describe_cache_clusters"] = {
        "CacheClusters": [
            {
                "CacheClusterId": m,
                "ReplicationGroupId": g["ReplicationGroupId"],
                "Engine": "redis",
                "EngineVersion": "7.1",
            }
            for g in gs
            for m in g["MemberClusters"]
        ]
    }
    values: dict[str, list[float]] = {}
    for g in gs:
        for m in g["MemberClusters"]:
            values[f"{m}|DatabaseMemoryUsagePercentage"] = [mem] * 48
            values[f"{m}|EngineCPUUtilization"] = [cpu] * 48
            values[f"{m}|GetTypeCmds"] = [100.0] * 48
    return ec, Fake({"get_metric_data": metric_result(values)})


@pytest.mark.parametrize(
    ("node_type", "expected"),
    [
        ("cache.r6g.xlarge", "cache.r6g.large"),
        ("cache.r7g.2xlarge", "cache.r7g.xlarge"),
        ("cache.m5.large", None),
        ("cache.t4g.medium", "cache.t4g.small"),
        ("cache.t4g.micro", None),
        ("db.r6g.large", None),
        (None, None),
    ],
)
def test_smaller_node_type_stays_in_family(node_type, expected):
    assert smaller_node_type(node_type) == expected


def test_overprovisioned_group_names_a_smaller_node_type():
    ec, cw = _fleet({"prod": "cache.r6g.xlarge"}, cpu=20.0, mem=18.0)
    out = plane(ec, cw).cost_overview()
    f = next(x for x in out["findings"] if x.get("hint") == "oversized")
    assert "cache.r6g.large" in f["message"] and f["suggested_node_type"] == "cache.r6g.large"
    assert out["groups"][0]["suggested_node_type"] == "cache.r6g.large"
    assert not [x for x in out["findings"] if x.get("hint") == "idle"]


def test_idle_group_is_a_warning_with_a_shrink_option():
    ec, cw = _fleet({"ghost": "cache.r6g.xlarge"}, cpu=1.0, mem=4.0)
    out = plane(ec, cw).cost_overview()
    idle = next(x for x in out["findings"] if x.get("hint") == "idle")
    assert idle["severity"] == "warning" and idle["resource"] == "ghost"
    assert "looks idle" in idle["message"] and "cache.r6g.large" in idle["message"]
    assert not [x for x in out["findings"] if x.get("hint") == "oversized"]  # idle replaces it, no double report


def test_busy_group_gets_no_rightsizing_finding():
    ec, cw = _fleet({"busy": "cache.r6g.xlarge"}, cpu=40.0, mem=70.0)
    out = plane(ec, cw).cost_overview()
    assert not [x for x in out["findings"] if x.get("hint") in {"idle", "oversized"}]
    assert out["groups"][0]["suggested_node_type"] is None


def test_smallest_size_of_a_family_says_so_instead_of_inventing_a_type():
    ec, cw = _fleet({"small": "cache.m5.large"}, cpu=20.0, mem=18.0)
    out = plane(ec, cw).cost_overview()
    f = next(x for x in out["findings"] if x.get("hint") == "oversized")
    assert "smallest size of its family" in f["message"] and f["suggested_node_type"] is None


def test_savings_notes_are_not_repeated_per_group_and_output_stays_capped():
    groups = {f"g{i}": "cache.m5.2xlarge" for i in range(6)}
    ec, cw = _fleet(groups, cpu=20.0, mem=15.0)
    out = plane(ec, cw).cost_overview()
    valkey = [x for x in out["findings"] if "Valkey" in x["message"]]
    assert len(valkey) <= 1
    assert len(out["findings"]) <= 40
    assert len(json.dumps(out)) < 20_000
    sev = [x["severity"] for x in out["findings"]]
    assert sev == sorted(sev, key={"critical": 0, "warning": 1, "info": 2}.get)  # findings-first, worst first
    assert next(iter(out)) in {"window_days", "findings"}
