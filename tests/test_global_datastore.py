"""aws_global_datastore_failover_readiness: one verdict per global datastore, findings first, worst first.

Uses the same canned Describe and CloudWatch responses as the global datastore tests in test_controlplane_findings.
"""

from __future__ import annotations

import pytest

from mcp_elasticache_ops import server
from mcp_elasticache_ops.controlplane.inventory import _datastore_readiness
from tests.test_controlplane_findings import REGION, Fake, _global, _regional_plane, denied, metric_result

SECONDARY_REGION = "eu-west-1"


def _plane(lag=(0.2,), sec_node_type="cache.r6g.large", sec_version="7.1", sec_status="associated", groups=None):
    primary = Fake(
        {"describe_global_replication_groups": groups if groups is not None else _global(secondary_status=sec_status)}
    )
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
    secondary_cw = Fake({"get_metric_data": metric_result({"sec-001|GlobalDatastoreReplicationLag": list(lag)})})
    return _regional_plane({REGION: (primary, Fake()), SECONDARY_REGION: (secondary_ec, secondary_cw)})


def _only(out: dict) -> dict:
    assert out["count"] == 1 and len(out["datastores"]) == 1, out
    return out["datastores"][0]


def test_healthy_datastore_is_ready_with_no_reasons_and_no_warnings():
    out = _plane(lag=(0.2, 0.1)).global_datastore_failover_readiness()
    ds = _only(out)
    assert ds["readiness"] == "ready" and ds["reasons"] == []
    assert ds["primary_region"] == REGION and ds["engine_version"] == "7.1" and ds["node_type"] == "cache.r6g.large"
    assert ds["secondaries"] == [
        {
            "replication_group_id": "sec",
            "region": SECONDARY_REGION,
            "status": "associated",
            "node_type": "cache.r6g.large",
            "engine_version": "7.1",
            "replication_lag_max": 0.2,
        }
    ]
    assert [f for f in out["findings"] if f["severity"] in ("warning", "critical")] == []


def test_lagging_secondary_needs_attention_and_names_the_lag():
    out = _plane(lag=(3.0, 0.5)).global_datastore_failover_readiness()
    ds = _only(out)
    assert ds["readiness"] == "attention"
    assert any("replication lag 3.0 s is above 1 s" in r for r in ds["reasons"])
    assert [f["severity"] for f in out["findings"] if "GlobalDatastoreReplicationLag" in f["message"]] == ["warning"]


def test_critical_lag_blocks_failover():
    ds = _only(_plane(lag=(14.0, 2.0)).global_datastore_failover_readiness())
    assert ds["readiness"] == "blocked"
    assert any("replication lag 14.0 s is above 10 s" in r for r in ds["reasons"])


def test_mismatched_engine_version_needs_attention():
    out = _plane(sec_version="6.2").global_datastore_failover_readiness()
    ds = _only(out)
    assert ds["readiness"] == "attention"
    assert "engine version 6.2 differs from the primary (7.1)" in " ".join(ds["reasons"])


def test_mismatched_node_type_needs_attention():
    ds = _only(_plane(sec_node_type="cache.r6g.xlarge").global_datastore_failover_readiness())
    assert ds["readiness"] == "attention"
    assert "node type cache.r6g.xlarge differs from the primary (cache.r6g.large)" in " ".join(ds["reasons"])


@pytest.mark.parametrize("status", ["associating", "disassociated"])
def test_secondary_not_associated_blocks_failover(status):
    ds = _only(_plane(sec_status=status).global_datastore_failover_readiness())
    assert ds["readiness"] == "blocked"
    assert f"{SECONDARY_REGION}" in " ".join(ds["reasons"]) and status in " ".join(ds["reasons"])


def test_datastore_without_secondary_is_blocked():
    groups = {
        "GlobalReplicationGroups": [
            {
                "GlobalReplicationGroupId": "g-1",
                "Status": "available",
                "CacheNodeType": "cache.r6g.large",
                "EngineVersion": "7.1",
                "Members": [
                    {
                        "ReplicationGroupId": "prim",
                        "ReplicationGroupRegion": REGION,
                        "Role": "PRIMARY",
                        "Status": "associated",
                    }
                ],
            }
        ]
    }
    ds = _only(_plane(groups=groups).global_datastore_failover_readiness())
    assert ds["readiness"] == "blocked" and "no secondary region" in ds["reasons"]


def test_worst_datastore_is_listed_first():
    groups = {
        "GlobalReplicationGroups": [
            _global()["GlobalReplicationGroups"][0] | {"GlobalReplicationGroupId": "g-ready"},
            _global(secondary_status="disassociated")["GlobalReplicationGroups"][0]
            | {"GlobalReplicationGroupId": "g-bad"},
        ]
    }
    out = _plane(groups=groups).global_datastore_failover_readiness()
    assert [d["id"] for d in out["datastores"]] == ["g-bad", "g-ready"]
    assert [d["readiness"] for d in out["datastores"]] == ["blocked", "ready"]


def test_findings_come_before_datastores_in_the_output():
    out = _plane(lag=(14.0,)).global_datastore_failover_readiness()
    assert list(out)[:3] == ["count", "findings", "datastores"]
    assert out["findings"][0]["severity"] in ("warning", "critical")


def test_empty_fleet_reports_no_datastores_as_info():
    groups = {"GlobalReplicationGroups": []}
    out = _plane(groups=groups).global_datastore_failover_readiness()
    assert out["count"] == 0 and out["datastores"] == []
    assert out["findings"] == [{"severity": "info", "message": "no global datastores in this region"}]


def test_describe_denied_returns_the_error_result_not_a_verdict():
    primary = Fake({"describe_global_replication_groups": denied("DescribeGlobalReplicationGroups")})
    cp = _regional_plane({REGION: (primary, Fake())})
    out = cp.global_datastore_failover_readiness()
    assert "datastores" not in out and out.get("error") == "AccessDenied"


def test_unreadable_secondary_keeps_a_ready_verdict_with_info_finding():
    primary = Fake({"describe_global_replication_groups": _global()})
    secondary = (Fake({"describe_replication_groups": denied("DescribeReplicationGroups")}), Fake())
    cp = _regional_plane({REGION: (primary, Fake()), SECONDARY_REGION: secondary})
    out = cp.global_datastore_failover_readiness()
    assert _only(out)["readiness"] == "ready"
    assert any(f["severity"] == "info" and "could not be inspected" in f["message"] for f in out["findings"])


def test_verdict_helper_ignores_unread_secondaries():
    view = {
        "id": "g",
        "status": "available",
        "node_type": "cache.r6g.large",
        "engine_version": "7.1",
        "members": [{"role": "SECONDARY", "replication_group_id": "s", "region": SECONDARY_REGION, "status": None}],
    }
    assert _datastore_readiness(view)["readiness"] == "ready"


def test_tool_is_registered_as_a_read_tool():
    import asyncio

    from fastmcp import Client

    async def names():
        async with Client(server.mcp) as c:
            return [t.name for t in await c.list_tools()]

    assert "aws_global_datastore_failover_readiness" in asyncio.run(names())
