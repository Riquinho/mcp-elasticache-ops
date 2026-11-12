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


# ------------------------------------------------------------------ aws_reserved_nodes findings and contract


def _res(rid, node_type, product, count, days_left=300):
    import datetime as dt

    from tests.test_controlplane_findings import NOW

    return {
        "ReservedCacheNodeId": rid,
        "CacheNodeType": node_type,
        "ProductDescription": product,
        "CacheNodeCount": count,
        "State": "active",
        "StartTime": NOW - dt.timedelta(days=365 - days_left),
        "Duration": 365 * 24 * 3600,
    }


def _cl(cid, node_type, engine, n=1, **extra):
    return {"CacheClusterId": cid, "CacheNodeType": node_type, "Engine": engine, "NumCacheNodes": n, **extra}


def _reserved(reservations, clusters):
    ec = Fake(
        {
            "describe_reserved_cache_nodes": {"ReservedCacheNodes": reservations},
            "describe_cache_clusters": {"CacheClusters": clusters},
        }
    )
    return plane(ec).reserved_nodes()


def _by_category(out):
    return {(f["category"], f["resource"]): f for f in out["findings"]}


def test_expiring_reservations_warn_inside_30_days_and_note_inside_90():
    out = _reserved(
        [
            _res("soon", "cache.r6g.large", "redis", 1, days_left=12),
            _res("later", "cache.m6g.large", "redis", 1, days_left=70),
            _res("far", "cache.t4g.small", "redis", 1, days_left=200),
        ],
        [
            _cl("a", "cache.r6g.large", "redis"),
            _cl("b", "cache.m6g.large", "redis"),
            _cl("c", "cache.t4g.small", "redis"),
        ],
    )
    found = _by_category(out)
    assert found[("expiring reservation", "soon")]["severity"] == "warning"
    assert found[("expiring reservation", "later")]["severity"] == "info"
    assert ("expiring reservation", "far") not in found
    assert all(f["next"] and f["category"] and f["resource"] for f in out["findings"])


def test_unmatched_reservation_names_the_mismatch_kind():
    out = _reserved(
        [
            _res("wrong-engine", "cache.r6g.large", "redis", 1),
            _res("wrong-type", "cache.m6g.large", "valkey", 1),
            _res("nothing", "cache.t4g.small", "memcached", 1),
        ],
        [_cl("v", "cache.r6g.large", "valkey"), _cl("w", "cache.r7g.large", "valkey")],
    )
    found = _by_category(out)
    assert found[("unmatched reservation", "cache.r6g.large/redis")]["reason"].startswith("engine mismatch")
    assert found[("unmatched reservation", "cache.m6g.large/valkey")]["reason"].startswith("node type mismatch")
    assert found[("unmatched reservation", "cache.t4g.small/memcached")]["reason"].startswith("no running node")


def test_size_flexibility_covers_smaller_nodes_for_valkey_and_redis_only():
    out = _reserved(
        [_res("big", "cache.r6g.xlarge", "valkey", 1), _res("mc", "cache.r6g.xlarge", "memcached", 1)],
        [_cl("a", "cache.r6g.large", "valkey", 2), _cl("m", "cache.r6g.large", "memcached", 2)],
    )
    assert out["summary"]["covered_nodes"] == 2 and out["summary"]["size_flexible_nodes"] == 2
    assert out["summary"]["uncovered_nodes"] == 2  # memcached is exact-match only
    found = _by_category(out)
    assert ("unmatched reservation", "cache.r6g.xlarge/memcached") in found
    assert ("unmatched reservation", "cache.r6g.xlarge/valkey") not in found


def test_uncovered_nodes_are_reported_as_node_hours_per_month():
    out = _reserved([_res("r", "cache.r6g.large", "redis", 1)], [_cl("a", "cache.r6g.large", "redis", 3)])
    assert out["summary"]["uncovered_nodes"] == 2
    assert out["summary"]["uncovered_node_hours_per_month"] == 2 * 730
    f = _by_category(out)[("uncovered node", "cache.r6g.large/redis")]
    assert f["node_hours_per_month"] == 1460 and f["next"] == "aws_cost_overview"


def test_mixed_region_fleet_fans_out_bounded_and_isolates_a_denied_region():
    from tests.test_controlplane_findings import _fleet_plane, denied

    ok = Fake(
        {
            "describe_reserved_cache_nodes": {"ReservedCacheNodes": [_res("r", "cache.r6g.large", "redis", 1, 10)]},
            "describe_cache_clusters": {"CacheClusters": [_cl("a", "cache.r6g.large", "redis", 2)]},
        }
    )
    bad = Fake({"describe_reserved_cache_nodes": denied("DescribeReservedCacheNodes")})
    cp = _fleet_plane({"us-east-1": (ok, Fake()), "eu-west-1": (bad, Fake())})
    out = cp.reserved_nodes_fan_out()
    assert out["reached"] == "1/2" and out["partial"] is True
    assert out["region_errors"]["eu-west-1"]["error"] == "AccessDenied"
    assert all(f["region"] == "us-east-1" for f in out["findings"])
    assert out["summary"]["covered_nodes"] == 1 and out["summary"]["uncovered_nodes"] == 1
    assert all(op.startswith("describe_") for op, _ in ok.calls + bad.calls)


def test_cost_overview_and_reserved_nodes_never_disagree_on_covered_nodes():
    groups = [_cost_group("a", "cache.r6g.large"), _cost_group("b", "cache.m7g.xlarge")]
    clusters = [
        _cl(m, g["CacheNodeType"], "redis", ReplicationGroupId=g["ReplicationGroupId"], EngineVersion="7.1")
        for g in groups
        for m in g["MemberClusters"]
    ] + [_cl("mc", "cache.m6g.large", "memcached", 2, EngineVersion="1.6")]
    reservations = [_res("r1", "cache.r6g.xlarge", "redis", 1), _res("r2", "cache.m6g.large", "memcached", 1)]
    responses = {
        "describe_replication_groups": {"ReplicationGroups": groups},
        "describe_cache_clusters": {"CacheClusters": clusters},
        "describe_reserved_cache_nodes": {"ReservedCacheNodes": reservations},
    }
    cost = plane(Fake(responses), Fake({"get_metric_data": metric_result({})})).cost_overview()
    reserved = plane(Fake(responses)).reserved_nodes()
    assert cost["reserved_coverage"]["covered_nodes"] == reserved["summary"]["covered_nodes"] == 3
    assert cost["reserved_coverage"]["running_nodes"] == reserved["summary"]["running_nodes"] == 6
    group_covered = sum(g["reserved_nodes_covering"] for g in cost["groups"])
    assert group_covered == 2  # the Memcached reservation covers a node outside any replication group


def _reserved_fleet(node_type: str, reservation_type: str, cpu: float, mem: float, count: int = 2):
    """One replication group of ``node_type`` at a flat load, fully covered by a reservation of ``reservation_type``."""
    group = _cost_group("prod", node_type)
    members = group["MemberClusters"]
    clusters = [_cl(m, node_type, "redis", ReplicationGroupId="prod", EngineVersion="7.1") for m in members]
    reservations = [_res("r1", reservation_type, "redis", count)]
    responses = {
        "describe_replication_groups": {"ReplicationGroups": [group]},
        "describe_cache_clusters": {"CacheClusters": clusters},
        "describe_reserved_cache_nodes": {"ReservedCacheNodes": reservations},
    }
    values: dict[str, list[float]] = {}
    for m in members:
        values[f"{m}|DatabaseMemoryUsagePercentage"] = [mem] * 48
        values[f"{m}|EngineCPUUtilization"] = [cpu] * 48
        values[f"{m}|GetTypeCmds"] = [100.0] * 48
    return plane(Fake(responses), Fake({"get_metric_data": metric_result(values)})).cost_overview()


def test_reserved_idle_group_warns_that_the_reservation_keeps_billing():
    out = _reserved_fleet("cache.r6g.xlarge", "cache.r6g.xlarge", cpu=1.0, mem=4.0)
    idle = next(x for x in out["findings"] if x.get("hint") == "idle")
    assert "cache.r6g.large" in idle["message"]  # the shrink option is still named
    assert "reservation" in idle["message"] and "aws_reserved_nodes" in idle["message"]
    assert "2 of 2 cache.r6g.xlarge node(s) are under a reservation" in idle["message"]


def test_reserved_oversized_group_mentions_the_reservation_before_downsizing():
    out = _reserved_fleet("cache.r6g.xlarge", "cache.r6g.xlarge", cpu=20.0, mem=18.0)
    f = next(x for x in out["findings"] if x.get("hint") == "oversized")
    assert "cache.r6g.large" in f["message"] and f["suggested_node_type"] == "cache.r6g.large"
    assert "reservation" in f["message"] and "aws_reserved_nodes" in f["message"]


def test_reserved_group_with_no_matching_reservation_gets_no_reservation_note():
    out = _reserved_fleet("cache.r6g.xlarge", "cache.m6g.large", cpu=1.0, mem=4.0)
    idle = next(x for x in out["findings"] if x.get("hint") == "idle")
    assert "reservation" not in idle["message"]


def test_covered_count_contract_breaks_if_the_tools_use_different_matching():
    from mcp_elasticache_ops.controlplane.cost_rules import cluster_nodes, plan_coverage

    nodes = cluster_nodes([_cl("a", "cache.r6g.large", "redis", 2)])
    flex = plan_coverage([_res("r", "cache.r6g.xlarge", "redis", 1)], nodes)
    assert len(flex["covered"]) == 2  # exact-only matching would report 0: the shared plan is what keeps them equal


@pytest.mark.parametrize(
    ("days_left", "severity"),
    [(30, "info"), (60, "info"), (29, "warning"), (89, "info")],
)
def test_expiry_boundaries_at_30_and_90_days(days_left, severity):
    out = _reserved(
        [_res("edge", "cache.r6g.large", "redis", 1, days_left=days_left)], [_cl("a", "cache.r6g.large", "redis")]
    )
    found = _by_category(out)
    assert found[("expiring reservation", "edge")]["severity"] == severity


def test_reservation_ending_in_exactly_90_days_is_not_reported():
    out = _reserved(
        [_res("ninety", "cache.r6g.large", "redis", 1, days_left=90)], [_cl("a", "cache.r6g.large", "redis")]
    )
    assert ("expiring reservation", "ninety") not in _by_category(out)


def test_uncovered_node_type_is_reported_even_when_another_type_is_reserved():
    out = _reserved(
        [_res("r", "cache.r6g.large", "redis", 1)],
        [_cl("a", "cache.r6g.large", "redis"), _cl("b", "cache.m6g.xlarge", "redis", 2)],
    )
    found = _by_category(out)
    assert found[("uncovered node", "cache.m6g.xlarge/redis")]["node_hours_per_month"] == 2 * 730
    assert ("uncovered node", "cache.r6g.large/redis") not in found
    assert out["summary"]["uncovered_nodes"] == 2
