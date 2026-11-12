"""Round 25: aws_shard_balance names outlier members (hot primary, lagging replica) and bounds its member read."""

from __future__ import annotations

from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane
from mcp_elasticache_ops.controlplane.triage_shards import MAX_LAG_OUTLIERS, MAX_SHARD_MEMBERS
from tests.test_controlplane_tools import NOW, REGION, _CountingCW, _Recorder, _sharded_rg


def _plane(n: int, values: dict[str, list[float]]) -> tuple[ControlPlane, _CountingCW]:
    cw = _CountingCW(values)
    ec = _Recorder({"describe_replication_groups": {"ReplicationGroups": [_sharded_rg(n)]}})

    class Session:
        def client(self, service, region_name=None, config=None):
            return {"elasticache": ec, "cloudwatch": cw}[service]

    return ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW), cw


def _six_shards(cpu: dict[int, float] | None = None, lag: dict[int, float] | None = None) -> dict:
    values: dict[str, list[float]] = {}
    for i in range(1, 7):
        values[f"rg1-000{i}-001|EngineCPUUtilization"] = [(cpu or {}).get(i, 20.0)] * 3
        values[f"rg1-000{i}-001|DatabaseMemoryUsagePercentage"] = [40.0] * 3
        values[f"rg1-000{i}-002|ReplicationLag"] = [(lag or {}).get(i, 0.1)] * 3
    return values


def test_one_member_at_cpu_90_against_a_median_of_20_is_named():
    out = _plane(6, _six_shards(cpu={1: 90.0}))[0].shard_balance("rg1")
    named = [f for f in out["findings"] if "rg1-0001-001" in f["message"]]
    assert named and named[0]["category"] == "hot-shard"
    assert out["median"]["cpu_avg"] == 20.0


def test_a_lagging_replica_is_reported_as_an_outlier_naming_the_member():
    out = _plane(6, _six_shards(lag={4: 14.0}))[0].shard_balance("rg1")
    lag = [f for f in out["findings"] if f["category"] == "replica-lag-outlier"]
    assert len(lag) == 1 and lag[0]["resource"] == "rg1-0004-002" and lag[0]["severity"] == "critical"
    assert "median of 0.1s" in lag[0]["message"]


def test_lag_outliers_are_capped_at_three_worst_first():
    lag = {i: 5.0 + i for i in range(1, 5)}  # four lagging replicas, six healthy ones: the median stays low
    values = _six_shards(lag=lag)
    for i in range(7, 11):
        values[f"rg1-000{i}-001|EngineCPUUtilization"] = [20.0]
        values[f"rg1-000{i}-002|ReplicationLag"] = [0.1]
    out = _plane(10, values)[0].shard_balance("rg1")
    found = [f["resource"] for f in out["findings"] if f["category"] == "replica-lag-outlier"]
    assert len(found) == MAX_LAG_OUTLIERS == 3
    assert found == ["rg1-0004-002", "rg1-0003-002", "rg1-0002-002"]


def test_even_replica_lag_has_no_outlier_and_small_lag_is_ignored():
    for lag in ({}, {2: 0.9}):  # 0.9s is 9x the median but under the 1s floor
        out = _plane(6, _six_shards(lag=lag))[0].shard_balance("rg1")
        assert not [f for f in out["findings"] if f["category"] == "replica-lag-outlier"], lag


def test_member_read_is_capped_with_a_truncated_note():
    shards = MAX_SHARD_MEMBERS // 2 + 5  # two members per shard
    cp, cw = _plane(shards, {})
    out = cp.shard_balance("rg1")
    assert cw.metric_calls == MAX_SHARD_MEMBERS
    assert any(
        f"metrics cover {MAX_SHARD_MEMBERS} of {shards * 2} members (primaries first)" in n for n in out["notes"]
    )
    assert out["shards_total"] == shards
