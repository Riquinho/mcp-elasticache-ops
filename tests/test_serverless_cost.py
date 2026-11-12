"""Serverless right-sizing in aws_cost_overview: idle, near-limit and over-limit caches, plus the cost hint."""

from __future__ import annotations

import pytest

from mcp_elasticache_ops.controlplane._core import _summarize
from mcp_elasticache_ops.controlplane.cost_rules import _cost_serverless, _serverless_billed_floor_gb
from tests.test_controlplane_findings import (  # noqa: F401  (fake_aws_env is an autouse fixture)
    Fake,
    _cost_ec,
    fake_aws_env,
    metric_result,
    plane,
)

GB = 1024**3


def _cache(name="sc", engine="valkey", ecpu_max=10_000, storage_max=10, **limits):
    return {
        "ServerlessCacheName": name,
        "Engine": engine,
        "Status": "available",
        "CacheUsageLimits": {
            "ECPUPerSecond": {"Maximum": ecpu_max},
            "DataStorage": {"Maximum": storage_max, "Unit": "GB"},
            **limits,
        },
    }


def _summary(ecpu_per_s: list[float], used_gb: list[float]):
    """Hourly points as GetMetricData returns them: ECPU summed per hour, bytes as a gauge."""
    return {
        "ElastiCacheProcessingUnits": _summarize([v * 3600 for v in ecpu_per_s]),
        "BytesUsedForCache": _summarize([v * GB for v in used_gb]),
    }


def _hints(findings):
    return {f.get("hint") or f.get("category") for f in findings}


def test_idle_cache_is_flagged_with_the_engine_minimum_in_gb_hours():
    row, found = _cost_serverless(_cache(), _summary([0.0] * 48, [0.01] * 48))
    idle = next(f for f in found if f.get("hint") == "idle")
    assert row["idle"] is True and idle["billed_floor_gb"] == 0.1 and "73 GB-hours" in idle["message"]
    assert idle["severity"] == "warning" and "14 days" in idle["message"]


@pytest.mark.parametrize(("engine", "floor"), [("valkey", 0.1), ("redis", 1.0), ("memcached", 1.0), (None, 1.0)])
def test_billed_floor_per_engine(engine, floor):
    assert _serverless_billed_floor_gb({"Engine": engine}) == floor


def test_configured_storage_minimum_raises_the_billed_floor():
    cache = _cache(DataStorage={"Maximum": 10, "Minimum": 2, "Unit": "GB"})
    assert _serverless_billed_floor_gb(cache) == 2.0
    tb = _cache(DataStorage={"Maximum": 2, "Minimum": 1, "Unit": "TB"})
    assert _serverless_billed_floor_gb(tb) == 1024.0


def test_cache_with_no_datapoints_is_not_called_idle():
    row, found = _cost_serverless(_cache(), {})
    assert row["idle"] is False and "idle" not in _hints(found)


def test_cache_with_any_traffic_is_not_idle():
    row, found = _cost_serverless(_cache(), _summary([0.0] * 47 + [5.0], [1.0] * 48))
    assert row["idle"] is False and "idle" not in _hints(found)


def test_ecpu_near_limit_recommends_a_higher_maximum():
    row, found = _cost_serverless(_cache(ecpu_max=10_000), _summary([9_000.0] * 48, [1.0] * 48))
    f = next(f for f in found if f["category"] == "serverless-limits")
    assert f["severity"] == "warning" and "ECPUPerSecond" in f["message"]
    assert f["recommendation"]["ecpu_per_second_max"] > 10_000
    assert row["ecpu_p95_pct"] == 90.0


def test_ecpu_at_the_limit_is_critical():
    _, found = _cost_serverless(_cache(ecpu_max=10_000), _summary([10_000.0] * 48, [1.0] * 48))
    assert any(f["severity"] == "critical" and "throttled" in f["message"] for f in found)


def test_storage_over_limit_is_critical_and_names_the_peak():
    row, found = _cost_serverless(_cache(storage_max=10), _summary([100.0] * 48, [9.5] * 48))
    f = next(f for f in found if "DataStorage maximum" in f["message"])
    assert f["severity"] == "critical" and f["recommendation"]["data_storage_max"] > 10
    assert row["data_storage_p95_pct"] == 95.0


def test_comfortable_cache_has_no_findings_and_overprovisioned_ecpu_is_info():
    _, found = _cost_serverless(_cache(ecpu_max=10_000), _summary([2_000.0] * 48, [1.0] * 48))
    assert found == []
    _, over = _cost_serverless(_cache(ecpu_max=100_000), _summary([500.0] * 48, [1.0] * 48))
    assert [f["severity"] for f in over] == ["info"] and "over-provisioned" in over[0]["message"]


def test_unused_minimums_are_reported_as_cost():
    cache = _cache(ECPUPerSecond={"Maximum": 10_000, "Minimum": 5_000})
    _, found = _cost_serverless(cache, _summary([100.0] * 48, [1.0] * 48))
    assert any("minimum is set but unused" in f["message"] for f in found)


# --- through aws_cost_overview, one GetMetricData call for all serverless caches --------------------------------


def test_cost_overview_makes_a_single_serverless_metric_call_and_reports_the_idle_cache():
    ec = _cost_ec()
    ec.responses["describe_serverless_caches"] = {
        "ServerlessCaches": [_cache("idle-sc"), _cache("busy-sc", ecpu_max=10_000)]
    }
    values = {
        "idle-sc|ElastiCacheProcessingUnits": [0.0] * 48,
        "idle-sc|BytesUsedForCache": [1e6] * 48,
        "busy-sc|ElastiCacheProcessingUnits": [9_500.0 * 3600] * 48,
        "busy-sc|BytesUsedForCache": [GB] * 48,
    }
    cw = Fake({"get_metric_data": metric_result(values)})
    out = plane(ec, cw).cost_overview()
    rows = {r["id"]: r for r in out["serverless"]}
    assert rows["idle-sc"]["idle"] is True and rows["busy-sc"]["idle"] is False
    assert rows["busy-sc"]["ecpu_p95_pct"] == 95.0
    hits = {(f.get("resource"), f.get("hint")) for f in out["findings"]}
    assert ("idle-sc", "idle") in hits
    serverless_calls = [
        c for c in cw.calls if any("sc" in q["Label"] for q in c[1]["MetricDataQueries"] if "Label" in q)
    ]
    assert len(serverless_calls) == 1
