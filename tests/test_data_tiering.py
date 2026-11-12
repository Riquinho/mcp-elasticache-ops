"""Round 25: DatabaseCapacityUsagePercentage for data-tiering (r6gd) groups, requested for tiered groups only."""

from __future__ import annotations

from tests.test_controlplane_findings import Fake, _cost_group, metric_result, plane, rg

CAP = "DatabaseCapacityUsagePercentage"


def _requested(cw: Fake) -> list[str]:
    return [
        q["MetricStat"]["Metric"]["MetricName"]
        for name, kw in cw.calls
        if name == "get_metric_data"
        for q in kw["MetricDataQueries"]
    ]


def _tiered_group(gid: str = "prod", tiering: str | None = "enabled") -> dict:
    g = rg()
    g.update({"ReplicationGroupId": gid, "CacheNodeType": "cache.r6gd.xlarge"})
    if tiering is not None:
        g["DataTiering"] = tiering
    g["MemberClusters"] = ["prod-001", "prod-002"]
    return g


def _ec(group: dict) -> Fake:
    return Fake(
        {
            "describe_replication_groups": {"ReplicationGroups": [group]},
            "describe_events": {"Events": []},
            "describe_update_actions": {"UpdateActions": []},
            "describe_snapshots": {"Snapshots": []},
        }
    )


def test_metrics_flags_capacity_92_percent_for_a_tiered_group():
    cw = Fake({"get_metric_data": metric_result({f"prod-001|{CAP}": [91.0, 92.0, 92.0]})})
    out = plane(_ec(_tiered_group()), cw).metrics(replication_group_id="prod")
    hits = [f for f in out["findings"] if CAP in f["message"] and "above 90%" in f["message"]]
    assert [f["severity"] for f in hits] == ["critical"]
    assert hits[0]["resource"] == "prod-001"
    assert set(_requested(cw)) >= {CAP, "DatabaseMemoryUsagePercentage"}
    assert len([c for c in cw.calls if c[0] == "get_metric_data"]) == 1  # still one GetMetricData call


def test_metrics_capacity_between_80_and_90_is_a_warning():
    cw = Fake({"get_metric_data": metric_result({f"prod-001|{CAP}": [84.0, 85.0]})})
    out = plane(_ec(_tiered_group()), cw).metrics(replication_group_id="prod")
    hits = [f for f in out["findings"] if CAP in f["message"]]
    assert [f["severity"] for f in hits] == ["warning"] and "above 80%" in hits[0]["message"]


def test_low_memory_percentage_with_high_capacity_says_memory_is_misleading():
    cw = Fake(
        {
            "get_metric_data": metric_result(
                {f"prod-001|{CAP}": [88.0, 89.0], "prod-001|DatabaseMemoryUsagePercentage": [30.0, 31.0]}
            )
        }
    )
    out = plane(_ec(_tiered_group()), cw).metrics(replication_group_id="prod")
    assert any("understates" in f["message"] and f["category"] == "data-tiering" for f in out["findings"])


def test_healthy_capacity_has_no_capacity_finding():
    cw = Fake({"get_metric_data": metric_result({f"prod-001|{CAP}": [40.0, 41.0]})})
    out = plane(_ec(_tiered_group()), cw).metrics(replication_group_id="prod")
    assert not any(CAP in f["message"] for f in out["findings"])


def test_no_capacity_metric_is_requested_for_a_non_tiered_group():
    for tiering in (None, "disabled"):
        cw = Fake({"get_metric_data": metric_result({})})
        plane(_ec(_tiered_group(tiering=tiering)), cw).metrics(replication_group_id="prod")
        assert CAP not in _requested(cw), tiering


def test_triage_requests_capacity_for_tiered_groups_and_flags_it():
    cw = Fake({"get_metric_data": metric_result({f"prod-002|{CAP}": [93.0, 94.0]})})
    out = plane(_ec(_tiered_group()), cw).triage("prod")
    assert CAP in _requested(cw)
    assert any(CAP in f["message"] and f["severity"] == "critical" for f in out["findings"])
    cw = Fake({"get_metric_data": metric_result({})})
    plane(_ec(_tiered_group(tiering="disabled")), cw).triage("prod")
    assert CAP not in _requested(cw)


def _forecast_ec(tiered: bool) -> Fake:
    groups = [_cost_group("tier", "cache.r6gd.xlarge"), _cost_group("plain", "cache.r6g.xlarge")]
    groups[0]["DataTiering"] = "enabled" if tiered else "disabled"
    clusters = [
        {"CacheClusterId": m, "ReplicationGroupId": g["ReplicationGroupId"], "Engine": "valkey"}
        for g in groups
        for m in g["MemberClusters"]
    ]
    return Fake(
        {
            "describe_replication_groups": {"ReplicationGroups": groups},
            "describe_cache_clusters": {"CacheClusters": clusters},
            "describe_serverless_caches": {"ServerlessCaches": []},
        }
    )


def test_capacity_forecast_uses_capacity_for_tiered_groups_only_in_one_batch():
    n = 336
    ramp = [30 + 60 * i / (n - 1) for i in range(n)][::-1]
    cw = Fake(
        {
            "get_metric_data": metric_result(
                {
                    f"tier-001|{CAP}": ramp,
                    "tier-001|DatabaseMemoryUsagePercentage": [20.0] * n,
                    "plain-001|DatabaseMemoryUsagePercentage": [20.0] * n,
                }
            )
        }
    )
    out = plane(_forecast_ec(True), cw).capacity_forecast()
    by_id = {r["id"]: r for r in out["forecast"]}
    assert by_id["tier"]["metric"] == CAP and by_id["tier"]["status"] == "growing"
    assert "metric" not in by_id["plain"] and by_id["plain"]["status"] == "stable"
    assert any("capacity (memory plus SSD)" in f["message"] for f in out["findings"])
    requested = {(q["Label"]) for name, kw in cw.calls if name == "get_metric_data" for q in kw["MetricDataQueries"]}
    assert {x for x in requested if x.endswith(CAP)} == {"tier-001|" + CAP, "tier-002|" + CAP}
    assert len([c for c in cw.calls if c[0] == "get_metric_data"]) == 1


def test_capacity_forecast_requests_no_capacity_metric_without_tiering():
    cw = Fake({"get_metric_data": metric_result({})})
    plane(_forecast_ec(False), cw).capacity_forecast()
    assert CAP not in _requested(cw)
