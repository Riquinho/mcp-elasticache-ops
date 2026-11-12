"""Round 25: aws_alarms quality rules, each with a positive and a negative case."""

from __future__ import annotations

import pytest

from tests.test_controlplane_findings import Fake, denied, plane

TOPIC = "arn:aws:sns:us-east-1:123456789012:oncall"


def alarm(metric: str = "EngineCPUUtilization", ref: str = "rg1-001", dim: str = "CacheClusterId", **over) -> dict:
    base = {
        "AlarmName": f"{ref}-{metric}",
        "Namespace": "AWS/ElastiCache",
        "MetricName": metric,
        "Dimensions": [{"Name": dim, "Value": ref}],
        "StateValue": "OK",
        "ActionsEnabled": True,
        "AlarmActions": [TOPIC],
        "Threshold": 80.0,
        "ComparisonOperator": "GreaterThanThreshold",
        "Period": 60,
        "EvaluationPeriods": 5,
        "TreatMissingData": "missing",
    }
    return {**base, **over}


def run(*alarms: dict, group: str | None = "rg1") -> dict:
    ec = Fake(
        {
            "describe_replication_groups": {
                "ReplicationGroups": [
                    {"ReplicationGroupId": "rg1", "Engine": "valkey", "MemberClusters": ["rg1-001", "rg1-002"]}
                ]
            },
            "describe_cache_clusters": {
                "CacheClusters": [
                    {"CacheClusterId": "rg1-001", "ReplicationGroupId": "rg1", "Engine": "valkey"},
                    {"CacheClusterId": "rg1-002", "ReplicationGroupId": "rg1", "Engine": "valkey"},
                    {"CacheClusterId": "mc1", "Engine": "memcached"},
                    {"CacheClusterId": "r1", "Engine": "redis"},
                ]
            },
        }
    )
    cw = Fake({"describe_alarms": {"MetricAlarms": list(alarms)}})
    return plane(ec, cw).alarms(group)


def rules(out: dict) -> list[str]:
    return [f["rule"] for f in out["findings"] if f.get("category") == "alarm-quality"]


def test_no_alarm_actions_pages_nobody():
    assert rules(run(alarm(AlarmActions=[]))) == ["no-actions"]
    assert rules(run(alarm())) == []


@pytest.mark.parametrize("metric", ["EngineCPUUtilization", "DatabaseMemoryUsagePercentage"])
def test_not_breaching_missing_data_on_cpu_or_memory(metric):
    assert rules(run(alarm(metric, TreatMissingData="notBreaching"))) == ["missing-data-not-breaching"]
    assert rules(run(alarm(metric, TreatMissingData="breaching"))) == []
    assert rules(run(alarm(metric))) == []


def test_not_breaching_is_fine_for_other_metrics():
    assert rules(run(alarm("Evictions", TreatMissingData="notBreaching", Threshold=1.0))) == []


@pytest.mark.parametrize(
    ("metric", "threshold", "fires"),
    [("EngineCPUUtilization", 98.0, True), ("EngineCPUUtilization", 90.0, False)]
    + [("DatabaseMemoryUsagePercentage", 99.0, True), ("DatabaseMemoryUsagePercentage", 90.0, False)],
)
def test_threshold_that_never_fires_in_time(metric, threshold, fires):
    assert rules(run(alarm(metric, Threshold=threshold))) == (["threshold-never-fires"] if fires else [])


def test_a_low_side_alarm_above_95_is_not_a_never_fires_case():
    assert rules(run(alarm(Threshold=98.0, ComparisonOperator="LessThanThreshold"))) == []


def test_evaluation_window_over_15_minutes_is_slow():
    assert rules(run(alarm(Period=300, EvaluationPeriods=4))) == ["slow-evaluation"]  # 20 minutes
    assert rules(run(alarm(Period=300, EvaluationPeriods=3))) == []  # exactly 15 minutes
    assert rules(run(alarm(Period=None, EvaluationPeriods=None))) == []  # metric-math alarm without Period


def test_host_cpu_alarm_on_a_valkey_or_redis_node():
    assert rules(run(alarm("CPUUtilization"))) == ["host-cpu-instead-of-engine-cpu"]
    assert rules(run(alarm("CPUUtilization", "r1"), group=None)) == ["host-cpu-instead-of-engine-cpu"]
    assert rules(run(alarm("EngineCPUUtilization"))) == []
    assert rules(run(alarm("CPUUtilization", "mc1"), group=None)) == []  # memcached has no engine CPU metric


def test_alarm_dimension_must_name_a_node_or_group():
    wrong = alarm(ref="rg1")  # CacheClusterId=rg1 is the group id, not a node
    assert rules(run(wrong)) == ["wrong-dimension"]
    assert rules(run(alarm(ref="rg1", dim="ReplicationGroupId"))) == []
    assert rules(run(alarm())) == []
    orphan = alarm(Dimensions=[{"Name": "Role", "Value": "Primary"}])
    out = run(orphan, group=None)
    assert "missing-dimension" in rules(out)
    assert "missing-dimension" not in rules(run(alarm(), group=None))


def test_denied_describe_alarms_is_partial_and_runs_no_quality_rule():
    ec = Fake({"describe_replication_groups": {"ReplicationGroups": []}})
    out = plane(ec, Fake({"describe_alarms": denied("DescribeAlarms")})).alarms("rg1")
    assert out["partial"] is True and rules(out) == []
    assert any("DescribeAlarms failed (AccessDenied)" in f["message"] for f in out["findings"])
