"""Alarm quality rules for aws_alarms: judged from the DescribeAlarms rows already fetched, no extra calls."""

from __future__ import annotations

from typing import Any

from ._shared import finding

# Alarms on these must page when data stops: missing data treated as "not breaching" hides a dead node.
MISSING_DATA_SENSITIVE = (
    "EngineCPUUtilization",
    "CPUUtilization",
    "DatabaseMemoryUsagePercentage",
    "DatabaseCapacityUsagePercentage",
)

# Threshold above which the alarm cannot fire in time (the engine is already saturated or failing writes).
NEVER_FIRES_ABOVE = {"EngineCPUUtilization": 95.0, "DatabaseMemoryUsagePercentage": 95.0}

SLOW_ALARM_SECONDS = 15 * 60  # EvaluationPeriods * Period above this: the page arrives late

_UPPER = {"GreaterThanThreshold", "GreaterThanOrEqualToThreshold"}


def alarm_quality_findings(alarm: dict, dims: dict[str, Any], target: dict | None) -> list[dict]:
    """Quality findings for one ElastiCache metric alarm.

    ``target`` is the alarm target the alarm refers to (``kind``, ``engine``, ``id``, ``members``) or ``None``
    when it names a resource outside the scanned scope; the engine and dimension rules need it."""
    name = str(alarm.get("AlarmName"))
    metric = str(alarm.get("MetricName") or "")
    ref = dims.get("CacheClusterId") or dims.get("ReplicationGroupId") or dims.get("clusterId")
    out: list[dict] = []

    def add(severity: str, message: str, rule: str) -> None:
        out.append(finding(severity, message, resource=ref, alarm=name, category="alarm-quality", rule=rule))

    if not alarm.get("AlarmActions"):
        add("warning", f"alarm {name} has no AlarmActions: nobody is paged when it fires", "no-actions")
    if metric in MISSING_DATA_SENSITIVE and alarm.get("TreatMissingData") == "notBreaching":
        add(
            "warning",
            f"alarm {name} on {metric} treats missing data as notBreaching: a node that stops reporting looks "
            "healthy; use missing or breaching",
            "missing-data-not-breaching",
        )
    threshold = alarm.get("Threshold")
    limit = NEVER_FIRES_ABOVE.get(metric)
    if limit is not None and threshold is not None and threshold > limit and alarm.get("ComparisonOperator") in _UPPER:
        why = (
            "the core is saturated long before"
            if metric == "EngineCPUUtilization"
            else "with a noeviction policy writes already fail before this, and with an eviction policy keys are "
            "already being dropped"
        )
        add(
            "warning",
            f"alarm {name} threshold {threshold:g} on {metric} is above {limit:g}: it fires too late to act "
            f"({why}); alarm at 80 to 90",
            "threshold-never-fires",
        )
    period, evaluations = alarm.get("Period"), alarm.get("EvaluationPeriods")
    if period and evaluations and period * evaluations > SLOW_ALARM_SECONDS:
        minutes = period * evaluations / 60
        add(
            "info",
            f"alarm {name} needs {evaluations} x {period}s = {minutes:g} minutes of breach before it fires "
            f"(over {SLOW_ALARM_SECONDS // 60}); shorten the window for a node-level page",
            "slow-evaluation",
        )
    if metric == "CPUUtilization" and target is not None and target.get("engine") != "memcached":
        add(
            "warning",
            f"alarm {name} watches host CPUUtilization on a Valkey/Redis node: the engine runs on one core, so "
            "alarm on EngineCPUUtilization (host CPU stays low while the main thread is pinned)",
            "host-cpu-instead-of-engine-cpu",
        )
    if target and target["kind"] == "replication-group" and dims.get("CacheClusterId") == target["id"]:
        add(
            "warning",
            f"alarm {name} uses CacheClusterId={target['id']} but that is a replication group id, not a node: "
            f"it never receives data; use a member node id such as {target['members'][0]}",
            "wrong-dimension",
        )
    return out


def unscoped_dimension_findings(alarm: dict) -> list[dict]:
    """An ElastiCache alarm with none of CacheClusterId, ReplicationGroupId or clusterId watches no resource."""
    dims = {d.get("Name") for d in alarm.get("Dimensions", [])}
    if dims & {"CacheClusterId", "ReplicationGroupId", "clusterId"}:
        return []
    name = str(alarm.get("AlarmName"))
    return [
        finding(
            "warning",
            f"alarm {name} on {alarm.get('MetricName')} has no CacheClusterId, ReplicationGroupId or clusterId "
            "dimension: it matches no node and stays in INSUFFICIENT_DATA",
            alarm=name,
            category="alarm-quality",
            rule="missing-dimension",
        )
    ]
