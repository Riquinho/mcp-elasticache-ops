"""Slow-log and engine-log delivery findings: missing, failing, split and healthy, in aws_triage and the audits."""

import pytest

from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane
from mcp_elasticache_ops.controlplane._shared import _rg_findings, log_delivery_findings
from tests.test_controlplane_tools import NOW, REGION, _member, _placed_rg, _Recorder


def _cfg(log_type, status="active", destination="cloudwatch-logs", message=None):
    cfg = {"LogType": log_type, "DestinationType": destination, "Status": status}
    if message:
        cfg["Message"] = message
    return cfg


HEALTHY = [_cfg("slow-log"), _cfg("engine-log")]


def _triage(configs, engine="valkey"):
    rg = {
        **_placed_rg([_member("rg1-001", "primary", "us-east-1a"), _member("rg1-002", "replica", "us-east-1b")]),
        "Engine": engine,
        "MemberClusters": ["rg1-001", "rg1-002"],
        "LogDeliveryConfigurations": configs,
    }
    ec = _Recorder(
        {
            "describe_replication_groups": {"ReplicationGroups": [rg]},
            "describe_events": {"Events": []},
            "describe_update_actions": {"UpdateActions": []},
            "describe_snapshots": {"Snapshots": []},
        }
    )

    class Session:
        def client(self, service, region_name=None, config=None):
            return {"elasticache": ec, "cloudwatch": _Recorder()}[service]

    cp = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)
    return cp.triage("rg1")["findings"]


def _logs(findings):
    return [f for f in findings if "-log" in f["message"]]


def test_healthy_delivery_is_quiet_everywhere():
    assert log_delivery_findings({"LogDeliveryConfigurations": HEALTHY}, "valkey") == []
    assert _logs(_triage(HEALTHY)) == []
    assert _logs(_rg_findings({"Engine": "valkey", "LogDeliveryConfigurations": HEALTHY}, None)) == []


def test_missing_delivery_warns_for_slow_log_and_points_at_the_live_tools():
    found = log_delivery_findings({}, "redis")
    by_next = {f["next"]: f for f in found}
    assert (
        by_next["node_slowlog"]["severity"] == "warning"
        and "slow-log delivery is not enabled" in by_next["node_slowlog"]["message"]
    )
    assert (
        by_next["node_commandlog"]["severity"] == "info"
        and "engine-log delivery is not enabled" in by_next["node_commandlog"]["message"]
    )
    assert "node_slowlog" in by_next["node_slowlog"]["message"]


def test_aws_triage_reports_missing_delivery_with_its_pointer():
    found = _logs(_triage([]))
    assert {f["next"] for f in found} == {"node_slowlog", "node_commandlog"}
    assert [f["severity"] for f in found] == ["warning", "info"]


def test_failing_destination_is_a_warning_with_the_service_message():
    configs = [_cfg("slow-log", "error", message="log group not found"), _cfg("engine-log")]
    found = log_delivery_findings({"LogDeliveryConfigurations": configs}, "valkey")
    failing = [f for f in found if "status is error" in f["message"]]
    assert len(failing) == 1 and failing[0]["severity"] == "warning" and "log group not found" in failing[0]["message"]
    assert failing[0]["next"] == "node_slowlog"
    # an erroring slow-log is not delivering, so the missing-delivery warning stays too
    assert any("slow-log delivery is not enabled" in f["message"] for f in found)
    assert any("status is error" in f["message"] for f in _triage(configs))


@pytest.mark.parametrize("status", ["error", "failed", "FAILED", "disabling"])
def test_failure_states_are_matched_case_insensitively(status):
    found = log_delivery_findings(
        {"LogDeliveryConfigurations": [_cfg("engine-log", status), _cfg("slow-log")]}, "redis"
    )
    assert any(f"engine-log delivery status is {status}" in f["message"] for f in found)


def test_transitional_states_count_as_delivering():
    configs = [_cfg("slow-log", "enabling"), _cfg("engine-log", "modifying")]
    assert log_delivery_findings({"LogDeliveryConfigurations": configs}, "valkey") == []


def test_destination_type_split_between_the_two_logs_is_an_info():
    configs = [_cfg("slow-log"), _cfg("engine-log", destination="kinesis-firehose")]
    found = log_delivery_findings({"LogDeliveryConfigurations": configs}, "valkey")
    assert [f["severity"] for f in found] == ["info"]
    assert "cloudwatch-logs" in found[0]["message"] and "kinesis-firehose" in found[0]["message"]
    same = [_cfg("slow-log", destination="kinesis-firehose"), _cfg("engine-log", destination="kinesis-firehose")]
    assert log_delivery_findings({"LogDeliveryConfigurations": same}, "valkey") == []


@pytest.mark.parametrize("engine", ["memcached", "", "serverless"])
def test_engines_without_log_delivery_are_not_judged(engine):
    assert log_delivery_findings({}, engine) == []


def test_replication_group_audit_and_inventory_share_the_same_findings():
    from mcp_elasticache_ops.controlplane.group_audit import group_audit_findings

    group = {"ReplicationGroupId": "rg", "Engine": "valkey", "LogDeliveryConfigurations": []}
    audit = [f["next"] for f in group_audit_findings(group, []) if f["category"] == "log-delivery"]
    inventory = [f["next"] for f in _rg_findings(group, None) if f.get("category") == "log-delivery"]
    assert audit == inventory == ["node_slowlog", "node_commandlog"]
