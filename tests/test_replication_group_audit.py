"""aws_replication_group_audit: one case per finding, the clean case, narrowing, and error paths."""

import boto3
import pytest
from botocore.stub import Stubber

from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane
from mcp_elasticache_ops.controlplane.group_audit import group_audit_findings
from tests.test_scale_readiness import NOW, REGION, fake_aws_env  # noqa: F401  (autouse fixture)


def _plane():
    ec = boto3.client("elasticache", region_name=REGION)

    class Session:
        def client(self, service, region_name=None, config=None):
            return ec

    return ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW), ec


def _group(**over):
    base = {
        "ReplicationGroupId": "rg",
        "Engine": "valkey",
        "MultiAZ": "enabled",
        "AutomaticFailover": "enabled",
        "ClusterEnabled": True,
        "CacheNodeType": "cache.r7g.large",
        "AutoMinorVersionUpgrade": True,
        "SnapshotRetentionLimit": 7,
        "TransitEncryptionEnabled": True,
        "AtRestEncryptionEnabled": True,
        "NetworkType": "dual_stack",
        "LogDeliveryConfigurations": [
            {"LogType": "slow-log", "DestinationType": "cloudwatch-logs", "Status": "active"},
            {"LogType": "engine-log", "DestinationType": "cloudwatch-logs", "Status": "active"},
        ],
        "NodeGroups": [
            {
                "NodeGroupId": "0001",
                "NodeGroupMembers": [
                    {"CacheClusterId": "rg-0001-001", "PreferredAvailabilityZone": "eu-west-1a"},
                    {"CacheClusterId": "rg-0001-002", "PreferredAvailabilityZone": "eu-west-1b"},
                ],
            }
        ],
    }
    return {**base, **over}


def _audit(groups, clusters=(), **kw):
    cp, ec = _plane()
    with Stubber(ec) as stub:
        stub.add_response("describe_replication_groups", {"ReplicationGroups": groups})
        stub.add_response("describe_cache_clusters", {"CacheClusters": list(clusters)})
        out = cp.replication_group_audit(**kw)
        stub.assert_no_pending_responses()
    return out


def test_healthy_group_has_no_findings():
    out = _audit([_group()])
    assert out["findings"] == [] and out["summary"]["groups_checked"] == 1
    assert out["summary"]["groups_with_findings"] == 0


ONE_NODE = [{"NodeGroupId": "0001", "NodeGroupMembers": [{"CacheClusterId": "a"}]}]
SAME_AZ = [
    {
        "NodeGroupId": "0001",
        "NodeGroupMembers": [
            {"PreferredAvailabilityZone": "eu-west-1a"},
            {"PreferredAvailabilityZone": "eu-west-1a"},
        ],
    }
]


@pytest.mark.parametrize(
    ("over", "category", "severity", "next_tool"),
    [
        ({"MultiAZ": "disabled"}, "multi-az", "warning", "aws_failover_readiness"),
        ({"AutomaticFailover": "disabled"}, "automatic-failover", "warning", "aws_failover_readiness"),
        ({"NodeGroups": ONE_NODE}, "zero-replicas", "warning", "aws_failover_readiness"),
        ({"NodeGroups": SAME_AZ}, "single-az", "warning", "aws_failover_readiness"),
        (
            {"ClusterEnabled": False, "CacheNodeType": "cache.r7g.4xlarge"},
            "cluster-mode-big-node",
            "info",
            "aws_scale_readiness",
        ),
        ({"AutoMinorVersionUpgrade": False}, "auto-minor-upgrade", "info", "aws_upgrade_plan"),
        ({"SnapshotRetentionLimit": 0}, "no-snapshots", "warning", "aws_backup_audit"),
        ({"LogDeliveryConfigurations": []}, "log-delivery", "warning", "node_slowlog"),
        ({"TransitEncryptionEnabled": False}, "encryption-mix", "warning", "aws_security_audit"),
        ({"AtRestEncryptionEnabled": False}, "encryption-mix", "warning", "aws_security_audit"),
        ({"NetworkType": "ipv4"}, "network-type", "info", "aws_replication_groups"),
        ({"NetworkType": "ipv6", "IpDiscovery": "ipv4"}, "network-type", "warning", "aws_replication_groups"),
    ],
)
def test_each_posture_finding(over, category, severity, next_tool):
    out = _audit([_group(**over)])
    hits = [f for f in out["findings"] if f["category"] == category]
    assert hits, out["findings"]
    assert hits[0]["severity"] == severity and hits[0]["next"] == next_tool and hits[0]["resource"] == "rg"
    assert hits[0]["message"].startswith("rg: ")


def test_cluster_mode_disabled_on_a_small_node_is_fine():
    assert _audit([_group(ClusterEnabled=False)])["findings"] == []


def test_both_encryptions_off_is_one_finding_and_mixed_names_the_missing_one():
    both = _audit([_group(TransitEncryptionEnabled=False, AtRestEncryptionEnabled=False)])["findings"]
    assert [f["category"] for f in both] == ["encryption-mix"] and "neither" in both[0]["message"]
    mixed = _audit([_group(AtRestEncryptionEnabled=False)])["findings"]
    assert "in-transit is on but at-rest is off" in mixed[0]["message"]


def test_failing_log_delivery_is_reported_with_its_message():
    cfg = [
        {"LogType": "slow-log", "DestinationType": "cloudwatch-logs", "Status": "error", "Message": "no perms"},
        {"LogType": "engine-log", "DestinationType": "cloudwatch-logs", "Status": "active"},
    ]
    messages = [f["message"] for f in _audit([_group(LogDeliveryConfigurations=cfg)])["findings"]]
    assert any("slow-log delivery status is error: no perms" in m for m in messages)
    assert any("slow-log delivery is not enabled" in m for m in messages)  # an erroring log is not delivering


def test_member_network_type_disagreement_uses_cluster_rows():
    clusters = [
        {"CacheClusterId": "a", "ReplicationGroupId": "rg", "NetworkType": "ipv4"},
        {"CacheClusterId": "b", "ReplicationGroupId": "rg", "NetworkType": "dual_stack"},
    ]
    group = _group()
    del group["NetworkType"]
    out = _audit([group], clusters)
    assert any("disagree on network type (dual_stack, ipv4)" in f["message"] for f in out["findings"])


def test_findings_are_sorted_worst_first_across_groups():
    out = _audit(
        [
            _group(ReplicationGroupId="a", AutoMinorVersionUpgrade=False),
            _group(ReplicationGroupId="b", MultiAZ="disabled"),
        ]
    )
    assert [f["severity"] for f in out["findings"]] == ["warning", "info"]
    assert out["summary"]["groups_with_findings"] == 2
    assert out["summary"]["severity_counts"] == {"warning": 1, "info": 1}


def test_findings_are_capped():
    groups = [_group(ReplicationGroupId=f"g{i}", MultiAZ="disabled", AutomaticFailover="disabled") for i in range(40)]
    out = _audit(groups)
    assert len(out["findings"]) == 60 and out["findings_truncated"] == 80


def test_describe_cache_clusters_failure_degrades_to_group_checks():
    cp, ec = _plane()
    with Stubber(ec) as stub:
        stub.add_response("describe_replication_groups", {"ReplicationGroups": [_group(MultiAZ="disabled")]})
        stub.add_client_error("describe_cache_clusters", "AccessDenied")
        out = cp.replication_group_audit()
    assert out["partial"] is True and "DescribeCacheClusters failed" in out["notes"][0]
    assert [f["category"] for f in out["findings"]] == ["multi-az"]


def test_describe_replication_groups_client_error_is_reported():
    cp, ec = _plane()
    with Stubber(ec) as stub:
        stub.add_client_error("describe_replication_groups", "AccessDenied")
        out = cp.replication_group_audit()
    assert "error" in out and "findings" not in out


def test_unknown_group_id_is_not_found():
    cp, ec = _plane()
    with Stubber(ec) as stub:
        stub.add_response("describe_replication_groups", {"ReplicationGroups": []})
        out = cp.replication_group_audit("nope")
    assert out["error"] == "NotFound"


def test_pure_function_tolerates_missing_fields():
    out = group_audit_findings({"ReplicationGroupId": "bare"}, [])
    assert all(f["resource"] == "bare" for f in out)
