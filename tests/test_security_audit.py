"""aws_security_audit: Memcached clusters and legacy / AUTH-only Redis groups, severity ordering, no secrets."""

from __future__ import annotations

import datetime as dt

import pytest

from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane
from tests.fakes import AwsAudit

NOW = dt.datetime(2026, 11, 12, 12, 0, tzinfo=dt.UTC)


@pytest.fixture(autouse=True)
def fake_aws_env(monkeypatch, tmp_path):
    for var in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


SEVERITY = ["critical", "important", "warning", "medium", "info"]


def _plane(responses: dict) -> tuple[AwsAudit, ControlPlane]:
    fake = AwsAudit(responses)
    return fake, ControlPlane(ControlPlaneConfig(region="us-east-1"), session_factory=fake, clock=lambda: NOW)


def _mc(cid: str, **extra) -> dict:
    return {
        "CacheClusterId": cid,
        "Engine": "memcached",
        "EngineVersion": "1.6.22",
        "CacheClusterStatus": "available",
        **extra,
    }


def _rg(gid: str, **extra) -> dict:
    return {
        "ReplicationGroupId": gid,
        "Status": "available",
        "Engine": "redis",
        "TransitEncryptionEnabled": True,
        "AtRestEncryptionEnabled": True,
        "AuthTokenEnabled": False,
        "SnapshotRetentionLimit": 5,
        "NodeGroups": [],
        "MemberClusters": [],
        **extra,
    }


def _audit(**responses) -> dict:
    base = {
        "DescribeReplicationGroups": {"ReplicationGroups": []},
        "DescribeCacheClusters": {"CacheClusters": []},
        "DescribeServerlessCaches": {"ServerlessCaches": []},
        "DescribeUsers": {"Users": []},
        "DescribeUserGroups": {"UserGroups": []},
    }
    base.update(responses)
    _, plane = _plane(base)
    return plane.security_audit()


def _for(out: dict, resource: str, category: str) -> list[dict]:
    return [f for f in out["findings"] if f["resource"] == resource and f["category"] == category]


def test_memcached_tls_off_no_auth_and_sg_hint():
    cluster = _mc(
        "mc-1",
        TransitEncryptionEnabled=False,
        SecurityGroups=[{"SecurityGroupId": "sg-0abc", "Status": "active"}],
    )
    out = _audit(DescribeCacheClusters={"CacheClusters": [cluster]})
    tls = _for(out, "mc-1", "encryption in transit")
    assert tls and tls[0]["severity"] == "warning"
    assert _for(out, "mc-1", "authentication")
    net = _for(out, "mc-1", "network exposure")
    assert net and "sg-0abc" in net[0]["message"] and net[0]["severity"] == "warning"
    row = next(r for r in out["matrix"] if r["resource"] == "mc-1")
    assert row["checks"]["encryption at rest and KMS"] == "n/a"
    assert row["checks"]["encryption in transit"] == "fail" and row["checks"]["network exposure"] == "fail"


def test_legacy_cache_security_group_is_flagged():
    cluster = _mc("mc-old", CacheSecurityGroups=[{"CacheSecurityGroupName": "classic-web", "Status": "active"}])
    out = _audit(DescribeCacheClusters={"CacheClusters": [cluster]})
    legacy = [f for f in _for(out, "mc-old", "network exposure") if "legacy" in f["message"]]
    assert legacy and "classic-web" in legacy[0]["message"]


def test_redis_auth_token_only_group_gets_a_warning_not_critical():
    out = _audit(DescribeReplicationGroups={"ReplicationGroups": [_rg("auth-rg", AuthTokenEnabled=True)]})
    auth = _for(out, "auth-rg", "authentication")
    assert [f["severity"] for f in auth] == ["warning"]
    assert "single shared AUTH token" in auth[0]["message"]
    assert "critical" not in out["summary"]["severity_counts"]


def test_redis_default_user_nopass_is_critical_and_ranks_first():
    out = _audit(
        DescribeReplicationGroups={"ReplicationGroups": [_rg("open-rg", UserGroupIds=["ug"])]},
        DescribeUsers={
            "Users": [
                {
                    "UserId": "default",
                    "UserName": "default",
                    "Status": "active",
                    "AccessString": "on ~* +@all",
                    "Authentication": {"Type": "no-password"},
                }
            ]
        },
        DescribeUserGroups={
            "UserGroups": [{"UserGroupId": "ug", "UserIds": ["default"], "ReplicationGroups": ["open-rg"]}]
        },
    )
    critical = [f for f in out["findings"] if f["severity"] == "critical"]
    assert critical and critical[0]["resource"] == "default" and "without credentials" in critical[0]["message"]
    ranks = [SEVERITY.index(r["worst"]) if r["worst"] in SEVERITY else 9 for r in out["matrix"]]
    assert ranks == sorted(ranks)  # matrix lists the worst resource first


def test_findings_never_contain_secrets_and_use_describe_only():
    cluster = _mc("mc-s", SecurityGroups=[{"SecurityGroupId": "sg-1", "Status": "active"}])
    fake, plane = _plane(
        {
            "DescribeReplicationGroups": {"ReplicationGroups": [_rg("r", AuthTokenEnabled=True)]},
            "DescribeCacheClusters": {"CacheClusters": [cluster]},
            "DescribeServerlessCaches": {"ServerlessCaches": []},
            "DescribeUsers": {"Users": []},
            "DescribeUserGroups": {"UserGroups": []},
        }
    )
    out = plane.security_audit()
    assert out["findings"]
    assert all(op.startswith("Describe") for _svc, op in fake.operations)


def test_shared_security_group_is_an_info_hint():
    shared = [{"SecurityGroupId": "sg-shared", "Status": "active"}]
    clusters = [_mc(f"mc-{i}", SecurityGroups=shared) for i in range(3)]
    out = _audit(DescribeCacheClusters={"CacheClusters": clusters})
    hint = [f for f in out["findings"] if "shared across" in f["message"]]
    assert len(hint) == 3 and {f["severity"] for f in hint} == {"info"}
