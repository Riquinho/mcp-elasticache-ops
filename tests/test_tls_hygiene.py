"""Round 25: TLS and AUTH-token hygiene findings in aws_maintenance, with a botocore-model shape check."""

from __future__ import annotations

import datetime as dt

import botocore.session
import pytest

from mcp_elasticache_ops.controlplane.monitoring import _transport_hygiene_findings
from tests.test_controlplane_findings import NOW, Fake, plane


def _cluster(cid="rg1-001", **over) -> dict:
    return {"CacheClusterId": cid, "ReplicationGroupId": "rg1", "Engine": "valkey", "EngineVersion": "8.0", **over}


def _categories(findings: list[dict]) -> list[str]:
    return [f["category"] for f in findings if f.get("category") in {"tls-hygiene", "auth-token-rotation"}]


def test_transit_encryption_off_yields_one_finding_per_group_not_per_member():
    members = [_cluster("rg1-001", TransitEncryptionEnabled=False), _cluster("rg1-002", TransitEncryptionEnabled=False)]
    out = _transport_hygiene_findings(members, NOW)
    assert _categories(out) == ["tls-hygiene"] and out[0]["resource"] == "rg1"


def test_transit_encryption_on_or_field_absent_yields_nothing():
    assert _transport_hygiene_findings([_cluster(TransitEncryptionEnabled=True)], NOW) == []
    assert _transport_hygiene_findings([_cluster()], NOW) == []


def test_auth_token_older_than_365_days_suggests_rotation():
    old = NOW - dt.timedelta(days=400)
    out = _transport_hygiene_findings([_cluster(AuthTokenEnabled=True, AuthTokenLastModifiedDate=old)], NOW)
    assert _categories(out) == ["auth-token-rotation"] and "400 days" in out[0]["message"]


@pytest.mark.parametrize(
    "fields",
    [
        {"AuthTokenEnabled": True, "AuthTokenLastModifiedDate": NOW - dt.timedelta(days=30)},
        {"AuthTokenEnabled": True},  # date absent
        {"AuthTokenEnabled": False, "AuthTokenLastModifiedDate": NOW - dt.timedelta(days=900)},
    ],
)
def test_recent_absent_or_unused_auth_token_yields_nothing(fields):
    assert _transport_hygiene_findings([_cluster(**fields)], NOW) == []


def test_maintenance_reports_both_rules_from_describe_cache_clusters():
    old = NOW - dt.timedelta(days=500)
    ec = Fake(
        {
            "describe_update_actions": {"UpdateActions": []},
            "describe_service_updates": {"ServiceUpdates": []},
            "describe_cache_clusters": {
                "CacheClusters": [
                    _cluster(TransitEncryptionEnabled=False, AuthTokenEnabled=True, AuthTokenLastModifiedDate=old)
                ]
            },
        }
    )
    out = plane(ec).maintenance()
    assert sorted(_categories(out["findings"])) == ["auth-token-rotation", "tls-hygiene"]


def test_field_names_used_exist_in_the_botocore_describe_shapes():
    model = botocore.session.get_session().get_service_model("elasticache")
    for shape in ("CacheCluster", "ReplicationGroup"):
        members = model.shape_for(shape).members
        for field in ("TransitEncryptionEnabled", "AuthTokenEnabled", "AuthTokenLastModifiedDate"):
            assert field in members, f"{shape}.{field}"
        assert members["AuthTokenLastModifiedDate"].type_name == "timestamp"
        assert members["TransitEncryptionEnabled"].type_name == "boolean"
    # The API has no certificate-authority field: a CA rule cannot be built from describe data.
    names = {n for s in ("CacheCluster", "ReplicationGroup") for n in model.shape_for(s).members}
    assert not {n for n in names if "certificate" in n.lower()}
