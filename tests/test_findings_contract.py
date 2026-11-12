"""Findings contract for the round 20 tools: every finding is ``{severity, message}`` with a known severity,
sorted worst-first, and the list sits ahead of the bulk data in the payload."""

import json

from mcp_elasticache_ops import dataplane
from mcp_elasticache_ops.controlplane.scale import scale_readiness
from mcp_elasticache_ops.controlplane.triage_shards import _shard_layout

from .fakes import FakeRedis

SEVERITIES = {"critical": 0, "warning": 1, "info": 2}


def _check(findings):
    assert findings, "the case should produce findings"
    for f in findings:
        assert set(f) >= {"severity", "message"} and f["severity"] in SEVERITIES
        assert isinstance(f["message"], str) and f["message"]
    ranks = [SEVERITIES[f["severity"]] for f in findings]
    assert ranks == sorted(ranks)


def test_client_summary_findings_follow_the_contract():
    fake = FakeRedis(infos={"clients": {"connected_clients": 60, "maxclients": 62}})
    fake.clients = [
        {"id": str(i), "addr": "10.0.0.1:1", "idle": "9000", "omem": str(40 * 1024 * 1024 if i == 0 else 0)}
        for i in range(60)
    ]
    out = dataplane.client_summary(fake)
    _check(out["findings"])
    assert next(iter(json.loads(json.dumps(out)))) == "findings"


def test_scale_readiness_findings_follow_the_contract():
    g = {
        "ReplicationGroupId": "rg",
        "Status": "modifying",
        "CacheNodeType": "cache.t4g.small",
        "ClusterEnabled": True,
        "MultiAZ": "disabled",
        "AutomaticFailover": "disabled",
        "NodeGroups": [
            {"NodeGroupId": "0001", "NodeGroupMembers": [{"CacheClusterId": "a", "CurrentRole": "primary"}]},
            {"NodeGroupId": "0002", "NodeGroupMembers": [{"CacheClusterId": "b", "CurrentRole": "primary"}]},
        ],
    }
    points = {"points": 2, "max": 70.0, "avg": 35.0, "p95": 70.0, "min": 3.0, "sum": 0.0}
    summary = {m: {"DatabaseMemoryUsagePercentage": points, "EngineCPUUtilization": points} for m in ("a", "b")}
    findings, *_ = scale_readiness(g, _shard_layout(g), summary, {})
    sorted_findings = sorted(findings, key=lambda f: SEVERITIES[f["severity"]])
    _check(sorted_findings)
