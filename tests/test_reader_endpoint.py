"""aws_reader_endpoint_audit: reader endpoint use against replica count, one case per finding and failure mode."""

import boto3
import pytest
from botocore.exceptions import ConnectTimeoutError
from botocore.stub import Stubber

from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane
from tests.test_scale_readiness import NOW, REGION, FakeCloudWatch, fake_aws_env  # noqa: F401  (autouse fixture)


def _group(replicas=2, azs=("us-east-1a", "us-east-1b", "us-east-1c"), cluster=False, reader=True, shards=1):
    node_groups = []
    for s in range(1, shards + 1):
        members = [
            {
                "CacheClusterId": f"rg-000{s}-001",
                "CurrentRole": "primary",
                "PreferredAvailabilityZone": azs[0],
            }
        ]
        for r in range(replicas):
            members.append(
                {
                    "CacheClusterId": f"rg-000{s}-00{r + 2}",
                    "CurrentRole": "replica",
                    "PreferredAvailabilityZone": azs[(r + 1) % len(azs)],
                }
            )
        ng: dict = {"NodeGroupId": f"000{s}", "NodeGroupMembers": members}
        if not cluster:
            ng["PrimaryEndpoint"] = {"Address": "rg.primary.cache.example", "Port": 6379}
            if reader:
                ng["ReaderEndpoint"] = {"Address": "rg-ro.primary.cache.example", "Port": 6379}
        node_groups.append(ng)
    return {
        "ReplicationGroupId": "rg",
        "Status": "available",
        "ClusterEnabled": cluster,
        "NodeGroups": node_groups,
    }


def _run(group, values=None, clusters=(), clusters_error=False, cw_error=None):
    ec = boto3.client("elasticache", region_name=REGION)
    cw = FakeCloudWatch(values or {}, cw_error)

    class Session:
        def client(self, service, region_name=None, config=None):
            return cw if service == "cloudwatch" else ec

    cp = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)
    with Stubber(ec) as stub:
        stub.add_response("describe_replication_groups", {"ReplicationGroups": [group] if group else []})
        if group:
            if clusters_error:
                stub.add_client_error("describe_cache_clusters", "AccessDenied")
            else:
                stub.add_response("describe_cache_clusters", {"CacheClusters": list(clusters)})
        result = cp.reader_endpoint_audit("rg")
        stub.assert_no_pending_responses()
    return result, cw


def _cats(result):
    return {f.get("category") for f in result["findings"]}


def test_healthy_group_only_points_at_the_reader_endpoint():
    r, cw = _run(_group(replicas=2))
    assert r["status"] == "ok"
    assert _cats(r) == {"primary-endpoint-reads"}
    assert {f["severity"] for f in r["findings"]} == {"info"}
    text = r["findings"][0]["message"]
    assert "rg-ro.primary.cache.example:6379" in text and "rg.primary.cache.example:6379" in text
    assert r["shards"][0]["reader_endpoint"] == "rg-ro.primary.cache.example:6379"
    assert cw.calls == 1


def test_single_replica_sends_all_reads_to_the_primary_on_failure():
    r, _ = _run(_group(replicas=1))
    assert "single-replica" in _cats(r)
    f = next(f for f in r["findings"] if f["category"] == "single-replica")
    assert f["severity"] == "warning" and "0001" in f["message"] and "primary" in f["message"]


def test_replicas_in_the_primary_az_are_flagged():
    r, _ = _run(_group(replicas=2, azs=("us-east-1a",)))
    assert "replica-same-az" in _cats(r)
    assert r["shards"][0]["replicas_in_primary_az"] == ["rg-0001-002", "rg-0001-003"]


def test_missing_reader_endpoint_is_a_warning():
    r, _ = _run(_group(replicas=2, reader=False))
    f = next(f for f in r["findings"] if f["category"] == "no-reader-endpoint")
    assert f["severity"] == "warning" and r["overall"] == "warning"


def test_cluster_mode_group_mentions_readonly_not_a_reader_endpoint():
    r, _ = _run(_group(replicas=1, cluster=True, shards=3))
    assert r["cluster_mode"] == "enabled" and "no-reader-endpoint" not in _cats(r)
    assert "READONLY" in next(f for f in r["findings"] if f["category"] == "primary-endpoint-reads")["message"]
    assert r["shards_total"] == 3


def test_group_without_replicas_has_no_reader_findings():
    r, cw = _run(_group(replicas=0))
    assert r["findings"] == [] and r["overall"] == "ok" and cw.calls == 0


def test_replication_lag_above_threshold_is_flagged():
    r, _ = _run(_group(replicas=2), {("rg-0001-002", "ReplicationLag"): [0.2, 3.5]})
    f = next(f for f in r["findings"] if f["category"] == "replica-lag")
    assert "rg-0001-002" in f["message"] and r["replication_lag_p95"]["rg-0001-002"] == 3.5


def test_replica_not_available_is_flagged():
    clusters = [{"CacheClusterId": "rg-0001-002", "ReplicationGroupId": "rg", "CacheClusterStatus": "modifying"}]
    r, _ = _run(_group(replicas=2), clusters=clusters)
    assert "replica-state" in _cats(r)


def test_describe_cache_clusters_denied_degrades_to_partial():
    r, _ = _run(_group(replicas=2), clusters_error=True)
    assert r["status"] == "partial" and "DescribeCacheClusters failed (AccessDenied)" in r["notes"][0]
    assert "primary-endpoint-reads" in _cats(r)


def test_cloudwatch_denied_degrades_to_partial_and_keeps_layout_findings():
    r, _ = _run(_group(replicas=1), cw_error="AccessDenied")
    assert r["status"] == "partial" and "GetMetricData failed (AccessDenied)" in r["notes"][-1]
    assert "single-replica" in _cats(r)


def test_unknown_group_is_not_found():
    r, _ = _run(None)
    assert r["error"] == "NotFound"


@pytest.mark.parametrize("code", ["AccessDenied", "AccessDeniedException", "Throttling"])
def test_first_call_aws_error_becomes_an_error_dict(code):
    ec = boto3.client("elasticache", region_name=REGION)

    class Session:
        def client(self, service, region_name=None, config=None):
            return ec

    cp = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)
    with Stubber(ec) as stub:
        stub.add_client_error("describe_replication_groups", code)
        out = cp.reader_endpoint_audit("rg")
    assert out["error"] == code and "findings" not in out


def test_timeout_becomes_an_error_dict_with_a_hint():
    class Client:
        def __getattr__(self, name):
            def boom(**_kw):
                raise ConnectTimeoutError(endpoint_url="https://x")

            return boom

    class Session:
        def client(self, service, region_name=None, config=None):
            return Client()

    cp = ControlPlane(ControlPlaneConfig(region=REGION), session_factory=Session, clock=lambda: NOW)
    out = cp.reader_endpoint_audit("rg")
    assert out["error"] == "ConnectTimeoutError" and out.get("hint")
