"""aws_scale_readiness: scale-in projection, scale-out advice and node-type change risk, one case per finding."""

import datetime as dt

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from mcp_elasticache_ops.config import ControlPlaneConfig
from mcp_elasticache_ops.controlplane import ControlPlane

REGION = "us-east-1"
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


class FakeCloudWatch:
    """Answers GetMetricData from ``values[(member, metric)]`` (a list of floats); no entry means no datapoints."""

    def __init__(self, values, error=None):
        self.values = values
        self.error = error
        self.calls = 0

    def get_metric_data(self, MetricDataQueries, **_kw):
        self.calls += 1
        if self.error:
            raise ClientError({"Error": {"Code": self.error, "Message": "x"}}, "GetMetricData")
        results = []
        for q in MetricDataQueries:
            vals = self.values.get(tuple(q["Label"].split("|")), [])
            stamps = [NOW - dt.timedelta(hours=i) for i in range(len(vals))]
            results.append({"Id": q["Id"], "Label": q["Label"], "Timestamps": stamps, "Values": vals})
        return {"MetricDataResults": results}


def _group(shards=3, replicas=1, node_type="cache.r6g.large", cluster=True, multi_az="enabled", **extra):
    node_groups = []
    for s in range(1, shards + 1):
        members = [{"CacheClusterId": f"rg-000{s}-001", "CurrentRole": "primary"}]
        members += [{"CacheClusterId": f"rg-000{s}-00{r + 2}", "CurrentRole": "replica"} for r in range(replicas)]
        node_groups.append({"NodeGroupId": f"000{s}", "NodeGroupMembers": members})
    g = {
        "ReplicationGroupId": "rg",
        "Status": "available",
        "CacheNodeType": node_type,
        "ClusterEnabled": cluster,
        "MultiAZ": multi_az,
        "AutomaticFailover": multi_az,
        "NodeGroups": node_groups,
    }
    g.update(extra)
    return g


def _run(group, values, clusters=(), cw_error=None, clusters_error=False):
    ec = boto3.client("elasticache", region_name=REGION)
    cw = FakeCloudWatch(values, cw_error)

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
        result = cp.scale_readiness("rg")
        stub.assert_no_pending_responses()
    return result


def _mem(*peaks, cpu=20.0):
    """Memory peak (and a flat CPU) for the primary of each shard."""
    out = {}
    for i, peak in enumerate(peaks, start=1):
        out[(f"rg-000{i}-001", "DatabaseMemoryUsagePercentage")] = [peak / 2, peak]
        out[(f"rg-000{i}-001", "EngineCPUUtilization")] = [cpu, cpu]
    return out


def _categories(result):
    return {f.get("category") for f in result["findings"]}


def test_scale_in_is_safe_with_headroom():
    r = _run(_group(shards=4), _mem(30, 30, 30, 30))
    assert r["scale_in"]["safe"] is True
    assert r["scale_in"]["remaining_shards"] == 3
    assert r["scale_in"]["projected_memory_pct"] == 40.0
    assert "scale-in-safe" in _categories(r)
    assert r["scale_out"]["advised"] is False


def test_scale_in_unsafe_when_survivors_would_overflow():
    r = _run(_group(shards=3), _mem(70, 70, 70))
    assert r["scale_in"]["safe"] is False
    assert r["scale_in"]["projected_memory_pct"] == 105.0
    assert r["findings"][0]["category"] == "scale-in-unsafe"
    assert r["overall"] == "warning"


def test_scale_in_tight_between_the_targets():
    r = _run(_group(shards=3), _mem(50, 50, 50))
    assert r["scale_in"]["projected_memory_pct"] == 75.0
    assert r["scale_in"]["safe"] is False
    assert "scale-in-tight" in _categories(r)


def test_scale_in_cpu_projection_blocks_a_memory_safe_scale_in():
    r = _run(_group(shards=3), _mem(10, 10, 10, cpu=50.0))
    assert r["scale_in"]["projected_cpu_pct"] == 75.0
    assert r["scale_in"]["safe"] is False
    assert "scale-in-cpu" in _categories(r)


def test_single_shard_and_cluster_mode_disabled_cannot_scale_in():
    single = _run(_group(shards=1), _mem(10))
    assert single["scale_in"]["safe"] is False
    classic = _run(_group(shards=1, cluster=False), _mem(10))
    assert classic["scale_in"]["safe"] is None
    assert "cluster-mode-disabled" in classic["scale_in"]["reason"]


def test_missing_memory_metrics_leave_the_scale_in_verdict_open():
    r = _run(_group(shards=2), {})
    assert r["scale_in"]["safe"] is None
    assert "missing" in r["scale_in"]["reason"]


def test_scale_out_advised_for_memory_and_for_cpu():
    r = _run(_group(shards=3), _mem(80, 30, 30, cpu=70.0))
    assert r["scale_out"]["advised"] is True
    assert len(r["scale_out"]["reasons"]) == 2
    assert "scale-out-advised" in _categories(r)


def test_scale_out_notes_memory_skew():
    r = _run(_group(shards=3), _mem(80, 10, 10))
    msg = next(f["message"] for f in r["findings"] if f.get("category") == "scale-out-advised")
    assert "aws_shard_balance" in msg


def test_scale_out_with_a_nearly_full_shard_warns_about_reshard_memory():
    r = _run(_group(shards=3), _mem(95, 80, 80))
    assert "reshard-memory" in _categories(r)
    assert "node-change-memory" in _categories(r)


def test_cluster_mode_disabled_group_needs_a_bigger_node_not_shards():
    r = _run(_group(shards=1, cluster=False), _mem(85))
    assert r["scale_out"]["advised"] is False
    assert "scale-up-needed" in _categories(r)


def test_network_allowance_exceeded_advises_scale_out():
    values = _mem(30, 30)
    values[("rg-0001-001", "NetworkBandwidthOutAllowanceExceeded")] = [0.0, 120.0]
    r = _run(_group(shards=2), values)
    assert r["scale_out"]["advised"] is True
    assert any("network allowance" in reason for reason in r["scale_out"]["reasons"])


def test_node_type_change_low_risk_on_a_healthy_multi_az_group():
    r = _run(_group(shards=2), _mem(30, 30))
    assert r["node_type_change"] == {"risk": "low", "reasons": []}


def test_node_type_change_flags_multi_az_off_and_no_replicas_as_high():
    r = _run(_group(shards=2, replicas=0, multi_az="disabled"), _mem(30, 30))
    assert r["node_type_change"]["risk"] == "high"
    assert {"multi-az-off", "no-replicas"} <= set(r["node_type_change"]["reasons"])


def test_node_type_change_flags_replica_lag():
    values = _mem(30, 30)
    values[("rg-0001-002", "ReplicationLag")] = [0.1, 4.0]
    r = _run(_group(shards=2), values)
    assert r["node_type_change"]["risk"] == "medium"
    assert "node-change-replica-lag" in _categories(r)
    assert r["shards"][0]["replication_lag_p95"] == 4.0


def test_pending_modification_is_a_warning_and_a_risk():
    r = _run(_group(shards=2, PendingModifiedValues={"AutomaticFailoverStatus": "disabled"}), _mem(30, 30))
    assert "modification-in-progress" in _categories(r)
    assert "modification-in-progress" in r["node_type_change"]["reasons"]
    modifying = _run(_group(shards=2, Status="modifying"), _mem(30, 30))
    assert "modification-in-progress" in _categories(modifying)


def test_burstable_nodes_report_low_credits():
    values = _mem(30, 30)
    values[("rg-0001-001", "CPUCreditBalance")] = [100.0, 5.0]
    low = _run(_group(shards=2, node_type="cache.t4g.medium"), values)
    assert "burstable-low-credits" in low["node_type_change"]["reasons"]
    assert low["node_type_change"]["risk"] == "medium"
    fine = _run(_group(shards=2, node_type="cache.t4g.medium"), _mem(30, 30))
    assert fine["node_type_change"]["reasons"] == ["burstable"]
    assert fine["node_type_change"]["risk"] == "low"


def test_unavailable_node_is_a_reason_but_not_a_hard_risk():
    clusters = [{"CacheClusterId": "rg-0001-002", "ReplicationGroupId": "rg", "CacheClusterStatus": "creating"}]
    r = _run(_group(shards=2), _mem(30, 30), clusters=clusters)
    assert "node-not-available" in r["node_type_change"]["reasons"]


def test_metrics_failure_is_partial_and_keeps_describe_checks():
    r = _run(_group(shards=2, replicas=0, multi_az="disabled"), {}, cw_error="AccessDenied")
    assert r["status"] == "partial"
    assert "metrics-unavailable" in _categories(r)
    assert r["scale_in"]["safe"] is None
    assert "multi-az-off" in r["node_type_change"]["reasons"]


def test_describe_cache_clusters_failure_is_a_note():
    r = _run(_group(shards=2), _mem(30, 30), clusters_error=True)
    assert r["status"] == "partial"
    assert any("DescribeCacheClusters" in n for n in r["notes"])


def test_unknown_group_is_not_found():
    assert _run(None, {})["error"] == "NotFound"


def test_output_is_bounded_for_a_large_group():
    r = _run(_group(shards=20, replicas=2), _mem(*[30] * 20))
    assert r["shards_total"] == 20
    assert len(r["shards"]) <= 50
    assert r["window_days"] == 7
