import os

import pytest
import redis

from mcp_elasticache_ops import dataplane
from mcp_elasticache_ops.safe_client import ReadOnlyViolation, SafeRedis

pytestmark = pytest.mark.integration


def test_health(safe):
    h = dataplane.health_summary(safe)
    assert h["engine"] in {"redis", "valkey"}
    assert h["role"] == "master"
    assert h["findings"]


def test_info_section(safe):
    out = dataplane.server_info(safe, "memory")
    assert "used_memory" in out["info"]


def test_memory(safe):
    m = dataplane.memory_report(safe)
    assert m["used_memory_rss"] > 0
    assert m["fragmentation_verdict"]
    assert "memory_stats" in m


def test_slowlog_hides_values(safe):
    s = dataplane.slowlog(safe, count=200)
    assert s["returned"] > 0
    assert s["by_command"]
    for e in s["entries"]:
        assert "x" * 10 not in e["command"]
        assert "v" * 50 not in e["command"]


def test_clients(safe):
    c = dataplane.client_list(safe)
    assert c["total"] >= 2
    assert any(name == "seed-client" for name, _ in c["by_name"])


def test_latency(safe):
    lat = dataplane.latency(safe, ping_samples=5)
    assert lat["ping_rtt_ms"]["p50"] >= 0
    assert str(lat["latency_monitor_threshold"]) == "1"


def test_commandstats(safe):
    cs = dataplane.commandstats(safe)
    assert cs["commands"] > 0
    assert cs["top_by_total_time"][0]["calls"] > 0


def test_keyspace_sample_finds_big_keys(safe):
    ks = dataplane.keyspace_sample(safe, sample_size=10_000, top=5)
    assert ks["complete_scan"]
    assert ks["sampled_keys"] == ks["dbsize"] == 325
    assert ks["big_keys_by_bytes"][0]["key"] in {"big:string", "big:hash", "big:list"}
    assert ks["big_keys_by_length"][0]["key"] == "big:list"
    assert ks["big_keys_by_length"][0]["length"] == 5000
    assert ks["by_type"]["string"]["keys"] == 321
    assert ks["keys_without_ttl"] == ks["sampled_keys"] - 20
    assert "coldest_keys_by_idle" in ks


def test_keyspace_sample_bounded_and_match(safe):
    ks = dataplane.keyspace_sample(safe, sample_size=10, scan_count=10)
    assert ks["sampled_keys"] == 10
    assert not ks["complete_scan"]
    only = dataplane.keyspace_sample(safe, sample_size=1000, match="session:*")
    assert list(only["by_type"]) == ["string"]
    assert only["by_type"]["string"]["keys"] == 20
    assert all(k["ttl_ms"] > 0 for k in only["big_keys_by_bytes"])


def test_replication_and_cluster(safe):
    rep = dataplane.replication(safe)
    assert rep["role"] == "master"
    assert dataplane.cluster(safe)["cluster_enabled"] is False


def test_guard_holds_on_live_server(safe):
    with pytest.raises(ReadOnlyViolation):
        safe.set("small:0", "changed")
    with pytest.raises(ReadOnlyViolation):
        safe.get("small:0")


# ---------------------------------------------------------------- cluster (3-primary compose stack)

CLUSTER_HOST = os.getenv("CLUSTER_TEST_HOST")
CLUSTER_PORT = int(os.getenv("CLUSTER_TEST_PORT", "7001"))
needs_cluster = pytest.mark.skipif(not CLUSTER_HOST, reason="CLUSTER_TEST_HOST not set")


@pytest.fixture()
def cluster_factory():
    def factory(host, port):
        return SafeRedis(host=host, port=port, decode_responses=True, socket_timeout=5, socket_connect_timeout=5)

    return factory


@pytest.fixture()
def cluster_seed(cluster_factory):
    seed = cluster_factory(CLUSTER_HOST, CLUSTER_PORT)
    yield seed
    seed.close()


@needs_cluster
def test_cluster_nodes_integration(cluster_seed):
    out = dataplane.cluster_nodes(cluster_seed)
    assert out["cluster_enabled"] is True
    assert out["slots_covered"] == 16384
    assert len(out["shards"]) == 3
    assert not out["findings"]


@needs_cluster
def test_cluster_fan_out_integration(cluster_seed, cluster_factory):
    raw = redis.RedisCluster(host=CLUSTER_HOST, port=CLUSTER_PORT)  # test-only writer; product code never writes
    for i in range(300):
        raw.set(f"fan:{i}", "x" * (i + 1))
    raw.close()
    ks = dataplane.cluster_keyspace_sample(cluster_seed, cluster_factory, sample_size=3000, top=5, max_seconds=10)
    assert ks["shards_total"] == 3 and ks["shards_ok"] == 3 and ks["partial"] is False
    assert ks["sampled_keys"] == ks["dbsize"] >= 300
    assert len({k["shard"] for k in ks["big_keys_by_bytes"]} | set(ks["per_shard"])) == 3
    assert all("shard" in k for k in ks["big_keys_by_bytes"])
    mem = dataplane.cluster_memory(cluster_seed, cluster_factory)
    assert mem["shards_ok"] == 3
    slow = dataplane.cluster_slowlog(cluster_seed, cluster_factory, count=5)
    assert slow["shards_ok"] == 3
    rep = dataplane.replication(cluster_seed, cluster_factory)
    assert rep["role"] == "master"


@needs_cluster
def test_cluster_acl_log_integration(cluster_seed):
    out = dataplane.acl_log(cluster_seed, 5)
    assert out["whoami"] == "default"
    with pytest.raises(ReadOnlyViolation):
        cluster_seed.execute_command("ACL", "LOG", "RESET")
