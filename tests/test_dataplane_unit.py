"""Pure unit tests of dataplane.py with fake redis objects (no server needed)."""

import itertools
import time

import pytest
import redis

from mcp_elasticache_ops import dataplane
from tests.fakes import FakeRedis


def _mem_info(**kw):
    base = {
        "used_memory": 100,
        "maxmemory": 1000,
        "mem_fragmentation_ratio": 1.1,
        "used_memory_rss": 110,
        "maxmemory_policy": "allkeys-lru",
    }
    return {**base, **kw}


def test_health_summary_flags_problems():
    info = {
        "server": {"server_name": "valkey", "valkey_version": "8.0.1"},
        "default": {
            "role": "slave",
            "master_link_status": "down",
            "keyspace_hits": 90,
            "keyspace_misses": 10,
            "used_memory": 950,
            "maxmemory": 1000,
            "mem_fragmentation_ratio": 1.8,
            "evicted_keys": 7,
            "rejected_connections": 2,
            "blocked_clients": 1,
            "db0": {"keys": 3},
        },
    }
    out = dataplane.health_summary(FakeRedis(infos=info))
    assert out["engine"] == "valkey" and out["version"] == "8.0.1"
    assert out["hit_ratio"] == 0.9
    text = " ".join(out["findings"])
    for needle in ("95%", "7 keys evicted", "fragmentation", "rejected", "blocked", "link is down"):
        assert needle in text
    assert out["keyspace"] == {"db0": {"keys": 3}}


def test_health_summary_clean_and_low_fragmentation():
    out = dataplane.health_summary(FakeRedis(infos={"d": {"role": "master", "redis_version": "7.1.0"}}))
    assert out["engine"] == "redis" and out["findings"] == ["no issues detected by basic thresholds"]
    out = dataplane.health_summary(FakeRedis(infos={"d": {"used_memory": 10, "mem_fragmentation_ratio": 0.5}}))
    assert "swapping" in out["findings"][0]


def test_memory_report_verdicts_and_unavailable():
    r = FakeRedis(infos={"memory": _mem_info(mem_fragmentation_ratio=2.0), "stats": {"evicted_keys": 3}})
    r.commands["MEMORY DOCTOR"] = redis.ResponseError("disabled")
    out = dataplane.memory_report(r)
    assert out["fragmentation_verdict"].startswith("high")
    assert out["usage_of_maxmemory"] == 0.1
    assert out["memory_doctor"] == {"unavailable": "disabled"}
    assert out["memory_stats"] == {"peak.allocated": 1}
    low = dataplane.memory_report(FakeRedis(infos={"memory": _mem_info(mem_fragmentation_ratio=0.4), "stats": {}}))
    assert low["fragmentation_verdict"].startswith("below 1.0")


def _slowlog_entries():
    return [
        {
            "id": 1,
            "start_time": 1,
            "duration": 500,
            "command": "SET secretkey supersecretvalue",
            "client_address": "1.2.3.4:5",
            "client_name": b"app",
        },
        {
            "id": 2,
            "start_time": 2,
            "duration": 900,
            "command": b"HGETALL big",
            "client_address": "x",
            "client_name": "",
        },
    ]


def test_slowlog_redacts_arguments_by_default():
    r = FakeRedis()
    r.slowlog_entries = _slowlog_entries()
    out = dataplane.slowlog(r, count=10)
    first = out["entries"][0]
    assert first["command"] == "SET secretkey ..."
    assert "supersecretvalue" not in repr(out)
    assert out["by_command"][0]["command"] == "HGETALL"  # ranked by total time
    assert out["slowlog_len"] == 2 and first["client_name"] == "app"


def test_slowlog_include_args_returns_full_command():
    r = FakeRedis()
    r.slowlog_entries = _slowlog_entries()
    out = dataplane.slowlog(r, count=10, include_args=True)
    assert out["entries"][0]["command"] == "SET secretkey supersecretvalue"


def test_slowlog_clamps_count():
    r = FakeRedis()
    r.slowlog_entries = _slowlog_entries()
    assert dataplane.slowlog(r, count=0)["returned"] == 1


def test_client_list_aggregates():
    r = FakeRedis()
    r.clients = [
        {"id": 1, "addr": "10.0.0.1:1000", "name": "a", "user": "u1", "idle": "5000", "cmd": "get", "omem": "10"},
        {"id": 2, "addr": "10.0.0.1:1001", "name": "", "user": "", "idle": "1", "cmd": "set", "qbuf": "999"},
        {"id": 3, "addr": "10.0.0.2:5", "name": "a", "user": "u1", "idle": "20", "cmd": "get"},
    ]
    out = dataplane.client_list(r, top=2)
    assert out["total"] == 3
    assert out["by_source_ip"][0] == ("10.0.0.1", 2)
    assert dict(out["by_name"]) == {"a": 2, "(unnamed)": 1}
    assert dict(out["by_user"])["default"] == 1
    assert out["idle_seconds"]["max"] == 5000 and out["idle_seconds"]["over_1h"] == 1
    assert out["top_by_buffer_memory"][0]["id"] == 2


def test_client_list_empty():
    out = dataplane.client_list(FakeRedis())
    assert out["total"] == 0 and out["idle_seconds"]["max"] == 0


def test_commandstats_ranked_by_time():
    r = FakeRedis(
        infos={
            "commandstats": {
                "cmdstat_get": {"calls": 10, "usec": 100, "usec_per_call": 10.0, "failed_calls": 1},
                "cmdstat_hgetall": {"calls": 2, "usec": 5000, "usec_per_call": 2500.0},
            }
        }
    )
    out = dataplane.commandstats(r, top=5)
    assert out["commands"] == 2
    assert out["top_by_total_time"][0]["command"] == "hgetall"
    assert out["top_by_total_time"][1]["failed_calls"] == 1


def test_replication_lag_and_role_unavailable():
    r = FakeRedis(
        infos={
            "replication": {
                "role": "master",
                "connected_slaves": 1,
                "master_repl_offset": 1000,
                "slave0": {"ip": "1.1.1.1", "port": 6379, "offset": 400},
            }
        }
    )
    out = dataplane.replication(r)
    assert out["replicas"][0]["lag_bytes"] == 600
    assert "unavailable" in out["role_command"]
    r.commands["ROLE"] = [b"master", 1000, []]
    assert dataplane.replication(r)["role_command"] == ["master", 1000, []]


def test_latency_reports_events_and_threshold():
    out = dataplane.latency(FakeRedis(), ping_samples=5)
    assert out["ping_rtt_ms"]["samples"] == 5
    assert out["latency_latest"][0]["event"] == "command"
    assert out["latency_monitor_threshold"] == "100"


def test_cluster_disabled_and_enabled():
    assert dataplane.cluster(FakeRedis(infos={"cluster": {"cluster_enabled": 0}}))["cluster_enabled"] is False
    r = FakeRedis(infos={"cluster": {"cluster_enabled": 1}})
    r.commands["CLUSTER INFO"] = "cluster_state:ok\r\ncluster_slots_assigned:16384\r\n"
    r.commands["CLUSTER SLOTS"] = [[0, 8191, [b"10.0.0.1", 6379]], [8192, 16383, [b"10.0.0.2", 6379]]]
    out = dataplane.cluster(r)
    assert out["slots_covered"] == 16384
    assert out["cluster_info"]["cluster_state"] == "ok"
    assert out["shards"] == {"unavailable": "unknown command CLUSTER SHARDS"}


# ------------------------------------------------------------ node_info redaction


def test_node_info_redacts_password_like_keys():
    r = FakeRedis(infos={"server": {"masterauth": "hunter2", "requirepass": "p", "redis_version": "7.0.0"}})
    r.infos["x"] = {"nested": {"masteruser": "root", "ok": 1}, "acl_access_denied_auth": 3, "my_token": "t"}
    out = dataplane.server_info(r)["info"]
    assert out["masterauth"] == out["requirepass"] == dataplane.REDACTED
    assert out["nested"] == {"masteruser": dataplane.REDACTED, "ok": 1}
    assert out["my_token"] == dataplane.REDACTED
    assert out["acl_access_denied_auth"] == 3  # a counter, not a secret
    assert out["redis_version"] == "7.0.0"
    assert "hunter2" not in repr(out)


def test_node_info_redacts_in_section_call():
    r = FakeRedis(infos={"server": {"requirepass": "p"}})
    assert dataplane.server_info(r, "server")["info"] == {"requirepass": dataplane.REDACTED}


# ---------------------------------------------------------------------- keyspace


def _keys(n):
    return {f"k{i:04d}": ("string", 100 + i, -1, 10 + i) for i in range(n)}


def test_keyspace_sample_complete_scan():
    r = FakeRedis(infos={"memory": _mem_info()}, data=_keys(25))
    out = dataplane.keyspace_sample(r, sample_size=1000, top=3)
    assert out["sampled_keys"] == 25
    assert out["complete_scan"] is True and out["partial"] is False and out["partial_reason"] is None
    assert out["keys_without_ttl"] == 25
    assert out["big_keys_by_bytes"][0]["key"] == "k0024"
    assert out["cluster_mode"] is False
    assert "coldest_keys_by_idle" in out


def test_keyspace_sample_lfu_branch_and_sample_cap():
    r = FakeRedis(infos={"memory": _mem_info(maxmemory_policy="allkeys-lfu")}, data=_keys(30))
    out = dataplane.keyspace_sample(r, sample_size=12)
    assert out["sampled_keys"] == 12
    assert out["complete_scan"] is False and out["partial"] is False
    assert "hot_keys_by_lfu" in out


def test_keyspace_sample_deadline_stops_scan_with_partial():
    # Every SCAN batch really sleeps; the 0.05 s budget must cut the scan short.
    r = FakeRedis(infos={"memory": _mem_info()}, data=_keys(500), scan_batch=5, scan_delay=0.03)
    out = dataplane.keyspace_sample(r, sample_size=500, max_seconds=0.05)
    assert out["partial"] is True
    assert out["complete_scan"] is False
    assert "scanning" in out["partial_reason"]
    assert r.scan_calls < 100  # a full scan needs 100 batches
    assert out["sampled_keys"] < 500


def test_keyspace_sample_deadline_stops_pipeline_loop():
    # SCAN is instant but each pipeline round trip is slow: the loop must stop between chunks.
    r = FakeRedis(infos={"memory": _mem_info()}, data=_keys(1000), scan_batch=1000, pipeline_delay=0.05)
    out = dataplane.keyspace_sample(r, sample_size=1000, max_seconds=0.08)
    assert out["partial"] is True and out["complete_scan"] is False
    assert "inspecting" in out["partial_reason"]
    assert 0 < out["sampled_keys"] < 1000


def test_keyspace_sample_deadline_with_fake_clock_is_deterministic():
    ticks = itertools.count(0, 4)  # each clock() call advances 4 s
    r = FakeRedis(infos={"memory": _mem_info()}, data=_keys(300), scan_batch=300)
    out = dataplane.keyspace_sample(r, sample_size=300, max_seconds=10, clock=lambda: next(ticks))
    assert out["partial"] is True
    assert out["max_seconds"] == 10


def test_keyspace_sample_max_seconds_is_clamped():
    r = FakeRedis(infos={"memory": _mem_info()}, data=_keys(3))
    assert dataplane.keyspace_sample(r, max_seconds=10_000)["max_seconds"] == dataplane.MAX_SAMPLE_SECONDS == 60.0
    assert dataplane.keyspace_sample(r, max_seconds=-5)["max_seconds"] == 0.01


def test_keyspace_sample_notes_cluster_mode():
    r = FakeRedis(infos={"memory": _mem_info(), "cluster": {"cluster_enabled": 1}}, data=_keys(3))
    out = dataplane.keyspace_sample(r)
    assert out["cluster_mode"] is True
    assert "only the slots owned by this node" in out["cluster_note"]
    assert out["scope"] == "connected node only"


# ------------------------------------------------------------------ cluster nodes

NODES = """\
aaa 10.0.0.1:6379@16379,shard1-a.example.com master - 0 1700000000000 1 connected 0-5460
bbb 10.0.0.2:6379@16379,shard1-b.example.com slave aaa 0 1700000000000 1 connected
ccc 10.0.0.3:6379@16379 myself,master - 0 0 2 connected 5461-10922 [5500->-zzz]
ddd 10.0.0.4:6379@16379 master,fail - 0 0 3 disconnected 10923-16383
"""


def test_parse_cluster_nodes():
    nodes = {n["id"]: n for n in dataplane.parse_cluster_nodes(NODES)}
    assert nodes["aaa"]["hostname"] == "shard1-a.example.com" and nodes["aaa"]["slot_count"] == 5461
    assert nodes["bbb"]["role"] == "replica" and nodes["bbb"]["master_id"] == "aaa"
    assert nodes["ccc"]["myself"] and nodes["ccc"]["hostname"] is None
    assert nodes["ccc"]["slots"] == ["5461-10922"]  # migrating slot markers ignored
    assert nodes["ddd"]["failing"] is True and nodes["aaa"]["failing"] is False


def test_cluster_nodes_groups_by_shard_and_flags_failures():
    r = FakeRedis(infos={"cluster": {"cluster_enabled": 1}})
    r.commands["CLUSTER NODES"] = NODES
    out = dataplane.cluster_nodes(r)
    assert out["shards"][0]["primary"] == "shard1-a.example.com:6379"
    assert out["shards"][0]["replicas"] == ["shard1-b.example.com:6379"]
    assert [s["slot_count"] for s in out["shards"]] == [5461, 5462, 5461]  # ordered by first slot
    assert out["slots_covered"] == 16384
    assert any("10.0.0.4:6379" in f for f in out["findings"])
    assert "ELASTICACHE_HOST" in out["recommendation"]


def test_cluster_nodes_standalone_and_unavailable():
    assert dataplane.cluster_nodes(FakeRedis(infos={"cluster": {"cluster_enabled": 0}}))["cluster_enabled"] is False
    r = FakeRedis(infos={"cluster": {"cluster_enabled": 1}})
    assert "unavailable" in dataplane.cluster_nodes(r)


# ---------------------------------------------------------------- cluster health


def _healthy_topology():
    return (
        "p1 10.0.0.1:6379@1 master - 0 0 1 connected 0-5460\n"
        "p2 10.0.0.2:6379@1 master - 0 0 2 connected 5461-10922\n"
        "p3 10.0.0.3:6379@1 master - 0 0 3 connected 10923-16383\n"
        "r1 10.0.0.4:6379@1 slave p1 0 0 1 connected\n"
    )


def _fleet(topology, node_infos):
    seed = FakeRedis(infos={"cluster": {"cluster_enabled": 1}})
    seed.commands["CLUSTER NODES"] = topology
    clients: dict[str, FakeRedis] = {}

    def factory(host, port):
        info = node_infos[f"{host}:{port}"]
        if isinstance(info, Exception):
            raise info
        clients[host] = FakeRedis(infos={"all": info})
        return clients[host]

    return seed, factory, clients


def test_cluster_health_flags_skew_lag_and_closes_clients():
    infos = {
        "10.0.0.1:6379": {
            "role": "master",
            "used_memory": 9000,
            "instantaneous_ops_per_sec": 5000,
            "master_repl_offset": 5_000_000,
            "slave0": {"ip": "10.0.0.4", "port": 6379, "offset": 100},
        },
        "10.0.0.2:6379": {"role": "master", "used_memory": 1000, "instantaneous_ops_per_sec": 100},
        "10.0.0.3:6379": {"role": "master", "used_memory": 1000, "instantaneous_ops_per_sec": 100},
        "10.0.0.4:6379": {"role": "slave", "master_link_status": "down"},
    }
    seed, factory, clients = _fleet(_healthy_topology(), infos)
    out = dataplane.cluster_health(seed, factory)
    text = " | ".join(out["findings"])
    assert "10.0.0.1:6379 memory" in text and "skew" in text
    assert "10.0.0.1:6379 ops/sec" in text
    assert "lags" in text and "10.0.0.4:6379" in text
    assert "link is down" in text
    assert out["nodes_probed"] == 4 and out["slots_covered"] == 16384
    assert all(c.closed for c in clients.values())


def test_cluster_health_balanced_has_no_findings():
    infos = {
        f"10.0.0.{i}:6379": {"role": "master", "used_memory": 1000, "instantaneous_ops_per_sec": 100} for i in (1, 2, 3)
    }
    infos["10.0.0.4:6379"] = {"role": "slave", "master_link_status": "up"}
    seed, factory, _ = _fleet(_healthy_topology(), infos)
    out = dataplane.cluster_health(seed, factory)
    assert out["findings"] == ["no skew, lag or coverage problems detected"]


def test_cluster_health_flags_uncovered_slots_failed_and_unreachable_nodes():
    topo = (
        "p1 10.0.0.1:6379@1 master - 0 0 1 connected 0-5460\n"
        "p2 10.0.0.2:6379@1 master,fail - 0 0 2 disconnected 5461-10922\n"
        "p3 10.0.0.3:6379@1 master - 0 0 3 connected 10923-16000\n"
    )
    infos = {
        "10.0.0.1:6379": {"role": "master", "used_memory": 10},
        "10.0.0.3:6379": ConnectionError("boom"),
    }
    seed, factory, _ = _fleet(topo, infos)
    out = dataplane.cluster_health(seed, factory)
    text = " | ".join(out["findings"])
    assert "slots covered" in text
    assert "10.0.0.2:6379 is master,fail" in text
    assert "10.0.0.3:6379 unreachable" in text and "boom" in text
    assert out["nodes_probed"] == 2  # the failed node was not probed


def test_cluster_health_per_node_timeout_does_not_hang():
    seed = FakeRedis(infos={"cluster": {"cluster_enabled": 1}})
    seed.commands["CLUSTER NODES"] = "p1 10.0.0.1:6379@1 master - 0 0 1 connected 0-16383\n"

    class Slow(FakeRedis):
        def info(self, section=None):
            time.sleep(0.5)
            return {}

    t0 = time.monotonic()
    out = dataplane.cluster_health(seed, lambda h, p: Slow(), per_node_timeout=0.05)
    assert time.monotonic() - t0 < 0.4
    assert "timeout" in out["per_node"]["10.0.0.1:6379"]["error"]


def test_cluster_health_non_cluster_returns_note():
    out = dataplane.cluster_health(FakeRedis(infos={"cluster": {"cluster_enabled": 0}}), lambda h, p: None)
    assert out["cluster_enabled"] is False


def test_helpers():
    def boom():
        raise redis.ResponseError("nope")

    assert dataplane._try(boom) == (None, "nope")
    assert dataplane._num("x", 3.0) == 3.0
    assert dataplane._jsonable({b"k": [b"v", (1,)]}) == {"k": ["v", [1]]}


@pytest.mark.parametrize("info,engine", [({"server_name": "valkey"}, "valkey"), ({"redis_version": "7"}, "redis")])
def test_engine_of(info, engine):
    assert dataplane.engine_of(info)["engine"] == engine
