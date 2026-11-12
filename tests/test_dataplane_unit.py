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


# ------------------------------------------------------------------ node_config


class ConfigFake(FakeRedis):
    """Serves CONFIG GET from a dict (glob patterns like the real server) and records every request."""

    def __init__(self, values: dict[str, str] | None = None, refuse: bool = False, **kw):
        super().__init__(**kw)
        self.values = values or {}
        self.refuse = refuse
        self.requested: list[str] = []

    def config_get(self, pattern):
        self.requested.append(pattern)
        if self.refuse:
            raise redis.ResponseError("unknown command 'CONFIG'")
        import fnmatch

        return {k: v for k, v in self.values.items() if fnmatch.fnmatchcase(k, pattern)}


def _messages(out: dict) -> str:
    return " | ".join(f["message"] for f in out["findings"])


def test_config_view_findings_for_a_misconfigured_cache():
    values = {
        "maxmemory": "1000",
        "maxmemory-policy": "noeviction",
        "timeout": "0",
        "appendonly": "yes",
        "latency-monitor-threshold": "0",
        "slowlog-log-slower-than": "-1",
        "notify-keyspace-events": "KEA",
        "io-threads": "4",
        "client-output-buffer-limit": "normal 0 0 0 replica 268435456 67108864 60 pubsub 33554432 8388608 60",
    }
    fake = ConfigFake(values)
    fake.clients = [{"idle": "7200"}] * 25 + [{"idle": "1"}]
    out = dataplane.config_view(fake)
    assert out["available"] is True
    assert out["config"]["io-threads"] == "4"
    assert out["config"]["client-output-buffer-limit"].startswith("normal 0 0 0")
    text = _messages(out)
    for needle in (
        "noeviction",
        "timeout is 0",
        "25 clients",
        "appendonly is yes",
        "latency-monitor-threshold is 0",
        "slow log is disabled",
        "notify-keyspace-events",
    ):
        assert needle in text, needle
    severities = [f["severity"] for f in out["findings"]]
    assert severities == sorted(severities, key={"critical": 0, "warning": 1, "info": 2}.get)
    assert {f["parameter"] for f in out["findings"]} >= {"maxmemory-policy", "timeout", "appendonly"}


def test_config_view_clean_config_has_no_findings():
    values = {
        "maxmemory": "1000",
        "maxmemory-policy": "allkeys-lru",
        "timeout": "300",
        "appendonly": "no",
        "latency-monitor-threshold": "100",
        "slowlog-log-slower-than": "10000",
        "notify-keyspace-events": "",
    }
    out = dataplane.config_view(ConfigFake(values))
    assert out["findings"] == []


def test_config_view_timeout_zero_needs_many_idle_clients():
    fake = ConfigFake({"timeout": "0"})
    fake.clients = [{"idle": "7200"}] * 3
    assert dataplane.config_view(fake)["findings"] == []


def test_config_view_slowlog_zero_and_narrow_keyspace_events():
    out = dataplane.config_view(ConfigFake({"slowlog-log-slower-than": "0", "notify-keyspace-events": "Ex"}))
    by_param = {f["parameter"]: f for f in out["findings"]}
    assert "every command is logged" in by_param["slowlog-log-slower-than"]["message"]
    assert by_param["notify-keyspace-events"]["severity"] == "info"


def test_config_view_falls_back_when_config_is_refused():
    out = dataplane.config_view(ConfigFake(refuse=True))
    assert out["available"] is False
    assert out["config"] == {} and out["findings"] == []
    assert "aws_parameters" in " ".join(out["notes"])


def test_config_view_partial_refusal_keeps_what_it_got():
    class Partial(ConfigFake):
        def config_get(self, pattern):
            if pattern.startswith("slowlog"):
                self.requested.append(pattern)
                raise redis.ResponseError("denied")
            return super().config_get(pattern)

    out = dataplane.config_view(Partial({"timeout": "5"}))
    assert out["available"] is True and out["config"] == {"timeout": "5"}
    assert out["refused_patterns"] == ["slowlog-*"]


def test_config_view_never_requests_secret_parameters():
    from mcp_elasticache_ops import safe_client

    fake = ConfigFake({"requirepass": "hunter2", "masterauth": "hunter2", "masteruser": "u", "timeout": "5"})
    out = dataplane.config_view(fake)
    assert fake.requested, "nothing was requested"
    secret = ("requirepass", "masterauth", "masteruser", "tls-", "aclfile", "user")
    for pattern in fake.requested:
        assert not pattern.startswith(secret), pattern
        assert pattern != "*" and "?" not in pattern
        safe_client.check(("CONFIG", "GET", pattern))  # the SafeRedis allowlist accepts every request
    assert "hunter2" not in str(out)
    assert set(out["config"]) == {"timeout"}


def test_config_view_through_safe_redis_is_never_blocked(monkeypatch):
    """Every pattern config_view sends passes the real SafeRedis CONFIG GET check."""
    from mcp_elasticache_ops import safe_client

    seen = []
    monkeypatch.setattr(redis.Redis, "execute_command", lambda self, *a, **k: seen.append(a) or {})
    client = safe_client.SafeRedis()
    dataplane.config_view(client)
    assert seen and all(a[0] == "CONFIG GET" for a in seen)


# -------------------------------------------------------------------- serverless


class RefusingRedis(FakeRedis):
    """Behaves like an endpoint that rejects admin commands with ResponseError."""

    def slowlog_get(self, count):
        raise redis.ResponseError("unknown command 'SLOWLOG'")

    def slowlog_len(self):
        raise redis.ResponseError("unknown command 'SLOWLOG'")

    def memory_stats(self):
        raise redis.ResponseError("unknown command 'MEMORY'")

    def info(self, section=None):
        if section is None or section in {"cluster", "memory", "stats"}:
            raise redis.ResponseError("ERR unsupported INFO section")
        return super().info(section)


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("mycache-abc123.serverless.use1.cache.amazonaws.com", True),
        ("MyCache.SERVERLESS.eu-west-1.cache.amazonaws.com", True),
        ("my-rg.abc123.ng.0001.use1.cache.amazonaws.com", False),
        ("serverless.example.com", False),
        ("127.0.0.1", False),
        (None, False),
    ],
)
def test_is_serverless_host(host, expected):
    assert dataplane.is_serverless_host(host) is expected


def test_serverless_tools_return_notes_instead_of_raising():
    r = RefusingRedis(infos={"server": {"redis_version": "7.1"}, "clients": {"connected_clients": 3}})
    health = dataplane.health_summary(r, serverless=True)
    assert health["connected_clients"] == 3 and health["serverless"] is True
    assert any("serverless: command not supported" in n for n in health["notes"])

    mem = dataplane.memory_report(r, serverless=True)
    assert any("INFO memory" in n and "serverless: command not supported" in n for n in mem["notes"])
    assert any("aws_metrics" in n for n in mem["notes"])

    slow = dataplane.slowlog(r, serverless=True)
    assert slow["entries"] == [] and slow["slowlog_len"] is None
    assert "serverless: command not supported" in slow["notes"][0]

    cl = dataplane.cluster(r, serverless=True)
    assert cl["cluster_enabled"] is True
    assert any("CLUSTER" in n for n in cl["notes"])

    nodes = dataplane.cluster_nodes(r, serverless=True)
    assert nodes["cluster_enabled"] is True and "unavailable" in nodes
    assert any("single TLS endpoint" in n or "one TLS endpoint" in n for n in nodes["notes"])


def test_refused_commands_on_a_plain_endpoint_say_unavailable():
    r = RefusingRedis()
    health = dataplane.health_summary(r)
    assert health["findings"] == ["INFO is not available on this endpoint"]
    assert all("serverless" not in n for n in health["notes"])
    assert dataplane.slowlog(r)["notes"][0].startswith("SLOWLOG GET: unavailable")
    assert dataplane.cluster(r)["cluster_enabled"] is False


def test_working_endpoint_output_is_unchanged_by_serverless_flag():
    info = {"server": {"redis_version": "7.2"}, "default": {"role": "master", "used_memory": 10, "maxmemory": 100}}
    out = dataplane.health_summary(FakeRedis(infos=info))
    assert "notes" not in out and "serverless" not in out


# ------------------------------------------------------------ round 03: cluster-wide fan-out


def _shard_data(tag, n, size):
    return {f"{tag}:k{j:03d}": ("string", size + j, -1, 1) for j in range(n)}


def _shard_client(tag, n=20, size=100, **kw):
    return FakeRedis(infos={"memory": _mem_info()}, data=_shard_data(tag, n, size), **kw)


def _fan_factory(clients):
    opened = []

    def factory(host, port):
        c = clients[f"{host}:{port}"]
        if isinstance(c, Exception):
            raise c
        if callable(c):
            c = c()
        opened.append(c)
        return c

    return factory, opened


def _seed():
    seed = FakeRedis(infos={"cluster": {"cluster_enabled": 1}})
    seed.commands["CLUSTER NODES"] = _healthy_topology()
    return seed


def test_cluster_keyspace_sample_merges_top_keys_with_shard_label():
    clients = {
        "10.0.0.1:6379": _shard_client("a", size=100),
        "10.0.0.2:6379": _shard_client("b", size=5000),
        "10.0.0.3:6379": _shard_client("c", size=300),
    }
    factory, opened = _fan_factory(clients)
    out = dataplane.cluster_keyspace_sample(_seed(), factory, sample_size=90, top=3, max_seconds=5)
    assert out["scope"] == "all shard primaries"
    assert (out["shards_total"], out["shards_ok"], out["shards_unreachable"]) == (3, 3, 0)
    assert out["partial"] is False
    top = out["big_keys_by_bytes"]
    assert [k["shard"] for k in top] == ["10.0.0.2:6379"] * 3  # the big shard owns the top 3
    assert all(k["key"].startswith("b:") for k in top)
    assert set(out["per_shard"]) == {"10.0.0.1:6379", "10.0.0.2:6379", "10.0.0.3:6379"}
    assert out["sampled_keys"] == 60 and out["dbsize"] == 60
    assert all(c.closed for c in opened)
    assert all("shard" in k for k in out["big_keys_by_length"])


def test_cluster_keyspace_sample_reports_dead_shard_without_failing():
    clients = {
        "10.0.0.1:6379": _shard_client("a"),
        "10.0.0.2:6379": redis.ConnectionError("connection refused"),
        "10.0.0.3:6379": _shard_client("c"),
    }
    factory, _ = _fan_factory(clients)
    out = dataplane.cluster_keyspace_sample(_seed(), factory, sample_size=60, max_seconds=5)
    assert (out["shards_ok"], out["shards_unreachable"]) == (2, 1)
    assert out["partial"] is True
    assert out["per_shard"]["10.0.0.2:6379"]["status"] == "unreachable"
    assert "connection refused" in out["per_shard"]["10.0.0.2:6379"]["error"]
    crit = [f for f in out["findings"] if f["severity"] == "critical"]
    assert crit and crit[0]["shard"] == "10.0.0.2:6379"
    assert out["findings"][0]["severity"] == "critical"  # worst first
    assert {k["shard"] for k in out["big_keys_by_bytes"]} <= {"10.0.0.1:6379", "10.0.0.3:6379"}


def test_cluster_keyspace_sample_does_not_contact_failing_nodes():
    topo = _healthy_topology().replace("p2 10.0.0.2:6379@1 master -", "p2 10.0.0.2:6379@1 master,fail -")
    seed = FakeRedis(infos={"cluster": {"cluster_enabled": 1}})
    seed.commands["CLUSTER NODES"] = topo
    clients = {"10.0.0.1:6379": _shard_client("a"), "10.0.0.3:6379": _shard_client("c")}
    factory, opened = _fan_factory(clients)  # a KeyError would surface if 10.0.0.2 were contacted
    out = dataplane.cluster_keyspace_sample(seed, factory, sample_size=40, max_seconds=5)
    assert out["per_shard"]["10.0.0.2:6379"]["status"] == "unreachable"
    assert "not contacted" in out["per_shard"]["10.0.0.2:6379"]["error"]
    assert len(opened) == 2


def _slow_shard(tag):
    return lambda: _shard_client(tag, n=3000, scan_batch=5, scan_delay=0.02)


def test_cluster_keyspace_sample_respects_total_time_budget():
    clients = {f"10.0.0.{i}:6379": _slow_shard(t) for i, t in ((1, "a"), (2, "b"), (3, "c"))}
    factory, _ = _fan_factory(clients)
    started = time.monotonic()
    out = dataplane.cluster_keyspace_sample(
        _seed(), factory, sample_size=9000, max_seconds=0.6, max_workers=3, per_node_timeout=1.0
    )
    wall = time.monotonic() - started
    assert wall < 0.6 + 1.0  # budget plus the hard per-node grace, never the full scan time (~12s)
    assert out["partial"] is True and out["shards_partial"] == 3
    assert all(s["status"] == "partial" for s in out["per_shard"].values())
    assert out["sampled_keys"] < 9000


def test_fan_out_splits_budget_across_waves():
    seen = []

    def work(client, budget, shards):
        seen.append((budget, shards))
        return {}

    factory, _ = _fan_factory({f"10.0.0.{i}:6379": FakeRedis for i in (1, 2, 3)})
    dataplane._fan_out_primaries(_seed(), factory, work, max_workers=1, total_seconds=9.0, per_node_timeout=1.0)
    assert seen == [(3.0, 3)] * 3  # 3 primaries, 1 worker -> 3 waves of 3s
    seen.clear()
    dataplane._fan_out_primaries(_seed(), factory, work, max_workers=3, total_seconds=9.0, per_node_timeout=1.0)
    assert seen == [(9.0, 3)] * 3


def test_cluster_keyspace_sample_hung_shard_is_abandoned():
    def hang():
        time.sleep(3)
        return _shard_client("b")

    clients = {"10.0.0.1:6379": _shard_client("a"), "10.0.0.2:6379": hang, "10.0.0.3:6379": _shard_client("c")}
    factory, _ = _fan_factory(clients)
    started = time.monotonic()
    out = dataplane.cluster_keyspace_sample(_seed(), factory, sample_size=60, max_seconds=0.5, per_node_timeout=0.3)
    assert time.monotonic() - started < 2.0
    assert out["per_shard"]["10.0.0.2:6379"]["status"] == "unreachable"
    assert out["shards_ok"] == 2


def test_cluster_keyspace_sample_non_cluster_falls_back_to_single_node():
    r = _shard_client("solo")
    out = dataplane.cluster_keyspace_sample(r, lambda h, p: pytest.fail("no fan-out expected"), sample_size=10)
    assert out["cluster_enabled"] is False and out["sampled_keys"] == 10


def test_cluster_slowlog_merges_and_labels():
    def shard(cmd, us):
        c = FakeRedis(infos={"memory": _mem_info()})
        c.slowlog_entries = [{"id": 1, "start_time": 1, "duration": us, "command": f"{cmd} k", "client_name": ""}]
        return c

    clients = {
        "10.0.0.1:6379": shard("LRANGE", 900),
        "10.0.0.2:6379": ConnectionError("down"),
        "10.0.0.3:6379": shard("SORT", 50000),
    }
    factory, _ = _fan_factory(clients)
    out = dataplane.cluster_slowlog(_seed(), factory, count=5, max_seconds=5)
    assert out["shards_unreachable"] == 1
    assert out["entries"][0]["shard"] == "10.0.0.3:6379"
    assert {e["shard"] for e in out["entries"]} == {"10.0.0.1:6379", "10.0.0.3:6379"}
    assert out["findings"][0]["severity"] == "critical"


def test_cluster_memory_flags_pressure_and_dead_shard():
    def shard(used, maxmem=1000):
        return FakeRedis(infos={"memory": _mem_info(used_memory=used, maxmemory=maxmem), "stats": {"evicted_keys": 0}})

    clients = {
        "10.0.0.1:6379": shard(950),
        "10.0.0.2:6379": shard(100),
        "10.0.0.3:6379": ConnectionError("down"),
    }
    factory, _ = _fan_factory(clients)
    out = dataplane.cluster_memory(_seed(), factory, max_seconds=5)
    assert out["shards_unreachable"] == 1 and out["per_shard"]["10.0.0.3:6379"]["status"] == "unreachable"
    text = " ".join(f["message"] for f in out["findings"])
    assert "10.0.0.1:6379" in text
    assert out["per_shard"]["10.0.0.1:6379"]["used_memory"] == 950


# ------------------------------------------------------- round 03: replication read-safety


def _repl_info(role="master", **over):
    base = {"role": role, "master_repl_offset": 10_000_000, "connected_slaves": 0}
    return {**base, **over}


def _repl_client(info, config=None):
    r = FakeRedis(infos={"replication": info, "server": {"valkey_version": "8.0.1", "server_name": "valkey"}})
    if config is not None:
        r.config_get = lambda name: {name: config[name]} if name in config else {}
    return r


def test_replication_flags_lagging_and_link_down_replicas():
    info = _repl_info(
        connected_slaves=2,
        slave0={"ip": "10.0.0.4", "port": 6379, "state": "online", "offset": 1_000, "lag": 0},
        slave1={"ip": "10.0.0.5", "port": 6379, "state": "wait_bgsave", "offset": 10_000_000, "lag": 42},
    )
    out = dataplane.replication(_repl_client(info))
    msgs = [f["message"] for f in out["findings"]]
    assert any("10.0.0.4:6379" in m and "bytes behind" in m for m in msgs)
    assert any("10.0.0.5:6379" in m and "wait_bgsave" in m for m in msgs)
    assert any("last acknowledged 42s ago" in m for m in msgs)
    assert out["findings"][0]["severity"] == "critical"  # the link problem sorts first


def test_replication_primary_without_replicas_is_a_finding():
    out = dataplane.replication(_repl_client(_repl_info()))
    assert any("no replicas connected" in f["message"] for f in out["findings"])


def test_replica_link_down_and_offset_gap_through_the_factory():
    info = _repl_info(
        role="slave",
        master_host="10.0.0.1",
        master_port=6379,
        master_link_status="down",
        master_link_down_since_seconds=120,
        master_last_io_seconds_ago=60,
        slave_repl_offset=1_000,
    )
    primary = FakeRedis(infos={"replication": {"master_repl_offset": 9_000_000}})
    seen = []

    def factory(host, port):
        seen.append((host, port))
        return primary

    out = dataplane.replication(_repl_client(info), factory)
    msgs = [f["message"] for f in out["findings"]]
    assert seen == [("10.0.0.1", 6379)] and primary.closed
    assert any("link to the primary is down for 120s" in m for m in msgs)
    assert any("last I/O with the primary was 60s ago" in m for m in msgs)
    assert any("8999000 bytes behind the primary" in m for m in msgs)


def test_replica_unreachable_primary_becomes_a_note():
    info = _repl_info(role="slave", master_host="10.0.0.1", master_port=6379, slave_repl_offset=5)

    def factory(host, port):
        raise ConnectionError("refused")

    out = dataplane.replication(_repl_client(info), factory)
    assert any("unreachable for offset comparison" in n for n in out["notes"])


def test_replication_setting_findings():
    config = {"replica-read-only": "no", "min-replicas-to-write": "2", "cluster-allow-reads-when-down": "yes"}
    replica = dataplane.replication(_repl_client(_repl_info(role="slave"), config))
    text = " ".join(f["message"] for f in replica["findings"])
    assert "replica-read-only is no" in text and "cluster-allow-reads-when-down is yes" in text
    primary = dataplane.replication(_repl_client(_repl_info(connected_slaves=1), config))
    assert any(
        f["severity"] == "critical" and "min-replicas-to-write is 2" in f["message"] for f in primary["findings"]
    )
    assert primary["settings"]["min-replicas-to-write"] == "2"


class _Redis6(FakeRedis):
    def __init__(self):
        super().__init__(infos={"cluster": {"cluster_enabled": 1}, "server": {"redis_version": "6.2.6"}})
        self.commands["CLUSTER INFO"] = "cluster_state:ok\r\ncluster_slots_assigned:16384\r\n"
        self.commands["CLUSTER SHARDS"] = redis.ResponseError("unknown subcommand shards")
        self.commands["CLUSTER SLOTS"] = [[0, 16383, ["10.0.0.1", 6379, "id"]]]


def test_redis6_refusing_cluster_shards_is_a_note_not_an_error():
    out = dataplane.cluster(_Redis6())
    assert out["cluster_enabled"] is True and out["slots_covered"] == 16384
    assert out["shards"] == {"unavailable": "unknown subcommand shards"}
    note = " ".join(out["notes"])
    assert "CLUSTER SHARDS: not supported by redis 6.2.6 (needs 7.0+)" in note
    assert "node_cluster_nodes" in note


def test_command_support_note_and_version_tuple():
    assert dataplane.version_tuple("7.2.4") == (7, 2, 4)
    assert dataplane.version_tuple("8.0-rc1") == (8, 0)
    assert dataplane.version_tuple(None) == ()
    old = {"redis_version": "5.0.7"}
    assert "not supported by redis 5.0.7 (needs 6.0+)" in dataplane.command_support_note("ACL LOG", old, "x")
    new = {"valkey_version": "8.0.1", "server_name": "valkey"}
    assert dataplane.command_support_note("ACL LOG", new, "boom") == "ACL LOG: unavailable (boom)"


# ------------------------------------------------------------------- round 03: ACL log


def _acl_entry(reason="auth", user="app", count=1, age=10.0, obj="GET", info=None):
    return {
        "count": count,
        "reason": reason,
        "context": "toplevel",
        "object": obj,
        "username": user,
        "age-seconds": age,
        "client-info": info or "id=5 addr=10.1.1.1:5000 name=svc user=app lib-name=redis-py cmd=get password=hunter2",
    }


def test_acl_log_aggregates_redacts_and_flags():
    r = FakeRedis(infos={"server": {"valkey_version": "8.0.1"}})
    r.commands["ACL WHOAMI"] = "default"
    r.commands["ACL LOG 25"] = [
        _acl_entry("auth", "mallory", count=6),
        _acl_entry("key", "app", count=2, obj="user:secret:42"),
        _acl_entry("command", "app", count=25, age=5),
    ]
    out = dataplane.acl_log(r, 25)
    assert out["whoami"] == "default"
    assert out["by_reason"] == {"auth": 6, "key": 2, "command": 25}
    assert out["by_user"] == {"mallory": 6, "app": 27}
    text = " ".join(f["message"] for f in out["findings"])
    assert "6 failed authentications" in text and "mallory" in text and "ACL spike" in text
    dump = repr(out)
    assert "user:secret:42" not in dump and "hunter2" not in dump
    key_entry = next(e for e in out["entries"] if e["reason"] == "key")
    assert key_entry["object"] == "(name hidden)"
    assert out["entries"][0]["count"] == 25  # most frequent first
    assert set(out["entries"][0]["client"]) <= {"addr", "name", "user", "lib-name", "lib-ver", "cmd"}


def test_acl_log_clean_and_unsupported():
    r = FakeRedis(infos={"server": {"valkey_version": "8.0.1"}})
    r.commands["ACL WHOAMI"] = "default"
    r.commands["ACL LOG 25"] = []
    out = dataplane.acl_log(r, 25)
    assert out["entries"] == [] and out["findings"] == []

    old = FakeRedis(infos={"server": {"redis_version": "5.0.7"}})
    got = dataplane.acl_log(old, 25)
    assert got["entries"] == [] and "not supported by redis 5.0.7" in got["notes"][0]


# ------------------------------------------------- round 05: policy, fragmentation, persistence, buffers


def _risk_infos(**over):
    """Healthy single node; ``over`` is merged into the memory/stats/persistence/clients sections by prefix."""
    infos = {
        "server": {"redis_version": "7.2.4", "uptime_in_seconds": 6000},
        "memory": {
            "used_memory": 10,
            "maxmemory": 100,
            "used_memory_rss": 12,
            "mem_fragmentation_ratio": 1.1,
            "maxmemory_policy": "allkeys-lru",
        },
        "stats": {"keyspace_hits": 90, "keyspace_misses": 10, "evicted_keys": 0},
        "persistence": {"rdb_last_bgsave_status": "ok", "aof_last_write_status": "ok"},
        "clients": {"connected_clients": 3},
        "replication": {
            "role": "master",
            "connected_slaves": 1,
            "master_repl_offset": 1000,
            "slave0": {"ip": "10.0.0.2", "port": 6379, "state": "online", "offset": 1000, "lag": 0},
        },
        "commandstats": {},
    }
    for section, values in over.items():
        infos[section] = {**infos[section], **values}
    return infos


def _triage_messages(**over):
    out = dataplane.triage(FakeRedis(infos=_risk_infos(**over)), None)
    return out, {f["message"]: f for f in out["findings"]}


def _find(messages, needle):
    hits = [f for m, f in messages.items() if needle in m]
    assert hits, f"no finding containing {needle!r} in {list(messages)}"
    return hits[0]


def test_triage_baseline_is_quiet():
    out, _ = _triage_messages()
    # only the fake latency event (info) remains
    assert [f["severity"] for f in out["findings"]] == ["info"]


def test_triage_noeviction_with_high_memory_is_critical():
    _, msgs = _triage_messages(memory={"used_memory": 88, "maxmemory_policy": "noeviction"})
    assert _find(msgs, "noeviction at 88%")["severity"] == "critical"
    _, quiet = _triage_messages(memory={"used_memory": 50, "maxmemory_policy": "noeviction"})
    assert not any("noeviction at" in m for m in quiet)
    _, other = _triage_messages(memory={"used_memory": 88})
    assert not any("noeviction at" in m for m in other)


def test_triage_high_fragmentation_ratio():
    _, msgs = _triage_messages(memory={"mem_fragmentation_ratio": 1.8})
    assert _find(msgs, "high fragmentation ratio 1.80")["severity"] == "warning"


def test_triage_fragmentation_below_one_means_swapping():
    _, msgs = _triage_messages(memory={"mem_fragmentation_ratio": 0.6})
    assert _find(msgs, "fragmentation ratio 0.60 < 1")


def test_triage_evicted_keys_report_average_rate():
    _, msgs = _triage_messages(stats={"evicted_keys": 500})
    # 500 keys over 6000 s of uptime = 5.0 per minute
    assert _find(msgs, "500 keys evicted since restart, about 5.0/min on average")


def test_triage_failed_rdb_bgsave_is_reported():
    _, msgs = _triage_messages(persistence={"rdb_last_bgsave_status": "err"})
    assert _find(msgs, "rdb_last_bgsave_status=err")["severity"] == "warning"
    _, aof = _triage_messages(persistence={"aof_last_write_status": "err"})
    assert _find(aof, "aof_last_write_status=err")


def test_triage_replica_link_down_is_critical():
    _, msgs = _triage_messages(replication={"role": "slave", "master_link_status": "down"})
    assert any(f["severity"] == "critical" and "link is down" in m for m, f in msgs.items())


def test_triage_large_client_output_buffer():
    _, msgs = _triage_messages(clients={"client_recent_max_output_buffer": 64 * 1024 * 1024})
    assert _find(msgs, "client output buffer peaked at 64 MiB")["severity"] == "warning"
    _, inp = _triage_messages(clients={"client_recent_max_input_buffer": 32 * 1024 * 1024})
    assert _find(inp, "client input buffer peaked at 32 MiB")
    _, small = _triage_messages(clients={"client_recent_max_output_buffer": 20_000})
    assert not any("buffer peaked" in m for m in small)


def test_health_summary_falls_back_to_the_persistence_section():
    class NoBareInfo(FakeRedis):
        def info(self, section=None):
            if section is None:
                raise redis.ResponseError("unknown command 'INFO'")
            return super().info(section)

    out = dataplane.health_summary(NoBareInfo(infos=_risk_infos(persistence={"rdb_last_bgsave_status": "err"})))
    assert any("rdb_last_bgsave_status=err" in f for f in out["findings"])


def test_memory_report_findings_cover_policy_fragmentation_and_evictions():
    def run(mem=None, stats=None):
        infos = _risk_infos(memory=mem or {}, stats=stats or {})
        return dataplane.memory_report(FakeRedis(infos=infos))["findings"]

    def messages(findings):
        return " | ".join(f["message"] for f in findings)

    assert run() == []
    noevict = run(mem={"used_memory": 92, "maxmemory_policy": "noeviction"})
    assert {f["severity"] for f in noevict} == {"critical"}
    assert "maxmemory-policy is noeviction at 92%" in messages(noevict) and "memory at 92%" in messages(noevict)
    assert "mem_fragmentation_ratio 1.70 > 1.5" in messages(run(mem={"mem_fragmentation_ratio": 1.7}))
    assert "mem_fragmentation_ratio 0.50 < 1" in messages(run(mem={"mem_fragmentation_ratio": 0.5}))
    assert "42 keys evicted since restart" in messages(run(stats={"evicted_keys": 42}))


# ------------------------------------------- round 06: shared fan-out budget, partial_nodes


class _EndlessScan(FakeRedis):
    """A node whose SCAN never reaches cursor 0 and takes ``delay`` seconds per call; records call times."""

    def __init__(self, delay: float, **kw):
        super().__init__(infos={"memory": _mem_info()}, data=_shard_data("slow", 50, 100), **kw)
        self.delay = delay
        self.scan_times: list[float] = []

    def scan(self, cursor=0, match=None, count=10):
        self.scan_times.append(time.monotonic())
        time.sleep(self.delay)
        return 1 + cursor % 7, []  # never 0, never enough keys to stop on sample_size


def test_cluster_keyspace_sample_endless_scan_node_is_partial_and_within_budget():
    slow = _EndlessScan(delay=0.05)
    clients = {"10.0.0.1:6379": _shard_client("a"), "10.0.0.2:6379": lambda: slow, "10.0.0.3:6379": _shard_client("c")}
    factory, _ = _fan_factory(clients)
    start = time.monotonic()
    out = dataplane.cluster_keyspace_sample(
        _seed(), factory, sample_size=60, max_seconds=0.5, per_node_timeout=0.3, scan_count=5
    )
    wall = time.monotonic() - start
    assert wall < 0.5 + 0.3 + 0.5  # overall budget + grace + slack
    assert [n["node"] for n in out["partial_nodes"]] == ["10.0.0.2:6379"]
    assert out["partial_nodes"][0]["status"] == "partial"
    assert out["partial"] is True
    assert any("10.0.0.2:6379" in f["message"] and "partial" in f["message"] for f in out["findings"])
    assert slow.scan_times and max(slow.scan_times) - slow.scan_times[0] < 0.5 + 0.1


def test_cluster_keyspace_sample_hung_node_is_listed_and_stops_scanning_after_the_deadline():
    hung = _EndlessScan(delay=1.0)
    clients = {"10.0.0.1:6379": _shard_client("a"), "10.0.0.2:6379": lambda: hung, "10.0.0.3:6379": _shard_client("c")}
    factory, _ = _fan_factory(clients)
    start = time.monotonic()
    out = dataplane.cluster_keyspace_sample(
        _seed(), factory, sample_size=60, max_seconds=0.3, per_node_timeout=0.2, scan_count=5
    )
    returned = time.monotonic()
    assert returned - start < 0.3 + 0.2 + 0.4
    node = next(n for n in out["partial_nodes"] if n["node"] == "10.0.0.2:6379")
    assert node["status"] == "unreachable"
    assert any(f["severity"] == "critical" and f.get("shard") == "10.0.0.2:6379" for f in out["findings"])
    assert (out["shards_ok"], out["shards_unreachable"]) == (2, 1)
    time.sleep(1.3)  # let the straggler's in-flight SCAN return
    assert len(hung.scan_times) == 1, "straggler kept issuing SCAN after the deadline"
    assert hung.scan_times[0] < start + 0.3


def test_fan_out_late_shard_gets_the_remaining_budget_or_never_starts():
    # one worker, three shards: the first hangs past the shared deadline, so the others must not start scanning
    hung = _EndlessScan(delay=0.8)
    others = [_shard_client("b"), _shard_client("c")]
    clients = {"10.0.0.1:6379": lambda: hung, "10.0.0.2:6379": others[0], "10.0.0.3:6379": others[1]}
    factory, _ = _fan_factory(clients)
    start = time.monotonic()
    out = dataplane.cluster_keyspace_sample(
        _seed(), factory, sample_size=60, max_seconds=0.3, per_node_timeout=0.1, max_workers=1, scan_count=5
    )
    assert time.monotonic() - start < 0.3 + 0.1 + 0.4
    assert {n["node"] for n in out["partial_nodes"]} == {"10.0.0.1:6379", "10.0.0.2:6379", "10.0.0.3:6379"}
    time.sleep(1.0)
    assert others[0].scan_calls == 0 and others[1].scan_calls == 0


def test_cluster_slowlog_and_memory_report_partial_nodes_for_dead_shards():
    clients = {
        "10.0.0.1:6379": _shard_client("a"),
        "10.0.0.2:6379": redis.ConnectionError("refused"),
        "10.0.0.3:6379": _shard_client("c"),
    }
    factory, _ = _fan_factory(clients)
    for out in (dataplane.cluster_slowlog(_seed(), factory), dataplane.cluster_memory(_seed(), factory)):
        assert [n["node"] for n in out["partial_nodes"]] == ["10.0.0.2:6379"]


# ------------------------------------------------- round 07: connection pressure, client buffers, churn


def test_triage_connections_near_maxclients_warning_and_critical():
    _, msgs = _triage_messages(clients={"connected_clients": 850, "maxclients": 1000})
    assert _find(msgs, "connections at 85% of maxclients (850/1000)")["severity"] == "warning"
    _, crit = _triage_messages(clients={"connected_clients": 970, "maxclients": 1000})
    assert _find(crit, "connections at 97% of maxclients")["severity"] == "critical"
    _, ok = _triage_messages(clients={"connected_clients": 800, "maxclients": 1000})
    assert not any("connections at" in m for m in ok)


def test_connections_pressure_reads_maxclients_from_config_get_when_info_lacks_it():
    class WithConfig(FakeRedis):
        def config_get(self, pattern):
            return {"maxclients": "100"} if pattern == "maxclients" else {}

    r = WithConfig(infos=_risk_infos(clients={"connected_clients": 96}))
    out = dataplane.health_summary(r)
    assert any(f.startswith("connections at 96% of maxclients (96/100)") for f in out["findings"])
    assert out["maxclients"] == 100
    quiet = dataplane.health_summary(FakeRedis(infos=_risk_infos(clients={"connected_clients": 96})))
    assert not any("maxclients" in f for f in quiet["findings"])


def test_triage_blocked_clients_are_reported_and_silent_at_zero():
    _, msgs = _triage_messages(clients={"blocked_clients": 4})
    assert _find(msgs, "4 blocked clients")
    _, none = _triage_messages(clients={"blocked_clients": 0})
    assert not any("blocked clients" in m for m in none)


def test_triage_client_buffers_share_of_used_memory():
    mib = 1024 * 1024
    _, msgs = _triage_messages(memory={"used_memory": 100 * mib, "mem_clients_normal": 30 * mib})
    assert _find(msgs, "client buffers hold 30% of used_memory (30 MiB")["severity"] == "warning"
    _, small_share = _triage_messages(memory={"used_memory": 1000 * mib, "mem_clients_normal": 30 * mib})
    assert not any("client buffers hold" in m for m in small_share)
    _, tiny = _triage_messages(memory={"used_memory": 10 * mib, "mem_clients_normal": 4 * mib})
    assert not any("client buffers hold" in m for m in tiny)


def test_triage_connection_churn_hints_at_missing_pooling():
    # uptime is 6000 s in the healthy fixture: 300_000 connections = 50/s
    _, msgs = _triage_messages(stats={"total_connections_received": 300_000})
    assert _find(msgs, "connection churn: 50 new connections/s")["severity"] == "warning"
    _, calm = _triage_messages(stats={"total_connections_received": 6_000})
    assert not any("connection churn" in m for m in calm)
    young = _risk_infos(stats={"total_connections_received": 5_000})
    young["server"]["uptime_in_seconds"] = 60  # too early to average
    assert not any("connection churn" in f for f in dataplane.health_summary(FakeRedis(infos=young))["findings"])


# ------------------------------------------------- round 07: cluster replica lag and role mismatch


def _two_shard_topology():
    return (
        "p1 10.0.0.1:6379@1 master - 0 0 1 connected 0-8191\n"
        "p2 10.0.0.2:6379@1 master - 0 0 2 connected 8192-16383\n"
        "r1 10.0.0.3:6379@1 slave p1 0 0 1 connected\n"
        "r2 10.0.0.4:6379@1 slave p2 0 0 2 connected\n"
    )


def _repl_infos(**over):
    infos = {
        "10.0.0.1:6379": {"role": "master", "master_repl_offset": 9_000_000},
        "10.0.0.2:6379": {"role": "master", "master_repl_offset": 4_000_000},
        "10.0.0.3:6379": {"role": "slave", "master_link_status": "up", "slave_repl_offset": 9_000_000},
        "10.0.0.4:6379": {"role": "slave", "master_link_status": "up", "slave_repl_offset": 4_000_000},
    }
    infos.update(over)
    return infos


def test_cluster_health_replica_offset_lag_per_shard():
    infos = _repl_infos(
        **{"10.0.0.3:6379": {"role": "slave", "master_link_status": "up", "slave_repl_offset": 6_000_000}}
    )
    seed, factory, _ = _fleet(_two_shard_topology(), infos)
    out = dataplane.cluster_health(seed, factory)
    lag = [f for f in out["findings"] if "lags" in f]
    assert lag == [
        "replica 10.0.0.3:6379 of 10.0.0.1:6379 lags 3000000 bytes "
        "(master_repl_offset 9000000 vs slave_repl_offset 6000000)"
    ]
    row = next(r for r in out["shard_replication"] if r["primary"] == "10.0.0.1:6379")
    assert row["max_lag_bytes"] == 3_000_000 and row["replicas"] == 1
    assert out["partial_nodes"] == []


def test_cluster_health_caught_up_replicas_are_silent():
    seed, factory, _ = _fleet(_two_shard_topology(), _repl_infos())
    out = dataplane.cluster_health(seed, factory)
    assert out["findings"] == ["no skew, lag or coverage problems detected"]
    assert [r["max_lag_bytes"] for r in out["shard_replication"]] == [0, 0]


def test_cluster_health_replica_reporting_master_is_a_role_mismatch():
    infos = _repl_infos(**{"10.0.0.4:6379": {"role": "master", "master_repl_offset": 4_000_100}})
    seed, factory, _ = _fleet(_two_shard_topology(), infos)
    out = dataplane.cluster_health(seed, factory)
    assert (
        "replica 10.0.0.4:6379 of 10.0.0.2:6379 reports role:master (split or failover in progress)" in out["findings"]
    )
    infos = _repl_infos(**{"10.0.0.1:6379": {"role": "slave", "master_link_status": "up"}})
    seed, factory, _ = _fleet(_two_shard_topology(), infos)
    out = dataplane.cluster_health(seed, factory)
    assert any("shard primary 10.0.0.1:6379 reports role:slave" in f for f in out["findings"])


def test_cluster_health_shard_without_replica_is_reported_with_zero_replicas():
    topo = "p1 10.0.0.1:6379@1 master - 0 0 1 connected 0-16383\n"
    seed, factory, _ = _fleet(topo, {"10.0.0.1:6379": {"role": "master", "master_repl_offset": 5}})
    out = dataplane.cluster_health(seed, factory)
    assert out["shard_replication"] == [
        {"primary": "10.0.0.1:6379", "replicas": 0, "lag_bytes": {}, "max_lag_bytes": None}
    ]
    assert any("no shard has a replica" in f["message"] for f in out["topology_findings"])


def test_cluster_health_timed_out_replica_is_isolated_in_partial_nodes():
    class SlowOnReplica(FakeRedis):
        def info(self, section=None):
            if self.infos["all"].get("role") == "slave" and self.infos["all"].get("slow"):
                time.sleep(0.5)
            return super().info(section)

    infos = _repl_infos(**{"10.0.0.3:6379": {"role": "slave", "slow": True, "slave_repl_offset": 1}})
    seed = FakeRedis(infos={"cluster": {"cluster_enabled": 1}})
    seed.commands["CLUSTER NODES"] = _two_shard_topology()

    def factory(host, port):
        return SlowOnReplica(infos={"all": infos[f"{host}:{port}"]})

    t0 = time.monotonic()
    out = dataplane.cluster_health(seed, factory, per_node_timeout=0.05)
    assert time.monotonic() - t0 < 0.4
    assert out["partial_nodes"][0]["node"] == "10.0.0.3:6379"
    assert "timeout" in out["partial_nodes"][0]["reason"]
    assert out["nodes_probed"] == 4
    assert not any("lags" in f for f in out["findings"])  # the healthy shard still gets its verdict
    assert any("10.0.0.3:6379 unreachable" in f for f in out["findings"])


# ------------------------------------------------- round 08: fork, resync, client eviction, error replies


def _health_findings(**over):
    out = dataplane.health_summary(FakeRedis(infos=_risk_infos(**over)))
    return out, out["findings"]


def _has(findings, needle):
    return any(needle in f for f in findings)


@pytest.mark.parametrize(
    "usec,fires,severity",
    [
        (1_000_000, False, None),
        (1_000_001, True, "warning"),
        (5_000_000, True, "warning"),
        (5_000_001, True, "critical"),
    ],
)
def test_fork_latency_thresholds(usec, fires, severity):
    _, findings = _health_findings(persistence={"latest_fork_usec": usec})
    assert _has(findings, "fork latency") is fires
    if fires:
        triage = dataplane.triage(FakeRedis(infos=_risk_infos(persistence={"latest_fork_usec": usec})), None)
        hit = next(f for f in triage["findings"] if "fork latency" in f["message"])
        assert hit["severity"] == severity


def test_sync_partial_err_fires_and_zero_is_quiet():
    _, findings = _health_findings(stats={"sync_partial_err": 2, "sync_partial_ok": 1})
    assert _has(findings, "2 partial resync requests refused")
    _, quiet = _health_findings(stats={"sync_partial_err": 0})
    assert not _has(quiet, "resync")


@pytest.mark.parametrize(
    "full,uptime,fires",
    [(2, 6000, False), (3, 6000, True), (3, 36000, False), (50, 100, False), (4, 7200, True)],
)
def test_sync_full_rate(full, uptime, fires):
    _, findings = _health_findings(server={"uptime_in_seconds": uptime}, stats={"sync_full": full})
    assert _has(findings, "full resyncs") is fires


def test_evicted_clients_fires_only_above_zero():
    _, findings = _health_findings(stats={"evicted_clients": 3})
    assert _has(findings, "3 clients evicted")
    _, quiet = _health_findings(stats={"evicted_clients": 0})
    assert not _has(quiet, "clients evicted")


@pytest.mark.parametrize(
    "errors,commands,fires", [(50, 1000, False), (51, 1000, True), (900, 999, False), (10, 100_000, False)]
)
def test_error_reply_share(errors, commands, fires):
    stats = {"total_error_replies": errors, "total_commands_processed": commands}
    _, findings = _health_findings(stats=stats)
    assert _has(findings, "ended in an error reply") is fires


def test_new_fields_absent_produce_no_finding_and_raw_fields_exposed():
    out, findings = _health_findings()
    assert findings == ["no issues detected by basic thresholds"]
    assert "latest_fork_usec" not in out and "sync_full" not in out
    out, _ = _health_findings(
        persistence={"latest_fork_usec": 10, "rdb_last_bgsave_time_sec": 2},
        stats={"sync_full": 1, "expired_stale_perc": 0.5, "evicted_clients": 0},
    )
    assert out["latest_fork_usec"] == 10 and out["rdb_last_bgsave_time_sec"] == 2
    assert out["sync_full"] == 1 and out["expired_stale_perc"] == 0.5 and out["evicted_clients"] == 0


# ------------------------------------------------- round 08: errorstats and latencystats


def _stats_infos(**extra):
    infos = _risk_infos()
    infos["commandstats"] = {
        "cmdstat_get": {"calls": 1000, "usec": 9000, "usec_per_call": 9.0, "rejected_calls": 0, "failed_calls": 0},
        "cmdstat_sort": {"calls": 50, "usec": 900000, "usec_per_call": 18000.0, "rejected_calls": 0, "failed_calls": 0},
    }
    infos.update(extra)
    return infos


def test_commandstats_errorstats_findings_name_the_cause():
    infos = _stats_infos(
        errorstats={
            "errorstat_OOM": {"count": 4},
            "errorstat_READONLY": {"count": 2},
            "errorstat_NOPERM": {"count": 1},
            "errorstat_ERR": {"count": 90},
        }
    )
    out = dataplane.commandstats(FakeRedis(infos=infos), 10)
    assert [e["error"] for e in out["errorstats"]] == ["ERR", "OOM", "READONLY", "NOPERM"]
    text = " | ".join(out["findings"])
    assert "4 OOM error replies" in text and "maxmemory" in text
    assert "2 READONLY" in text and "replica" in text
    assert "1 NOPERM" in text and "ACL" in text
    assert "ERR error replies" not in text  # generic errors are listed, not flagged


def test_commandstats_latency_p99_over_10ms_is_flagged_only_for_top_commands():
    lat = {
        "latency_percentiles_usec_get": {"p50": 5.0, "p99": 9000.0, "p99.9": 20000.0},
        "latency_percentiles_usec_sort": {"p50": 8000.0, "p99": 12000.5, "p99.9": 30000.0},
    }
    out = dataplane.commandstats(FakeRedis(infos=_stats_infos(latencystats=lat)), 10)
    assert out["latencystats"]["sort"] == {"p50_usec": 8000.0, "p99_usec": 12000.5, "p99_9_usec": 30000.0}
    assert [f for f in out["findings"] if "p99" in f] == [
        "sort p99 latency is 12.0 ms (above 10 ms) over 50 calls; see node_slowlog for the arguments"
    ]
    capped = dataplane.commandstats(FakeRedis(infos=_stats_infos(latencystats=lat)), 1)
    assert list(capped["latencystats"]) == ["sort"] and len(capped["top_by_total_time"]) == 1


def test_commandstats_old_engine_gets_notes_not_errors():
    infos = _stats_infos()
    infos["server"] = {"redis_version": "6.0.9", "uptime_in_seconds": 10}
    out = dataplane.commandstats(FakeRedis(infos=infos), 5)
    assert out["errorstats"] == [] and out["latencystats"] == {} and out["findings"] == []
    assert any("INFO ERRORSTATS: not supported by redis 6.0.9" in n for n in out["notes"])
    assert any("INFO LATENCYSTATS: not supported by redis 6.0.9" in n for n in out["notes"])
    assert [c["command"] for c in out["top_by_total_time"]] == ["sort", "get"]


def test_commandstats_refused_sections_on_a_modern_engine_say_unavailable():
    out = dataplane.commandstats(FakeRedis(infos=_stats_infos()), 5)
    assert all("unavailable" in n for n in out["notes"]) and len(out["notes"]) == 2


def test_triage_includes_errorstats_findings():
    infos = _stats_infos(errorstats={"errorstat_OOM": {"count": 7}})
    out = dataplane.triage(FakeRedis(infos=infos), None)
    assert any(f["section"] == "commandstats" and "OOM" in f["message"] for f in out["findings"])


# ------------------------------------------------------------------ round 11: pub/sub, TTL histogram, cluster triage


def _pubsub_fake(channels=None, patterns=0, clients=None, shard=None, infos=None):
    fake = FakeRedis(infos=infos or {"memory": _mem_info()})
    names = channels or {}
    fake.commands["PUBSUB CHANNELS"] = [c.encode() for c in names]
    fake.commands["PUBSUB NUMPAT"] = patterns
    fake.commands["PUBSUB SHARDCHANNELS"] = shard or []
    fake.clients = clients or []
    keys = list(names)
    for i in range(0, len(keys), 100):
        batch = keys[i : i + 100]
        fake.commands["PUBSUB NUMSUB " + " ".join(batch)] = [x for c in batch for x in (c.encode(), names[c])]
    return fake


def _psub_client(cid, omem=0, idle=0):
    return {
        "id": str(cid),
        "addr": f"10.0.0.{cid}:5000",
        "name": "",
        "user": "default",
        "idle": str(idle),
        "omem": str(omem),
        "sub": "1",
        "psub": "0",
        "ssub": "0",
        "flags": "P",
        "type": "pubsub",
    }


def test_pubsub_report_counts_top_channels_and_flags_pressure():
    fake = _pubsub_fake(
        channels={"a": 5, "b": 50, "c": 1},
        patterns=150,
        clients=[_psub_client(1, omem=40 * 1024 * 1024), _psub_client(2, omem=9 * 1024 * 1024), _psub_client(3)]
        + [_psub_client(10 + i, idle=7200) for i in range(20)],
        shard=["s1"],
    )
    out = dataplane.pubsub_report(fake, top=2)
    assert out["channels"] == 3 and out["pattern_subscriptions"] == 150 and out["shard_channels"] == 1
    assert out["top_channels_by_subscribers"] == [
        {"channel": "b", "subscribers": 50},
        {"channel": "a", "subscribers": 5},
    ]
    msgs = {(f["severity"], f["message"]) for f in out["findings"]}
    assert any(s == "warning" and "150 pattern subscriptions" in m for s, m in msgs)
    assert any(s == "critical" and "id=1" in m for s, m in msgs)
    assert any(s == "warning" and "id=2" in m for s, m in msgs)
    assert any(s == "info" and "20 pubsub clients" in m for s, m in msgs)
    assert out["findings"][0]["severity"] == "critical"


def test_pubsub_report_critical_patterns_and_quiet_node():
    assert dataplane.pubsub_report(_pubsub_fake(patterns=2000))["findings"][0]["severity"] == "critical"
    quiet = dataplane.pubsub_report(_pubsub_fake(channels={"a": 1}, patterns=1))
    assert quiet["findings"] == [] and "notes" not in quiet


def test_pubsub_report_degrades_when_commands_are_unavailable():
    fake = FakeRedis(infos={"memory": _mem_info()})  # every PUBSUB command is an unknown command
    out = dataplane.pubsub_report(fake)
    assert out["channels"] == 0 and out["pattern_subscriptions"] == 0 and out["shard_channels"] is None
    assert any("PUBSUB CHANNELS: unavailable" in n for n in out["notes"])


def test_pubsub_report_batches_numsub_in_calls_of_100():
    names = {f"c{i:03d}": i for i in range(150)}
    out = dataplane.pubsub_report(_pubsub_fake(channels=names), top=3)
    assert out["channels_with_subscriber_counts"] == 150
    assert out["top_channels_by_subscribers"][0] == {"channel": "c149", "subscribers": 149}


def test_cluster_pubsub_sums_shards_and_labels_findings():
    clients = {
        "10.0.0.1:6379": _pubsub_fake(channels={"a": 2}, patterns=120),
        "10.0.0.2:6379": _pubsub_fake(channels={"a": 3, "b": 1}, patterns=0),
        "10.0.0.3:6379": redis.ConnectionError("refused"),
    }
    factory, opened = _fan_factory(clients)
    out = dataplane.cluster_pubsub(_seed(), factory, top=5)
    assert out["cluster_enabled"] is True and out["partial"] is True
    assert (out["shards_ok"], out["shards_unreachable"]) == (2, 1)
    assert out["channels"] == 3 and out["pattern_subscriptions"] == 120
    assert out["top_channels_by_subscribers"][0] == {"channel": "a", "subscribers": 5}
    labelled = [f for f in out["findings"] if "pattern subscriptions" in f["message"]]
    assert labelled and labelled[0]["shard"] == "10.0.0.1:6379"
    assert out["findings"][0]["severity"] == "critical"  # the dead shard
    assert all(c.closed for c in opened)


def test_cluster_pubsub_on_a_standalone_node_reports_that_node():
    seed = _pubsub_fake(channels={"a": 1})
    seed.infos["cluster"] = {"cluster_enabled": 0}
    out = dataplane.cluster_pubsub(seed, lambda h, p: seed)
    assert out["cluster_enabled"] is False and out["channels"] == 1


def _ttl_fake(rows, hits=0, misses=0, policy="allkeys-lru"):
    data = {f"u:{i}:s": ("string", 10, pttl, 1) for i, pttl in enumerate(rows)}
    infos = {"memory": _mem_info(maxmemory_policy=policy), "stats": {"keyspace_hits": hits, "keyspace_misses": misses}}
    return FakeRedis(infos=infos, data=data, scan_batch=1000)


def test_keyspace_sample_ttl_histogram_buckets():
    rows = [-1] * 3 + [30_000, 30_000, 7_200_000, 3_600_000 * 24 * 3]
    out = dataplane.keyspace_sample(_ttl_fake(rows), sample_size=100)
    hist = out["ttl_histogram"]
    overall = hist["overall"]
    assert overall["no_ttl"] == 3 and overall["lt_1m"] == 2 and overall["lt_1d"] == 1 and overall["gte_1d"] == 1
    assert sum(overall.values()) == len(rows)


def test_keyspace_sample_call_count_unchanged_by_ttl_histogram():
    fake = _ttl_fake([-1] * 40)
    dataplane.keyspace_sample(fake, sample_size=100)
    assert fake.scan_calls == 1  # the histogram reuses the PTTL already in the pipeline
    assert fake.pipeline_runs == 2  # types/TTL/size pipeline and the element-count pipeline, as before


def test_keyspace_sample_flags_no_ttl_dominance_and_low_hit_rate():
    out = dataplane.keyspace_sample(_ttl_fake([-1] * 30, hits=200, misses=1800, policy="volatile-lru"), sample_size=100)
    msgs = [(f["severity"], f["message"]) for f in out["findings"]]
    assert any(s == "warning" and "TTL" in m for s, m in msgs)
    assert any(s == "critical" and "hit rate" in m for s, m in msgs)
    assert out["keyspace_hit_rate"] == pytest.approx(0.1)


def test_keyspace_sample_quiet_for_healthy_ttl_mix_and_hit_rate():
    out = dataplane.keyspace_sample(_ttl_fake([-1] * 5 + [30_000] * 25, hits=9500, misses=500), sample_size=100)
    assert not any("hit rate" in f["message"] or "without a TTL" in f["message"] for f in out["findings"])
    tiny = dataplane.keyspace_sample(_ttl_fake([-1] * 30, hits=1, misses=9), sample_size=100)
    assert not any("hit rate" in f["message"] for f in tiny["findings"])  # too few lookups


def test_client_list_flags_clients_idle_over_an_hour():
    fake = FakeRedis(infos={"clients": {"connected_clients": 25}})
    fake.clients = [
        {
            "id": str(i),
            "addr": f"10.0.0.{i}:1",
            "name": "",
            "user": "default",
            "idle": "9000",
            "cmd": "get",
            "omem": "0",
            "qbuf": "0",
            "age": "9000",
        }
        for i in range(25)
    ]
    out = dataplane.client_list(fake)
    assert any("idle" in f["message"] for f in out["findings"])


def _triage_node(**mem):
    info = {
        "memory": _mem_info(**mem),
        "clients": {"connected_clients": 1},
        "stats": {},
        "commandstats": {},
        "replication": {"role": "master", "connected_slaves": 1},
    }
    return _pubsub_fake(infos=info)


def test_cluster_triage_ranks_worst_node_first_and_isolates_a_dead_shard():
    clients = {
        "10.0.0.1:6379": _triage_node(),
        "10.0.0.2:6379": _triage_node(used_memory=980, maxmemory=1000),
        "10.0.0.3:6379": redis.ConnectionError("refused"),
    }
    factory, opened = _fan_factory(clients)
    out = dataplane.cluster_triage(_seed(), factory)
    assert out["cluster_enabled"] is True and out["partial"] is True
    assert (out["shards_ok"], out["shards_unreachable"]) == (2, 1)
    assert out["worst_node"] in {"10.0.0.2:6379", "10.0.0.3:6379"}
    assert list(out["per_node"])[0] == out["worst_node"]
    assert out["findings"][0]["severity"] == "critical"
    assert all("node" in f for f in out["findings"])
    assert any(f["node"] == "10.0.0.3:6379" and "unreachable" in f["message"] for f in out["findings"])
    mem = [f for f in out["findings"] if f.get("nodes") == ["10.0.0.2:6379"] and "memory" in f["message"].lower()]
    assert mem and mem[0]["shard"] == "shard-2"
    assert all(c.closed for c in opened)


def test_cluster_triage_merges_identical_findings_across_nodes():
    clients = {f"10.0.0.{i}:6379": _triage_node(used_memory=980, maxmemory=1000) for i in (1, 2, 3)}
    factory, _ = _fan_factory(clients)
    out = dataplane.cluster_triage(_seed(), factory)
    merged = [f for f in out["findings"] if f.get("count") == 3]
    assert merged and sorted(merged[0]["nodes"]) == sorted(clients)
    assert out["findings_total"] == len(out["findings"])


def test_cluster_triage_healthy_cluster_raises_nothing_above_info():
    clients = {f"10.0.0.{i}:6379": _triage_node() for i in (1, 2, 3)}
    factory, _ = _fan_factory(clients)
    healthy = dataplane.cluster_triage(_seed(), factory)
    assert healthy["partial"] is False and healthy["shards_ok"] == 3
    assert all(f["severity"] == "info" for f in healthy["findings"])
    assert all(n["critical"] == 0 and n["warning"] == 0 for n in healthy["per_node"].values())
    assert len(healthy["findings"]) <= dataplane.CLUSTER_TRIAGE_MAX_FINDINGS


def test_cluster_triage_on_a_standalone_node_falls_back_to_plain_triage():
    seed = _triage_node()
    seed.infos["cluster"] = {"cluster_enabled": 0}
    out = dataplane.cluster_triage(seed, lambda h, p: seed)
    assert out["cluster_enabled"] is False and "sections" in out


def test_valkey_compat_redis_version_is_not_redis_eol_and_is_labelled():
    server = {"server_name": "valkey", "valkey_version": "8.0.1", "redis_version": "7.2.4"}
    r = FakeRedis(infos={"server": server})
    out = dataplane.health_summary(r)
    assert out["engine"] == "valkey" and out["version"] == "8.0.1"
    assert out["version_label"] == "Valkey 8.0.1" and out["redis_compat_version"] == "7.2.4"
    assert not any("end-of-life" in str(f) or "Redis OSS" in str(f) for f in out["findings"])
    tri = dataplane.triage(r)
    assert tri["sections"]["health"]["version_label"] == "Valkey 8.0.1"
    assert not any("end-of-life" in f["message"] for f in tri["findings"])


def test_valkey_config_findings_flag_single_io_thread_and_lazyfree_off():
    server = {"server_name": "valkey", "valkey_version": "8.0.1"}
    cfg = {"io-threads": "1", "lazyfree-lazy-eviction": "no", "lazyfree-lazy-expire": "yes"}
    params = {f["parameter"] for f in dataplane.config_findings(cfg, None, server)}
    assert params == {"io-threads", "lazyfree-lazy-eviction"}
    redis_server = {"redis_version": "7.2.4"}
    assert dataplane.config_findings(cfg, None, redis_server) == []
    assert dataplane.config_findings({"io-threads": "1"}, None, {"valkey_version": "7.2.6"}) == []


# ------------------------------------------------------------- round 14: node_latency_events


class _LatencyRedis(FakeRedis):
    def __init__(self, threshold="100", config_error=False):
        super().__init__()
        self.threshold = threshold
        self.config_error = config_error

    def config_get(self, pattern):
        if self.config_error:
            raise redis.ResponseError("unknown command CONFIG")
        return {"latency-monitor-threshold": self.threshold}


def _latency_redis(latest, history=None, threshold="100"):
    r = _LatencyRedis(threshold)
    r.commands["LATENCY LATEST"] = latest
    for event, rows in (history or {}).items():
        r.commands[f"LATENCY HISTORY {event}"] = rows
    r.commands["LATENCY DOCTOR"] = "Dave, I have observed latency spikes. " + "x" * 5000
    r.commands["MEMORY DOCTOR"] = "Hi Sam, all is fine."
    return r


def test_latency_events_slow_fork_and_aof_are_findings_with_history():
    r = _latency_redis(
        [["fork", 1700000100, 450, 1500], ["aof-fsync-always", 1700000200, 120, 130], ["command", 1700000300, 5, 9]],
        {"fork": [[1700000000 + i, 10 + i] for i in range(30)], "aof-fsync-always": [[1700000200, 130]]},
    )
    out = dataplane.latency_events(r)
    assert out["events_total"] == 3 and out["events"][0]["event"] == "fork"
    assert len(out["events"][0]["history"]) == dataplane.LATENCY_HISTORY_SAMPLES  # bounded
    assert out["events"][0]["history"][-1] == {"timestamp": 1700000029, "ms": 39.0}
    sev = {f["event"]: f["severity"] for f in out["findings"] if "event" in f}
    assert sev["fork"] == "critical" and sev["aof-fsync-always"] == "warning"
    assert out["findings"][0]["severity"] == "critical"
    assert len(out["latency_doctor"]) <= dataplane.LATENCY_DOCTOR_CHARS + 60
    assert out["memory_doctor"] == "Hi Sam, all is fine."


def test_latency_events_expire_cycle_spike_against_its_own_history():
    spiky = [[1700000000 + i, 3] for i in range(10)] + [[1700000100, 90]]
    r = _latency_redis([["expire-cycle", 1700000100, 90, 90]], {"expire-cycle": spiky})
    out = dataplane.latency_events(r)
    assert any(f.get("event") == "expire-cycle" and "spike" in f["message"] for f in out["findings"])
    calm = [[1700000000 + i, 40] for i in range(10)] + [[1700000100, 45]]
    quiet = dataplane.latency_events(_latency_redis([["expire-cycle", 1700000100, 45, 45]], {"expire-cycle": calm}))
    assert not any(f.get("event") == "expire-cycle" for f in quiet["findings"])


def test_latency_events_empty_with_threshold_zero_names_the_parameter():
    out = dataplane.latency_events(_latency_redis([], threshold="0"))
    (f,) = out["findings"]
    assert f["severity"] == "warning" and f["parameter"] == "latency-monitor-threshold"
    assert "aws_parameters" in f["message"] and out["latency_doctor"] is None
    assert out["latency_monitor_threshold_ms"] == 0 and out["events_total"] == 0


def test_latency_events_empty_with_threshold_set_or_unknown_is_informational():
    out = dataplane.latency_events(_latency_redis([], threshold="100"))
    assert [f["severity"] for f in out["findings"]] == ["info"] and "100 ms" in out["findings"][0]["message"]
    r = _latency_redis([])
    r.config_error = True
    unknown = dataplane.latency_events(r)
    assert unknown["latency_monitor_threshold_ms"] is None
    assert "unknown" in unknown["findings"][0]["message"]


def test_latency_events_tolerates_refused_commands_and_odd_replies():
    r = _LatencyRedis()
    r.commands["LATENCY LATEST"] = redis.ResponseError("unknown command LATENCY")
    out = dataplane.latency_events(r)
    assert any("LATENCY LATEST: unavailable" in n for n in out["notes"])
    assert any("MEMORY DOCTOR: unavailable" in n for n in out["notes"])
    r2 = _latency_redis([["fork", 1, 150, 150], "junk", [b"x"]], {"fork": "not-a-list"})
    odd = dataplane.latency_events(r2)
    assert odd["events_total"] == 1 and odd["events"][0]["history"] == []
    r3 = _latency_redis([[b"command", 1, 150, 150]], {"command": redis.ResponseError("nope")})
    err = dataplane.latency_events(r3)
    assert any("LATENCY HISTORY command: unavailable" in n for n in err["notes"])
    assert any(f["severity"] == "info" and f.get("event") == "command" for f in err["findings"])


# ------------------------------------------------------------ keyspace access evidence

DAY = 24 * 3600


def _access_redis(policy: str, values: dict[str, int], n: int = 10) -> FakeRedis:
    r = FakeRedis(infos={"memory": _mem_info(maxmemory_policy=policy)}, data=_keys(n))
    r.object_values = values
    return r


def test_keyspace_access_is_off_by_default():
    out = dataplane.keyspace_sample(_access_redis("allkeys-lru", {}))
    assert "access" not in out


def test_keyspace_access_lru_reports_share_idle_over_7_days():
    values = {f"k{i:04d}": (8 * DAY if i < 4 else 60) for i in range(10)}
    r = _access_redis("allkeys-lru", values)
    out = dataplane.keyspace_sample(r, include_access=True)
    access = out["access"]
    assert access["command"] == "OBJECT IDLETIME"
    assert (access["keys_read"], access["cold_keys"], access["cold_pct"]) == (10, 4, 40.0)
    assert access["eviction_risk_hint"] == "40% of sampled keys untouched for >7d, candidates for TTL or removal"
    assert any(f.get("section") == "access" and f["severity"] == "info" for f in out["findings"])
    assert not any(c[:2] == ("OBJECT", "FREQ") for c in r.sent)
    assert out["coldest_keys_by_idle"][0]["idle_seconds"] == 8 * DAY


def test_keyspace_access_lfu_uses_frequency_not_idle_time():
    values = {f"k{i:04d}": (0 if i < 5 else 200) for i in range(10)}
    r = _access_redis("allkeys-lfu", values)
    out = dataplane.keyspace_sample(r, include_access=True)
    assert out["access"]["command"] == "OBJECT FREQ"
    assert out["access"]["cold_pct"] == 50.0
    assert "low access frequency" in out["access"]["eviction_risk_hint"]
    assert not any(c[:2] == ("OBJECT", "IDLETIME") for c in r.sent)


def test_keyspace_access_warns_under_memory_pressure_and_stays_quiet_when_warm():
    cold = {f"k{i:04d}": 9 * DAY for i in range(10)}
    out = dataplane.keyspace_sample(_access_redis("noeviction", cold), include_access=True)
    assert any(f.get("section") == "access" and f["severity"] == "warning" for f in out["findings"])
    warm = dataplane.keyspace_sample(_access_redis("allkeys-lru", {}), include_access=True)
    assert warm["access"]["cold_pct"] == 0.0 and "eviction_risk_hint" not in warm["access"]
    assert not [f for f in warm["findings"] if f.get("section") == "access"]


def test_keyspace_access_respects_the_time_budget():
    r = FakeRedis(infos={"memory": _mem_info()}, data=_keys(500), scan_batch=5, scan_delay=0.03)
    r.object_values = dict.fromkeys(r.data, 9 * DAY)
    out = dataplane.keyspace_sample(r, sample_size=500, max_seconds=0.05, include_access=True)
    assert out["partial"] is True
    assert out["access"]["partial"] is True
    assert out["access"]["keys_read"] == out["sampled_keys"] < 500


def test_keyspace_access_sends_only_allowlisted_commands():
    from mcp_elasticache_ops import safe_client

    r = _access_redis("allkeys-lru", {})
    dataplane.keyspace_sample(r, include_access=True)
    assert r.sent
    for command in r.sent:
        safe_client.check(command)


# ------------------------------------------------------------------ node_doctor

_HEALTHY_MEMORY = (
    "Hi Sam, I can't find any memory issue in your instance. I can only account for what occurs on this base."
)
_HEALTHY_LATENCY = (
    "Dave, no latency spike was observed during the lifetime of this Redis instance, not in the slightest bit. "
    "I honestly think you ought to sit down calmly, take a stress pill, and think things over."
)
_PROBLEM_MEMORY = (
    "Hi Sam, this instance is having memory issues.\n\n"
    "* High total RSS: This instance has a memory fragmentation and RSS overhead greater than 1.4.\n"
    "* Big replica buffers: The replica output buffers in this instance are greater than 10% of the dataset size."
)
_PROBLEM_LATENCY = (
    "Dave, I have observed latency spikes in this Redis instance.\n\n"
    "1. command: 4 latency spikes (average 300ms, mean deviation 120ms, period 73.40 sec).\n\n"
    "I have a few advices for you:\n\n- Check SLOWLOG to see which commands are slow."
)


def test_node_doctor_healthy_reply_has_no_findings():
    r = FakeRedis(infos={"server": {"redis_version": "7.1.0"}})
    r.commands["MEMORY DOCTOR"] = _HEALTHY_MEMORY
    r.commands["LATENCY DOCTOR"] = _HEALTHY_LATENCY.encode()
    out = dataplane.node_doctor(r)
    assert out["findings"] == [] and out["notes"] == []
    assert out["memory_doctor"] == {"status": "healthy", "advice": _HEALTHY_MEMORY}
    assert out["latency_doctor"]["status"] == "healthy"


def test_node_doctor_problem_reply_keeps_only_unhealthy_lines_and_trims_advice():
    r = FakeRedis(infos={"server": {"redis_version": "7.1.0"}})
    r.commands["MEMORY DOCTOR"] = _PROBLEM_MEMORY
    r.commands["LATENCY DOCTOR"] = _PROBLEM_LATENCY + "\n- " + "x" * 5000
    out = dataplane.node_doctor(r)
    messages = [f["message"] for f in out["findings"]]
    assert any(m.startswith("MEMORY DOCTOR: * High total RSS") for m in messages)
    assert any(m.startswith("LATENCY DOCTOR: 1. command: 4 latency spikes") for m in messages)
    assert all(f["severity"] in {"warning", "info"} and len(f["message"]) < 400 for f in out["findings"])
    assert out["memory_doctor"]["status"] == "findings"
    assert out["latency_doctor"]["status"] == "findings"
    assert len(out["latency_doctor"]["advice"]) <= dataplane.LATENCY_DOCTOR_CHARS + 60


def test_node_doctor_unsupported_command_is_a_note_not_an_error():
    r = FakeRedis(infos={"server": {"redis_version": "3.2.0"}})
    r.commands["MEMORY DOCTOR"] = redis.ResponseError("unknown subcommand 'doctor'")
    out = dataplane.node_doctor(r)  # LATENCY DOCTOR is unknown to the fake: also refused
    assert out["findings"] == []
    assert out["memory_doctor"]["status"] == "not available"
    assert out["latency_doctor"]["status"] == "not available"
    assert any(n.startswith("MEMORY DOCTOR: not available") and "3.2.0" in n for n in out["notes"])
    serverless = dataplane.node_doctor(r, serverless=True)
    assert "serverless" in serverless["memory_doctor"]["reason"]


def test_triage_includes_the_doctor_section():
    r = FakeRedis(infos={"server": {"redis_version": "7.1.0"}, "default": {"role": "master"}})
    r.commands["MEMORY DOCTOR"] = _PROBLEM_MEMORY
    r.commands["LATENCY DOCTOR"] = _HEALTHY_LATENCY
    out = dataplane.triage(r)
    assert out["sections"]["doctor"] == {"status": "ok", "memory": "findings", "latency": "healthy"}
    assert any(f.get("section") == "doctor" for f in out["findings"])


# ------------------------------------------------------------------ engine quirk findings


def _sources(info: dict) -> set[str]:
    return {f["source"] for f in dataplane.engine_quirk_findings(info)}


_VALKEY8 = {"server_name": "valkey", "valkey_version": "8.0.1", "redis_version": "7.2.4"}


def test_quirk_io_threads_idle_with_busy_loop_only_on_valkey_8():
    busy = {"io_threads_active": 0, "instantaneous_eventloop_duration_usec": 9000}
    assert "io-threads" in _sources({**_VALKEY8, **busy})
    assert "io-threads" not in _sources({**_VALKEY8, **busy, "io_threads_active": 1})
    assert "io-threads" not in _sources({**_VALKEY8, **busy, "instantaneous_eventloop_duration_usec": 100})
    assert "io-threads" not in _sources({**_VALKEY8, **busy, "valkey_version": "7.2.5"})
    assert "io-threads" not in _sources({"redis_version": "7.2.4", **busy})


def test_quirk_lazyfree_backlog_threshold_and_engine():
    big = {"lazyfree_pending_objects": dataplane.LAZYFREE_PENDING_WARN + 1}
    assert "lazyfree" in _sources({"redis_version": "7.0.0", **big})
    assert "lazyfree" not in _sources({"redis_version": "3.2.0", **big})
    assert "lazyfree" not in _sources({"redis_version": "7.0.0", "lazyfree_pending_objects": 10})


def test_quirk_dict_rehash_needs_valkey_8_and_enough_memory_share():
    heavy = {"used_memory": 1000, "mem_overhead_db_hashtable_rehashing": 50}
    assert "dict-rehash" in _sources({**_VALKEY8, **heavy})
    assert "dict-rehash" not in _sources({**_VALKEY8, **heavy, "mem_overhead_db_hashtable_rehashing": 1})
    assert "dict-rehash" not in _sources({"redis_version": "7.2.4", **heavy})


def test_quirk_replica_stale_data_only_when_link_down():
    down = {"redis_version": "7.0.0", "role": "slave", "master_link_status": "down"}
    assert "replica-serve-stale-data" in _sources(down)
    assert "replica-serve-stale-data" not in _sources({**down, "master_link_status": "up"})
    assert "replica-serve-stale-data" not in _sources({**down, "role": "master"})


def test_quirk_lua_and_functions_memory_gated_by_version():
    info = {
        "redis_version": "7.2.0",
        "used_memory": 10_000_000,
        "used_memory_lua": 100_000,
        "used_memory_vm_functions": 900_000,
    }
    assert "lua-functions" in _sources(info)  # 10% of used memory incl. functions
    old = {**info, "redis_version": "6.2.0"}
    assert "lua-functions" not in _sources(old)  # functions heap does not exist before 7.0
    assert "lua-functions" in _sources({**old, "used_memory_lua": 80 * 1024 * 1024})
    assert _sources({"redis_version": "7.2.0", "used_memory": 10_000_000, "used_memory_lua": 1000}) == set()


def test_node_doctor_surfaces_quirk_findings():
    r = FakeRedis(
        infos={"server": {"redis_version": "7.0.0"}, "replication": {"role": "slave", "master_link_status": "down"}}
    )
    r.commands["MEMORY DOCTOR"] = _HEALTHY_MEMORY
    r.commands["LATENCY DOCTOR"] = _HEALTHY_LATENCY
    out = dataplane.node_doctor(r)
    assert [f["source"] for f in out["findings"]] == ["replica-serve-stale-data"]
