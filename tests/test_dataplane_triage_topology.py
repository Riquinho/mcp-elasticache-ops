"""Round 04: node_triage, prefix-grouped keyspace sample, cluster topology findings."""

from __future__ import annotations

import redis
from fastmcp import Client

from mcp_elasticache_ops import dataplane, server
from tests.fakes import FakeRedis

# ------------------------------------------------------------------------------- node_triage


def _healthy_infos() -> dict[str, dict]:
    return {
        "server": {"redis_version": "7.2.4"},
        "memory": {
            "used_memory": 10,
            "maxmemory": 100,
            "used_memory_rss": 12,
            "mem_fragmentation_ratio": 1.1,
            "maxmemory_policy": "allkeys-lru",
        },
        "stats": {"keyspace_hits": 90, "keyspace_misses": 10, "evicted_keys": 0},
        "clients": {"connected_clients": 3},
        "replication": {
            "role": "master",
            "connected_slaves": 1,
            "master_repl_offset": 1000,
            "slave0": {"ip": "10.0.0.2", "port": 6379, "state": "online", "offset": 1000, "lag": 0},
        },
        "commandstats": {
            "cmdstat_get": {
                "calls": 100,
                "usec": 500,
                "usec_per_call": 5.0,
                "rejected_calls": 0,
                "failed_calls": 0,
            }
        },
    }


def test_triage_healthy_case_covers_every_section():
    out = dataplane.triage(FakeRedis(infos=_healthy_infos()), None)
    assert out["status"] == "ok"
    assert out["serverless"] is False
    assert set(out["sections"]) == {
        "health",
        "memory",
        "replication",
        "clients",
        "doctor",
        "commandstats",
        "slowlog",
        "latency",
    }
    assert all(s["status"] == "ok" for s in out["sections"].values())
    assert [f["severity"] for f in out["findings"]] == ["info"]
    assert out["findings_total"] == 1 and "latency event" in out["findings"][0]["message"]
    assert out["sections"]["replication"]["connected_replicas"] == 1
    assert out["sections"]["memory"]["usage_of_maxmemory"] == 0.1


def test_triage_merges_findings_worst_first_and_caps_them():
    infos = _healthy_infos()
    infos["memory"]["used_memory"] = 95  # critical: above 90% of maxmemory
    infos["commandstats"] = {
        f"cmdstat_cmd{i}": {"calls": 10, "usec": 1, "usec_per_call": 0.1, "rejected_calls": 1, "failed_calls": 2}
        for i in range(8)
    }
    fake = FakeRedis(infos=infos)
    fake.slowlog_entries = [{"id": 1, "start_time": 1, "duration": 250_000, "command": "KEYS *"}]
    out = dataplane.triage(fake, None)
    severities = [f["severity"] for f in out["findings"]]
    assert severities == sorted(severities, key=["critical", "warning", "info"].index)
    assert out["findings"][0]["severity"] == "critical" and out["findings"][0]["section"] == "health"
    assert any(f["section"] == "slowlog" and f["severity"] == "warning" for f in out["findings"])
    assert sum(1 for f in out["findings"] if f["section"] == "commandstats") == 5  # per-section cut
    assert len(out["findings"]) <= dataplane.TRIAGE_MAX_FINDINGS


def test_triage_caps_at_thirty_findings(monkeypatch):
    many = [dataplane._finding("warning", f"w{i}") for i in range(45)]
    monkeypatch.setattr(dataplane, "_triage_replication", lambda d: ({}, many))
    out = dataplane.triage(FakeRedis(infos=_healthy_infos()), None)
    assert len(out["findings"]) == 30
    assert out["findings_total"] == 46 and out["findings_omitted"] == 16


class _BrokenClients(FakeRedis):
    def client_list(self):
        raise redis.ConnectionError("boom")


def test_triage_section_failure_is_partial_not_fatal():
    out = dataplane.triage(_BrokenClients(infos=_healthy_infos()), None)
    assert out["status"] == "partial"
    assert out["sections"]["clients"]["status"] == "unavailable"
    assert "ConnectionError" in out["sections"]["clients"]["error"]
    assert out["sections"]["health"]["status"] == "ok"
    assert out["sections"]["latency"]["status"] == "ok"
    unavailable = [f for f in out["findings"] if f["section"] == "clients"]
    assert unavailable and unavailable[0]["severity"] == "warning"


def test_triage_serverless_marks_missing_sections_as_info():
    out = dataplane.triage(FakeRedis(infos={}), None, serverless=True)
    assert out["serverless"] is True
    assert out["status"] == "partial"
    assert out["sections"]["memory"]["status"] == "unavailable"
    assert out["sections"]["commandstats"]["status"] == "unavailable"
    assert out["findings"], "unavailable sections are still reported"
    assert all(f["severity"] == "info" for f in out["findings"])


async def test_node_triage_registered_and_read_only():
    async with Client(server.mcp) as c:
        tools = {t.name: t for t in await c.list_tools()}
    tool = tools["node_triage"]
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.destructive_hint is False


def test_node_triage_calls_dataplane(monkeypatch):
    seen = {}

    def fake_triage(r, factory, serverless):
        seen.update(r=r, factory=factory, serverless=serverless)
        return {"status": "ok"}

    monkeypatch.setattr(server, "redis_client", lambda: "client")
    monkeypatch.setattr(server, "_serverless", lambda: True)
    monkeypatch.setattr(dataplane, "triage", fake_triage)
    assert server.node_triage() == {"status": "ok"}
    assert seen["r"] == "client" and seen["serverless"] is True and seen["factory"] is server._node_client


# ------------------------------------------------------------------------- prefix grouping


def test_normalize_key_replaces_digits_hex_and_uuid_segments():
    n = dataplane.normalize_key
    assert n("user:123:cart") == "user:*:cart"
    assert n("session:550e8400-e29b-41d4-a716-446655440000") == "session:*"
    assert n("obj:5f1d7f3a9c2b4e6a8d0c1b2a") == "obj:*"
    assert n("img/2024/05/thumb.jpg") == "img/*/*/thumb.jpg"
    assert n("v1.2.cfg") == "v1.*.cfg"
    assert n("{user:7}:cart") == "{user:*}:cart"
    assert n(b"order:99") == "order:*"
    assert n("feature:defaced") == "feature:defaced"  # hex-looking word without a digit stays
    assert n("user1:name") == "user1:name"  # mixed alphanumerics are not generic ids


def _prefix_data():
    data = {}
    for i in range(30):
        data[f"cache:{i}:blob"] = ("string", 1000, -1, 1000)  # big, never expires
    for i in range(10):
        data[f"session:{i}"] = ("string", 100, 60_000, 100)
    for i in range(10):
        data[f"queue:{i}"] = ("list", 50, -1, 5)
    return data


def _prefix_fake(policy="noeviction", used=95, **kw):
    infos = {"memory": {"used_memory": used, "maxmemory": 100, "maxmemory_policy": policy}}
    return FakeRedis(infos=infos, data=_prefix_data(), scan_batch=100, **kw)


def test_keyspace_sample_groups_by_prefix_with_ttl_and_types():
    out = dataplane.keyspace_sample(_prefix_fake(), sample_size=100, top_prefixes=2)
    assert [p["prefix"] for p in out["prefixes"]] == ["cache:*:blob", "session:*"]
    cache = out["prefixes"][0]
    assert cache["sampled_keys"] == 30 and cache["est_bytes"] == 30_000
    assert cache["no_ttl_pct"] == 100.0 and cache["types"] == {"string": 30}
    assert out["prefixes"][1]["no_ttl_pct"] == 0.0
    assert out["prefixes_summary"] == {"distinct": 3, "shown": 2, "est_bytes_total": 31_500}
    assert round(cache["pct_of_memory"]) == 95


def test_prefix_bytes_are_scaled_up_to_dbsize():
    # the sample only inspects 10 of 50 keys: estimates are multiplied by dbsize / sampled
    fake = _prefix_fake()
    out = dataplane.keyspace_sample(fake, sample_size=10, top_prefixes=5)
    assert out["sampled_keys"] == 10 and out["dbsize"] == 50
    total_sampled = sum(p["sampled_keys"] for p in out["prefixes"])
    assert total_sampled == 10
    assert sum(p["est_keys"] for p in out["prefixes"]) == 50


def test_prefix_finding_only_under_memory_pressure():
    noeviction = dataplane.keyspace_sample(_prefix_fake("noeviction", used=10), sample_size=100)
    assert any("cache:*:blob" in f["message"] and "no TTL" in f["message"] for f in noeviction["findings"])
    near_limit = dataplane.keyspace_sample(_prefix_fake("allkeys-lru", used=85), sample_size=100)
    assert near_limit["findings"] and near_limit["findings"][0]["severity"] == "warning"
    critical = dataplane.keyspace_sample(_prefix_fake("allkeys-lru", used=95), sample_size=100)
    assert critical["findings"][0]["severity"] == "critical"
    relaxed = dataplane.keyspace_sample(_prefix_fake("allkeys-lru", used=10), sample_size=100)
    assert relaxed["findings"] == []


def test_top_prefixes_bound_is_enforced():
    data = {f"p{i}x:{j}": ("string", 10, -1, 1) for i in range(80) for j in range(2)}
    fake = FakeRedis(infos={"memory": {"maxmemory_policy": "noeviction"}}, data=data, scan_batch=1000)
    out = dataplane.keyspace_sample(fake, sample_size=1000, top_prefixes=500)
    assert len(out["prefixes"]) == dataplane.MAX_TOP_PREFIXES
    assert out["prefixes_summary"]["distinct"] == 80
    assert len(dataplane.keyspace_sample(fake, sample_size=1000)["prefixes"]) == dataplane.DEFAULT_TOP_PREFIXES


def _cluster_text(*nodes: str) -> str:
    return "\n".join(nodes) + "\n"


TWO_SHARDS = _cluster_text(
    "a1 10.0.0.1:6379@16379 master - 0 0 1 connected 0-8191",
    "b1 10.0.0.2:6379@16379 master - 0 0 2 connected 8192-16383",
)


def _fan_factory(clients: dict[str, FakeRedis]):
    opened: list[str] = []

    def factory(host: str, port: int):
        opened.append(f"{host}:{port}")
        return clients[f"{host}:{port}"]

    return factory, opened


def _shard(prefix_keys: dict[str, tuple]):
    return FakeRedis(
        infos={"memory": {"used_memory": 50, "maxmemory": 100, "maxmemory_policy": "noeviction"}},
        data=prefix_keys,
        scan_batch=1000,
    )


def test_cluster_keyspace_sample_merges_prefixes_across_shards_within_budget():
    clients = {
        "10.0.0.1:6379": _shard({f"cart:{i}": ("string", 100, -1, 1) for i in range(20)}),
        "10.0.0.2:6379": _shard(
            {**{f"cart:{i}": ("string", 100, -1, 1) for i in range(100, 130)}, "tmp:1": ("string", 10, 5000, 1)}
        ),
    }
    seed = FakeRedis(infos={"cluster": {"cluster_enabled": 1}})
    seed.commands["CLUSTER NODES"] = TWO_SHARDS
    factory, opened = _fan_factory(clients)
    out = dataplane.cluster_keyspace_sample(seed, factory, sample_size=100, top_prefixes=3, max_seconds=5)
    assert sorted(opened) == ["10.0.0.1:6379", "10.0.0.2:6379"]
    cart = out["prefixes"][0]
    assert cart["prefix"] == "cart:*"
    assert cart["sampled_keys"] == 50 and cart["est_keys"] == 50 and cart["est_bytes"] == 5000
    assert cart["no_ttl_keys"] == 50 and cart["no_ttl_pct"] == 100.0
    assert [p["prefix"] for p in out["prefixes"]] == ["cart:*", "tmp:*"]
    assert out["prefixes_summary"]["est_bytes_total"] == 5010
    assert any("cart:*" in f["message"] for f in out["findings"])  # noeviction + no TTL
    assert out["sampled_keys"] == 51  # per shard budget ceil(100 / 2) never exceeded


def test_cluster_keyspace_sample_per_shard_sample_is_split():
    clients = {
        "10.0.0.1:6379": _shard({f"k:{i}": ("string", 10, -1, 1) for i in range(400)}),
        "10.0.0.2:6379": _shard({f"k:{i}": ("string", 10, -1, 1) for i in range(400)}),
    }
    seed = FakeRedis(infos={"cluster": {"cluster_enabled": 1}})
    seed.commands["CLUSTER NODES"] = TWO_SHARDS
    factory, _ = _fan_factory(clients)
    out = dataplane.cluster_keyspace_sample(seed, factory, sample_size=100, max_seconds=5)
    assert out["sampled_keys"] == 100
    assert [s["sampled_keys"] for s in out["per_shard"].values()] == [50, 50]
    assert out["prefixes"][0]["est_keys"] == 800  # scaled to each shard's dbsize


# ----------------------------------------------------------------------- cluster topology

ID_A, ID_B, ID_C, ID_R = "a" * 40, "b" * 40, "c" * 40, "d" * 40


def _node(node_id, addr, flags, master="-", link="connected", slots=""):
    return f"{node_id} {addr}@16379 {flags} {master} 0 0 1 {link} {slots}".rstrip()


def _messages(findings):
    return [f["message"] for f in findings]


def test_cluster_topology_flags_fail_handshake_and_noaddr():
    text = _cluster_text(
        _node(ID_A, "10.0.0.1:6379", "myself,master", slots="0-8191"),
        _node(ID_B, "10.0.0.2:6379", "master,fail", link="disconnected", slots="8192-16383"),
        _node(ID_C, "10.0.0.3:6379", "slave,fail?", master=ID_A),
        _node(ID_R, "10.0.0.4:6379", "slave,handshake", master=ID_B, link="disconnected"),
        _node("e" * 40, ":0", "noaddr,slave", master=ID_B),
    )
    findings = dataplane.cluster_topology_findings(dataplane.parse_cluster_nodes(text))
    msgs = _messages(findings)
    assert findings[0]["severity"] == "critical" and "10.0.0.2:6379 is flagged fail" in msgs[0]
    assert any("10.0.0.3:6379 is flagged fail?" in m for m in msgs)
    assert any("10.0.0.4:6379 is still in handshake" in m for m in msgs)
    assert any("noaddr" in m for m in msgs)
    ranks = [f["severity"] for f in findings]
    assert ranks == sorted(ranks, key=["critical", "warning", "info"].index)


def test_cluster_topology_parses_migrating_and_importing_slots():
    text = _cluster_text(
        _node(ID_A, "10.0.0.1:6379", "myself,master", slots=f"0-8191 [93->-{ID_B}] [94->-{ID_B}]"),
        _node(ID_B, "10.0.0.2:6379", "master", slots=f"8192-16383 [93-<-{ID_A}]"),
    )
    nodes = dataplane.parse_cluster_nodes(text)
    assert nodes[0]["migrating"] == [{"slot": 93, "to": ID_B}, {"slot": 94, "to": ID_B}]
    assert nodes[1]["importing"] == [{"slot": 93, "from": ID_A}]
    assert nodes[0]["slot_count"] == 8192  # the bracketed markers never count as owned slots
    resharding = [f for f in dataplane.cluster_topology_findings(nodes) if "resharding" in f["message"]]
    assert len(resharding) == 2 and all(f["severity"] == "info" for f in resharding)
    assert "2 slot(s) migrating out" in resharding[0]["message"]


def test_cluster_topology_primary_without_replica_and_uneven_slots():
    text = _cluster_text(
        _node(ID_A, "10.0.0.1:6379", "myself,master", slots="0-9999"),
        _node(ID_B, "10.0.0.2:6379", "master", slots="10000-16383"),
        _node(ID_R, "10.0.0.4:6379", "slave", master=ID_A),
    )
    msgs = _messages(dataplane.cluster_topology_findings(dataplane.parse_cluster_nodes(text)))
    assert any("primary 10.0.0.2:6379 has no replica" in m for m in msgs)
    assert not any("primary 10.0.0.1:6379 has no replica" in m for m in msgs)
    assert any("owns 10000 slots" in m for m in msgs) and any("owns 6384 slots" in m for m in msgs)


def test_cluster_topology_balanced_group_has_no_findings():
    text = _cluster_text(
        _node(ID_A, "10.0.0.1:6379", "myself,master", slots="0-8191"),
        _node(ID_B, "10.0.0.2:6379", "master", slots="8192-16383"),
        _node(ID_C, "10.0.0.3:6379", "slave", master=ID_A),
        _node(ID_R, "10.0.0.4:6379", "slave", master=ID_B),
    )
    assert dataplane.cluster_topology_findings(dataplane.parse_cluster_nodes(text)) == []


def test_cluster_topology_without_any_replica_is_one_info_finding():
    findings = dataplane.cluster_topology_findings(dataplane.parse_cluster_nodes(TWO_SHARDS))
    assert [f["severity"] for f in findings] == ["info"]


def _seed_cluster(shards_reply):
    seed = FakeRedis(infos={"cluster": {"cluster_enabled": 1}, "server": {"redis_version": "6.2.14"}})
    seed.commands["CLUSTER NODES"] = TWO_SHARDS
    if shards_reply is not None:
        seed.commands["CLUSTER SHARDS"] = shards_reply
    return seed


def test_cluster_topology_6x_fallback_notes_missing_cluster_shards():
    out = dataplane.cluster_nodes(_seed_cluster(None))
    assert "shards_check" not in out
    assert any("CLUSTER SHARDS" in n and "6.2.14" in n for n in out["notes"])
    assert out["topology_findings"]  # still derived from CLUSTER NODES alone


def test_cluster_topology_cluster_shards_cross_check_reports_replica_lag():
    shards = [
        {
            "slots": [0, 8191],
            "nodes": [
                {
                    "id": "x",
                    "endpoint": "10.0.0.1",
                    "port": 6379,
                    "role": "master",
                    "replication-offset": 5_000_000,
                    "health": "online",
                },
                {
                    "id": "y",
                    "endpoint": "10.0.0.3",
                    "port": 6379,
                    "role": "replica",
                    "replication-offset": 1_000,
                    "health": "online",
                },
            ],
        },
        [  # RESP2 shape: flat key/value lists
            b"slots",
            [8192, 16383],
            b"nodes",
            [
                [
                    b"id",
                    b"z",
                    b"endpoint",
                    b"10.0.0.2",
                    b"port",
                    6379,
                    b"role",
                    b"master",
                    b"replication-offset",
                    10,
                    b"health",
                    b"online",
                ],
                [
                    b"id",
                    b"w",
                    b"endpoint",
                    b"10.0.0.4",
                    b"port",
                    6379,
                    b"role",
                    b"replica",
                    b"replication-offset",
                    10,
                    b"health",
                    b"loading",
                ],
            ],
        ],
    ]
    out = dataplane.cluster_nodes(_seed_cluster(shards))
    assert "notes" not in out
    assert out["shards_check"][0] == {
        "slot_count": 8192,
        "primary": "10.0.0.1:6379",
        "replicas": [{"endpoint": "10.0.0.3:6379", "health": "online", "lag_bytes": 4_999_000}],
    }
    assert out["shards_check"][1]["replicas"][0]["health"] == "loading"
    msgs = _messages(out["topology_findings"])
    assert any("10.0.0.3:6379 is 4999000 bytes behind" in m for m in msgs)
    assert any("10.0.0.4:6379 health is loading" in m for m in msgs)


def test_cluster_topology_health_output_includes_findings():
    clients = {
        "10.0.0.1:6379": FakeRedis(infos={"default": {"role": "master"}}),
        "10.0.0.2:6379": FakeRedis(infos={"default": {"role": "master"}}),
    }
    factory, _ = _fan_factory(clients)
    out = dataplane.cluster_health(_seed_cluster(None), factory)
    assert out["topology_findings"][0]["severity"] == "info"


def test_cluster_topology_fan_out_does_not_probe_cluster_shards():
    seed = _seed_cluster([])
    calls: list[tuple] = []
    original = seed.execute_command
    seed.execute_command = lambda *a: (calls.append(a), original(*a))[1]
    dataplane._fan_out_primaries(seed, lambda h, p: FakeRedis(), lambda c, b, n: {}, 2, 1.0, 1.0)
    assert ("CLUSTER", "SHARDS") not in calls


# ------------------------------------------------- CLUSTER SHARDS cross-check (round 15)


def _shards_entry(slots, *members):
    """CLUSTER SHARDS entry (RESP3 dict shape); members are (ip, role, offset, health)."""
    return {
        "slots": slots,
        "nodes": [
            {"id": ip, "endpoint": ip, "port": 6379, "role": role, "replication-offset": offset, "health": health}
            for ip, role, offset, health in members
        ],
    }


SHARDS_TOPOLOGY = _cluster_text(
    _node(ID_A, "10.0.0.1:6379", "myself,master", slots="0-8191"),
    _node(ID_B, "10.0.0.2:6379", "master", slots="8192-16383"),
    _node(ID_C, "10.0.0.3:6379", "slave", master=ID_A),
    _node(ID_R, "10.0.0.4:6379", "slave", master=ID_B),
)


def _seed_shards(reply, text=SHARDS_TOPOLOGY, version="7.2.4"):
    seed = FakeRedis(infos={"cluster": {"cluster_enabled": 1}, "server": {"redis_version": version}})
    seed.commands["CLUSTER NODES"] = text
    if reply is not None:
        seed.commands["CLUSTER SHARDS"] = reply
    return seed


def test_cluster_shards_check_reports_offset_gap_and_failed_replica():
    reply = [
        _shards_entry(
            [0, 8191],
            ("10.0.0.1", "master", 9_000_000, "online"),
            ("10.0.0.3", "replica", 1_000, "online"),
        ),
        _shards_entry(
            [8192, 16383],
            ("10.0.0.2", "master", 100, "online"),
            ("10.0.0.4", "replica", 100, "fail"),
        ),
    ]
    out = dataplane.cluster_nodes(_seed_shards(reply))
    findings = {f["message"]: f for f in out["topology_findings"]}
    gap = findings["replica 10.0.0.3:6379 is 8999000 bytes behind its primary"]
    assert gap["severity"] == "warning" and gap["source"] == "CLUSTER SHARDS"
    failed = findings["CLUSTER SHARDS: node 10.0.0.4:6379 health is fail"]
    assert failed["severity"] == "critical"
    none_healthy = [m for m in findings if "has no healthy replica" in m]
    assert none_healthy and findings[none_healthy[0]]["severity"] == "critical"
    assert out["topology_findings"][0]["severity"] == "critical"  # findings first, worst first


def test_cluster_shards_check_flags_a_shard_without_replica_once():
    text = _cluster_text(
        _node(ID_A, "10.0.0.1:6379", "myself,master", slots="0-8191"),
        _node(ID_B, "10.0.0.2:6379", "master", slots="8192-16383"),
        _node(ID_C, "10.0.0.3:6379", "slave", master=ID_A),
    )
    reply = [
        _shards_entry([0, 8191], ("10.0.0.1", "master", 10, "online"), ("10.0.0.3", "replica", 10, "online")),
        _shards_entry([8192, 16383], ("10.0.0.2", "master", 10, "online")),
    ]
    out = dataplane.cluster_nodes(_seed_shards(reply, text))
    assert sum("10.0.0.2:6379 has no replica" in f["message"] for f in out["topology_findings"]) == 1
    assert out["topology_findings"][0]["message"].startswith("primary 10.0.0.2:6379 has no replica")  # topology wins
    findings, shards = dataplane.cluster_shards_check(reply)
    assert any(f["category"] == "no-replica" and f["source"] == "CLUSTER SHARDS" for f in findings)
    assert shards[1]["replicas"] == []


def test_cluster_shards_check_dedupes_a_node_already_flagged_fail():
    text = _cluster_text(
        _node(ID_A, "10.0.0.1:6379", "myself,master", slots="0-16383"),
        _node(ID_C, "10.0.0.3:6379", "slave,fail", master=ID_A, link="disconnected"),
    )
    reply = [_shards_entry([0, 16383], ("10.0.0.1", "master", 10, "online"), ("10.0.0.3", "replica", 10, "fail"))]
    out = dataplane.cluster_nodes(_seed_shards(reply, text))
    down = [f for f in out["topology_findings"] if f["node"] == "10.0.0.3:6379" and f["category"] == "node-down"]
    assert len(down) == 1 and "flagged fail" in down[0]["message"]


def test_cluster_shards_check_older_engine_falls_back_to_cluster_nodes():
    seed = _seed_shards(redis.ResponseError("unknown subcommand 'shards'"), version="6.2.14")
    out = dataplane.cluster_nodes(seed)
    assert "shards_check" not in out
    assert any("CLUSTER SHARDS: not supported by redis 6.2.14" in n for n in out["notes"])
    assert out["shards"] and out["topology_findings"] == []


def test_cluster_triage_reports_cluster_shards_findings_and_the_fallback_note():
    reply = [
        _shards_entry([0, 8191], ("10.0.0.1", "master", 10, "online"), ("10.0.0.3", "replica", 10, "loading")),
        _shards_entry([8192, 16383], ("10.0.0.2", "master", 10, "online"), ("10.0.0.4", "replica", 10, "online")),
    ]
    clients = {ep: FakeRedis(infos={"default": {"role": "master"}}) for ep in ("10.0.0.1:6379", "10.0.0.2:6379")}
    factory, _ = _fan_factory(clients)
    out = dataplane.cluster_triage(_seed_shards(reply), factory)
    topo = [f for f in out["findings"] if f.get("section") == "topology"]
    assert [f["message"] for f in topo if "loading" in f["message"]]
    assert any("has no healthy replica" in f["message"] for f in topo)
    old = dataplane.cluster_triage(_seed_shards(redis.ResponseError("unknown"), version="6.0.9"), factory)
    assert any("CLUSTER SHARDS" in n for n in old["notes"])
