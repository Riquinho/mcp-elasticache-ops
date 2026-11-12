import os
import socket
import threading

import pytest

from mcp_elasticache_ops import memcached

STATS = (
    b"STAT pid 1\r\nSTAT uptime 100\r\nSTAT version 1.6.29\r\nSTAT curr_connections 3\r\n"
    b"STAT total_connections 9\r\nSTAT curr_items 10\r\nSTAT bytes 950\r\nSTAT limit_maxbytes 1000\r\n"
    b"STAT get_hits 75\r\nSTAT get_misses 25\r\nSTAT evictions 4\r\nSTAT threads 4\r\nEND\r\n"
)


@pytest.fixture()
def fake_memcached():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    seen: list[bytes] = []

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                cmd = conn.recv(1024)
                seen.append(cmd)
                conn.sendall(STATS if cmd.startswith(b"stats") else b"ERROR\r\n")

    threading.Thread(target=serve, daemon=True).start()
    yield srv.getsockname()[1], seen
    srv.close()


def test_summary(fake_memcached):
    port, seen = fake_memcached
    s = memcached.summary("127.0.0.1", port, timeout=2)
    assert s["version"] == "1.6.29"
    assert s["get_hit_ratio"] == 0.75
    assert s["evictions"] == 4
    assert any("evictions" in f for f in s["findings"])
    assert any("memory at 95%" in f for f in s["findings"])
    assert seen == [b"stats\r\n"]


def test_rejects_unknown_group():
    with pytest.raises(ValueError):
        memcached.stats("127.0.0.1", 11211, "detail on")


@pytest.mark.integration
def test_live_memcached():
    host = os.getenv("MEMCACHED_TEST_HOST")
    if not host:
        pytest.skip("MEMCACHED_TEST_HOST not set")
    port = int(os.getenv("MEMCACHED_TEST_PORT", "11211"))
    s = memcached.summary(host, port)
    assert s["version"]
    assert memcached.stats(host, port, "settings")


# ------------------------------------------------------------ cluster fan-out (fake socket)


class FakeSocket:
    def __init__(self, replies, sent):
        self._replies = replies
        self._sent = sent
        self._chunks: list[bytes] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def sendall(self, data):
        self._sent.append(data)
        cmd = data.decode("ascii").strip()
        reply = self._replies.get(cmd, b"ERROR\r\n")
        self._chunks = list(reply) if isinstance(reply, list) else [reply]

    def recv(self, n):
        return self._chunks.pop(0) if self._chunks else b""


def _general(items=1000, size=10 * 1024 * 1024, hits=90, misses=10, evictions=0, conns=3, listen=0, maxconn=1000):
    lines = {
        "version": "1.6.29",
        "uptime": 100,
        "curr_connections": conns,
        "max_connections": maxconn,
        "curr_items": items,
        "bytes": size,
        "limit_maxbytes": 64 * 1024 * 1024,
        "get_hits": hits,
        "get_misses": misses,
        "evictions": evictions,
        "listen_disabled_num": listen,
    }
    return ("".join(f"STAT {k} {v}\r\n" for k, v in lines.items()) + "END\r\n").encode()


def _slabs(pages_by_class):
    body = "".join(f"STAT {c}:chunk_size {96 * c}\r\nSTAT {c}:total_pages {p}\r\n" for c, p in pages_by_class.items())
    return (body + "STAT active_slabs 2\r\nEND\r\n").encode()


def _items(evicted_by_class):
    body = "".join(
        f"STAT items:{c}:number 5\r\nSTAT items:{c}:evicted {e}\r\nSTAT items:{c}:outofmemory {e}\r\n"
        for c, e in evicted_by_class.items()
    )
    return (body + "END\r\n").encode()


def _node(general, slabs=None, items=None):
    return {
        "stats": general,
        "stats slabs": slabs or _slabs({1: 1}),
        "stats items": items or _items({1: 0}),
    }


@pytest.fixture()
def fake_cluster(monkeypatch):
    nodes: dict[tuple[str, int], dict | Exception] = {}
    sent: list[bytes] = []

    def create(addr, timeout=None):
        spec = nodes[addr]
        if isinstance(spec, Exception):
            raise spec
        return FakeSocket(spec, sent)

    monkeypatch.setattr(socket, "create_connection", create)
    return nodes, sent


def test_cluster_stats_findings_first(fake_cluster):
    nodes, sent = fake_cluster
    nodes[("a", 11211)] = _node(_general())
    nodes[("b", 11211)] = _node(_general())
    nodes[("c", 11211)] = _node(
        _general(items=5000, hits=40, misses=60, evictions=7, conns=900, listen=2),
        _slabs({1: 1, 2: 9}),
        _items({1: 0, 2: 7}),
    )
    out = memcached.cluster_stats([("a", 11211), ("b", 11211), ("c", 11211)], timeout=2)
    assert out["status"] == "ok" and out["nodes_ok"] == 3
    msgs = [f["message"] for f in out["findings"]]
    assert any("c:11211 has 7 evictions" in m for m in msgs)
    assert any("c:11211 hit ratio 40%" in m and "median 90%" in m for m in msgs)
    assert any("c:11211 items imbalance" in m for m in msgs)
    assert any("listen_disabled_num=2" in m for m in msgs)
    assert any("900/1000 near maxconns" in m for m in msgs)
    assert any("slab class 2" in m and "7 evictions" in m and "7 out-of-memory" in m for m in msgs)
    assert any("slab class 2" in m and "90% of the allocated pages" in m for m in msgs)
    assert not any("a:11211 has" in m for m in msgs)
    ranks = [f["severity"] for f in out["findings"]]
    assert ranks == sorted(ranks, key=["critical", "warning", "info"].index)
    assert out["summary"]["evictions"] == 7
    assert [n["node"] for n in out["nodes"]] == ["a:11211", "b:11211", "c:11211"]
    assert set(sent) == {b"stats\r\n", b"stats slabs\r\n", b"stats items\r\n"}


def test_cluster_stats_dead_node_makes_result_partial(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("a", 11211)] = _node(_general())
    nodes[("down", 11211)] = ConnectionRefusedError("refused")
    out = memcached.cluster_stats([("a", 11211), ("down", 11211)], timeout=2)
    assert out["status"] == "partial" and out["nodes_ok"] == 1 and out["nodes_total"] == 2
    assert out["findings"][0]["severity"] == "warning"
    assert "down:11211 unreachable" in out["findings"][0]["message"] and "partial" in out["findings"][0]["message"]
    assert out["nodes"][1]["status"] == "error"


def test_cluster_stats_all_down_and_no_nodes(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("x", 1)] = OSError("boom")
    assert memcached.cluster_stats([("x", 1)], timeout=2)["status"] == "error"
    assert memcached.cluster_stats([])["status"] == "error"


def test_response_split_across_several_recv_calls(fake_cluster):
    nodes, _ = fake_cluster
    whole = _general(items=42)
    pieces = [whole[:7], whole[7:30], whole[30:-3], whole[-3:]]  # splits mid-line and inside END
    nodes[("a", 11211)] = {**_node(whole), "stats": pieces}
    assert memcached.stats("a", 11211, "", 2)["curr_items"] == "42"
    report = memcached.node_report("a", 11211, 2)
    assert report["status"] == "ok" and report["curr_items"] == 42


def test_error_reply_degrades_to_partial_and_raises_for_stats(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("a", 11211)] = {"stats": _general()}  # slabs and items answer ERROR
    with pytest.raises(RuntimeError, match="ERROR"):
        memcached.stats("a", 11211, "slabs", 2)
    report = memcached.node_report("a", 11211, 2)
    assert report["status"] == "partial" and "stats slabs" in report["error"] and "stats items" in report["error"]
    out = memcached.cluster_stats([("a", 11211)], timeout=2)
    assert out["status"] == "ok"  # the node answered; only optional groups failed
    assert any(f["severity"] == "info" and "stats slabs" in f["message"] for f in out["findings"])


def test_only_stats_and_version_reach_the_socket(fake_cluster):
    nodes, sent = fake_cluster
    nodes[("a", 11211)] = _node(_general())
    nodes[("a", 11211)].update(
        {"version": b"VERSION 1.6.29\r\n", "stats settings": b"END\r\n", "stats conns": b"END\r\n"}
    )
    memcached.cluster_stats([("a", 11211)], timeout=2)
    for group in ("", "settings", "slabs", "items", "conns"):
        memcached.stats("a", 11211, group, 2)
    memcached._query("a", 11211, "version", 2)
    assert sent
    allowed = {"stats", "stats settings", "stats slabs", "stats items", "stats conns", "version", "config get cluster"}
    assert allowed == memcached.ALLOWED_COMMANDS  # round 12 added exactly one read-only form
    assert {s.decode().strip() for s in sent} <= allowed
    assert all(s.endswith(b"\r\n") and s.count(b"\r\n") == 1 for s in sent)


def test_cluster_findings_need_three_nodes_for_hit_ratio_outlier(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("a", 1)] = _node(_general())
    nodes[("b", 1)] = _node(_general(hits=10, misses=90))
    out = memcached.cluster_stats([("a", 1), ("b", 1)], timeout=2)
    assert not any("hit ratio" in f["message"] for f in out["findings"])
    assert out["findings"][0]["message"] == "no issues detected by basic thresholds"


def test_memcached_cluster_stats_tool(fake_cluster, monkeypatch):
    from mcp_elasticache_ops import server

    nodes, _ = fake_cluster
    nodes[("m1", 11211)] = _node(_general())
    nodes[("m2", 11212)] = _node(_general())
    monkeypatch.setenv("MEMCACHED_NODES", "m1:11211,m2:11212")
    out = server.memcached_cluster_stats()
    assert out["status"] == "ok" and out["nodes_total"] == 2


# ------------------------------------------------------------------ usage and endpoint findings


def _report(evictions=0, hits=90, misses=10, used=10 * 1024 * 1024, items=1000, node="n1:11211"):
    return {
        "node": node,
        "status": "ok",
        "limit_maxbytes": 64 * 1024 * 1024,
        "bytes": used,
        "curr_items": items,
        "evictions": evictions,
        "gets": hits + misses,
        "get_hit_ratio": hits / (hits + misses),
        "listen_disabled_num": 0,
        "curr_connections": 1,
        "max_connections": 1000,
        "slabs": {"findings": [], "notes": []},
    }


def _messages(report):
    return " | ".join(f["message"] for f in memcached.cluster_findings([report]))


def test_evictions_with_low_hit_rate_say_the_working_set_does_not_fit():
    text = _messages(_report(evictions=500, hits=50, misses=50, used=60 * 1024 * 1024))
    assert "working set does not fit" in text
    assert "working set" not in _messages(_report(evictions=500, hits=95, misses=5, used=60 * 1024 * 1024))
    assert "working set" not in _messages(
        _report(evictions=500, hits=1, misses=5, used=60 * 1024 * 1024)
    )  # too few gets


def test_evictions_far_below_the_memory_limit_point_at_slab_imbalance():
    assert "slab imbalance" in _messages(_report(evictions=3, used=8 * 1024 * 1024))
    assert "slab imbalance" not in _messages(_report(evictions=3, used=60 * 1024 * 1024))
    assert "slab imbalance" not in _messages(_report(evictions=0, used=8 * 1024 * 1024))


def test_near_full_node_with_huge_average_items_is_flagged():
    assert "averaging" in _messages(_report(used=62 * 1024 * 1024, items=100))
    assert "averaging" not in _messages(_report(used=62 * 1024 * 1024, items=100_000))


def test_summary_adds_eviction_context(monkeypatch):
    stats = {"evictions": "9", "get_hits": "40", "get_misses": "60", "bytes": "1000", "limit_maxbytes": "100000"}
    monkeypatch.setattr(memcached, "stats", lambda *a, **k: stats)
    text = " | ".join(memcached.summary("h")["findings"])
    assert "working set does not fit" in text and "slab imbalance" in text


def test_auto_discovery_endpoint_in_memcached_nodes_is_flagged():
    cfg = "mc.abc123.cfg.use1.cache.amazonaws.com"
    assert memcached.is_discovery_endpoint(cfg)
    assert not memcached.is_discovery_endpoint("mc.abc123.0001.use1.cache.amazonaws.com")
    assert not memcached.is_discovery_endpoint("10.0.0.5")
    alone = memcached.cluster_findings([_report(node=f"{cfg}:11211")])
    assert any("single arbitrary node" in f["message"] for f in alone)
    mixed = memcached.cluster_findings(
        [_report(node=f"{cfg}:11211"), _report(node="mc.abc123.0001.use1.cache.amazonaws.com:11211")]
    )
    assert any("counted twice" in f["message"] for f in mixed)
    assert not any("auto-discovery" in f["message"] for f in memcached.cluster_findings([_report()]))


# ------------------------------------------------------------------ control plane: engine versions


def _control_plane(cluster, versions):
    import datetime as dt

    import boto3
    from botocore.stub import Stubber

    from mcp_elasticache_ops.config import ControlPlaneConfig
    from mcp_elasticache_ops.controlplane import ControlPlane

    ec = boto3.client("elasticache", region_name="us-east-1", aws_access_key_id="t", aws_secret_access_key="t")
    stub = Stubber(ec)
    stub.add_response("describe_cache_clusters", {"CacheClusters": [cluster]})
    stub.add_response("describe_cache_engine_versions", {"CacheEngineVersions": versions})
    stub.add_response("describe_cache_parameter_groups", {"CacheParameterGroups": []})

    class Session:
        def client(self, service, region_name=None, config=None):
            return ec

    cp = ControlPlane(
        ControlPlaneConfig(region="us-east-1"),
        session_factory=Session,
        clock=lambda: dt.datetime(2026, 11, 12, tzinfo=dt.UTC),
    )
    return cp, stub


def test_aws_cache_clusters_flags_old_and_retired_memcached_version_and_discovery_endpoint():
    cluster = {
        "CacheClusterId": "mc",
        "Engine": "memcached",
        "EngineVersion": "1.4.34",
        "CacheClusterStatus": "available",
        "NumCacheNodes": 3,
        "ConfigurationEndpoint": {"Address": "mc.x.cfg.use1.cache.amazonaws.com", "Port": 11211},
    }
    versions = [
        {"Engine": "memcached", "EngineVersion": "1.6.6", "CacheParameterGroupFamily": "memcached1.6"},
        {"Engine": "memcached", "EngineVersion": "1.6.22", "CacheParameterGroupFamily": "memcached1.6"},
    ]
    cp, stub = _control_plane(cluster, versions)
    with stub:
        out = cp.cache_clusters()
    text = " | ".join(f["message"] for f in out["findings"])
    assert "end-of-life (< 1.6)" in text
    assert "no longer offered" in text
    assert "auto-discovery endpoint mc.x.cfg.use1.cache.amazonaws.com:11211 fronts 3 nodes" in text


def test_aws_cache_clusters_is_quiet_for_a_current_memcached_version():
    cluster = {
        "CacheClusterId": "mc",
        "Engine": "memcached",
        "EngineVersion": "1.6.22",
        "CacheClusterStatus": "available",
        "NumCacheNodes": 1,
    }
    versions = [{"Engine": "memcached", "EngineVersion": "1.6.22", "CacheParameterGroupFamily": "memcached1.6"}]
    cp, stub = _control_plane(cluster, versions)
    with stub:
        out = cp.cache_clusters()
    text = " | ".join(f["message"] for f in out["findings"])
    assert "end-of-life" not in text and "no longer offered" not in text and "auto-discovery" not in text


# ------------------------------------------------------------------ auto-discovery check

CONFIG_REPLY = (
    b"CONFIG cluster 0 100\r\n3\nmc.0001.use1.cache.amazonaws.com|10.0.0.1|11211 "
    b"mc.0002.use1.cache.amazonaws.com|10.0.0.2|11211\n\r\nEND\r\n"
)


def _aws_cluster(*addresses, version="1.6.22", status="available"):
    return {
        "CacheClusterId": "mc",
        "Engine": "memcached",
        "EngineVersion": version,
        "ConfigurationEndpoint": {"Address": "mc.cfg.use1.cache.amazonaws.com", "Port": 11211},
        "CacheNodes": [{"CacheNodeStatus": status, "Endpoint": {"Address": a, "Port": 11211}} for a in addresses],
    }


def test_parse_config_cluster():
    parsed = memcached.parse_config_cluster(["CONFIG cluster 0 100", "3\nh1|1.1.1.1|11211 h2||11212", ""])
    assert parsed["config_version"] == 3
    assert [(n["host"], n["port"]) for n in parsed["nodes"]] == [("h1", 11211), ("h2", 11212)]
    with pytest.raises(ValueError):
        memcached.parse_config_cluster(["garbage"])
    with pytest.raises(ValueError):
        memcached.parse_config_cluster(["1 nohostport"])


def test_discovery_matches(fake_cluster):
    nodes, sent = fake_cluster
    nodes[("mc.cfg", 11211)] = {"config get cluster": CONFIG_REPLY, "version": b"VERSION 1.6.22\r\n"}
    cluster = _aws_cluster("mc.0001.use1.cache.amazonaws.com", "mc.0002.use1.cache.amazonaws.com")
    out = memcached.discovery_report(cluster, "mc.cfg", 11211, 2)
    assert out["status"] == "ok" and out["config_version"] == 3
    assert out["findings"][0]["severity"] == "info" and "matches" in out["findings"][0]["message"]
    assert {s.decode().strip() for s in sent} == {"config get cluster", "version"}


def test_discovery_flags_missing_stale_and_version(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("mc.cfg", 11211)] = {"config get cluster": CONFIG_REPLY, "version": b"VERSION 1.5.16\r\n"}
    cluster = _aws_cluster("mc.0001.use1.cache.amazonaws.com", "mc.0003.use1.cache.amazonaws.com")
    out = memcached.discovery_report(cluster, "mc.cfg", 11211, 2)
    msgs = [(f["severity"], f["message"]) for f in out["findings"]]
    assert msgs[0][0] == "critical" and "mc.0003" in msgs[0][1] and "missing from the discovery config" in msgs[0][1]
    assert any(sev == "warning" and "mc.0002" in m and "stale" in m for sev, m in msgs)
    assert any("1.5.16" in m and "1.6.22" in m for _, m in msgs)


def test_discovery_node_still_creating_is_info_only(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("mc.cfg", 11211)] = {"config get cluster": CONFIG_REPLY, "version": b"VERSION 1.6.22\r\n"}
    cluster = _aws_cluster("mc.0001.use1.cache.amazonaws.com", "mc.0002.use1.cache.amazonaws.com")
    cluster["CacheNodes"].append({"CacheNodeStatus": "creating", "Endpoint": {"Address": "mc.0009.x", "Port": 11211}})
    out = memcached.discovery_report(cluster, "mc.cfg", 11211, 2)
    assert [f["severity"] for f in out["findings"]] == ["info"] and "creating" in out["findings"][0]["message"]


def test_discovery_unreachable_endpoint_is_a_finding(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("nowhere", 11211)] = ConnectionRefusedError("refused")
    out = memcached.discovery_report(_aws_cluster("a"), "nowhere", 11211, 2)
    assert out["status"] == "error" and out["findings"][0]["severity"] == "warning"


@pytest.mark.parametrize(
    "verb",
    ["set k 0 0 1", "flush_all", "config set cluster 0 1", "config get cluster extra", "CONFIG GET CLUSTER", "get k"],
)
def test_other_memcached_verbs_stay_blocked(verb):
    assert verb not in memcached.ALLOWED_COMMANDS
    with pytest.raises(ValueError, match="not allowed"):
        memcached._query("127.0.0.1", 1, verb, 1)


def test_controlplane_memcached_discovery_end_to_end(fake_cluster):
    from mcp_elasticache_ops.config import ControlPlaneConfig
    from mcp_elasticache_ops.controlplane import ControlPlane

    nodes, _ = fake_cluster
    nodes[("mc.cfg.use1.cache.amazonaws.com", 11211)] = {
        "config get cluster": CONFIG_REPLY,
        "version": b"VERSION 1.6.22\r\n",
    }
    cluster = _aws_cluster("mc.0001.use1.cache.amazonaws.com")

    class Client:
        def describe_cache_clusters(self, **kwargs):
            assert kwargs["CacheClusterId"] == "mc" and kwargs["ShowCacheNodeInfo"] is True
            return {"CacheClusters": [cluster]}

    class Session:
        def client(self, service, region_name=None, config=None):
            return Client()

    def plane():
        return ControlPlane(ControlPlaneConfig(region="us-east-1"), session_factory=Session)

    out = plane().memcached_discovery("mc")
    assert out["status"] == "ok" and any("mc.0002" in f["message"] for f in out["findings"])
    cluster["Engine"] = "redis"
    assert plane().memcached_discovery("mc")["error"] == "NotMemcached"


# ------------------------------------------------------------ round 27: eviction rate, slab calcification, conns


def _general_with(**extra):
    base = {
        "version": "1.6.29",
        "uptime": 100,
        "curr_connections": 3,
        "max_connections": 1000,
        "curr_items": 1000,
        "bytes": 40 * 1024 * 1024,
        "limit_maxbytes": 64 * 1024 * 1024,
        "get_hits": 1000,
        "get_misses": 10,
        "evictions": 0,
        "reclaimed": 0,
        "listen_disabled_num": 0,
        "accepting_conns": 1,
        **extra,
    }
    return ("".join(f"STAT {k} {v}\r\n" for k, v in base.items()) + "END\r\n").encode()


def _msgs(out, severity=None):
    return [f["message"] for f in out["findings"] if severity in (None, f["severity"])]


def test_evictions_weighed_against_get_hits_name_the_reclaimed_count(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("a", 11211)] = _node(_general_with(evictions=50, reclaimed=3))
    out = memcached.cluster_stats([("a", 11211)], timeout=2)
    msg = next(m for m in _msgs(out) if "per 100 get_hits" in m)
    assert "5.0 items per 100 get_hits (50 evictions, 1000 hits)" in msg and "only 3 expired items" in msg


def test_reclaimed_items_are_named_but_do_not_hide_live_evictions(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("a", 11211)] = _node(_general_with(evictions=50, reclaimed=900))
    msg = next(m for m in _msgs(memcached.cluster_stats([("a", 11211)], timeout=2)) if "per 100 get_hits" in m)
    assert "900 expired items were reclaimed too" in msg


def test_a_trickle_of_evictions_or_too_few_hits_is_not_a_rate_finding(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("a", 11211)] = _node(_general_with(evictions=2))  # 0.2 per 100 hits
    nodes[("b", 11211)] = _node(_general_with(evictions=50, get_hits=20))  # ratio means nothing under 100 hits
    out = memcached.cluster_stats([("a", 11211), ("b", 11211)], timeout=2)
    assert not any("per 100 get_hits" in m for m in _msgs(out))


def test_slab_calcification_is_a_finding_when_other_classes_hold_free_chunks(fake_cluster):
    nodes, _ = fake_cluster
    slabs = (
        b"STAT 1:chunk_size 96\r\nSTAT 1:total_pages 1\r\nSTAT 1:free_chunks 0\r\n"
        b"STAT 5:chunk_size 1024\r\nSTAT 5:total_pages 40\r\nSTAT 5:free_chunks 40000\r\nEND\r\n"
    )
    nodes[("a", 11211)] = _node(_general_with(), slabs=slabs, items=_items({1: 30, 5: 0}))
    out = memcached.cluster_stats([("a", 11211)], timeout=2)
    msg = next(m for m in _msgs(out, "warning") if "slab calcification" in m)
    assert "slab class 1 evicts (30)" in msg and "39 MiB of free chunks" in msg


def test_slab_eviction_without_idle_space_is_not_calcification(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("a", 11211)] = _node(_general_with(), slabs=_slabs({1: 5, 5: 5}), items=_items({1: 30, 5: 0}))
    assert not any("calcification" in m for m in _msgs(memcached.cluster_stats([("a", 11211)], timeout=2)))


def test_accepting_conns_zero_is_critical_and_sorts_first(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("a", 11211)] = _node(_general_with(accepting_conns=0, listen_disabled_num=4, evictions=60))
    out = memcached.cluster_stats([("a", 11211)], timeout=2)
    assert out["findings"][0]["severity"] == "critical" and "accepting_conns=0" in out["findings"][0]["message"]
    assert any("listen_disabled_num=4" in m for m in _msgs(out))


def test_connections_near_max_and_accepting_conns_missing(fake_cluster):
    nodes, _ = fake_cluster
    general = _general(conns=900, maxconn=1000)  # no accepting_conns key at all: older builds
    nodes[("a", 11211)] = _node(general)
    out = memcached.cluster_stats([("a", 11211)], timeout=2)
    assert any("connections 900/1000 near maxconns" in m for m in _msgs(out))
    assert not any("accepting_conns" in m for m in _msgs(out))
    assert out["nodes"][0]["accepting_conns"] is None


def test_timeout_on_one_node_is_partial_not_fatal(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("a", 11211)] = _node(_general_with())
    nodes[("slow", 11211)] = TimeoutError("timed out")
    out = memcached.cluster_stats([("a", 11211), ("slow", 11211)], timeout=1)
    assert out["status"] == "partial" and out["nodes_ok"] == 1
    assert any("slow:11211 unreachable: TimeoutError: timed out" in m for m in _msgs(out))


def test_recv_timeout_mid_reply_marks_the_node(monkeypatch):
    class Stalled(FakeSocket):
        def recv(self, n):
            raise TimeoutError("timed out")

    sent: list[bytes] = []
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: Stalled({"stats": b""}, sent))
    report = memcached.node_report("a", 11211, 1)
    assert report["status"] == "error" and "TimeoutError" in report["error"]


def test_stats_cachedump_is_denied_before_the_socket(fake_cluster):
    nodes, sent = fake_cluster
    nodes[("a", 11211)] = _node(_general_with())
    with pytest.raises(ValueError, match="group must be one of"):
        memcached.stats("a", 11211, "cachedump", 2)
    for command in ("stats cachedump 1 100", "stats cachedump", "flush_all", "stats reset"):
        with pytest.raises(ValueError, match="not allowed"):
            memcached._query("a", 11211, command, 2)
    assert sent == [] and "stats cachedump" not in memcached.ALLOWED_COMMANDS


def test_discovery_node_count_disagreeing_with_numcachenodes_is_a_warning(fake_cluster):
    nodes, _ = fake_cluster
    nodes[("mc.cfg", 11211)] = {"config get cluster": CONFIG_REPLY, "version": b"VERSION 1.6.22\r\n"}
    cluster = _aws_cluster("mc.0001.use1.cache.amazonaws.com", "mc.0002.use1.cache.amazonaws.com")
    cluster["NumCacheNodes"] = 3
    out = memcached.discovery_report(cluster, "mc.cfg", 11211, 2)
    msg = next(m for m in _msgs(out, "warning") if "NumCacheNodes=3" in m)
    assert "lists 2" in msg
    cluster["NumCacheNodes"] = 2
    assert not any("NumCacheNodes" in m for m in _msgs(memcached.discovery_report(cluster, "mc.cfg", 11211, 2)))
