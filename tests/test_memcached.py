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
    allowed = {"stats", "stats settings", "stats slabs", "stats items", "stats conns", "version"}
    assert allowed == memcached.ALLOWED_COMMANDS  # allowlist unchanged
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
