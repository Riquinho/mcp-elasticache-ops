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
