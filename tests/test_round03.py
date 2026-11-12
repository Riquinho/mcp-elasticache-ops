"""Round 03: read-only invariant for fan-out clients, and no raw redis connections outside connection.py."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import redis

from mcp_elasticache_ops import connection, server
from mcp_elasticache_ops.config import DataPlaneConfig
from mcp_elasticache_ops.safe_client import ReadOnlyViolation, SafeRedis

SRC = Path(__file__).resolve().parent.parent / "src" / "mcp_elasticache_ops"
RAW_NAMES = {"Redis", "StrictRedis", "RedisCluster", "ConnectionPool", "BlockingConnectionPool", "Sentinel", "from_url"}


@pytest.fixture()
def env(monkeypatch):
    monkeypatch.setenv("ELASTICACHE_HOST", "127.0.0.1")
    monkeypatch.setenv("ELASTICACHE_PORT", "1")
    monkeypatch.setenv("ELASTICACHE_CONTROL_PLANE", "false")


def test_node_client_for_fan_out_is_safe_redis(env):
    client = server._node_client("10.9.9.9", 6380)
    try:
        assert isinstance(client, SafeRedis)
        assert type(client) is SafeRedis
        kw = client.connection_pool.connection_kwargs
        assert (kw["host"], kw["port"]) == ("10.9.9.9", 6380)
        for call in (
            lambda: client.set("k", "v"),
            lambda: client.delete("k"),
            lambda: client.execute_command("FLUSHALL"),
            lambda: client.execute_command("CONFIG", "SET", "maxmemory", "1"),
            lambda: client.execute_command("ACL", "LOG", "RESET"),
            lambda: client.execute_command("GET", "k"),
            lambda: client.pipeline(transaction=True),
            lambda: client.pipeline().set("k", "v"),
        ):
            with pytest.raises(ReadOnlyViolation):
                call()
    finally:
        client.close()


def test_build_client_returns_safe_redis_with_and_without_override():
    cfg = DataPlaneConfig.from_env()
    assert isinstance(connection.build_client(cfg), SafeRedis)
    assert isinstance(connection.build_client(cfg, host="h", port=1), SafeRedis)


def test_a_bare_redis_in_connection_would_be_caught(env, monkeypatch):
    monkeypatch.setattr(connection, "SafeRedis", redis.Redis)
    client = server._node_client("127.0.0.1", 1)
    try:
        assert not isinstance(client, SafeRedis)  # this is the state the invariant tests must reject
    finally:
        client.close()
    with pytest.raises(AssertionError):
        test_node_client_for_fan_out_is_safe_redis(env)


def _raw_redis_uses(source: str) -> list[str]:
    """Names of raw redis constructors that ``source`` calls or imports (annotations are ignored)."""
    tree = ast.parse(source)
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] == "redis":
            found += [f"import {a.name}" for a in node.names if a.name in RAW_NAMES]
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
            if name in RAW_NAMES:
                found.append(f"call {name}")
    return found


def _safe_redis_calls(source: str) -> int:
    return sum(
        1
        for n in ast.walk(ast.parse(source))
        if isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", None)) == "SafeRedis"
    )


def test_checker_detects_bare_redis():
    assert _raw_redis_uses("import redis\nr = redis.Redis(host='x')") == ["call Redis"]
    assert _raw_redis_uses("from redis import Redis\nr = Redis()") == ["import Redis", "call Redis"]
    assert _raw_redis_uses("import redis\nr = redis.from_url('redis://x')") == ["call from_url"]
    assert _raw_redis_uses("import redis\ndef f(r: redis.Redis) -> redis.Redis: ...") == []


def test_no_module_builds_a_raw_redis_connection():
    offenders = {}
    for path in sorted(SRC.glob("*.py")):
        uses = _raw_redis_uses(path.read_text(encoding="utf-8"))
        if uses:
            offenders[path.name] = uses
    assert offenders == {}


def test_safe_redis_is_only_instantiated_in_connection_py():
    callers = {p.name for p in SRC.glob("*.py") if _safe_redis_calls(p.read_text(encoding="utf-8"))}
    assert callers == {"connection.py"}
