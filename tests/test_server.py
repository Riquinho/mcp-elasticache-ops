import json
from urllib.parse import urlparse

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from mcp_elasticache_ops import server


@pytest.fixture()
def env(monkeypatch, seeded):
    u = urlparse(seeded)
    monkeypatch.setenv("ELASTICACHE_HOST", u.hostname)
    monkeypatch.setenv("ELASTICACHE_PORT", str(u.port or 6379))
    monkeypatch.setenv("ELASTICACHE_CONTROL_PLANE", "false")
    server.redis_client.cache_clear()
    server.control_plane.cache_clear()
    yield
    server.redis_client.cache_clear()
    server.control_plane.cache_clear()


def _data(result):
    if result.structured_content is not None:
        return result.structured_content.get("result", result.structured_content)
    return json.loads(result.content[0].text)


async def test_all_tools_read_only():
    async with Client(server.mcp) as c:
        tools = await c.list_tools()
    names = {t.name for t in tools}
    assert len(tools) == 26
    assert {
        "node_health",
        "node_info",
        "node_memory",
        "node_slowlog",
        "node_clients",
        "node_latency",
        "node_commandstats",
        "node_keyspace_sample",
        "node_replication",
        "node_cluster",
        "memcached_stats",
        "aws_replication_groups",
        "aws_cache_clusters",
        "aws_serverless_caches",
        "aws_events",
        "aws_parameters",
        "aws_metrics",
    } <= names  # the original 17
    assert {
        "node_cluster_nodes",
        "node_cluster_health",
        "aws_snapshots",
        "aws_users",
        "aws_user_groups",
        "aws_global_replication_groups",
        "aws_reserved_nodes",
        "aws_service_updates",
        "aws_subnet_groups",
    } <= names
    for t in tools:
        assert t.annotations.read_only_hint is True, t.name
        assert t.annotations.destructive_hint is False, t.name


async def test_validation_rejects_out_of_range():
    async with Client(server.mcp) as c:
        with pytest.raises(ToolError):
            await c.call_tool("node_slowlog", {"count": 5000})


def test_main_help(capsys):
    with pytest.raises(SystemExit) as exc:
        server.main(["--help"])
    assert exc.value.code == 0
    assert "--transport" in capsys.readouterr().out


@pytest.mark.integration
async def test_tools_end_to_end(env):
    async with Client(server.mcp) as c:
        health = _data(await c.call_tool("node_health", {}))
        assert health["role"] == "master"
        ks = _data(await c.call_tool("node_keyspace_sample", {"sample_size": 50, "top": 3}))
        assert ks["sampled_keys"] == 50
        slow = _data(await c.call_tool("node_slowlog", {"count": 5}))
        assert slow["returned"] <= 5
        aws = _data(await c.call_tool("aws_replication_groups", {}))
        assert "unavailable" in aws
