"""Output-budget audit: every registered tool, called through the server layer, must stay under the cap.

The backends (data plane, Memcached, control plane) are replaced by stand-ins that return a deliberately
oversized payload (hundreds of nodes, groups, events and keys). The assertions cover the server layer that
every tool shares: the size cap, ``findings``/``summary`` staying ahead of bulk data, and a truncation flag
with a hint on how to narrow the call.
"""

import json
from typing import Any

import pytest
from fastmcp import Client

from mcp_elasticache_ops import server
from mcp_elasticache_ops.config import MemcachedConfig

LIMIT = 8_000
BULK = 600

# One entry per registered tool: the arguments that tool requires. A tool added without an entry here fails
# test_every_registered_tool_has_a_budget_fixture, so a new tool cannot ship without a budget check.
_NO_ARGS: dict[str, Any] = {}
TOOL_ARGS: dict[str, dict[str, Any]] = {
    **dict.fromkeys(
        [
            "node_health",
            "node_connectivity",
            "node_triage",
            "node_doctor",
            "node_info",
            "node_memory",
            "node_config",
            "node_slowlog",
            "node_clients",
            "node_latency",
            "node_latency_events",
            "node_commandstats",
            "node_keyspace_sample",
            "node_replication",
            "node_acl_log",
            "node_cluster",
            "node_cluster_nodes",
            "node_cluster_health",
            "node_cluster_keyspace_sample",
            "node_cluster_slowlog",
            "node_cluster_memory",
            "node_pubsub",
            "node_cluster_triage",
            "memcached_stats",
            "memcached_cluster_stats",
            "aws_replication_groups",
            "aws_cache_clusters",
            "aws_serverless_caches",
            "aws_events",
            "aws_snapshots",
            "aws_serverless_snapshots",
            "aws_users",
            "aws_user_groups",
            "aws_global_replication_groups",
            "aws_reserved_nodes",
            "aws_parameter_groups",
            "aws_service_updates",
            "aws_subnet_groups",
            "aws_metrics",
            "aws_alarms",
            "aws_maintenance",
            "aws_cluster_overview",
            "aws_security_audit",
            "aws_cost_overview",
            "aws_capacity_forecast",
        ],
        _NO_ARGS,
    ),
    "memcached_discovery": {"cache_cluster_id": "mc-1"},
    "aws_parameters": {"parameter_group": "pg-1"},
    "aws_reserved_offerings": {"node_type": "cache.m7g.large", "engine": "valkey"},
    "aws_engine_versions": {"engine": "valkey"},
    "aws_parameter_drift": {"group_a": "pg-a", "group_b": "pg-b"},
    "aws_triage": {"replication_group_id": "rg-1"},
    "aws_serverless_triage": {"serverless_cache_name": "sc-1"},
    "aws_shard_balance": {"replication_group_id": "rg-1"},
}


def _bulk(*_args: Any, **_kwargs: Any) -> dict:
    """Findings and summary first, then bulk lists and a wide per-node map, as the real tools order them."""
    pad = "x" * 40
    return {
        "findings": [{"severity": "warning", "message": "something is off"}],
        "summary": {"count": BULK},
        "nodes": [{"id": f"node-{i}", "endpoint": f"n{i}.cache.example", "pad": pad} for i in range(BULK)],
        "events": [{"date": "2026-01-01", "message": pad + str(i)} for i in range(BULK)],
        "keys": [f"user:{i}:{pad}" for i in range(BULK)],
        "per_node": {f"node-{i}": {"status": "ok", "pad": pad} for i in range(BULK)},
        "notes": [],
    }


class _Backend:
    """Stands in for a backend module or class: callables return the bulk payload, other attributes are real."""

    def __init__(self, real: Any) -> None:
        self._real = real

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        attr = getattr(self._real, name, None)
        return attr if attr is not None and not callable(attr) else _bulk


class _FakeControlPlane:
    def in_region(self, _region: str | None) -> "_FakeControlPlane":
        return self

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return _bulk


@pytest.fixture()
def bulk_backends(monkeypatch):
    monkeypatch.setenv("MCP_MAX_OUTPUT_CHARS", str(LIMIT))
    monkeypatch.setattr(server, "dataplane", _Backend(server.dataplane))
    monkeypatch.setattr(server, "memcached", _Backend(server.memcached))
    monkeypatch.setattr(server, "redis_client", lambda: object())
    monkeypatch.setattr(server, "_node_client", lambda host, port: object())
    monkeypatch.setattr(server, "diagnose_connectivity", _bulk)  # does real DNS/TCP otherwise
    monkeypatch.setattr(server, "_serverless", lambda: False)
    monkeypatch.setattr(server, "_memcached_target", lambda: MemcachedConfig(host="mc.example", port=11211))
    monkeypatch.setattr(server, "control_plane", lambda: _FakeControlPlane())


async def test_every_registered_tool_has_a_budget_fixture():
    registered = {t.name for t in await server.mcp.list_tools()}
    assert registered == set(TOOL_ARGS), (
        f"tools without a budget fixture: {sorted(registered - set(TOOL_ARGS))}; "
        f"fixtures for removed tools: {sorted(set(TOOL_ARGS) - registered)}"
    )


@pytest.mark.parametrize("tool", sorted(TOOL_ARGS))
async def test_tool_output_stays_under_the_cap_with_findings_first(bulk_backends, tool):
    async with Client(server.mcp) as c:
        result = await c.call_tool(tool, TOOL_ARGS[tool])
    data = result.structured_content
    assert data is not None
    data = data.get("result", data)
    assert len(json.dumps(data, default=str, ensure_ascii=False)) <= LIMIT * 2  # cap plus the truncation envelope
    keys = list(data)
    bulk_at = min(keys.index(k) for k in ("nodes", "events", "keys", "per_node") if k in keys)
    lead = [keys.index(k) for k in ("findings", "summary") if k in keys]
    assert lead and max(lead) < bulk_at, f"{tool}: findings/summary must come before bulk data, got {keys}"
    assert data["findings"] == [{"severity": "warning", "message": "something is off"}]  # never trimmed
    assert data["truncated"] is True and data["omitted"] > 0
    assert "Narrow the call" in data["truncation_hint"] and str(LIMIT) in data["truncation_hint"]
