"""FastMCP server exposing read-only ElastiCache operations tools."""

from __future__ import annotations

import argparse
import functools
import json
import logging
import os
import socket
import ssl
from collections.abc import Callable
from functools import lru_cache
from typing import Annotated, Any

import botocore.exceptions
import redis
from fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from . import dataplane, memcached  # noqa: F401  (memcached: tool modules and tests reach it via server)
from .config import ControlPlaneConfig, DataPlaneConfig, MemcachedConfig, max_output_chars
from .connection import build_client, diagnose_connectivity  # noqa: F401  (patched via server in tests)
from .controlplane import REGION_PATTERN, ControlPlane, botocore_hint
from .safe_client import SafeRedis

log = logging.getLogger("mcp_elasticache_ops")

INSTRUCTIONS = """\
Read-only operations and monitoring for Amazon ElastiCache (Redis OSS, Valkey,
Memcached) and self-hosted Redis/Valkey. Data-plane tools (prefix `node_`) talk
to one endpoint over RESP; control-plane tools (prefix `aws_`) use the
ElastiCache/CloudWatch APIs and are optional. Start with `node_health` and
`aws_replication_groups`, then drill down. No tool writes, flushes or reads values.
"""

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)

mcp = FastMCP("mcp-elasticache-ops", instructions=INSTRUCTIONS)

# ------------------------------------------------------------------ output size cap

_KEEP_WHOLE = frozenset({"findings", "summary", "notes"})  # never trimmed: they are what the caller needs first
_KEEP_LEVELS = (50, 20, 10, 5, 2, 1, 0)
TRUNCATION_HINT = (
    "The result exceeded MCP_MAX_OUTPUT_CHARS={limit} characters, so long lists were cut to their first items "
    "(findings, notes, summaries and counts are intact). Narrow the call by id (replication_group_id, "
    "cache_cluster_id, parameter group) or lower top/count/hours to see the rest."
)


def _json_size(value: Any) -> int:
    return len(json.dumps(value, default=str, ensure_ascii=False))


def _trim(value: Any, keep: int) -> tuple[Any, int]:
    """Copy of ``value`` with every list cut to ``keep`` items; returns ``(copy, omitted)``. Never mutates."""
    if isinstance(value, list):
        head = value[:keep]
        omitted = len(value) - len(head)
        out = []
        for item in head:
            trimmed, n = _trim(item, keep)
            out.append(trimmed)
            omitted += n
        return out, omitted
    if isinstance(value, dict):
        limit = max(keep, 20)  # wide maps (per-node, per-group) keep a bit more than lists
        items = list(value.items())
        omitted = max(0, len(items) - limit)
        out_dict = {}
        for key, item in items[:limit]:
            if key in _KEEP_WHOLE:
                out_dict[key] = item
            else:
                out_dict[key], n = _trim(item, keep)
                omitted += n
        return out_dict, omitted
    return value, 0


def cap_output(result: Any, limit: int) -> Any:
    """Keep a tool result under ``limit`` JSON characters by trimming long lists to their head.

    Small results come back unchanged (same object). Larger ones get progressively shorter heads
    (50, 20, 10, 5, 2, 1, 0 items) until they fit; top-level scalars, ``findings``, ``summary`` and
    ``notes`` stay. The output gains ``truncated=true``, ``omitted`` (items dropped), ``original_chars``
    and ``truncation_hint``. The input is never modified.
    """
    if not isinstance(result, dict):
        return result
    size = _json_size(result)
    if size <= limit:
        return result
    trimmed: dict = result
    omitted = 0
    for keep in _KEEP_LEVELS:
        trimmed, omitted = _trim(result, keep)
        if _json_size(trimmed) <= limit:
            break
    return {
        **trimmed,
        "truncated": True,
        "omitted": omitted,
        "original_chars": size,
        "truncation_hint": TRUNCATION_HINT.format(limit=limit),
    }


def connection_error_result(exc: BaseException) -> dict:
    """Structured result for a network failure towards a node: error type, message and a next step."""
    name, message = type(exc).__name__, str(exc)
    low = message.lower()
    if isinstance(exc, botocore.exceptions.BotoCoreError):
        hint = botocore_hint(exc)
    elif isinstance(exc, redis.exceptions.AuthenticationError):
        hint = "The node rejected the credentials; check ELASTICACHE_USERNAME and ELASTICACHE_PASSWORD(_FILE)."
    elif "ssl" in low or "tls" in low or "certificate" in low or "handshake" in low:
        hint = (
            "TLS handshake failed; check ELASTICACHE_TLS (true for in-transit encryption, false otherwise), that "
            "ELASTICACHE_HOST is the endpoint DNS name (needed for certificate verification), and "
            "ELASTICACHE_TLS_CA_FILE / ELASTICACHE_TLS_VERIFY."
        )
    elif isinstance(exc, TimeoutError | redis.exceptions.TimeoutError):
        hint = (
            "The node did not answer in time; check security groups and routing to the endpoint, raise "
            "ELASTICACHE_TIMEOUT, or retry (the node may be busy or failing over)."
        )
    else:
        hint = (
            "Cannot reach the node; check ELASTICACHE_HOST/ELASTICACHE_PORT (or MEMCACHED_HOST/MEMCACHED_NODES), "
            "the security group and, if the endpoint requires it, ELASTICACHE_TLS."
        )
    return {"error": name, "message": message, "hint": hint}


def _lift_total_failure(result: Any) -> Any:
    """When every region of a fleet call failed, surface the first failure's error and hint at the top level."""
    if not isinstance(result, dict) or "error" in result:
        return result
    sections = result.get("sections")
    if isinstance(sections, list) and sections and all(sec.get("status") == "unavailable" for sec in sections):
        names = {str(sec.get("summary", "")).partition(":")[0] for sec in sections} - {"_TriageEmpty"}
        known = {n for n in names if hasattr(botocore.exceptions, n) and n != "ClientError"}
        if len(known) == 1 and len(names) == 1:
            name = known.pop()
            first = next(sec for sec in sections if str(sec.get("summary", "")).startswith(name))
            return {"error": name, "message": first["summary"], "hint": botocore_hint(name), **result}
    failures = result.get("region_errors")
    regions = result.get("regions")
    if not failures or not isinstance(regions, list) or len(failures) < len(regions):
        return result
    first = next(iter(failures.values()))
    if not isinstance(first, dict) or not first.get("error"):
        return result
    lifted = {k: first[k] for k in ("error", "message", "hint") if first.get(k)}
    return {**lifted, **result}


def _guarded(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Turn connection failures into a structured error result instead of a raw exception."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return _lift_total_failure(fn(*args, **kwargs))
        except (
            redis.exceptions.ConnectionError,
            redis.exceptions.TimeoutError,
            ConnectionError,
            TimeoutError,
            socket.gaierror,
            ssl.SSLError,
            botocore.exceptions.BotoCoreError,
        ) as exc:
            return connection_error_result(exc)

    return wrapper


def _capped(fn: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return cap_output(fn(*args, **kwargs), max_output_chars())

    wrapper.__capped__ = True  # type: ignore[attr-defined]
    return wrapper


def read_tool(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Register ``fn`` as a read-only MCP tool whose result is size-capped."""
    return mcp.tool(annotations=READ_ONLY)(_capped(_guarded(fn)))


@lru_cache(maxsize=1)
def redis_client() -> SafeRedis:
    return build_client(DataPlaneConfig.from_env())


def _serverless() -> bool:
    """True when ELASTICACHE_HOST is an ElastiCache Serverless endpoint."""
    return dataplane.is_serverless_host(DataPlaneConfig.from_env().host)


def _node_client(host: str, port: int) -> SafeRedis:
    return build_client(DataPlaneConfig.from_env(), host=host, port=port)


@lru_cache(maxsize=1)
def control_plane() -> ControlPlane:
    return ControlPlane(ControlPlaneConfig.from_env())


Region = Annotated[
    str | None,
    Field(
        pattern=REGION_PATTERN,
        max_length=32,
        description="AWS region; defaults to AWS_REGION",
    ),
]


def _cp(region: str | None) -> ControlPlane:
    """The control plane for ``region`` (the configured one when omitted); invalid names are refused."""
    return control_plane().in_region(region)


def _memcached_target() -> MemcachedConfig:
    cfg = MemcachedConfig.from_env()
    if not cfg.host:
        raise ValueError("MEMCACHED_HOST is not set")
    return cfg


# Tool registrations live in server_node / server_aws; importing them registers the tools on ``mcp``.
# Names re-exported here keep ``server.node_triage`` etc. working for callers and tests.
from .server_aws import *  # noqa: E402,F401,F403
from .server_node import *  # noqa: E402,F401,F403

# ------------------------------------------------------------------- on-call prompts
# Prompts, not tools: they only return text that tells the model which read-only tools to chain.

RunbookGroup = Annotated[str, Field(description="ReplicationGroupId of the affected replication group")]


@mcp.prompt
def oncall_high_cpu(replication_group_id: RunbookGroup) -> str:
    """Runbook: EngineCPUUtilization alarm on a replication group."""
    return f"""On-call runbook: high CPU on replication group `{replication_group_id}`. Read-only tools only; do not guess.

1. `aws_triage` (replication_group_id="{replication_group_id}"). Read `findings` first. A finding that says
   "transient spike" is not an incident: report it and stop. "sustained" EngineCPUUtilization means keep going.
   Note `ownership` so you know whom to page.
2. `aws_cluster_overview` (same id). A node far above the peer median means a hot shard or hot key; all nodes
   high means load or sizing. Check the right-sizing and CPU-credit findings on cache.t* nodes.
3. `node_triage` against the hot node (set ELASTICACHE_HOST to its endpoint), then `node_cluster_slowlog` for
   slow commands across shards and `node_commandstats` for the commands that burn the most time.
4. `node_clients` for clients with huge output buffers or blocked commands, `node_cluster_health` if the
   cluster state is not ok.
5. `aws_metrics` (cache_cluster_id of the hot node, metrics EngineCPUUtilization, CPUUtilization, CurrConnections,
   NewConnections, minutes=360). EngineCPUUtilization high with CPUUtilization low is the single Redis thread
   saturated: scale out (shards) or fix the commands, not a bigger host.

Conclude with: sustained or spike, one node or all, the top slow command, and the next step (fix the command,
add shards or replicas, change node type). Never run anything that writes."""


@mcp.prompt
def oncall_evictions_memory(replication_group_id: RunbookGroup) -> str:
    """Runbook: evictions or memory pressure on a replication group."""
    return f"""On-call runbook: evictions or memory pressure on `{replication_group_id}`. Read-only tools only.

1. `aws_triage` (replication_group_id="{replication_group_id}"). Look for DatabaseMemoryUsagePercentage and
   Evictions findings and for a "growing ... reached in about Nh" trend hint: that is your time budget.
2. `aws_metrics` (replication_group_id="{replication_group_id}", metrics DatabaseMemoryUsagePercentage,
   BytesUsedForCache, Evictions, CurrItems, CacheHitRate, SwapUsage, minutes=1440). Evictions with a falling
   CacheHitRate hurt users now; memory high without evictions means the policy is noeviction and writes may fail.
3. `node_memory` on the affected node: fragmentation ratio, maxmemory, eviction policy. `node_cluster_memory`
   to compare shards; one shard far above the others is a hot or big key.
4. `node_keyspace_sample` (or `node_cluster_keyspace_sample`) to find big keys and missing TTLs; it samples
   with SCAN and reports sizes only, never values.
5. `aws_parameters` (the group's parameter group): confirm maxmemory-policy and reserved-memory-percent.

Conclude with: leak (no TTL, growth) or burst, which keys or shard, the eviction policy in force, hours until
full, and the choice (set TTLs, change policy, add shards, larger node type)."""


@mcp.prompt
def oncall_replication_lag(replication_group_id: RunbookGroup) -> str:
    """Runbook: replica lag or global datastore lag."""
    return f"""On-call runbook: replication lag on `{replication_group_id}`. Read-only tools only.

1. `aws_triage` (replication_group_id="{replication_group_id}"): ReplicationLag findings, recent failover or
   node replacement events and pending service updates.
2. `aws_events` (source_identifier="{replication_group_id}", source_type="replication-group", hours=24): a
   failover or replacement just before the lag explains a resync; lag after it should fall by itself.
3. `node_replication` on the primary: replica offsets, link status, backlog size. A replica with
   master_link_status down or a growing offset gap is the culprit; `node_cluster_nodes` shows which shard.
4. `aws_metrics` (replication_group_id="{replication_group_id}", metrics ReplicationLag, ReplicationBytes,
   EngineCPUUtilization, NetworkBandwidthInAllowanceExceeded, NetworkBandwidthOutAllowanceExceeded, minutes=360). Heavy ReplicationBytes with bandwidth
   allowance exceeded means writes outrun the network of the node type.
5. Global datastore: `aws_global_replication_groups` (also with region set to the secondary region) reports
   GlobalDatastoreReplicationLag per secondary and flags secondaries with another node type or engine version.
   Lag above 1s is a warning, above 10s critical; do not fail over to a secondary that lags or is not associated.

Conclude with: which replica or region lags, since when, whether load, network or a resync explains it, and
whether a failover would lose data."""


@mcp.prompt
def oncall_connection_storm(replication_group_id: RunbookGroup) -> str:
    """Runbook: connection spike or maxclients exhaustion."""
    return f"""On-call runbook: connection storm on `{replication_group_id}`. Read-only tools only.

1. `aws_triage` (replication_group_id="{replication_group_id}"): CurrConnections findings; "transient spike"
   means a client restarted or deployed, "sustained" means a leak or a missing pool.
2. `aws_metrics` (replication_group_id="{replication_group_id}", metrics CurrConnections, NewConnections,
   EngineCPUUtilization, minutes=360). NewConnections high with CurrConnections flat is connection churn
   (no pooling, TLS handshakes burning CPU); CurrConnections climbing is a leak.
3. `node_clients` on the busiest node: connections grouped by address and name, idle times and blocked
   clients. One address owning thousands of connections is the offender.
4. `node_latency` (ping_samples=50) and `node_cluster_slowlog` to see whether the storm hurts every
   command or only slow ones; `node_acl_log` for authentication failures that look like a storm of retries.
5. `aws_alarms` (replication_group_id="{replication_group_id}") to check that a CurrConnections alarm exists.

Conclude with: the client address or service responsible, churn or leak, how close CurrConnections is to
maxclients (65000 default), and the fix (connection pool, idle timeout, client backoff)."""


# ------------------------------------------------------------------------ main


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="mcp-elasticache-ops", description=INSTRUCTIONS)
    parser.add_argument("--transport", choices=["stdio", "http"], default=os.getenv("MCP_TRANSPORT", "stdio"))
    parser.add_argument("--host", default=os.getenv("MCP_HOST", "127.0.0.1"), help="bind address for http")
    parser.add_argument("--port", type=int, default=int(os.getenv("MCP_PORT", "8000")), help="port for http")
    parser.add_argument("--log-level", default=os.getenv("MCP_LOG_LEVEL", "INFO"))
    args = parser.parse_args(argv)
    logging.basicConfig(level=args.log_level.upper())
    if args.transport == "http":
        mcp.run(transport="http", host=args.host, port=args.port, show_banner=False)
    else:
        mcp.run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
