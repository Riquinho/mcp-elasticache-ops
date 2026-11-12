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
from typing import Annotated, Any, Literal

import redis
from fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from . import dataplane, memcached
from .config import ControlPlaneConfig, DataPlaneConfig, MemcachedConfig, max_output_chars
from .connection import build_client
from .controlplane import ControlPlane
from .safe_client import SafeRedis

log = logging.getLogger("mcp_elasticache_ops")

INSTRUCTIONS = """\
Read-only operations and monitoring for Amazon ElastiCache (Redis OSS, Valkey,
Memcached) and self-hosted Redis/Valkey. Data-plane tools (prefix `node_`) talk
to one endpoint over RESP; control-plane tools (prefix `aws_`) use the
ElastiCache/CloudWatch APIs and are optional. Start with `node_health` and
`aws_replication_groups`, then drill down. No tool writes, flushes or reads values.
"""

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)

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
    if isinstance(exc, redis.exceptions.AuthenticationError):
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


def _guarded(fn: Callable[..., Any]) -> Callable[..., Any]:
    """Turn connection failures into a structured error result instead of a raw exception."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except (
            redis.exceptions.ConnectionError,
            redis.exceptions.TimeoutError,
            ConnectionError,
            TimeoutError,
            socket.gaierror,
            ssl.SSLError,
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


def _memcached_target() -> MemcachedConfig:
    cfg = MemcachedConfig.from_env()
    if not cfg.host:
        raise ValueError("MEMCACHED_HOST is not set")
    return cfg


# ------------------------------------------------------------------ data plane


@read_tool
def node_health() -> dict:
    """One-shot health summary of the configured Redis/Valkey endpoint: engine and
    version, role, clients, hit ratio, memory vs maxmemory, fragmentation,
    evictions and a list of findings."""
    return dataplane.health_summary(redis_client(), _serverless())


@read_tool
def node_triage() -> dict:
    """On-call snapshot of the connected endpoint in one call: health, memory, replication, clients,
    failed/rejected commandstats, top-5 slowlog and latency. Findings from every section are merged,
    worst-first (max 30), with a short per-section summary; a section that fails is reported as
    unavailable and the rest still run. Start here, then drill into the specific node_ tool."""
    return dataplane.triage(redis_client(), _node_client, _serverless())


@read_tool
def node_info(
    section: Annotated[
        str | None,
        Field(
            description="INFO section: server, clients, memory, persistence, stats, replication, cpu, commandstats, errorstats, cluster, keyspace. Omit for default."
        ),
    ] = None,
) -> dict:
    """Raw INFO output, optionally for a single section. Password-like keys are masked."""
    return dataplane.server_info(redis_client(), section)


@read_tool
def node_memory() -> dict:
    """Memory breakdown: used/RSS/peak/dataset/overhead, maxmemory and policy,
    fragmentation ratio with a verdict, evictions, MEMORY STATS and MEMORY DOCTOR
    when the engine allows them."""
    return dataplane.memory_report(redis_client(), _serverless())


@read_tool
def node_config() -> dict:
    """Allowlisted CONFIG GET view (maxmemory policy, timeout, appendonly, output buffer limits,
    keyspace notifications, slowlog and latency thresholds, io-threads) with findings. Secret
    parameters are never requested. Falls back to a pointer at aws_parameters when the endpoint
    refuses CONFIG, as ElastiCache usually does."""
    return dataplane.config_view(redis_client())


@read_tool
def node_slowlog(
    count: Annotated[int, Field(ge=1, le=1024, description="Entries to fetch")] = 25,
    include_args: Annotated[bool, Field(description="Return full command arguments (may expose values)")] = False,
) -> dict:
    """SLOWLOG entries plus per-command totals. Arguments beyond the key are hidden
    unless include_args is true."""
    return dataplane.slowlog(redis_client(), count, include_args, _serverless())


@read_tool
def node_clients(top: Annotated[int, Field(ge=1, le=500)] = 20) -> dict:
    """CLIENT LIST aggregated by source IP, client name, ACL user and last command,
    idle-time stats and the clients holding the most buffer memory."""
    return dataplane.client_list(redis_client(), top)


@read_tool
def node_latency(ping_samples: Annotated[int, Field(ge=1, le=500)] = 20) -> dict:
    """Client-side PING RTT percentiles plus LATENCY LATEST events from the server
    latency monitor (needs latency-monitor-threshold > 0)."""
    return dataplane.latency(redis_client(), ping_samples)


@read_tool
def node_commandstats(top: Annotated[int, Field(ge=1, le=500)] = 20) -> dict:
    """Commands ranked by total CPU time (INFO commandstats), with calls, usec per
    call, rejected and failed calls."""
    return dataplane.commandstats(redis_client(), top)


@read_tool
def node_keyspace_sample(
    sample_size: Annotated[int, Field(ge=1, le=100_000, description="Max keys to inspect")] = 1000,
    match: Annotated[str | None, Field(description="SCAN MATCH glob, e.g. 'session:*'")] = None,
    top: Annotated[int, Field(ge=1, le=500)] = 20,
    scan_count: Annotated[int, Field(ge=10, le=5000, description="SCAN COUNT hint")] = 250,
    pause_ms: Annotated[int, Field(ge=0, le=1000, description="Sleep between SCAN batches")] = 0,
    max_seconds: Annotated[
        float, Field(gt=0, le=60, description="Wall-clock budget; returns partial=true when exceeded")
    ] = 10.0,
    top_prefixes: Annotated[int, Field(ge=1, le=50, description="Key prefixes to report")] = 10,
) -> dict:
    """Big keys (bytes and element count), hot keys (LFU policies) or coldest keys,
    type distribution and TTL coverage from a bounded SCAN. Metadata only; values
    are never read. Stops at max_seconds and reports partial=true. On cluster-mode-enabled
    groups this samples the connected node's slots only: use node_cluster_keyspace_sample for every shard.
    `prefixes` groups the sampled keys by normalised prefix (user:123:cart -> user:*:cart) with key count,
    estimated bytes scaled to dbsize, % of keys without TTL and types; findings call out large no-TTL prefixes
    when the policy is noeviction or memory is near maxmemory."""
    return dataplane.keyspace_sample(
        redis_client(), sample_size, match, top, scan_count, pause_ms, max_seconds, top_prefixes=top_prefixes
    )


@read_tool
def node_replication() -> dict:
    """Replication role, replicas with byte lag, link status and backlog size, plus findings:
    replica links that are down, lagging replicas (also against the primary's offset when run on a
    replica), replica-read-only, min-replicas-to-write and cluster-allow-reads-when-down. Engine
    quirks (Redis 6 has no CLUSTER SHARDS, ACL LOG needs 6+) are notes, not errors."""
    return dataplane.replication(redis_client(), _node_client)


@read_tool
def node_acl_log(count: Annotated[int, Field(ge=1, le=128, description="ACL LOG entries to fetch")] = 25) -> dict:
    """ACL WHOAMI and recent ACL LOG entries (auth failures, denied commands, key/channel denials)
    with reason, user, client address and count; key and channel names are hidden. Findings flag
    repeated auth failures and denied-command spikes. ACL LIST/GETUSER (password hashes) are never used."""
    return dataplane.acl_log(redis_client(), count)


@read_tool
def node_cluster() -> dict:
    """Cluster-mode view: CLUSTER INFO, slots per primary and CLUSTER SHARDS when
    available. Reports cluster mode disabled otherwise."""
    return dataplane.cluster(redis_client(), _serverless())


@read_tool
def node_cluster_nodes() -> dict:
    """CLUSTER NODES parsed into per-shard primary/replica endpoints, slot counts and
    failing nodes, plus how to target each shard with ELASTICACHE_HOST."""
    return dataplane.cluster_nodes(redis_client(), _serverless())


@read_tool
def node_cluster_health(
    max_workers: Annotated[int, Field(ge=1, le=32, description="Concurrent node probes")] = 8,
    per_node_timeout: Annotated[float, Field(gt=0, le=60, description="Seconds to wait per node")] = 5.0,
) -> dict:
    """Cluster-mode fan-out: INFO on every node (bounded concurrency, per-node timeout)
    flagging memory/ops skew across shards, failed nodes, uncovered slots and replica lag."""
    return dataplane.cluster_health(redis_client(), _node_client, max_workers, per_node_timeout)


@read_tool
def node_cluster_keyspace_sample(
    sample_size: Annotated[
        int, Field(ge=1, le=100_000, description="Max keys to inspect, split across primaries")
    ] = 1000,
    match: Annotated[str | None, Field(description="SCAN MATCH glob, e.g. 'session:*'")] = None,
    top: Annotated[int, Field(ge=1, le=500)] = 20,
    scan_count: Annotated[int, Field(ge=10, le=5000, description="SCAN COUNT hint")] = 250,
    pause_ms: Annotated[int, Field(ge=0, le=1000, description="Sleep between SCAN batches")] = 0,
    max_seconds: Annotated[
        float, Field(gt=0, le=60, description="Total wall-clock budget, split across primaries")
    ] = 10.0,
    max_workers: Annotated[int, Field(ge=1, le=32, description="Concurrent shard samplers")] = 8,
    per_node_timeout: Annotated[float, Field(gt=0, le=60, description="Extra seconds to wait for a stuck shard")] = 5.0,
    top_prefixes: Annotated[int, Field(ge=1, le=50, description="Key prefixes to report")] = 10,
) -> dict:
    """node_keyspace_sample on every shard primary of a cluster-mode group: top big/hot/cold keys merged
    with a `shard` label, per-shard status (ok, partial, unreachable) and skew findings. A dead shard is
    reported, never fatal. The budget and sample size are split across primaries. Metadata only."""
    return dataplane.cluster_keyspace_sample(
        redis_client(),
        _node_client,
        sample_size,
        match,
        top,
        scan_count,
        pause_ms,
        max_seconds,
        max_workers,
        per_node_timeout,
        top_prefixes,
    )


@read_tool
def node_cluster_slowlog(
    count: Annotated[int, Field(ge=1, le=1024, description="Entries to return overall")] = 25,
    include_args: Annotated[bool, Field(description="Return full command arguments (may expose values)")] = False,
    max_workers: Annotated[int, Field(ge=1, le=32, description="Concurrent shard probes")] = 8,
    per_node_timeout: Annotated[float, Field(gt=0, le=60, description="Seconds to wait per node")] = 5.0,
) -> dict:
    """node_slowlog on every shard primary: the slowest entries overall labelled by shard, per-command
    totals and per-shard status. Arguments beyond the key are hidden unless include_args is true."""
    return dataplane.cluster_slowlog(redis_client(), _node_client, count, include_args, max_workers, per_node_timeout)


@read_tool
def node_cluster_memory(
    max_workers: Annotated[int, Field(ge=1, le=32, description="Concurrent shard probes")] = 8,
    per_node_timeout: Annotated[float, Field(gt=0, le=60, description="Seconds to wait per node")] = 5.0,
) -> dict:
    """node_memory headline for every shard primary: used/RSS/maxmemory, fragmentation, evictions, with
    findings for memory skew between shards, shards above 90% of maxmemory and unreachable shards."""
    return dataplane.cluster_memory(redis_client(), _node_client, max_workers, per_node_timeout)


@read_tool
def memcached_stats(
    group: Annotated[
        Literal["", "settings", "slabs", "items", "conns"], Field(description="stats group; empty for general")
    ] = "",
) -> dict:
    """Memcached summary (hit ratio, memory, evictions, connections) or a raw
    `stats <group>` output. Uses MEMCACHED_HOST/MEMCACHED_PORT."""
    cfg = _memcached_target()
    if group:
        return {"group": group, "stats": memcached.stats(cfg.host, cfg.port, group, cfg.timeout)}
    return memcached.summary(cfg.host, cfg.port, cfg.timeout)


@read_tool
def memcached_cluster_stats() -> dict:
    """Memcached fleet view over MEMCACHED_NODES (host:port list): queries every node with bounded
    concurrency and a per-node timeout, only `stats`, `stats slabs` and `stats items`. Findings first:
    evictions, hit-ratio outliers vs the median, item/memory imbalance, listen_disabled_num, connections
    near maxconns, slab classes evicting or running out of memory. A dead node makes the result partial."""
    cfg = MemcachedConfig.from_env()
    return memcached.cluster_stats(cfg.nodes, cfg.timeout)


# --------------------------------------------------------------- control plane


@read_tool
def aws_replication_groups(replication_group_id: str | None = None) -> dict:
    """DescribeReplicationGroups: status, engine, cluster mode, node type, Multi-AZ,
    failover, encryption, shards with primary/reader endpoints and member roles."""
    return control_plane().replication_groups(replication_group_id)


@read_tool
def aws_cache_clusters(cache_cluster_id: str | None = None, show_nodes: bool = True) -> dict:
    """DescribeCacheClusters: per-node-cluster engine version, node type, parameter
    group and apply status, maintenance window, pending changes and node endpoints."""
    return control_plane().cache_clusters(cache_cluster_id, show_nodes)


@read_tool
def aws_serverless_caches() -> dict:
    """DescribeServerlessCaches for ElastiCache Serverless (Valkey/Redis OSS/Memcached)."""
    return control_plane().serverless_caches()


@read_tool
def aws_events(
    source_identifier: str | None = None,
    source_type: Annotated[
        str | None,
        Field(
            description="cache-cluster, cache-parameter-group, cache-security-group, cache-subnet-group, replication-group, serverless-cache, user, user-group"
        ),
    ] = None,
    hours: Annotated[int, Field(ge=1, le=336)] = 24,
) -> dict:
    """DescribeEvents: failovers, node replacements, maintenance, snapshots."""
    return control_plane().events(source_identifier, source_type, hours)


@read_tool
def aws_parameters(parameter_group: str, only_modified: bool = True) -> dict:
    """DescribeCacheParameters for a parameter group; by default only values changed
    from the engine defaults (Source=user)."""
    return control_plane().parameters(parameter_group, only_modified)


@read_tool
def aws_snapshots(
    replication_group_id: str | None = None,
    cache_cluster_id: str | None = None,
    source: Annotated[Literal["automated", "manual"] | None, Field(description="Filter by snapshot source")] = None,
    stale_hours: Annotated[int, Field(ge=1, le=8760, description="Flag automatic snapshots older than this")] = 36,
) -> dict:
    """DescribeSnapshots: age, size, status, automatic vs manual, with findings for
    retention gaps, failed snapshots and groups without automatic backups."""
    return control_plane().snapshots(replication_group_id, cache_cluster_id, source, stale_hours)


@read_tool
def aws_serverless_snapshots(
    serverless_cache_name: str | None = None,
    snapshot_type: Annotated[
        Literal["automatic", "manual"] | None, Field(description="Filter by snapshot type")
    ] = None,
    stale_hours: Annotated[int, Field(ge=1, le=8760, description="Flag caches whose newest snapshot is older")] = 24,
) -> dict:
    """DescribeServerlessCacheSnapshots plus DescribeServerlessCaches: findings for caches without a
    recent snapshot, failed snapshots, snapshots about to expire, missing KMS key and unset retention."""
    return control_plane().serverless_snapshots(serverless_cache_name, snapshot_type, stale_hours)


@read_tool
def aws_users(engine: Annotated[Literal["redis", "valkey"] | None, Field(description="Engine filter")] = None) -> dict:
    """DescribeUsers (RBAC): authentication type and access strings, never passwords.
    Flags users with '~* +@all' access and users without a password."""
    return control_plane().users(engine)


@read_tool
def aws_user_groups() -> dict:
    """DescribeUserGroups: members, attached replication groups/serverless caches, pending changes."""
    return control_plane().user_groups()


@read_tool
def aws_global_replication_groups() -> dict:
    """DescribeGlobalReplicationGroups: global datastore members, regions, roles and status."""
    return control_plane().global_replication_groups()


@read_tool
def aws_reserved_nodes() -> dict:
    """DescribeReservedCacheNodes plus running nodes: reservation coverage per node type and
    engine, on-demand nodes not covered, unused or soon-expiring reservations."""
    return control_plane().reserved_nodes()


@read_tool
def aws_reserved_offerings(
    node_type: Annotated[str, Field(description="Node type, e.g. cache.r6g.large", min_length=1, max_length=64)],
    engine: Annotated[Literal["redis", "valkey", "memcached"], Field(description="Cache engine")],
) -> dict:
    """DescribeReservedCacheNodesOfferings: 1y/3y offerings for a node type and engine (capped), the number of
    running nodes no reservation covers and the cheapest offering per term. Never purchases anything."""
    return control_plane().reserved_offerings(node_type, engine)


@read_tool
def aws_engine_versions(
    engine: Annotated[Literal["redis", "valkey", "memcached"], Field(description="Cache engine")],
    version_prefix: Annotated[
        str | None, Field(description="Only versions starting with this, e.g. '7.')", max_length=16)
    ] = None,
) -> dict:
    """DescribeCacheEngineVersions: available versions with parameter group family, plus upgrade
    targets (latest minor of each major; latest Valkey when asking about Redis OSS)."""
    return control_plane().engine_versions(engine, version_prefix)


@read_tool
def aws_parameter_groups() -> dict:
    """DescribeCacheParameterGroups joined with running clusters: family, which clusters use each
    group, unused custom groups (info) and groups whose family differs from the running engine (warning)."""
    return control_plane().parameter_groups()


@read_tool
def aws_service_updates(
    status: Annotated[Literal["available", "cancelled", "expired"], Field(description="Update status")] = "available",
) -> dict:
    """DescribeServiceUpdates: pending updates by severity with apply-by and auto-update dates."""
    return control_plane().service_updates(status)


@read_tool
def aws_subnet_groups() -> dict:
    """DescribeCacheSubnetGroups: VPC, subnets and AZ spread (flags groups in fewer than 2 AZs)."""
    return control_plane().subnet_groups()


@read_tool
def aws_metrics(
    cache_cluster_id: Annotated[
        str | None,
        Field(description="CacheClusterId (node cluster, e.g. 'my-rg-0001-001') or serverless cache name"),
    ] = None,
    metrics: Annotated[list[str] | None, Field(description="CloudWatch metric names; default set if omitted")] = None,
    minutes: Annotated[int, Field(ge=1, le=20160)] = 60,
    period_seconds: Annotated[int, Field(ge=60, le=86400, multiple_of=60)] = 60,
    node_id: str | None = None,
    serverless: bool = False,
    include_series: Annotated[bool, Field(description="Return the full time series (token heavy)")] = False,
    replication_group_id: Annotated[
        str | None, Field(description="Query every member node of this replication group (cluster mode aware)")
    ] = None,
) -> dict:
    """CloudWatch AWS/ElastiCache metrics (EngineCPUUtilization, memory %, Evictions,
    CurrConnections, CacheHitRate, ReplicationLag, ...). Findings first, then a
    min/avg/max/latest summary; the raw series only with include_series=true."""
    return control_plane().metrics(
        cache_cluster_id, metrics, minutes, period_seconds, node_id, serverless, include_series, replication_group_id
    )


@read_tool
def aws_parameter_drift(
    group_a: Annotated[str, Field(description="First cache parameter group name (e.g. production)")],
    group_b: Annotated[str, Field(description="Second cache parameter group name (e.g. staging)")],
) -> dict:
    """DescribeCacheParameters on two groups: only parameters whose values differ and that someone
    modified (default-only differences are counted, not listed), plus family mismatch warnings."""
    return control_plane().parameter_drift(group_a, group_b)


@read_tool
def aws_triage(replication_group_id: Annotated[str, Field(description="ReplicationGroupId to triage")]) -> dict:
    """One-call incident summary for a replication group: status, Multi-AZ/failover, last 6h events,
    CloudWatch peaks per member, pending service updates and snapshot age. Findings are worst-first
    (max 30); a section that fails is reported as unavailable instead of failing the call."""
    return control_plane().triage(replication_group_id)


@read_tool
def aws_alarms(
    replication_group_id: Annotated[
        str | None,
        Field(description="Limit to one replication group; omit to check every group, cluster and serverless cache"),
    ] = None,
) -> dict:
    """CloudWatch alarm coverage for ElastiCache (DescribeAlarms, read-only). Findings first: alarms in
    ALARM, INSUFFICIENT_DATA or with actions disabled, and members with no alarm on EngineCPUUtilization,
    DatabaseMemoryUsagePercentage, Evictions, ReplicationLag, CurrConnections, SwapUsage (plus ThrottledCmds
    on Serverless). Returns partial=true if DescribeAlarms is denied."""
    return control_plane().alarms(replication_group_id)


@read_tool
def aws_cluster_overview(
    replication_group_id: Annotated[str, Field(description="ReplicationGroupId to summarise")],
    minutes: Annotated[int, Field(ge=5, le=20160, description="CloudWatch window (multiple of 5 min is fine)")] = 360,
) -> dict:
    """One findings-first call per replication group: shards, replicas per shard, AZ spread, failover and
    engine version joined with per-node CloudWatch signals (CPU, memory, replication lag, evictions,
    connections). Flags nodes above 1.5x their peers' median, reader endpoint gaps and right-sizing
    hints (memory p95 < 30% and CPU p95 < 20%; data tiering for r6gd). Worst-first, bounded; if
    GetMetricData is denied the topology is still returned with status partial."""
    return control_plane().cluster_overview(replication_group_id, minutes)


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
