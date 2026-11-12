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

import botocore.exceptions
import redis
from fastmcp import FastMCP
from mcp.types import ToolAnnotations
from pydantic import Field

from . import dataplane, memcached
from .config import ControlPlaneConfig, DataPlaneConfig, MemcachedConfig, max_output_chars
from .connection import build_client, diagnose_connectivity
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
        description="AWS region to query (for example the secondary region of a global datastore); "
        "defaults to AWS_REGION",
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


# ------------------------------------------------------------------ data plane


@read_tool
def node_health() -> dict:
    """One-shot health summary of the configured Redis/Valkey endpoint: engine and
    version, role, clients, hit ratio, memory vs maxmemory, fragmentation,
    evictions and a list of findings."""
    return dataplane.health_summary(redis_client(), _serverless())


@read_tool
def node_connectivity() -> dict:
    """Why can't I connect: staged diagnosis of the configured endpoint, stopping at the first failure.
    DNS (IPs, private or not, endpoint type), TCP, TLS (and plaintext fallback), PING, AUTH, each timed with a
    verdict. Findings first, one hint per failure class. Socket probes and PING only; credentials never echoed."""
    return diagnose_connectivity(DataPlaneConfig.from_env())


@read_tool
def node_triage() -> dict:
    """On-call snapshot of the connected endpoint in one call: health, memory, replication, clients,
    failed/rejected commandstats, top-5 slowlog, latency and MEMORY/LATENCY DOCTOR advice. Findings from every
    section are merged worst-first (max 30); a section that fails is reported unavailable and the rest still
    run. Start here, then drill into the specific node_ tool."""
    return dataplane.triage(redis_client(), _node_client, _serverless())


@read_tool
def node_doctor() -> dict:
    """MEMORY DOCTOR and LATENCY DOCTOR of the connected node: the engine's own advice text (trimmed) plus
    findings that keep only the non-healthy lines. Engines or managed services that reject the command
    (older versions, Serverless) get a 'not available' note, not an error. Per node: point
    ELASTICACHE_HOST at each node you suspect. node_triage already includes this section."""
    return dataplane.node_doctor(redis_client(), _serverless())


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
def node_latency_events() -> dict:
    """LATENCY LATEST, then LATENCY HISTORY for the 3 worst events (newest 20 samples), findings first: fork or
    aof-fsync events over 100 ms, expire-cycle spikes, plus trimmed LATENCY DOCTOR and MEMORY DOCTOR text.
    When latency-monitor-threshold is 0 (the ElastiCache default) the finding points at that parameter."""
    return dataplane.latency_events(redis_client())


@read_tool
def node_commandstats(top: Annotated[int, Field(ge=1, le=500)] = 20) -> dict:
    """Commands ranked by total CPU time (INFO commandstats), with calls, usec per call, rejected and
    failed calls, plus error prefix counts (errorstats) and p50/p99/p99.9 per command (latencystats)
    when the engine has them; findings for OOM/READONLY/NOPERM errors and commands with p99 over 10 ms."""
    return dataplane.commandstats(redis_client(), top)


@read_tool
def node_keyspace_sample(
    sample_size: Annotated[int, Field(ge=1, le=100_000, description="Max keys to inspect")] = 1000,
    match: Annotated[str | None, Field(description="SCAN MATCH glob, e.g. 'session:*'")] = None,
    top: Annotated[int, Field(ge=1, le=500)] = 20,
    scan_count: Annotated[int, Field(ge=10, le=1000, description="SCAN COUNT hint")] = 250,
    pause_ms: Annotated[int, Field(ge=0, le=1000, description="Sleep between SCAN batches")] = 0,
    max_seconds: Annotated[
        float, Field(gt=0, le=60, description="Wall-clock budget; returns partial=true when exceeded")
    ] = 10.0,
    top_prefixes: Annotated[int, Field(ge=1, le=50, description="Key prefixes to report")] = 10,
    include_access: Annotated[
        bool,
        Field(
            description="Add an access block: share of sampled keys idle over 7 days (OBJECT IDLETIME) or with a "
            "cold LFU counter (OBJECT FREQ), with an eviction-risk hint"
        ),
    ] = False,
) -> dict:
    """Big keys, hot keys (LFU) or coldest keys, type mix, TTL coverage and per-prefix bytes from a bounded
    SCAN. Metadata only; values never read. Partial=true at max_seconds. Cluster mode: connected node's
    slots only, use node_cluster_keyspace_sample for all shards. Flags large no-TTL prefixes under pressure.
    include_access=true adds the share of idle keys (IDLETIME, or FREQ on LFU)."""
    return dataplane.keyspace_sample(
        redis_client(),
        sample_size,
        match,
        top,
        scan_count,
        pause_ms,
        max_seconds,
        top_prefixes=top_prefixes,
        include_access=include_access,
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
    scan_count: Annotated[int, Field(ge=10, le=1000, description="SCAN COUNT hint")] = 250,
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
def node_pubsub(
    top: Annotated[int, Field(ge=1, le=100, description="Channels to list by subscriber count")] = 10,
    pattern: Annotated[str | None, Field(max_length=128, description="PUBSUB CHANNELS glob filter")] = None,
    max_workers: Annotated[int, Field(ge=1, le=32, description="Concurrent shard probes (cluster mode)")] = 8,
    per_node_timeout: Annotated[float, Field(gt=0, le=60, description="Seconds to wait per node")] = 5.0,
) -> dict:
    """Pub/Sub pressure from PUBSUB CHANNELS/NUMSUB/NUMPAT/SHARDCHANNELS and CLIENT LIST TYPE pubsub: channel
    and pattern-subscription counts, top channels by subscribers, subscribers with large output buffers.
    Counts only, never messages. Cluster mode aggregates every shard primary and labels findings by shard."""
    return dataplane.cluster_pubsub(redis_client(), _node_client, top, pattern, max_workers, per_node_timeout)


@read_tool
def node_cluster_triage(
    max_workers: Annotated[int, Field(ge=1, le=32, description="Concurrent shard probes")] = 8,
    per_node_timeout: Annotated[float, Field(gt=0, le=60, description="Extra seconds to wait for a stuck shard")] = 5.0,
    max_seconds: Annotated[
        float, Field(gt=0, le=60, description="Total wall-clock budget, split across shards")
    ] = 20.0,
) -> dict:
    """node_triage plus pub/sub pressure on every shard primary under one shared deadline: one ranked, deduplicated
    findings list naming node and shard, worst node first (max 40). A dead shard is a critical finding, never
    fatal. Use it first on a cluster-mode group instead of calling each node."""
    return dataplane.cluster_triage(
        redis_client(), _node_client, max_workers, per_node_timeout, max_seconds, _serverless()
    )


@read_tool
def memcached_stats(
    group: Annotated[
        Literal["", "settings", "slabs", "items", "conns"], Field(description="stats group; empty for general")
    ] = "",
) -> dict:
    """Memcached summary (hit ratio, memory, evictions, connections) or a raw
    `stats <group>` output. Uses MEMCACHED_HOST/MEMCACHED_PORT."""
    cfg = _memcached_target()
    host = cfg.host or ""  # _memcached_target already rejected an empty host
    if group:
        return {"group": group, "stats": memcached.stats(host, cfg.port, group, cfg.timeout)}
    return memcached.summary(host, cfg.port, cfg.timeout)


@read_tool
def memcached_cluster_stats() -> dict:
    """Memcached fleet view over MEMCACHED_NODES (host:port list): queries every node with bounded
    concurrency and a per-node timeout, only `stats`, `stats slabs` and `stats items`. Findings first:
    evictions, hit-ratio outliers vs the median, item/memory imbalance, listen_disabled_num, connections
    near maxconns, slab classes evicting or running out of memory. A dead node makes the result partial."""
    cfg = MemcachedConfig.from_env()
    return memcached.cluster_stats(cfg.nodes, cfg.timeout)


@read_tool
def memcached_discovery(
    cache_cluster_id: Annotated[str, Field(min_length=1, max_length=50, description="Memcached cache cluster id")],
    region: Region = None,
) -> dict:
    """Memcached auto-discovery check: reads `config get cluster` (read-only; MEMCACHED_HOST or the cluster's
    configuration endpoint) and compares it with DescribeCacheClusters nodes. Flags AWS nodes missing from the
    config, stale entries and engine version mismatch. An unreachable endpoint is a finding."""
    cfg = MemcachedConfig.from_env()
    return _cp(region).memcached_discovery(cache_cluster_id, cfg.host, cfg.port if cfg.host else None, cfg.timeout)


# --------------------------------------------------------------- control plane


@read_tool
def aws_replication_groups(replication_group_id: str | None = None, region: Region = None) -> dict:
    """DescribeReplicationGroups: status, engine, cluster mode, node type, Multi-AZ,
    failover, encryption, shards with primary/reader endpoints and member roles. Queries every region in
    ELASTICACHE_REGIONS unless `region` is given."""
    return control_plane().replication_groups_fan_out(replication_group_id, region)


@read_tool
def aws_cache_clusters(cache_cluster_id: str | None = None, show_nodes: bool = True, region: Region = None) -> dict:
    """DescribeCacheClusters: per-node-cluster engine version, node type, parameter
    group and apply status, maintenance window, pending changes and node endpoints."""
    return _cp(region).cache_clusters(cache_cluster_id, show_nodes)


@read_tool
def aws_serverless_caches(region: Region = None) -> dict:
    """DescribeServerlessCaches for ElastiCache Serverless (Valkey/Redis OSS/Memcached)."""
    return _cp(region).serverless_caches()


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
    region: Region = None,
) -> dict:
    """DescribeEvents, findings first: events classified critical (failover, failure, not available),
    warning (replacement, reboot, restart, maintenance) or info, worst then newest, plus counts per
    source and the 100 newest raw events (`truncated` says more exist). Invalid source_type is refused."""
    return _cp(region).events(source_identifier, source_type, hours)


@read_tool
def aws_parameters(
    parameter_group: str,
    only_modified: bool = True,
    diff_engine_defaults: Annotated[
        bool, Field(description="Compare with DescribeEngineDefaultParameters and list only non-default values")
    ] = False,
    region: Region = None,
) -> dict:
    """DescribeCacheParameters for a parameter group; by default only values changed (Source=user).
    Findings flag risky settings (noeviction, tiny output buffers, timeout 0, low maxmemory-samples)."""
    return _cp(region).parameters(parameter_group, only_modified, diff_engine_defaults)


@read_tool
def aws_snapshots(
    replication_group_id: str | None = None,
    cache_cluster_id: str | None = None,
    source: Annotated[Literal["automated", "manual"] | None, Field(description="Filter by snapshot source")] = None,
    stale_hours: Annotated[int, Field(ge=1, le=8760, description="Flag automatic snapshots older than this")] = 36,
    region: Region = None,
) -> dict:
    """DescribeSnapshots: age, size, status, automatic vs manual, with findings for
    retention gaps, failed snapshots and groups without automatic backups."""
    return _cp(region).snapshots(replication_group_id, cache_cluster_id, source, stale_hours)


@read_tool
def aws_serverless_snapshots(
    serverless_cache_name: str | None = None,
    snapshot_type: Annotated[
        Literal["automatic", "manual"] | None, Field(description="Filter by snapshot type")
    ] = None,
    stale_hours: Annotated[int, Field(ge=1, le=8760, description="Flag caches whose newest snapshot is older")] = 24,
    region: Region = None,
) -> dict:
    """DescribeServerlessCacheSnapshots plus DescribeServerlessCaches: findings for caches without a
    recent snapshot, failed snapshots, snapshots about to expire, missing KMS key and unset retention."""
    return _cp(region).serverless_snapshots(serverless_cache_name, snapshot_type, stale_hours)


@read_tool
def aws_users(
    engine: Annotated[Literal["redis", "valkey"] | None, Field(description="Engine filter")] = None,
    region: Region = None,
) -> dict:
    """DescribeUsers (RBAC): authentication type and access strings, never passwords.
    Flags users with '~* +@all' access and users without a password."""
    return _cp(region).users(engine)


@read_tool
def aws_user_groups(region: Region = None) -> dict:
    """DescribeUserGroups: members, attached replication groups/serverless caches, pending changes."""
    return _cp(region).user_groups()


@read_tool
def aws_global_replication_groups(region: Region = None) -> dict:
    """DescribeGlobalReplicationGroups: global datastore members, regions, roles and status."""
    return _cp(region).global_replication_groups()


@read_tool
def aws_reserved_nodes(region: Region = None) -> dict:
    """DescribeReservedCacheNodes plus running nodes: reservation coverage per node type and
    engine, on-demand nodes not covered, unused or soon-expiring reservations."""
    return _cp(region).reserved_nodes()


@read_tool
def aws_reserved_offerings(
    node_type: Annotated[str, Field(description="Node type, e.g. cache.r6g.large", min_length=1, max_length=64)],
    engine: Annotated[Literal["redis", "valkey", "memcached"], Field(description="Cache engine")],
    region: Region = None,
) -> dict:
    """DescribeReservedCacheNodesOfferings: 1y/3y offerings for a node type and engine (capped), the number of
    running nodes no reservation covers and the cheapest offering per term. Never purchases anything."""
    return _cp(region).reserved_offerings(node_type, engine)


@read_tool
def aws_engine_versions(
    engine: Annotated[Literal["redis", "valkey", "memcached"], Field(description="Cache engine")],
    version_prefix: Annotated[
        str | None, Field(description="Only versions starting with this, e.g. '7.')", max_length=16)
    ] = None,
    region: Region = None,
) -> dict:
    """DescribeCacheEngineVersions: available versions with parameter group family, plus upgrade
    targets (latest minor of each major; latest Valkey when asking about Redis OSS)."""
    return _cp(region).engine_versions(engine, version_prefix)


@read_tool
def aws_parameter_groups(region: Region = None) -> dict:
    """DescribeCacheParameterGroups joined with running clusters: family, which clusters use each
    group, unused custom groups (info) and groups whose family differs from the running engine (warning)."""
    return _cp(region).parameter_groups()


@read_tool
def aws_service_updates(
    status: Annotated[Literal["available", "cancelled", "expired"], Field(description="Update status")] = "available",
    region: Region = None,
) -> dict:
    """DescribeServiceUpdates: pending updates by severity with apply-by and auto-update dates."""
    return _cp(region).service_updates(status)


@read_tool
def aws_subnet_groups(region: Region = None) -> dict:
    """DescribeCacheSubnetGroups: VPC, subnets and AZ spread (flags groups in fewer than 2 AZs)."""
    return _cp(region).subnet_groups()


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
    region: Region = None,
) -> dict:
    """CloudWatch AWS/ElastiCache metrics (EngineCPUUtilization, memory %, Evictions,
    CurrConnections, CacheHitRate, ReplicationLag, ...). Findings first, then a
    min/avg/max/latest summary; the raw series only with include_series=true."""
    return _cp(region).metrics(
        cache_cluster_id, metrics, minutes, period_seconds, node_id, serverless, include_series, replication_group_id
    )


@read_tool
def aws_parameter_drift(
    group_a: Annotated[str, Field(description="First cache parameter group name (e.g. production)")],
    group_b: Annotated[str, Field(description="Second cache parameter group name (e.g. staging)")],
    region: Region = None,
) -> dict:
    """DescribeCacheParameters on two groups: only parameters whose values differ and that someone
    modified (default-only differences are counted, not listed), plus family mismatch warnings."""
    return _cp(region).parameter_drift(group_a, group_b)


@read_tool
def aws_triage(
    replication_group_id: Annotated[str, Field(description="ReplicationGroupId to triage")], region: Region = None
) -> dict:
    """One-call incident summary for a replication group: status, Multi-AZ/failover, last 6h events,
    CloudWatch peaks per member, pending service updates and snapshot age. Findings are worst-first
    (max 30); a section that fails is reported as unavailable instead of failing the call."""
    return control_plane().triage_fan_out(replication_group_id, region)


@read_tool
def aws_serverless_triage(
    serverless_cache_name: Annotated[str, Field(description="ServerlessCacheName to triage")],
    region: Region = None,
) -> dict:
    """One-call incident summary for a serverless cache: status and usage limits, snapshot health, and
    6h ThrottledCmds/ECPU/storage against the limits. Findings are worst-first (max 30); a section that
    fails (for example AccessDenied) is reported as unavailable instead of failing the call."""
    return _cp(region).serverless_triage(serverless_cache_name)


@read_tool
def aws_shard_balance(
    replication_group_id: Annotated[str, Field(description="ReplicationGroupId to check for shard skew")],
    minutes: Annotated[int, Field(ge=5, le=20160, description="CloudWatch window in minutes")] = 60,
    region: Region = None,
) -> dict:
    """Per-shard skew from CloudWatch only (one GetMetricData call per member; works without a data-plane
    connection). Findings first: hot shard (over 2x the median and above 50% CPU), memory skew, and one
    primary pinned near 100% CPU while the rest idle (hot-key signature)."""
    return _cp(region).shard_balance(replication_group_id, minutes)


@read_tool
def aws_alarms(
    replication_group_id: Annotated[
        str | None,
        Field(description="Limit to one replication group; omit to check every group, cluster and serverless cache"),
    ] = None,
    region: Region = None,
) -> dict:
    """CloudWatch alarm coverage (DescribeAlarms, read-only). Findings first: alarms in ALARM,
    INSUFFICIENT_DATA or with actions disabled, and members with no alarm on the core metrics (CPU, memory,
    evictions, lag, connections, swap). partial=true if DescribeAlarms is denied. Without a group id it
    covers every region in ELASTICACHE_REGIONS (findings carry `region`, failures in region_errors)."""
    if replication_group_id:
        return _cp(region).alarms(replication_group_id)
    return control_plane().alarms_fan_out(None, region)


@read_tool
def aws_maintenance(
    replication_group_id: Annotated[
        str | None,
        Field(description="Limit to one replication group; omit to check every cluster of every configured region"),
    ] = None,
    region: Region = None,
) -> dict:
    """Maintenance urgency (DescribeUpdateActions, ServiceUpdates, CacheClusters; read-only). Findings first:
    required updates past their apply-by date, maintenance windows overlapping the snapshot window, end-of-life
    engines. partial=true if a Describe call is denied. Without a group id it covers every region in
    ELASTICACHE_REGIONS (findings carry `region`, failures in region_errors)."""
    return control_plane().maintenance_fan_out(replication_group_id, region)


@read_tool
def aws_cluster_overview(
    replication_group_id: Annotated[
        str | None,
        Field(description="ReplicationGroupId to summarise; omit for a fleet pass over every configured region"),
    ] = None,
    minutes: Annotated[int, Field(ge=5, le=20160, description="CloudWatch window (multiple of 5 min is fine)")] = 360,
    region: Region = None,
) -> dict:
    """One findings-first call per replication group: shards, replicas, AZ spread, failover and engine
    version joined with per-node CloudWatch signals; flags outlier nodes, reader gaps and right-sizing.
    Without a group id: fleet mode over every region in ELASTICACHE_REGIONS (findings carry `region`,
    failures in region_errors)."""
    if replication_group_id:
        return _cp(region).cluster_overview(replication_group_id, minutes)
    return control_plane().cluster_overview_fan_out(None, minutes, region)


@read_tool
def aws_security_audit(
    top: Annotated[int, Field(ge=1, le=200, description="Rows of the per-resource pass/fail matrix")] = 25,
    region: Region = None,
) -> dict:
    """Fleet hardening roll-up from existing Describe data (no new IAM). Findings first: counts by severity,
    findings grouped by category (transit, at rest/KMS, authentication, ACL, snapshots, patching) naming the
    resource, then a pass/fail matrix capped to `top`. A denied call becomes a note and partial=true."""
    return control_plane().security_audit_fan_out(region, top)


@read_tool
def aws_cost_overview(region: Region = None) -> dict:
    """Fleet cost and right-sizing, findings first: per replication group and serverless cache, node type and
    count, reserved coverage, 14-day peak memory/CPU. Flags oversized nodes (peak memory under 30%), idle
    replicas, on-demand and non-Graviton nodes, old manual snapshots, uncapped serverless. Bounded GetMetricData
    calls under one deadline; all ELASTICACHE_REGIONS unless `region` is set."""
    return control_plane().cost_overview_fan_out(region)


@read_tool
def aws_capacity_forecast(region: Region = None) -> dict:
    """Days until memory is full across the fleet, findings first: every replication group, standalone cluster
    and serverless cache from 14 days of DatabaseMemoryUsagePercentage (Serverless: BytesUsedForCache against
    the storage maximum), ranked soonest-first. Under 7 days critical, under 30 warning, with a sizing
    hint. One GetMetricData batch; all ELASTICACHE_REGIONS unless `region` is set."""
    return control_plane().capacity_forecast_fan_out(region)


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
