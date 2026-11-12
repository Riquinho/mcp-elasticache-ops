"""Data-plane (node_*) and Memcached tools; registered on import by ``server``."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from . import server
from .config import DataPlaneConfig, MemcachedConfig

Region = server.Region

# ------------------------------------------------------------------ data plane


@server.read_tool
def node_health() -> dict:
    """One-shot health summary of the configured Redis/Valkey endpoint: engine and
    version, role, clients, hit ratio, memory vs maxmemory, fragmentation,
    evictions and a list of findings."""
    return server.dataplane.health_summary(server.redis_client(), server._serverless())


@server.read_tool
def node_connectivity() -> dict:
    """Why can't I connect: staged diagnosis of the endpoint, stopping at the first failure. DNS, TCP, TLS (and
    plaintext fallback), PING, AUTH, each timed with a verdict and one hint per failure class. Socket probes and
    PING only; credentials never echoed."""
    return server.diagnose_connectivity(DataPlaneConfig.from_env())


@server.read_tool
def node_triage() -> dict:
    """On-call snapshot of the connected endpoint: health, memory, replication, clients, failed commandstats, top-5
    slowlog, latency, DOCTOR. Findings worst-first (max 30); a failing section is reported unavailable. Start here."""
    return server.dataplane.triage(server.redis_client(), server._node_client, server._serverless())


@server.read_tool
def node_doctor() -> dict:
    """MEMORY DOCTOR and LATENCY DOCTOR of the connected node: the engine's advice plus findings for non-healthy
    lines. Engines that reject the command get a note, not an error. node_triage includes this."""
    return server.dataplane.node_doctor(
        server.redis_client(), server._serverless(), server.dataplane.DOCTOR_MAX_SECONDS
    )


@server.read_tool
def node_info(
    section: Annotated[
        str | None,
        Field(
            description="INFO section (server, memory, stats, replication, commandstats, keyspace...); omit for default"
        ),
    ] = None,
) -> dict:
    """Raw INFO output, optionally for a single section. Password-like keys are masked."""
    return server.dataplane.server_info(server.redis_client(), section)


@server.read_tool
def node_memory() -> dict:
    """Memory breakdown: used/RSS/peak/dataset/overhead, maxmemory and policy,
    fragmentation ratio with a verdict, evictions, MEMORY STATS and MEMORY DOCTOR
    when the engine allows them."""
    return server.dataplane.memory_report(server.redis_client(), server._serverless())


@server.read_tool
def node_config() -> dict:
    """Allowlisted CONFIG GET view (maxmemory policy, timeout, appendonly, output buffer limits, keyspace
    notifications, slowlog/latency thresholds, io-threads) with findings. Points at aws_parameters when CONFIG
    is refused, as ElastiCache usually does."""
    return server.dataplane.config_view(server.redis_client())


@server.read_tool
def node_slowlog(
    count: Annotated[int, Field(ge=1, le=1024, description="Entries to fetch")] = 25,
    include_args: Annotated[bool, Field(description="Return full command arguments (may expose values)")] = False,
) -> dict:
    """SLOWLOG entries plus per-command totals. Arguments beyond the key are hidden
    unless include_args is true."""
    return server.dataplane.slowlog(server.redis_client(), count, include_args, server._serverless())


@server.read_tool
def node_clients(top: Annotated[int, Field(ge=1, le=500)] = 20) -> dict:
    """CLIENT LIST aggregated by source IP, client name, ACL user and last command,
    idle-time stats and the clients holding the most buffer memory."""
    return server.dataplane.client_list(server.redis_client(), top)


@server.read_tool
def node_clients_summary(
    top: Annotated[int, Field(ge=1, le=50)] = 10,
    near_maxclients_pct: Annotated[int, Field(ge=1, le=100)] = 80,
) -> dict:
    """Who holds the connections: CLIENT LIST grouped by source IP, name or library, user and flags, top IPs, idle
    over 1h, big buffers, maxclients use. Capped rows per group; never commands, arguments or keys."""
    return server.dataplane.client_summary(server.redis_client(), top, near_maxclients_pct)


@server.read_tool
def node_latency(ping_samples: Annotated[int, Field(ge=1, le=500)] = 20) -> dict:
    """Client-side PING RTT percentiles plus LATENCY LATEST events from the server
    latency monitor (needs latency-monitor-threshold > 0)."""
    return server.dataplane.latency(server.redis_client(), ping_samples)


@server.read_tool
def node_latency_events() -> dict:
    """LATENCY LATEST, then HISTORY for the 3 worst events, findings first: fork or aof-fsync over 100 ms,
    expire-cycle spikes, trimmed LATENCY/MEMORY DOCTOR. With latency-monitor-threshold 0 the finding names it."""
    return server.dataplane.latency_events(server.redis_client())


@server.read_tool
def node_commandstats(top: Annotated[int, Field(ge=1, le=500)] = 20) -> dict:
    """Commands ranked by CPU time (INFO commandstats): calls, usec per call, rejected and failed, error prefixes,
    p50/p99/p99.9 when available. Findings for OOM/READONLY/NOPERM errors and p99 over 10 ms."""
    return server.dataplane.commandstats(server.redis_client(), top)


@server.read_tool
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
    include_sizes: Annotated[
        bool,
        Field(description="Add a collections block: key prefixes whose collections exceed size_threshold elements"),
    ] = False,
    size_threshold: Annotated[
        int, Field(ge=1, le=100_000_000, description="Element count above which a collection is flagged")
    ] = 10_000,
) -> dict:
    """Big keys, hot (LFU) or cold keys, type mix, TTL coverage, per-prefix bytes from a bounded SCAN. Metadata only,
    never values. partial=true at max_seconds. Cluster mode: this node only (see node_cluster_keyspace_sample).
    include_access adds the idle-key share; include_sizes flags large collections."""
    return server.dataplane.keyspace_sample(
        server.redis_client(),
        sample_size,
        match,
        top,
        scan_count,
        pause_ms,
        max_seconds,
        top_prefixes=top_prefixes,
        include_access=include_access,
        include_sizes=include_sizes,
        size_threshold=size_threshold,
    )


@server.read_tool
def node_replication() -> dict:
    """Replication role, replicas with byte lag, link status, backlog, plus findings: links down, lagging replicas
    (also vs the primary offset on a replica), replica-read-only, min-replicas-to-write, cluster-allow-reads-
    when-down. Engine quirks are notes, not errors."""
    return server.dataplane.replication(server.redis_client(), server._node_client)


@server.read_tool
def node_acl_log(count: Annotated[int, Field(ge=1, le=128, description="ACL LOG entries to fetch")] = 25) -> dict:
    """ACL WHOAMI and recent ACL LOG entries (auth failures, denied commands, key/channel denials) with reason,
    user, client address, count; key and channel names hidden. Findings flag repeated auth failures and denial
    spikes. ACL LIST/GETUSER never used."""
    return server.dataplane.acl_log(server.redis_client(), count)


@server.read_tool
def node_cluster() -> dict:
    """Cluster-mode view: CLUSTER INFO, slots per primary and CLUSTER SHARDS when
    available. Reports cluster mode disabled otherwise."""
    return server.dataplane.cluster(server.redis_client(), server._serverless())


@server.read_tool
def node_cluster_nodes() -> dict:
    """CLUSTER NODES parsed into per-shard primary/replica endpoints, slot counts and
    failing nodes, plus how to target each shard with ELASTICACHE_HOST."""
    return server.dataplane.cluster_nodes(server.redis_client(), server._serverless())


@server.read_tool
def node_cluster_health(
    max_workers: Annotated[int, Field(ge=1, le=32, description="Concurrent node probes")] = 8,
    per_node_timeout: Annotated[float, Field(gt=0, le=60, description="Seconds to wait per node")] = 5.0,
) -> dict:
    """Cluster-mode fan-out: INFO on every node (bounded concurrency, per-node timeout)
    flagging memory/ops skew across shards, failed nodes, uncovered slots and replica lag."""
    return server.dataplane.cluster_health(server.redis_client(), server._node_client, max_workers, per_node_timeout)


@server.read_tool
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
    """node_keyspace_sample on every shard primary: keys merged with a `shard` label, per-shard status, skew
    findings. A dead shard is reported, never fatal. Budget and sample split across primaries."""
    return server.dataplane.cluster_keyspace_sample(
        server.redis_client(),
        server._node_client,
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


@server.read_tool
def node_cluster_slowlog(
    count: Annotated[int, Field(ge=1, le=1024, description="Entries to return overall")] = 25,
    include_args: Annotated[bool, Field(description="Return full command arguments (may expose values)")] = False,
    max_workers: Annotated[int, Field(ge=1, le=32, description="Concurrent shard probes")] = 8,
    per_node_timeout: Annotated[float, Field(gt=0, le=60, description="Seconds to wait per node")] = 5.0,
) -> dict:
    """node_slowlog on every shard primary: the slowest entries overall labelled by shard, per-command
    totals and per-shard status. Arguments beyond the key are hidden unless include_args is true."""
    return server.dataplane.cluster_slowlog(
        server.redis_client(), server._node_client, count, include_args, max_workers, per_node_timeout
    )


@server.read_tool
def node_cluster_memory(
    max_workers: Annotated[int, Field(ge=1, le=32, description="Concurrent shard probes")] = 8,
    per_node_timeout: Annotated[float, Field(gt=0, le=60, description="Seconds to wait per node")] = 5.0,
) -> dict:
    """node_memory headline for every shard primary: used/RSS/maxmemory, fragmentation, evictions, with
    findings for memory skew between shards, shards above 90% of maxmemory and unreachable shards."""
    return server.dataplane.cluster_memory(server.redis_client(), server._node_client, max_workers, per_node_timeout)


@server.read_tool
def node_hot_slots(
    slots_per_shard: Annotated[int, Field(ge=1, le=256, description="Slots sampled per shard")] = 64,
    max_workers: Annotated[int, Field(ge=1, le=32, description="Concurrent probes")] = 8,
    per_node_timeout: Annotated[float, Field(gt=0, le=60, description="Seconds per node")] = 5.0,
    max_seconds: Annotated[float, Field(gt=0, le=60, description="Total budget")] = 15.0,
) -> dict:
    """Cluster-mode shard skew and hot slots: per-shard keys, memory, ops/sec plus CLUSTER COUNTKEYSINSLOT on a
    capped slot sample. Findings name hot shards and slots; `reached N/M shards`. Counts only."""
    return server.dataplane.cluster_hot_slots(
        server.redis_client(), server._node_client, slots_per_shard, max_workers, per_node_timeout, max_seconds
    )


@server.read_tool
def node_pubsub(
    top: Annotated[int, Field(ge=1, le=100, description="Channels to list by subscriber count")] = 10,
    pattern: Annotated[str | None, Field(max_length=128, description="PUBSUB CHANNELS glob filter")] = None,
    max_workers: Annotated[int, Field(ge=1, le=32, description="Concurrent shard probes (cluster mode)")] = 8,
    per_node_timeout: Annotated[float, Field(gt=0, le=60, description="Seconds to wait per node")] = 5.0,
) -> dict:
    """Pub/Sub pressure: channel and pattern counts, top channels by subscribers, subscribers with large output
    buffers. Counts only, never messages. Cluster mode aggregates shard primaries."""
    return server.dataplane.cluster_pubsub(
        server.redis_client(), server._node_client, top, pattern, max_workers, per_node_timeout
    )


@server.read_tool
def node_cluster_triage(
    max_workers: Annotated[int, Field(ge=1, le=32, description="Concurrent shard probes")] = 8,
    per_node_timeout: Annotated[float, Field(gt=0, le=60, description="Extra seconds to wait for a stuck shard")] = 5.0,
    max_seconds: Annotated[
        float, Field(gt=0, le=60, description="Total wall-clock budget, split across shards")
    ] = 20.0,
) -> dict:
    """node_triage plus pub/sub pressure on every shard primary under one deadline: one ranked, deduplicated
    findings list naming node and shard (max 40). A dead shard is a critical finding, never fatal. Use first on
    a cluster-mode group."""
    return server.dataplane.cluster_triage(
        server.redis_client(), server._node_client, max_workers, per_node_timeout, max_seconds, server._serverless()
    )


@server.read_tool
def memcached_stats(
    group: Annotated[
        Literal["", "settings", "slabs", "items", "conns"], Field(description="stats group; empty for general")
    ] = "",
) -> dict:
    """Memcached summary (hit ratio, memory, evictions, connections) or a raw
    `stats <group>` output. Uses MEMCACHED_HOST/MEMCACHED_PORT."""
    cfg = server._memcached_target()
    host = cfg.host or ""  # server._memcached_target already rejected an empty host
    if group:
        return {"group": group, "stats": server.memcached.stats(host, cfg.port, group, cfg.timeout)}
    return server.memcached.summary(host, cfg.port, cfg.timeout)


@server.read_tool
def memcached_cluster_stats() -> dict:
    """Memcached fleet view over MEMCACHED_NODES: every node queried with bounded concurrency, only `stats`, `stats
    slabs`, `stats items`. Findings first: evictions, hit-ratio outliers, item/memory imbalance,
    listen_disabled_num, connections near maxconns, evicting slab classes. A dead node makes it partial."""
    cfg = MemcachedConfig.from_env()
    return server.memcached.cluster_stats(cfg.nodes, cfg.timeout)


@server.read_tool
def memcached_discovery(
    cache_cluster_id: Annotated[str, Field(min_length=1, max_length=50, description="Memcached cache cluster id")],
    region: Region = None,
) -> dict:
    """Memcached auto-discovery check: `config get cluster` (MEMCACHED_HOST or the configuration endpoint) compared
    with DescribeCacheClusters nodes. Flags AWS nodes missing from the config, stale entries, engine version
    mismatch. An unreachable endpoint is a finding."""
    cfg = MemcachedConfig.from_env()
    return server._cp(region).memcached_discovery(
        cache_cluster_id, cfg.host, cfg.port if cfg.host else None, cfg.timeout
    )
