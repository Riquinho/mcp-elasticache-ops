"""Control-plane (aws_*) tools; registered on import by ``server``."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from . import server

Region = server.Region

# --------------------------------------------------------------- control plane


@server.read_tool
def aws_replication_groups(replication_group_id: str | None = None, region: Region = None) -> dict:
    """DescribeReplicationGroups: status, engine, cluster mode, node type, Multi-AZ,
    failover, encryption, shards with primary/reader endpoints and member roles. Queries every region in
    ELASTICACHE_REGIONS unless `region` is given."""
    return server.control_plane().replication_groups_fan_out(replication_group_id, region)


@server.read_tool
def aws_cache_clusters(cache_cluster_id: str | None = None, show_nodes: bool = True, region: Region = None) -> dict:
    """DescribeCacheClusters: per-node-cluster engine version, node type, parameter
    group and apply status, maintenance window, pending changes and node endpoints."""
    return server._cp(region).cache_clusters(cache_cluster_id, show_nodes)


@server.read_tool
def aws_serverless_caches(region: Region = None) -> dict:
    """DescribeServerlessCaches for ElastiCache Serverless (Valkey/Redis OSS/Memcached)."""
    return server._cp(region).serverless_caches()


@server.read_tool
def aws_events(
    source_identifier: str | None = None,
    source_type: Annotated[
        str | None,
        Field(
            description="cache-cluster, cache-parameter-group, cache-security-group, cache-subnet-group, "
            "replication-group, serverless-cache, user, user-group"
        ),
    ] = None,
    hours: Annotated[int, Field(ge=1, le=336)] = 24,
    region: Region = None,
) -> dict:
    """DescribeEvents, findings first: failover/failure critical, replacement/reboot/maintenance warning, worst then
    newest; counts per source and the 100 newest events (`truncated` if more). Invalid source_type is refused."""
    return server._cp(region).events(source_identifier, source_type, hours)


@server.read_tool
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
    return server._cp(region).parameters(parameter_group, only_modified, diff_engine_defaults)


@server.read_tool
def aws_snapshots(
    replication_group_id: str | None = None,
    cache_cluster_id: str | None = None,
    source: Annotated[Literal["automated", "manual"] | None, Field(description="Filter by snapshot source")] = None,
    stale_hours: Annotated[int, Field(ge=1, le=8760, description="Flag automatic snapshots older than this")] = 36,
    region: Region = None,
) -> dict:
    """DescribeSnapshots: age, size, status, automatic vs manual, with findings for
    retention gaps, failed snapshots and groups without automatic backups."""
    return server._cp(region).snapshots(replication_group_id, cache_cluster_id, source, stale_hours)


@server.read_tool
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
    return server._cp(region).serverless_snapshots(serverless_cache_name, snapshot_type, stale_hours)


@server.read_tool
def aws_users(
    engine: Annotated[Literal["redis", "valkey"] | None, Field(description="Engine filter")] = None,
    region: Region = None,
) -> dict:
    """DescribeUsers (RBAC): authentication type and access strings, never passwords.
    Flags users with '~* +@all' access and users without a password."""
    return server._cp(region).users(engine)


@server.read_tool
def aws_user_groups(region: Region = None) -> dict:
    """DescribeUserGroups: members, attached replication groups/serverless caches, pending changes."""
    return server._cp(region).user_groups()


@server.read_tool
def aws_global_replication_groups(region: Region = None) -> dict:
    """DescribeGlobalReplicationGroups: global datastore members, regions, roles and status."""
    return server._cp(region).global_replication_groups()


@server.read_tool
def aws_reserved_nodes(region: Region = None) -> dict:
    """DescribeReservedCacheNodes plus running nodes: reservation coverage per node type and
    engine, on-demand nodes not covered, unused or soon-expiring reservations."""
    return server._cp(region).reserved_nodes()


@server.read_tool
def aws_reserved_offerings(
    node_type: Annotated[str, Field(description="Node type, e.g. cache.r6g.large", min_length=1, max_length=64)],
    engine: Annotated[Literal["redis", "valkey", "memcached"], Field(description="Cache engine")],
    region: Region = None,
) -> dict:
    """DescribeReservedCacheNodesOfferings: 1y/3y offerings for a node type and engine (capped), the number of
    running nodes no reservation covers and the cheapest offering per term. Never purchases anything."""
    return server._cp(region).reserved_offerings(node_type, engine)


@server.read_tool
def aws_engine_versions(
    engine: Annotated[Literal["redis", "valkey", "memcached"], Field(description="Cache engine")],
    version_prefix: Annotated[
        str | None, Field(description="Only versions starting with this, e.g. '7.')", max_length=16)
    ] = None,
    region: Region = None,
) -> dict:
    """DescribeCacheEngineVersions: available versions with parameter group family, plus upgrade
    targets (latest minor of each major; latest Valkey when asking about Redis OSS)."""
    return server._cp(region).engine_versions(engine, version_prefix)


@server.read_tool
def aws_parameter_groups(region: Region = None) -> dict:
    """DescribeCacheParameterGroups joined with running clusters: family, which clusters use each
    group, unused custom groups (info) and groups whose family differs from the running engine (warning)."""
    return server._cp(region).parameter_groups()


@server.read_tool
def aws_service_updates(
    status: Annotated[Literal["available", "cancelled", "expired"], Field(description="Update status")] = "available",
    region: Region = None,
) -> dict:
    """DescribeServiceUpdates: pending updates by severity with apply-by and auto-update dates."""
    return server._cp(region).service_updates(status)


@server.read_tool
def aws_subnet_groups(region: Region = None) -> dict:
    """DescribeCacheSubnetGroups: VPC, subnets and AZ spread (flags groups in fewer than 2 AZs)."""
    return server._cp(region).subnet_groups()


@server.read_tool
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
    """CloudWatch AWS/ElastiCache metrics (Redis/Valkey: EngineCPUUtilization, memory %, Evictions, CacheHitRate,
    ReplicationLag; Memcached: CPU, swap, evictions, connections). Findings first, then min/avg/max/latest; raw
    series only with include_series=true."""
    return server._cp(region).metrics(
        cache_cluster_id, metrics, minutes, period_seconds, node_id, serverless, include_series, replication_group_id
    )


@server.read_tool
def aws_parameter_drift(
    group_a: Annotated[str, Field(description="First cache parameter group name (e.g. production)")],
    group_b: Annotated[str, Field(description="Second cache parameter group name (e.g. staging)")],
    region: Region = None,
) -> dict:
    """DescribeCacheParameters on two groups: only parameters whose values differ and that someone
    modified (default-only differences are counted, not listed), plus family mismatch warnings."""
    return server._cp(region).parameter_drift(group_a, group_b)


@server.read_tool
def aws_triage(
    replication_group_id: Annotated[str, Field(description="ReplicationGroupId to triage")],
    region: Region = None,
) -> dict:
    """One-call incident summary for a replication group: status, Multi-AZ/failover, 6h events, CloudWatch peaks per
    member, pending updates, snapshot age. Findings worst-first (max 30); a failing section is reported unavailable."""
    return server.control_plane().triage_fan_out(replication_group_id, region)


@server.read_tool
def aws_serverless_triage(
    serverless_cache_name: Annotated[str, Field(description="ServerlessCacheName to triage")],
    region: Region = None,
) -> dict:
    """One-call incident summary for a serverless cache: status, usage limits, snapshot health, 6h
    ThrottledCmds/ECPU/storage vs limits. Findings worst-first (max 30); a failing section is reported unavailable."""
    return server._cp(region).serverless_triage(serverless_cache_name)


@server.read_tool
def aws_shard_balance(
    replication_group_id: Annotated[str, Field(description="ReplicationGroupId to check for shard skew")],
    minutes: Annotated[int, Field(ge=5, le=20160, description="CloudWatch window in minutes")] = 60,
    region: Region = None,
) -> dict:
    """Per-shard skew from CloudWatch only (no data-plane connection). Findings first: hot shard (over 2x the median
    and above 50% CPU), memory skew, one primary pinned near 100% CPU (hot-key signature)."""
    return server._cp(region).shard_balance(replication_group_id, minutes)


@server.read_tool
def aws_snapshot_restore_readiness(
    replication_group_id: Annotated[str | None, Field(description="Replication group to check")] = None,
    serverless_cache_name: Annotated[str | None, Field(description="Serverless cache to check instead")] = None,
    stale_hours: Annotated[int, Field(ge=1, le=720, description="Flag when no automatic snapshot is newer")] = 24,
    region: Region = None,
) -> dict:
    """Can this group or serverless cache be restored? Pass exactly one id. Findings first: backups off, stale,
    expired or failed snapshot, none before an engine upgrade, KMS mismatch, snapshot too big for the target node."""
    return server._cp(region).snapshot_restore_readiness(replication_group_id, serverless_cache_name, stale_hours)


@server.read_tool
def aws_failover_readiness(
    replication_group_id: Annotated[str, Field(description="ReplicationGroupId to check")], region: Region = None
) -> dict:
    """Would a primary failure be survived? Findings first: failover or Multi-AZ off, shards without replicas,
    replicas in the primary's AZ, uneven or unavailable replicas, single-node group, recovery-risk level."""
    return server._cp(region).failover_readiness(replication_group_id)


@server.read_tool
def aws_reader_endpoint_audit(
    replication_group_id: Annotated[str, Field(description="ReplicationGroupId to check")], region: Region = None
) -> dict:
    """Are replicas usable for reads? Findings first: clients likely on the primary endpoint, no reader endpoint,
    single-replica shards, replicas in the primary's AZ, high ReplicationLag."""
    return server._cp(region).reader_endpoint_audit(replication_group_id)


@server.read_tool
def aws_scale_readiness(
    replication_group_id: Annotated[str, Field(description="ReplicationGroupId to check")], region: Region = None
) -> dict:
    """Headroom for resharding or a node-type change, from 7 days of CloudWatch. Findings first: is scale-in safe
    (projected memory per surviving shard), is scale-out advised, why a node-type change is risky (burstable
    credits, replica lag, pending modification, Multi-AZ off). Describe and GetMetricData only."""
    return server._cp(region).scale_readiness(replication_group_id)


@server.read_tool
def aws_upgrade_plan(
    replication_group_id: Annotated[str, Field(description="ReplicationGroupId to check")],
    target_engine: Annotated[
        Literal["redis", "valkey"] | None, Field(description="Default: the current engine")
    ] = None,
    target_version: Annotated[str | None, Field(description="Exact or major.minor prefix; default newest")] = None,
    snapshot_max_age_hours: Annotated[int, Field(ge=1, le=720, description="Newest snapshot must be younger")] = 24,
    region: Region = None,
) -> dict:
    """Engine upgrade pre-flight, verdict first: go or no-go plus blockers (version path, Redis to Valkey, parameter
    group family, status, failover, snapshot freshness), then caveats (ACL/TLS, quirks, service updates, window).
    An unreadable gate blocks. Describe calls only."""
    return server._cp(region).upgrade_plan(replication_group_id, target_engine, target_version, snapshot_max_age_hours)


@server.read_tool
def aws_alarms(
    replication_group_id: Annotated[
        str | None,
        Field(description="Limit to one replication group; omit to check every group, cluster and serverless cache"),
    ] = None,
    region: Region = None,
) -> dict:
    """CloudWatch alarm coverage. Findings first: alarms in ALARM, INSUFFICIENT_DATA or with actions disabled, members
    with no alarm on core metrics (CPU, memory, evictions, lag, connections, swap). partial=true if denied.
    No group id covers ELASTICACHE_REGIONS."""
    if replication_group_id:
        return server._cp(region).alarms(replication_group_id)
    return server.control_plane().alarms_fan_out(None, region)


@server.read_tool
def aws_maintenance(
    replication_group_id: Annotated[
        str | None,
        Field(description="Limit to one replication group; omit to check every cluster of every configured region"),
    ] = None,
    region: Region = None,
) -> dict:
    """Maintenance urgency. Findings first: required updates past apply-by, maintenance windows overlapping the
    snapshot window, end-of-life engines. partial=true if a call is denied. No group id covers ELASTICACHE_REGIONS."""
    return server.control_plane().maintenance_fan_out(replication_group_id, region)


@server.read_tool
def aws_cluster_overview(
    replication_group_id: Annotated[
        str | None,
        Field(description="ReplicationGroupId to summarise; omit for a fleet pass over every configured region"),
    ] = None,
    minutes: Annotated[int, Field(ge=5, le=20160, description="CloudWatch window (multiple of 5 min is fine)")] = 360,
    region: Region = None,
) -> dict:
    """One findings-first call per replication group: shards, replicas, AZ spread, failover, engine version plus
    per-node CloudWatch signals; flags outlier nodes, reader gaps, right-sizing. No group id: fleet mode."""
    if replication_group_id:
        return server._cp(region).cluster_overview(replication_group_id, minutes)
    return server.control_plane().cluster_overview_fan_out(None, minutes, region)


@server.read_tool
def aws_security_audit(
    top: Annotated[int, Field(ge=1, le=200, description="Rows of the per-resource pass/fail matrix")] = 25,
    region: Region = None,
) -> dict:
    """Fleet hardening roll-up from existing Describe data (no new IAM), Redis and Memcached. Findings first: counts
    by severity, findings by category (transit, at rest, auth, ACL, network, snapshots, patching) naming the
    resource, then a pass/fail matrix capped to `top`. A denied call is a note, partial=true."""
    return server.control_plane().security_audit_fan_out(region, top)


@server.read_tool
def aws_cost_overview(region: Region = None) -> dict:
    """Fleet cost and right-sizing, findings first: node type and count, reserved coverage, peak memory/CPU per group
    and serverless cache. Flags idle groups, oversized nodes (names the smaller node type), idle replicas,
    on-demand and non-Graviton nodes, old snapshots, uncapped serverless. All ELASTICACHE_REGIONS unless `region`."""
    return server.control_plane().cost_overview_fan_out(region)


@server.read_tool
def aws_capacity_forecast(region: Region = None) -> dict:
    """Days until memory is full across the fleet, findings first, from 14 days of DatabaseMemoryUsagePercentage
    (Serverless: BytesUsedForCache vs the storage maximum), soonest first. Under 7 days critical, under 30
    warning. All ELASTICACHE_REGIONS unless `region` is set."""
    return server.control_plane().capacity_forecast_fan_out(region)
