# mcp-elasticache-ops

Read-only MCP server for operating and monitoring Amazon ElastiCache (Valkey / Redis OSS / Memcached),
built on [FastMCP](https://gofastmcp.com). It answers the questions an on-call DBRE asks first —
*is it healthy, where is the memory, what is slow, who is connected, which keys are big or hot,
what did AWS do to the cluster* — without ever being able to change data or configuration.

Inspired by the scope of [call518/MCP-PostgreSQL-Ops](https://github.com/call518/MCP-PostgreSQL-Ops),
written from scratch for ElastiCache.

## Tools

All 42 tools are annotated `readOnlyHint=true`, `destructiveHint=false`.

**Data plane** (redis-py, talks to the node endpoint)

| Tool | What it does |
|---|---|
| `node_health` | One-shot summary: engine/version, role, memory, clients, hit ratio, evictions, findings |
| `node_triage` | On-call snapshot in one call: health, memory, replication, clients, failed/rejected commandstats, top-5 slowlog and latency. Findings merged worst-first (max 30) with a per-section summary; a failing section is `unavailable`, the rest still run. No extra Redis commands |
| `node_info` | Raw `INFO`, optionally one section; password-like fields (`masterauth`, `requirepass`, ...) are redacted |
| `node_memory` | used/RSS/peak/dataset/overhead, maxmemory + policy, fragmentation verdict, `findings` (memory > 90%, `noeviction` near full, fragmentation, evictions), `MEMORY STATS/DOCTOR` |
| `node_config` | Allowlisted `CONFIG GET` values (never secrets) with findings: `noeviction` with a maxmemory limit, `timeout 0` with idle clients, AOF, slowlog and latency monitor off, broad keyspace events. Points at `aws_parameters` when the endpoint refuses `CONFIG` |
| `node_slowlog` | `SLOWLOG GET` with per-command totals; arguments beyond the key are hidden |
| `node_clients` | `CLIENT LIST` aggregated by IP, name, user and last command; idle and buffer outliers |
| `node_latency` | Client-side PING RTT percentiles + `LATENCY LATEST` |
| `node_commandstats` | Commands ranked by total CPU time (`INFO commandstats`) |
| `node_keyspace_sample` | Bounded `SCAN` sample: big keys by bytes and by element count, hot keys (LFU) or coldest keys, TTL coverage, and `prefixes` (keys grouped by normalised prefix such as `user:*:cart`, with estimated bytes scaled to dbsize, % without TTL; large no-TTL prefixes are flagged under `noeviction` or memory pressure; `top_prefixes`, default 10, max 50). Stops at `max_seconds` (default 10, hard cap 60) and returns `partial=true` |
| `node_replication` | Role, replicas with byte lag, link status, backlog; findings for lagging or link-down replicas, offset gap vs the primary, `replica-read-only`, `min-replicas-to-write`, `cluster-allow-reads-when-down`. Engine-version quirks (no `CLUSTER SHARDS` before 7.0, ...) come back as `notes`, not errors |
| `node_cluster` | Cluster mode: `CLUSTER INFO`, slots per primary, `CLUSTER SHARDS` |
| `node_cluster_nodes` | `CLUSTER NODES` parsed into shards (primary, replicas, slots, failing nodes) and per-shard endpoints |
| `node_cluster_health` | Fan-out `INFO` to every node (bounded concurrency, per-node timeout): memory/ops skew, replica lag per shard (`master_repl_offset` vs `slave_repl_offset`), replicas reporting `role:master`, link status, uncovered slots; nodes that time out are listed in `partial_nodes` |
| `node_cluster_keyspace_sample` | Cluster-wide `node_keyspace_sample`: fans out to every primary (bounded concurrency, `max_seconds` split across primaries) and merges big/hot/cold keys with a `shard` label; per-shard `ok`/`partial`/`unreachable`, a dead shard never fails the call |
| `node_cluster_slowlog` | Same fan-out for `SLOWLOG GET`: merged slowest commands labelled by shard |
| `node_cluster_memory` | Same fan-out for memory: per-shard used/maxmemory/fragmentation/evictions, skew and >90% findings |
| `node_acl_log` | `ACL WHOAMI` + `ACL LOG` (optional count): auth failures and denied commands aggregated by reason and user, client info reduced and redacted, findings on bursts. `ACL LIST`, `GETUSER`, `SETUSER`, `DELUSER` and `LOG RESET` stay refused |
| `memcached_stats` | Memcached `stats` summary (hit ratio, memory, evictions; evictions are put in context of hit ratio and fill level) or a raw stats group |
| `memcached_cluster_stats` | Fan-out over `MEMCACHED_NODES` (bounded concurrency, per-node timeout), only `stats`, `stats slabs`, `stats items`. Findings first: evictions, hit-ratio outliers vs the median, item/memory imbalance, `listen_disabled_num`, connections near maxconns, slab classes evicting or out of memory, one class holding most pages, evictions with a low hit ratio, evictions far below the memory limit (slab imbalance), a near-full node of huge items, and an auto-discovery endpoint listed in `MEMCACHED_NODES`. A dead node gives `status: partial` |

**Control plane** (boto3, optional)

| Tool | What it does |
|---|---|
| `aws_replication_groups` | `DescribeReplicationGroups`: status, cluster mode, node type, Multi-AZ, members/roles |
| `aws_cache_clusters` | `DescribeCacheClusters`: engine version, parameter group apply status, nodes |
| `aws_serverless_caches` | `DescribeServerlessCaches` |
| `aws_events` | `DescribeEvents`: failovers, node replacements, maintenance, snapshots |
| `aws_parameters` | `DescribeCacheParameters` (user-modified by default) |
| `aws_metrics` | CloudWatch `AWS/ElastiCache` metrics: findings first, then min/avg/max/latest; series only with `include_series`; `replication_group_id` queries every member node |
| `aws_snapshots` | `DescribeSnapshots`: retention gaps, failed and missing automatic backups, old manual snapshots |
| `aws_serverless_snapshots` | `DescribeServerlessCacheSnapshots` + `DescribeServerlessCaches`: caches with no available snapshot in `stale_hours` (default 24), failed snapshots, newest snapshot about to expire, snapshots without a customer KMS key, unset per-cache retention; a failing cache listing degrades to `partial` |
| `aws_users` | `DescribeUsers` (RBAC): `~* +@all` access strings and users without a password; no secret material is returned |
| `aws_user_groups` | `DescribeUserGroups`: unattached groups, non-active status |
| `aws_global_replication_groups` | `DescribeGlobalReplicationGroups`: members per region, status, missing secondary. Per secondary region (max 6): `GlobalDatastoreReplicationLag` (> 1 s warning, > 10 s critical), node type or engine version that differs from the primary, members not `associated`/`available` |
| `aws_reserved_nodes` | `DescribeReservedCacheNodes` vs running nodes: coverage by exact node type and engine, unused reservations, reservations expiring with nodes still running; a failing cluster listing degrades to `partial` with the reservation list intact |
| `aws_reserved_offerings` | `DescribeReservedCacheNodesOfferings` for a `node_type` and `engine` (opt-in, capped at 20): 1y/3y offerings, uncovered running nodes and the cheapest offering per term (upfront + hourly). Never purchases |
| `aws_service_updates` | `DescribeServiceUpdates`: pending updates, past or near apply-by dates |
| `aws_subnet_groups` | `DescribeCacheSubnetGroups`: AZ spread (Multi-AZ needs 2+) |
| `aws_triage` | One call per replication group: status/Multi-AZ/failover, last 6h events, CloudWatch peaks per member (EngineCPU, memory %, Evictions, ReplicationLag, CurrConnections), pending service updates, newest snapshot. Worst-first findings (max 30); a failing section is reported `unavailable` |
| `aws_serverless_triage` | One call per serverless cache: status and usage limits, snapshot health, 6h `ThrottledCmds`, ECPU and storage against the limits. Worst-first findings (max 30); a failing section (for example `AccessDenied`) is reported `unavailable`. Describe/GetMetricData calls only |
| `aws_cluster_overview` | One findings-first call per replication group: shards, replicas per shard, AZ spread, failover, engine version joined with per-node CloudWatch (EngineCPU, memory %, ReplicationLag, Evictions, CurrConnections, NewConnections). Flags nodes above 1.5x the peer median, reader endpoint gaps and right-sizing (memory p95 < 30% and CPU p95 < 20%; data tiering for r6gd). Worst-first, bounded; `GetMetricData` denied gives `status: partial` |
| `aws_alarms` | `DescribeAlarms` (AWS/ElastiCache, paginated, optional `replication_group_id`): alarms in ALARM, INSUFFICIENT_DATA or with actions disabled, and members with no alarm on EngineCPUUtilization, DatabaseMemoryUsagePercentage, Evictions, ReplicationLag, CurrConnections, SwapUsage (plus ThrottledCmds on Serverless). Denied `DescribeAlarms` gives `partial: true` |
| `aws_engine_versions` | `DescribeCacheEngineVersions` for `redis`, `valkey` or `memcached` (optional `version_prefix`): versions with parameter group family and upgrade targets (latest minor of each major, latest Valkey for Redis OSS) |
| `aws_parameter_groups` | `DescribeCacheParameterGroups` joined with running clusters: family, users of each group, unused custom groups (info), family differing from the running engine (warning) |
| `aws_parameter_drift` | Diff of two parameter groups: only modified parameters whose values differ, family mismatch, important parameters flagged |

### Regions (global datastore, multi-region on-call)

Every `aws_*` tool takes an optional read-only `region` argument (for example `eu-west-1`, the secondary region of a global
datastore). It must look like an AWS region name (`us-east-1`, `eu-central-2`, `us-gov-west-1`); anything else is rejected.
The default is `AWS_REGION`. Credentials, timeouts and retry bounds are the same in every region, and only
`Describe*` / `List*` / `GetMetricData` calls are made.

Set `ELASTICACHE_REGIONS=us-east-1,eu-west-1` (max 8) to fan out: `aws_replication_groups` queries every listed region
and tags each group and finding with its `region` (a region that fails is listed under `region_errors`), and `aws_triage`
triages the group in the first region that holds it. Passing `region` explicitly overrides the list.

### Tags and ownership

`aws_cluster_overview`, `aws_triage` and `aws_serverless_triage` read the resource tags with `ListTagsForResource`
(read-only, at most 3 calls per tool call: the replication group, then a member cluster) and return `tags` (max 25) and
`ownership` (the `owner`, `team` and `environment`/`env` tags, keys matched case-insensitively) so the on-call person
knows whom to page. A resource with none of them gets an info finding. If the principal lacks
`elasticache:ListTagsForResource` the tool still succeeds and returns a `tags_note` instead.

`aws_replication_groups` also returns per-group findings (Multi-AZ, failover, encryption, auth, snapshots, old Redis OSS,
engine behind the newest minor, primary and replicas in one AZ). `aws_cache_clusters` adds findings for Redis OSS end of life,
parameter group family mismatch, changes pending a reboot, no TLS, no AUTH and auto minor upgrade off. `aws_serverless_caches`
flags missing usage limits, snapshots and user group; `aws_metrics` on a serverless cache compares usage with the configured limits
and gives right-sizing hints (info/warning) on node clusters.

Serverless endpoints refuse many commands (`INFO` sections, `CLUSTER NODES`, `CONFIG`). The data-plane tools detect
`*.serverless.*.cache.amazonaws.com` hosts and, on any endpoint, degrade to a note instead of an error.
Control-plane tools return `findings` first (`{"severity", "message", "resource"}`, worst first).

Without AWS credentials or region, the `aws_*` tools return `{"unavailable": ...}` instead of failing,
so the server is useful against a plain Redis/Valkey too.

### Sustained versus spike, p95 and trend

`EngineCPUUtilization`, `DatabaseMemoryUsagePercentage` and `CurrConnections` breaches are only reported at warning or
critical when at least 50% of the datapoints are above the threshold (message says `sustained (>=50% of points)`); a
shorter breach is an info finding saying `transient spike`. Every metric summary carries `p95`, the paging metrics add
`fraction_above_threshold`, and memory adds `trend` (first-quarter versus last-quarter average, with a rough
`hours_to_full` when growth is gradual). The time-to-full hint is a linear estimate: below 24 h it is a warning, else info.

## On-call runbooks (MCP prompts)

Four prompts (not tools, the read-only tool count is unchanged) return a step-by-step runbook that chains the tools
and says what to conclude from each. Each takes `replication_group_id`.

- `oncall_high_cpu`: `aws_triage`, `aws_cluster_overview`, `node_triage`, `node_cluster_slowlog`, `node_commandstats`, `node_clients`, `aws_metrics`
- `oncall_evictions_memory`: `aws_triage`, `aws_metrics`, `node_memory`, `node_cluster_memory`, `node_keyspace_sample`, `aws_parameters`
- `oncall_replication_lag`: `aws_triage`, `aws_events`, `node_replication`, `aws_metrics`, `aws_global_replication_groups`
- `oncall_connection_storm`: `aws_triage`, `aws_metrics`, `node_clients`, `node_latency`, `node_acl_log`, `aws_alarms`

### Finding thresholds

Fixed, bounded thresholds (not configurable) behind the data-plane findings that `node_health`, `node_triage`
and `node_memory` emit:

| Finding | Threshold | Severity |
|---|---|---|
| Memory near the limit | `used_memory / maxmemory` > 90% | critical |
| `noeviction` close to OOM | `maxmemory-policy` is `noeviction` and usage >= 85% | critical |
| Fragmentation | `mem_fragmentation_ratio` > 1.5 (high) or < 1.0 with data (swapping) | warning |
| Evictions | `evicted_keys` > 0; the message adds the average per minute since start | warning |
| Failed persistence | `rdb_last_bgsave_status` or `aof_last_write_status` not `ok` | warning |
| Fork latency | `latest_fork_usec` > 1 s (warning), > 5 s (critical): the main thread blocks while forking for a save or resync | warning / critical |
| Replication resync trouble | `sync_partial_err` > 0, or `sync_full` >= 3 at >= 1 per hour of uptime (after 10 minutes) | warning |
| Client eviction | `evicted_clients` > 0 (`maxmemory-clients` reached; Redis 7.0+/Valkey) | warning |
| Error replies | `total_error_replies` > 5% of `total_commands_processed` (at least 1000 commands) | warning |
| Burstable CPU credits | `CPUCreditBalance` minimum < 20 credits (warning) or 0 (critical) on `cache.t*` nodes in `aws_cluster_overview` / `aws_triage`, with a right-sizing hint towards a non-burstable type; `CPUCreditBalance` is also in the recommended alarms for `cache.t*` groups | warning / critical |
| Replica link down | `master_link_status` not `up` on a replica | critical |
| Large client buffers | `client_recent_max_output_buffer` or `..._input_buffer` >= 16 MiB; per client `omem + qbuf` >= 10 MiB in `node_triage` | warning |
| Connection pressure | `connected_clients / maxclients` > 80% (warning), > 95% (critical); `maxclients` from INFO or `CONFIG GET` | warning / critical |
| Client buffer memory | `mem_clients_normal` >= 8 MiB and > 10% of `used_memory` | warning |
| Connection churn | `total_connections_received / uptime` >= 20 per second after 10 minutes of uptime (missing pooling) | warning |
| Memcached evictions, low hit ratio | evictions > 0, hit ratio < 80% over at least 100 gets | warning |
| Memcached evictions below limit | evictions > 0 while `bytes` < 70% of `limit_maxbytes` | warning |
| Memcached huge items | node >= 90% full with an average item of 256 KiB or more | info |
| Log delivery | Redis/Valkey without an active `slow-log` delivery (warning) or `engine-log` (info); a delivery in `error` or `disabling` (warning) | warning / info |
| Transit encryption mode | `TransitEncryptionEnabled` with `TransitEncryptionMode` `preferred` (plaintext still accepted) | warning |
| AUTH token age | `AuthTokenLastModifiedDate` older than 365 days | info |
| Engine version | Redis OSS <= 6.x, Memcached < 1.6 (end-of-life), a Memcached version missing from `DescribeCacheEngineVersions` (retired) | warning |

## Safety model

- Every Redis command goes through `SafeRedis`, an allowlist of read-only commands (`INFO`, `SCAN`,
  `TYPE`, `MEMORY USAGE`, `OBJECT FREQ`, `SLOWLOG GET`, `CLIENT LIST`, ...). Anything else —
  `SET`, `DEL`, `FLUSHALL`, `CONFIG SET`, `CLIENT KILL`, `EVAL`, `MULTI`, even `GET` — raises
  `ReadOnlyViolation` before it reaches the network. Values are never read.
- `KEYS` is refused; key sampling uses bounded `SCAN` with a hard cap.
- `CONFIG GET` is allowed only for an explicit set of non-sensitive parameters (`maxmemory*`, `slowlog-*`,
  `latency-*`, `maxclients`, ...). `*`, `requirepass`, `masterauth`, `tls-*` and glob patterns are refused.
  Command names with extra tokens or whitespace are rejected, so a subcommand cannot be smuggled in.
- `node_info` redacts password-like fields; `node_slowlog` hides arguments unless `include_args=true`.
- `node_keyspace_sample` only inspects the connected node: in cluster mode that is only its own slots
  (the result says so). Use `node_cluster_keyspace_sample`, `node_cluster_slowlog` and `node_cluster_memory`
  for the whole cluster, or `node_cluster_nodes` / `node_cluster_health` for topology and a fan-out `INFO`.
  Fan-out clients are built by `connection.build_client` and are `SafeRedis` too; a test fails if any module
  creates a bare `redis.Redis`. Arguments of `MEMORY USAGE`, `SCAN`, `CLIENT LIST`, `OBJECT` and `ACL LOG` are validated.
- Control plane only calls `Describe*` / `List*` / `GetMetricData`. Give it an IAM policy with
  `elasticache:Describe*` and `cloudwatch:GetMetricData` only.
- Passwords / AUTH tokens come from the environment or a file and are never returned by tools.

### Allowlist

Generated from `safe_client.py`; the tests fail if this drifts from the code.

<!-- allowlist:start -->
- Allowed commands (43): `ACL LOG`, `ACL WHOAMI`, `CLIENT GETNAME`, `CLIENT ID`, `CLIENT INFO`, `CLIENT LIST`, `CLUSTER INFO`, `CLUSTER MYID`, `CLUSTER NODES`, `CLUSTER SHARDS`, `CLUSTER SLOTS`, `COMMAND COUNT`, `COMMAND DOCS`, `CONFIG GET`, `DBSIZE`, `EXISTS`, `HLEN`, `INFO`, `LASTSAVE`, `LATENCY DOCTOR`, `LATENCY HISTORY`, `LATENCY LATEST`, `LLEN`, `MEMORY DOCTOR`, `MEMORY STATS`, `MEMORY USAGE`, `OBJECT ENCODING`, `OBJECT FREQ`, `OBJECT IDLETIME`, `PFCOUNT`, `PING`, `PTTL`, `ROLE`, `SCAN`, `SCARD`, `SLOWLOG GET`, `SLOWLOG LEN`, `STRLEN`, `TIME`, `TTL`, `TYPE`, `XLEN`, `ZCARD`
- `CONFIG GET` exact names: `appendfsync`, `appendonly`, `client-query-buffer-limit`, `cluster-allow-reads-when-down`, `cluster-enabled`, `cluster-node-timeout`, `cluster-require-full-coverage`, `databases`, `dynamic-hz`, `hz`, `io-threads`, `lfu-decay-time`, `lfu-log-factor`, `maxclients`, `min-replicas-max-lag`, `min-replicas-to-write`, `notify-keyspace-events`, `proto-max-bulk-len`, `rdbcompression`, `repl-backlog-size`, `repl-backlog-ttl`, `repl-diskless-sync`, `replica-read-only`, `save`, `tcp-keepalive`, `timeout`
- `CONFIG GET` prefixes: `maxmemory*`, `slowlog-*`, `latency-*`, `activedefrag*`, `active-defrag-*`, `lazyfree-*`, `hash-max-*`, `list-max-*`, `set-max-*`, `zset-max-*`, `client-output-buffer-limit*`
- Always refused (self-tested never to be allowed): `ACL`, `ACL DELUSER`, `ACL GETUSER`, `ACL LIST`, `ACL LOG RESET`, `ACL SETUSER`, `AUTH`, `BGREWRITEAOF`, `BGSAVE`, `CLIENT KILL`, `CLIENT PAUSE`, `CLIENT REPLY`, `CLIENT TRACKING`, `CLIENT UNPAUSE`, `CLUSTER FAILOVER`, `CLUSTER RESET`, `CONFIG RESETSTAT`, `CONFIG REWRITE`, `CONFIG SET`, `DEBUG`, `DEL`, `DUMP`, `EVAL`, `EVALSHA`, `EXEC`, `EXPIRE`, `FAILOVER`, `FCALL`, `FLUSHALL`, `FLUSHDB`, `FUNCTION`, `GET`, `HELLO`, `HGET`, `HGETALL`, `KEYS`, `LATENCY RESET`, `LRANGE`, `MEMORY PURGE`, `MGET`, `MIGRATE`, `MODULE LOAD`, `MONITOR`, `MULTI`, `OBJECT HELP`, `PSUBSCRIBE`, `PSYNC`, `PUBLISH`, `REPLICAOF`, `RESTORE`, `SAVE`, `SCRIPT`, `SCRIPT FLUSH`, `SCRIPT LOAD`, `SET`, `SHUTDOWN`, `SLAVEOF`, `SLOWLOG RESET`, `SMEMBERS`, `SORT`, `SSUBSCRIBE`, `SUBSCRIBE`, `SYNC`, `UNLINK`, `WATCH`, `XRANGE`, `XREAD`, `XREADGROUP`, `ZRANGE`
- Memcached: only `stats`, `stats settings|slabs|items|conns` and `version`.
- AWS: operation names must start with `describe_`, `list_` or `get_metric_data`.
<!-- allowlist:end -->

### Minimal IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "elasticache:DescribeReplicationGroups",
        "elasticache:DescribeCacheClusters",
        "elasticache:DescribeServerlessCaches",
        "elasticache:DescribeEvents",
        "elasticache:DescribeCacheParameters",
        "elasticache:DescribeCacheParameterGroups",
        "elasticache:DescribeCacheEngineVersions",
        "elasticache:DescribeSnapshots",
        "elasticache:DescribeServerlessCacheSnapshots",
        "elasticache:DescribeUsers",
        "elasticache:DescribeUserGroups",
        "elasticache:DescribeGlobalReplicationGroups",
        "elasticache:DescribeReservedCacheNodes",
        "elasticache:DescribeReservedCacheNodesOfferings",
        "elasticache:DescribeServiceUpdates",
        "elasticache:DescribeUpdateActions",
        "elasticache:DescribeCacheSubnetGroups",
        "elasticache:ListTagsForResource",
        "cloudwatch:GetMetricData",
        "cloudwatch:DescribeAlarms"
      ],
      "Resource": "*"
    }
  ]
}
```

## Configuration

| Variable | Default | |
|---|---|---|
| `ELASTICACHE_HOST` | `127.0.0.1` | Primary/reader/configuration endpoint |
| `ELASTICACHE_PORT` | `6379` | |
| `ELASTICACHE_USERNAME` | | RBAC user |
| `ELASTICACHE_PASSWORD` / `ELASTICACHE_PASSWORD_FILE` | | AUTH token |
| `ELASTICACHE_TLS` | `false` | Set `true` for in-transit encryption |
| `ELASTICACHE_TLS_VERIFY` | `true` | `false` disables certificate and hostname checks |
| `ELASTICACHE_TLS_CA_FILE` | | CA bundle used to verify the endpoint (must exist) |
| `ELASTICACHE_TLS_CHECK_HOSTNAME` | `true` | Keep certificate validation but skip hostname matching |
| `ELASTICACHE_USE_IAM_AUTH` | `false` | IAM authentication: needs TLS, `ELASTICACHE_USERNAME`, `ELASTICACHE_IAM_CACHE_NAME`; no password. Tokens are signed locally and refreshed on reconnect |
| `ELASTICACHE_IAM_CACHE_NAME` | | Replication group id or serverless cache name used to sign the IAM token |
| `ELASTICACHE_READER_HOST` | | Reader endpoint (reserved for read-side checks) |
| `ELASTICACHE_DB` | `0` | |
| `ELASTICACHE_TIMEOUT` | `5` | Socket timeout (s), must be greater than 0 |
| `MEMCACHED_HOST` / `MEMCACHED_PORT` | / `11211` | For `memcached_stats` |
| `MEMCACHED_NODES` | | Comma-separated `host:port` list (max 64, IPv6 as `[::1]:11211`) for `memcached_cluster_stats`; invalid entries stop startup |
| `MCP_MAX_OUTPUT_CHARS` | `60000` | Cap on any tool result (JSON characters, 1000 to 5000000). Longer lists are cut to their head; `findings`, `summary`, `notes` and counts stay; the result gets `truncated=true`, `omitted` and a hint |
| `AWS_REGION` (or `AWS_DEFAULT_REGION`), `AWS_PROFILE` | | Standard boto3 credential chain |
| `ELASTICACHE_REGIONS` | | Comma-separated regions (max 8) that `aws_replication_groups` and `aws_triage` fan out over; the `region` tool argument overrides it |
| `AWS_CALL_TIMEOUT_SECONDS` | `10` | Connect and read timeout for every AWS API call (greater than 0, at most 120) |
| `AWS_MAX_ATTEMPTS` | `3` | Attempts per AWS call, botocore `standard` retry mode (1 to 10) |
| `ELASTICACHE_CONTROL_PLANE` | `true` | `false` disables all `aws_*` calls |

Invalid values (non-numeric or out-of-range port, timeout <= 0, missing CA file, incomplete IAM settings) stop startup
with a clear error.

ElastiCache notes: `CONFIG GET` is restricted by the service and this server allows only a small allowlist of it,
so the tools fall back to the parameter group (`aws_parameters`) where needed. `LATENCY LATEST` is empty unless `latency-monitor-threshold` is set in
the parameter group. Hot keys need an `*-lfu` `maxmemory-policy`.

## Run

```bash
uv sync
uv run mcp-elasticache-ops                         # stdio
uv run mcp-elasticache-ops --transport http --port 8000
```

Claude Desktop / Claude Code:

```json
{
  "mcpServers": {
    "elasticache-ops": {
      "command": "uv",
      "args": ["--directory", "/path/to/mcp-elasticache-ops", "run", "mcp-elasticache-ops"],
      "env": {
        "ELASTICACHE_HOST": "my-rg.xxxxxx.ng.0001.use1.cache.amazonaws.com",
        "ELASTICACHE_TLS": "true",
        "AWS_REGION": "us-east-1",
        "AWS_PROFILE": "readonly"
      }
    }
  }
}
```

## Tests

```bash
uv run pytest -q                 # unit tests; control plane uses moto + botocore Stubber, never real AWS
uv run pytest -q --cov=mcp_elasticache_ops   # 80% coverage gate (about 93% without a live server)
scripts/integration.sh           # starts valkey/valkey:8-alpine (--rm, removed on exit) and runs everything
IMAGE=redis:7-alpine scripts/integration.sh
scripts/cluster-integration.sh   # 3-node valkey cluster via tests/docker-compose.cluster.yml, torn down with `down -v`
```

The cluster test (`tests/test_dataplane_integration.py`, marker `integration`, needs `CLUSTER_TEST_HOST` and
`CLUSTER_TEST_PORT`) runs `node_cluster_nodes` and the cluster fan-out against that cluster. CI runs it in the
`cluster` job and removes the stack in an `always()` step; the `lint` job also builds the wheel and imports it in an
isolated interpreter (`python -I`).

## More

[SECURITY.md](SECURITY.md) explains the read-only guarantee; [CHANGELOG.md](CHANGELOG.md) lists changes.

## License

MIT
