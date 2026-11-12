# mcp-elasticache-ops

Read-only MCP server for operating and monitoring Amazon ElastiCache (Valkey / Redis OSS / Memcached),
built on [FastMCP](https://gofastmcp.com). It answers the questions an on-call DBRE asks first —
*is it healthy, where is the memory, what is slow, who is connected, which keys are big or hot,
what did AWS do to the cluster* — without ever being able to change data or configuration.

Inspired by the scope of [call518/MCP-PostgreSQL-Ops](https://github.com/call518/MCP-PostgreSQL-Ops),
written from scratch for ElastiCache.

## Tools

All 29 tools are annotated `readOnlyHint=true`, `destructiveHint=false`.

**Data plane** (redis-py, talks to the node endpoint)

| Tool | What it does |
|---|---|
| `node_health` | One-shot summary: engine/version, role, memory, clients, hit ratio, evictions, findings |
| `node_info` | Raw `INFO`, optionally one section; password-like fields (`masterauth`, `requirepass`, ...) are redacted |
| `node_memory` | used/RSS/peak/dataset/overhead, maxmemory + policy, fragmentation verdict, `MEMORY STATS/DOCTOR` |
| `node_config` | Allowlisted `CONFIG GET` values (never secrets) with findings: `noeviction` with a maxmemory limit, `timeout 0` with idle clients, AOF, slowlog and latency monitor off, broad keyspace events. Points at `aws_parameters` when the endpoint refuses `CONFIG` |
| `node_slowlog` | `SLOWLOG GET` with per-command totals; arguments beyond the key are hidden |
| `node_clients` | `CLIENT LIST` aggregated by IP, name, user and last command; idle and buffer outliers |
| `node_latency` | Client-side PING RTT percentiles + `LATENCY LATEST` |
| `node_commandstats` | Commands ranked by total CPU time (`INFO commandstats`) |
| `node_keyspace_sample` | Bounded `SCAN` sample: big keys by bytes and by element count, hot keys (LFU) or coldest keys, TTL coverage. Stops at `max_seconds` (default 10, hard cap 60) and returns `partial=true` |
| `node_replication` | Role, replicas with byte lag, link status, backlog |
| `node_cluster` | Cluster mode: `CLUSTER INFO`, slots per primary, `CLUSTER SHARDS` |
| `node_cluster_nodes` | `CLUSTER NODES` parsed into shards (primary, replicas, slots, failing nodes) and per-shard endpoints |
| `node_cluster_health` | Fan-out `INFO` to every node (bounded concurrency, per-node timeout): memory/ops skew, replica lag, link status, uncovered slots |
| `memcached_stats` | Memcached `stats` summary (hit ratio, memory, evictions) or a raw stats group |

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
| `aws_users` | `DescribeUsers` (RBAC): `~* +@all` access strings and users without a password; no secret material is returned |
| `aws_user_groups` | `DescribeUserGroups`: unattached groups, non-active status |
| `aws_global_replication_groups` | `DescribeGlobalReplicationGroups`: members per region, status, missing secondary |
| `aws_reserved_nodes` | `DescribeReservedCacheNodes` vs running nodes: coverage, unused and expiring reservations |
| `aws_service_updates` | `DescribeServiceUpdates`: pending updates, past or near apply-by dates |
| `aws_subnet_groups` | `DescribeCacheSubnetGroups`: AZ spread (Multi-AZ needs 2+) |
| `aws_triage` | One call per replication group: status/Multi-AZ/failover, last 6h events, CloudWatch peaks per member (EngineCPU, memory %, Evictions, ReplicationLag, CurrConnections), pending service updates, newest snapshot. Worst-first findings (max 30); a failing section is reported `unavailable` |
| `aws_parameter_drift` | Diff of two parameter groups: only modified parameters whose values differ, family mismatch, important parameters flagged |

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
  (the result says so). Use `node_cluster_nodes` for shard endpoints, or `node_cluster_health` for a fan-out.
- Control plane only calls `Describe*` / `List*` / `GetMetricData`. Give it an IAM policy with
  `elasticache:Describe*` and `cloudwatch:GetMetricData` only.
- Passwords / AUTH tokens come from the environment or a file and are never returned by tools.

### Allowlist

Generated from `safe_client.py`; the tests fail if this drifts from the code.

<!-- allowlist:start -->
- Allowed commands (41): `CLIENT GETNAME`, `CLIENT ID`, `CLIENT INFO`, `CLIENT LIST`, `CLUSTER INFO`, `CLUSTER MYID`, `CLUSTER NODES`, `CLUSTER SHARDS`, `CLUSTER SLOTS`, `COMMAND COUNT`, `COMMAND DOCS`, `CONFIG GET`, `DBSIZE`, `EXISTS`, `HLEN`, `INFO`, `LASTSAVE`, `LATENCY DOCTOR`, `LATENCY HISTORY`, `LATENCY LATEST`, `LLEN`, `MEMORY DOCTOR`, `MEMORY STATS`, `MEMORY USAGE`, `OBJECT ENCODING`, `OBJECT FREQ`, `OBJECT IDLETIME`, `PFCOUNT`, `PING`, `PTTL`, `ROLE`, `SCAN`, `SCARD`, `SLOWLOG GET`, `SLOWLOG LEN`, `STRLEN`, `TIME`, `TTL`, `TYPE`, `XLEN`, `ZCARD`
- `CONFIG GET` exact names: `appendfsync`, `appendonly`, `client-query-buffer-limit`, `cluster-allow-reads-when-down`, `cluster-enabled`, `cluster-node-timeout`, `cluster-require-full-coverage`, `databases`, `dynamic-hz`, `hz`, `io-threads`, `lfu-decay-time`, `lfu-log-factor`, `maxclients`, `min-replicas-max-lag`, `min-replicas-to-write`, `notify-keyspace-events`, `proto-max-bulk-len`, `rdbcompression`, `repl-backlog-size`, `repl-backlog-ttl`, `repl-diskless-sync`, `replica-read-only`, `save`, `tcp-keepalive`, `timeout`
- `CONFIG GET` prefixes: `maxmemory*`, `slowlog-*`, `latency-*`, `activedefrag*`, `active-defrag-*`, `lazyfree-*`, `hash-max-*`, `list-max-*`, `set-max-*`, `zset-max-*`, `client-output-buffer-limit*`
- Always refused (self-tested never to be allowed): `ACL`, `ACL GETUSER`, `ACL LIST`, `ACL SETUSER`, `AUTH`, `BGREWRITEAOF`, `BGSAVE`, `CLIENT KILL`, `CLIENT PAUSE`, `CLIENT REPLY`, `CLIENT TRACKING`, `CLIENT UNPAUSE`, `CLUSTER FAILOVER`, `CLUSTER RESET`, `CONFIG RESETSTAT`, `CONFIG REWRITE`, `CONFIG SET`, `DEBUG`, `DEL`, `DUMP`, `EVAL`, `EVALSHA`, `EXEC`, `EXPIRE`, `FAILOVER`, `FCALL`, `FLUSHALL`, `FLUSHDB`, `FUNCTION`, `GET`, `HELLO`, `HGET`, `HGETALL`, `KEYS`, `LATENCY RESET`, `LRANGE`, `MEMORY PURGE`, `MGET`, `MIGRATE`, `MODULE LOAD`, `MONITOR`, `MULTI`, `OBJECT HELP`, `PSUBSCRIBE`, `PSYNC`, `PUBLISH`, `REPLICAOF`, `RESTORE`, `SAVE`, `SCRIPT`, `SCRIPT FLUSH`, `SCRIPT LOAD`, `SET`, `SHUTDOWN`, `SLAVEOF`, `SLOWLOG RESET`, `SMEMBERS`, `SORT`, `SSUBSCRIBE`, `SUBSCRIBE`, `SYNC`, `UNLINK`, `WATCH`, `XRANGE`, `XREAD`, `XREADGROUP`, `ZRANGE`
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
        "elasticache:DescribeUsers",
        "elasticache:DescribeUserGroups",
        "elasticache:DescribeGlobalReplicationGroups",
        "elasticache:DescribeReservedCacheNodes",
        "elasticache:DescribeServiceUpdates",
        "elasticache:DescribeUpdateActions",
        "elasticache:DescribeCacheSubnetGroups",
        "cloudwatch:GetMetricData"
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
| `AWS_REGION`, `AWS_PROFILE` | | Standard boto3 credential chain |
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
```

## More

[SECURITY.md](SECURITY.md) explains the read-only guarantee; [CHANGELOG.md](CHANGELOG.md) lists changes.

## License

MIT
