# mcp-elasticache-ops

Read-only MCP server for operating and monitoring Amazon ElastiCache (Valkey / Redis OSS / Memcached),
built on [FastMCP](https://gofastmcp.com). It answers the questions an on-call DBRE asks first —
*is it healthy, where is the memory, what is slow, who is connected, which keys are big or hot,
what did AWS do to the cluster* — without ever being able to change data or configuration.

Inspired by the scope of [call518/MCP-PostgreSQL-Ops](https://github.com/call518/MCP-PostgreSQL-Ops),
written from scratch for ElastiCache.

## Tools

All 17 tools are annotated `readOnlyHint=true`, `destructiveHint=false`.

**Data plane** (redis-py, talks to the node endpoint)

| Tool | What it does |
|---|---|
| `node_health` | One-shot summary: engine/version, role, memory, clients, hit ratio, evictions, findings |
| `node_info` | Raw `INFO`, optionally one section |
| `node_memory` | used/RSS/peak/dataset/overhead, maxmemory + policy, fragmentation verdict, `MEMORY STATS/DOCTOR` |
| `node_slowlog` | `SLOWLOG GET` with per-command totals; arguments beyond the key are hidden |
| `node_clients` | `CLIENT LIST` aggregated by IP, name, user and last command; idle and buffer outliers |
| `node_latency` | Client-side PING RTT percentiles + `LATENCY LATEST` |
| `node_commandstats` | Commands ranked by total CPU time (`INFO commandstats`) |
| `node_keyspace_sample` | Bounded `SCAN` sample: big keys by bytes and by element count, hot keys (LFU) or coldest keys, TTL coverage |
| `node_replication` | Role, replicas with byte lag, link status, backlog |
| `node_cluster` | Cluster mode: `CLUSTER INFO`, slots per primary, `CLUSTER SHARDS` |
| `memcached_stats` | Memcached `stats` summary (hit ratio, memory, evictions) or a raw stats group |

**Control plane** (boto3, optional)

| Tool | What it does |
|---|---|
| `aws_replication_groups` | `DescribeReplicationGroups`: status, cluster mode, node type, Multi-AZ, members/roles |
| `aws_cache_clusters` | `DescribeCacheClusters`: engine version, parameter group apply status, nodes |
| `aws_serverless_caches` | `DescribeServerlessCaches` |
| `aws_events` | `DescribeEvents`: failovers, node replacements, maintenance, snapshots |
| `aws_parameters` | `DescribeCacheParameters` (user-modified by default) |
| `aws_metrics` | CloudWatch `AWS/ElastiCache` metrics with min/avg/max summary |

Without AWS credentials or region, the `aws_*` tools return `{"unavailable": ...}` instead of failing,
so the server is useful against a plain Redis/Valkey too.

## Safety model

- Every Redis command goes through `SafeRedis`, an allowlist of read-only commands (`INFO`, `SCAN`,
  `TYPE`, `MEMORY USAGE`, `OBJECT FREQ`, `SLOWLOG GET`, `CLIENT LIST`, ...). Anything else —
  `SET`, `DEL`, `FLUSHALL`, `CONFIG SET`, `CLIENT KILL`, `EVAL`, `MULTI`, even `GET` — raises
  `ReadOnlyViolation` before it reaches the network. Values are never read.
- `KEYS` is refused; key sampling uses bounded `SCAN` with a hard cap.
- Control plane only calls `Describe*` / `GetMetricData`. Give it an IAM policy with
  `elasticache:Describe*` and `cloudwatch:GetMetricData` only.
- Passwords / AUTH tokens come from the environment or a file and are never returned by tools.

## Configuration

| Variable | Default | |
|---|---|---|
| `ELASTICACHE_HOST` | `127.0.0.1` | Primary/reader/configuration endpoint |
| `ELASTICACHE_PORT` | `6379` | |
| `ELASTICACHE_USERNAME` | | RBAC user |
| `ELASTICACHE_PASSWORD` / `ELASTICACHE_PASSWORD_FILE` | | AUTH token |
| `ELASTICACHE_TLS` | `false` | Set `true` for in-transit encryption |
| `ELASTICACHE_TLS_VERIFY` | `true` | |
| `ELASTICACHE_DB` | `0` | |
| `ELASTICACHE_TIMEOUT` | `5` | Socket timeout (s) |
| `MEMCACHED_HOST` / `MEMCACHED_PORT` | / `11211` | For `memcached_stats` |
| `AWS_REGION`, `AWS_PROFILE` | | Standard boto3 credential chain |
| `ELASTICACHE_CONTROL_PLANE` | `true` | `false` disables all `aws_*` calls |

ElastiCache notes: `CONFIG GET` is blocked by the service, so the tools fall back to the parameter group
(`aws_parameters`) where needed. `LATENCY LATEST` is empty unless `latency-monitor-threshold` is set in
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
scripts/integration.sh           # starts valkey/valkey:8-alpine (--rm, removed on exit) and runs everything
IMAGE=redis:7-alpine scripts/integration.sh
```

## License

MIT
