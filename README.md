# mcp-elasticache-ops

**Ask your AI assistant why your ElastiCache is slow. It can look at everything and change nothing.**

[![CI](https://github.com/ritojoao/mcp-elasticache-ops/actions/workflows/ci.yml/badge.svg)](https://github.com/ritojoao/mcp-elasticache-ops/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![MCP](https://img.shields.io/badge/MCP-server-8A2BE2)
![Read-only](https://img.shields.io/badge/access-read--only-brightgreen)

A [Model Context Protocol](https://modelcontextprotocol.io) server for Amazon ElastiCache (Valkey, Redis OSS,
Memcached), built on [FastMCP](https://gofastmcp.com). Point Claude, Cursor or any MCP client at your cluster and
get the answers an on-call engineer needs in seconds: *is it healthy, where is the memory, what is slow, who is
connected, which keys are big or hot, what did AWS do to the cluster.*

**Contents:** [Why](#why) | [Without / with](#without--with) | [Example prompts](#example-prompts) | [Quick start](#quick-start) | [Tools](#tools) | [Safety model](#safety-model) | [Configuration](#configuration)

## Why

- **Safe by construction.** Every Redis command passes an allowlist of 53 read-only commands. `SET`, `DEL`,
  `FLUSHALL`, `CONFIG SET`, `EVAL` and even `GET` are refused before they reach the network. Key values are never
  read. The AWS side only calls `Describe*`, `List*` and `GetMetricData`. Tests fail if this ever drifts.
- **Built for incidents.** `node_triage` and `aws_triage` return a worst-first list of findings in one call, so the
  model starts from the diagnosis instead of from raw `INFO` output.
- **Data plane and control plane together.** 65 tools join what Redis says (memory, slowlog, clients, replication,
  cluster slots) with what AWS says (events, CloudWatch, parameter groups, security posture), across regions.
- **Runbooks included.** Four MCP prompts walk the model through high CPU, evictions, replication lag and
  connection storms, naming the tool to call at each step and what to conclude from it.
- **Production-minded.** TLS and IAM auth, bounded `SCAN` sampling, output size caps, per-call timeouts, secrets
  never returned by any tool.

## Without / with

**Without:** you SSH to a bastion, run `redis-cli INFO`, `SLOWLOG GET`, `CLIENT LIST`, open CloudWatch, open the
events page, and stitch it together while the pager keeps ringing. Or you hand an AI agent a Redis MCP server that
can also run `FLUSHALL`.

**With:** you ask one question. The assistant calls the right read-only tools, correlates Redis and AWS, and answers
with evidence. Nothing it can call is able to write.

| | Write-capable Redis MCP servers | mcp-elasticache-ops |
|---|---|---|
| Can the model delete or overwrite keys | Yes | No, refused before the network |
| Reads key values | Often | Never |
| AWS control plane (events, CloudWatch, parameter groups) | Usually not | Yes, `Describe*` and `List*` only |
| Incident triage in one call | No | `node_triage`, `aws_triage` |
| Runbooks as MCP prompts | No | 4 |

## Example prompts

```text
Is orders-prod healthy? Check every node and the AWS side.
Why did evictions start at 14:00?
Which keys are the biggest in this cluster? Sample, do not scan everything.
Is replication lagging on any replica, and did AWS do maintenance recently?
Who is connected to the primary and is one client hogging connections?
Audit the security posture of my replication groups: encryption, auth, subnet groups.
```

## Use cases

- **On-call triage.** Get a ranked diagnosis before you open a single dashboard.
- **Capacity reviews.** Memory, evictions, hit rate and big keys across regions.
- **Safe AI access to production.** Let a team use an assistant on prod caches without a write path.
- **Audits.** Encryption, auth, parameter groups and pending maintenance in one pass.

## Why you might not want it

- It cannot fix anything. It diagnoses; you or your automation apply the change.
- It never reads key values, so it cannot answer "what is stored under this key".
- Big-key and hot-key results come from bounded `SCAN` sampling, not an exhaustive pass.
- The server must reach the cache endpoint (same VPC, VPN or tunnel). ElastiCache has no public data plane.

## What it looks like

> **You:** orders-prod is slow since 14:00. What is going on?
>
> **Assistant:** (calls `aws_triage`, `node_triage`, `node_commandstats`) Evictions started at 14:02 on shard 2
> after `maxmemory` was reached. Policy is `allkeys-lru` and one hash prefix holds most of the sampled memory.
> A maintenance event also touched the replica at 13:55. Next step: raise the node type or set a TTL on that prefix.

## Quick start

```bash
uvx --from git+https://github.com/ritojoao/mcp-elasticache-ops mcp-elasticache-ops
```

Claude Desktop / Claude Code:

```json
{
  "mcpServers": {
    "elasticache-ops": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/ritojoao/mcp-elasticache-ops", "mcp-elasticache-ops"],
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

Give the AWS profile only `elasticache:Describe*` and `cloudwatch:GetMetricData` (see
[Minimal IAM policy](#minimal-iam-policy)). Full options are in [Configuration](#configuration).

Inspired by the scope of [call518/MCP-PostgreSQL-Ops](https://github.com/call518/MCP-PostgreSQL-Ops),
written from scratch for ElastiCache.

## Tools

All 65 tools are annotated `readOnlyHint=true`, `destructiveHint=false`. The full table, with what each tool does and
the finding thresholds, is in [docs/tools.md](docs/tools.md).

- **Data plane** (`node_*`, `memcached_*`): health, triage, connectivity, memory, slowlog, clients, replication,
  cluster slots, hot slots, big and hot keys, latency, ACL and config.
- **Control plane** (`aws_*`): replication groups, events, CloudWatch metrics, parameter groups, security posture,
  serverless, snapshots, shard balance, cross-region triage.
- **Triage entry points:** `node_triage`, `node_cluster_triage` and `aws_triage` return a ranked findings list in one call.

## On-call runbooks (MCP prompts)

Five step-by-step playbooks (CPU, evictions, replication lag, connection storm, failover and restore readiness) are in [docs/runbooks.md](docs/runbooks.md).

Four prompts (not tools, the read-only tool count is unchanged) return a step-by-step runbook that chains the tools
and says what to conclude from each. Each takes `replication_group_id`.

- `oncall_high_cpu`: `aws_triage`, `aws_cluster_overview`, `node_triage`, `node_cluster_slowlog`, `node_commandstats`, `node_clients`, `aws_metrics`
- `oncall_evictions_memory`: `aws_triage`, `aws_metrics`, `node_memory`, `node_cluster_memory`, `node_keyspace_sample`, `aws_parameters`
- `oncall_replication_lag`: `aws_triage`, `aws_events`, `node_replication`, `aws_metrics`, `aws_global_replication_groups`
- `oncall_connection_storm`: `aws_triage`, `aws_metrics`, `node_clients`, `node_latency`, `node_acl_log`, `aws_alarms`

### Network allowance and auth signals

Redis nodes are checked against the four real ENA allowance metrics (`NetworkBandwidthInAllowanceExceeded`,
`NetworkBandwidthOutAllowanceExceeded`, `NetworkPacketsPerSecondAllowanceExceeded`,
`NetworkConntrackAllowanceExceeded`) plus `FreeableMemory`; each warning names the limit that was hit. The auth
metrics `AuthenticationFailures`, `CommandAuthorizationFailures` and `KeyAuthorizationFailures` raise a finding on any
sustained count and point at `node_acl_log`. All of this uses `GetMetricData` only.

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
| Pub/Sub pattern subscriptions | `PUBSUB NUMPAT` >= 100 (warning), >= 1000 (critical) in `node_pubsub` | warning / critical |
| Pub/Sub subscriber buffers | pubsub client `omem` >= 8 MiB (warning), >= 32 MiB (critical) in `node_pubsub` | warning / critical |
| Idle clients | 20 or more clients idle over an hour in `node_clients` / `node_pubsub` | info |
| No-TTL dominance | >= 90% of at least 20 sampled keys without TTL under an eviction policy (`volatile-*` warning, others info) in `node_keyspace_sample` | warning / info |
| Low hit rate | `keyspace_hits / (hits + misses)` < 80% (warning), < 50% (critical) over at least 1000 lookups in `node_keyspace_sample` | warning / critical |
| Overdue required update | `ServiceUpdateRecommendedApplyByDate` in the past for a pending update in `aws_maintenance` | critical |
| Window overlap | `PreferredMaintenanceWindow` overlaps `SnapshotWindow` in `aws_maintenance` | warning |
| Engine version | Redis OSS <= 6.x, Memcached < 1.6 (end-of-life), a Memcached version missing from `DescribeCacheEngineVersions` (retired) | warning |

## Safety model

- Every Redis command goes through `SafeRedis`, an allowlist of read-only commands (`INFO`, `SCAN`,
  `TYPE`, `MEMORY USAGE`, `OBJECT FREQ`, `SLOWLOG GET`, `CLIENT LIST`, ...). Anything else, such as
  `SET`, `DEL`, `FLUSHALL`, `CONFIG SET`, `CLIENT KILL`, `EVAL`, `MULTI`, even `GET`, raises
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
- Allowed commands (53): `ACL LOG`, `ACL USERS`, `ACL WHOAMI`, `CLIENT GETNAME`, `CLIENT ID`, `CLIENT INFO`, `CLIENT LIST`, `CLUSTER COUNTKEYSINSLOT`, `CLUSTER INFO`, `CLUSTER LINKS`, `CLUSTER MYID`, `CLUSTER NODES`, `CLUSTER SHARDS`, `CLUSTER SLOTS`, `COMMANDLOG GET`, `COMMANDLOG LEN`, `COMMAND COUNT`, `COMMAND DOCS`, `CONFIG GET`, `DBSIZE`, `EXISTS`, `HLEN`, `INFO`, `LASTSAVE`, `LATENCY DOCTOR`, `LATENCY HISTOGRAM`, `LATENCY HISTORY`, `LATENCY LATEST`, `LLEN`, `MEMORY DOCTOR`, `MEMORY STATS`, `MEMORY USAGE`, `OBJECT ENCODING`, `OBJECT FREQ`, `OBJECT IDLETIME`, `PFCOUNT`, `PING`, `PTTL`, `PUBSUB CHANNELS`, `PUBSUB NUMPAT`, `PUBSUB NUMSUB`, `PUBSUB SHARDCHANNELS`, `ROLE`, `SCAN`, `SCARD`, `SLOWLOG GET`, `SLOWLOG LEN`, `STRLEN`, `TIME`, `TTL`, `TYPE`, `XLEN`, `ZCARD`
- `CONFIG GET` exact names: `appendfsync`, `appendonly`, `client-query-buffer-limit`, `cluster-allow-reads-when-down`, `cluster-enabled`, `cluster-node-timeout`, `cluster-require-full-coverage`, `databases`, `dynamic-hz`, `hz`, `io-threads`, `lfu-decay-time`, `lfu-log-factor`, `maxclients`, `min-replicas-max-lag`, `min-replicas-to-write`, `notify-keyspace-events`, `proto-max-bulk-len`, `rdbcompression`, `repl-backlog-size`, `repl-backlog-ttl`, `repl-diskless-sync`, `replica-read-only`, `save`, `tcp-keepalive`, `timeout`
- `CONFIG GET` prefixes: `maxmemory*`, `slowlog-*`, `latency-*`, `activedefrag*`, `active-defrag-*`, `lazyfree-*`, `hash-max-*`, `list-max-*`, `set-max-*`, `zset-max-*`, `client-output-buffer-limit*`
- Always refused (self-tested never to be allowed): `ACL`, `ACL DELUSER`, `ACL GETUSER`, `ACL LIST`, `ACL LOG RESET`, `ACL SETUSER`, `AUTH`, `BGREWRITEAOF`, `BGSAVE`, `CLIENT KILL`, `CLIENT PAUSE`, `CLIENT REPLY`, `CLIENT TRACKING`, `CLIENT UNPAUSE`, `CLUSTER FAILOVER`, `CLUSTER RESET`, `COMMANDLOG`, `COMMANDLOG HELP`, `COMMANDLOG RESET`, `CONFIG RESETSTAT`, `CONFIG REWRITE`, `CONFIG SET`, `DEBUG`, `DEL`, `DUMP`, `EVAL`, `EVALSHA`, `EXEC`, `EXPIRE`, `FAILOVER`, `FCALL`, `FLUSHALL`, `FLUSHDB`, `FUNCTION`, `GET`, `HELLO`, `HGET`, `HGETALL`, `KEYS`, `LATENCY RESET`, `LRANGE`, `MEMORY PURGE`, `MGET`, `MIGRATE`, `MODULE LOAD`, `MONITOR`, `MULTI`, `OBJECT HELP`, `PSUBSCRIBE`, `PSYNC`, `PUBLISH`, `PUBSUB`, `PUBSUB HELP`, `PUBSUB SHARDNUMSUB`, `REPLICAOF`, `RESTORE`, `SAVE`, `SCRIPT`, `SCRIPT FLUSH`, `SCRIPT LOAD`, `SET`, `SHUTDOWN`, `SLAVEOF`, `SLOWLOG RESET`, `SMEMBERS`, `SORT`, `SSUBSCRIBE`, `SUBSCRIBE`, `SYNC`, `UNLINK`, `WATCH`, `XRANGE`, `XREAD`, `XREADGROUP`, `ZRANGE`
- Memcached: only `stats`, `stats settings|slabs|items|conns`, `config get cluster` and `version`.
- AWS: operation names must start with `describe_`, `list_` or `get_metric_data`.
<!-- allowlist:end -->

### Minimal IAM policy

Which tool needs which action (and which tools lose data if one action is withheld) is in [docs/iam-matrix.md](docs/iam-matrix.md), generated from the code and checked by `tests/test_iam_policy.py`; a new boto3 call missing from this policy or from the matrix fails CI.

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
        "elasticache:DescribeEngineDefaultParameters",
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
scripts/integration.ps1          # Windows: disk gate (>= 5G free), cluster up, `pytest -m integration`, then `down -v`, `image prune -f`, fstrim
scripts/cluster-integration.sh   # 3-node valkey cluster via tests/docker-compose.cluster.yml, torn down with `down -v`
```

`scripts/integration.ps1` (`-MinFreeGB`, `-Wsl:$false` for a native Docker) skips itself below the gate and always tears down in a
`finally` block; it never runs `prune -a`.

Disk gate: the integration scripts pull images and grow the WSL vhdx, so run them only with at least 5G free on the
system drive (`df -h /c`). Below that, skip integration and rely on the unit suite. CI runs the integration job
weekly (`on.schedule`) and on push, and on demand through `workflow_dispatch` or the `integration` pull-request label, so drift in the live-server tests shows up without a code change. Tests that
start Docker must remove their own containers and volumes (`--rm`, `down -v`).

The cluster test (`tests/test_dataplane_integration.py`, marker `integration`, needs `CLUSTER_TEST_HOST` and
`CLUSTER_TEST_PORT`) runs `node_cluster_nodes` and the cluster fan-out against that cluster. CI runs it in the
`cluster` job and removes the stack in an `always()` step; the `lint` job also builds the wheel and imports it in an
isolated interpreter (`python -I`).

### Generated files

`docs/iam-matrix.md` and `tests/tool_schemas.json` are generated from the code. After adding or changing a tool run

```bash
uv run python -I scripts/regen.py
```

and commit the result. The `lint` job runs the same script and fails on `git diff --exit-code` when either file is stale. The README tool table and the "All N tools" line are checked by `scripts/release-check.sh`. Engine version quirks live only in `src/mcp_elasticache_ops/quirks.py`; every entry needs a remediation and a parseable version range (`tests/test_engine_quirks.py`).

## More

[SECURITY.md](SECURITY.md) explains the read-only guarantee; [CHANGELOG.md](CHANGELOG.md) lists changes.

## License

MIT
