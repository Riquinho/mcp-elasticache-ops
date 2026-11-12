# Changelog

## Unreleased

### Added
- `aws_serverless_snapshots` (`DescribeServerlessCacheSnapshots` + `DescribeServerlessCaches`): caches without an
  available snapshot in `stale_hours` (default 24), failed snapshots, a newest snapshot expiring within 24h, snapshots
  without a customer KMS key and unset per-cache retention; a failing cache listing degrades to `partial`.
- `aws_reserved_offerings` (opt-in, `DescribeReservedCacheNodesOfferings`): capped 1y/3y offerings for a node type and
  engine, the number of running nodes no reservation covers and the cheapest offering per term (upfront + hourly).
  Never purchases. Tool count is now 41; the IAM policy gains both Describe actions.
- `aws_cluster_overview` and `aws_triage` cross-check node AZ placement: Multi-AZ enabled with every node in one AZ,
  replicas sharing the primary's AZ while more AZs exist, subnet groups with fewer than 2 AZs (one
  `DescribeCacheSubnetGroups` call, only when a member names its subnet group).
- `node_health` / `node_triage` findings: connections vs `maxclients` (warning > 80%, critical > 95%; `CONFIG GET
  maxclients` when INFO lacks it), `mem_clients_normal` share of `used_memory`, connection churn from
  `total_connections_received` over uptime. `node_health` gains `maxclients`.
- `node_cluster_health`: per-shard replica offset lag (`master_repl_offset` vs `slave_repl_offset`), nodes whose INFO
  role contradicts `CLUSTER NODES`, a `shard_replication` summary (replica count per shard), and a top-level
  `partial_nodes` list for nodes that timed out or were not contacted.
- `scripts/release-check.sh` fails when a registered MCP tool name does not appear in the README text.
- `aws_reserved_nodes`: expiring reservations report how many matching nodes still run; a failing
  `DescribeCacheClusters` degrades to `partial` with a note instead of dropping the reservation list.
- `release-check.sh` also fails when an environment variable read in `config.py` is missing from the README; CI fails when
  `*.pyc`, `.coverage` or `.env*` files are tracked.
- `aws_engine_versions` (available versions, upgrade targets) and `aws_parameter_groups` (usage, unused custom groups,
  family mismatch); Describe calls only, no IAM change. Tool count is now 39.
- Cluster fan-out (`node_cluster_keyspace_sample`, `node_cluster_slowlog`, `node_cluster_memory`): one shared deadline
  (a shard that only gets a worker after the deadline never starts, and gets only the remaining budget otherwise),
  per-shard rows capped before merging, and a top-level `partial_nodes` list (node, status, reason).
- Replication group / standalone cluster findings for missing or failing slow-log and engine-log delivery, transit
  encryption mode `preferred` and AUTH tokens older than 365 days; views expose `data_tiering`, `network_type`,
  `ip_discovery`, `transit_encryption_mode`, `log_delivery` and `auth_token_age_days` (no new AWS calls).
- AWS calls are bounded by a botocore `Config`: `AWS_CALL_TIMEOUT_SECONDS` (default 10, connect and read) and
  `AWS_MAX_ATTEMPTS` (default 3, `standard` retry mode); user agent suffix `mcp-elasticache-ops`.
- Data-plane findings: `noeviction` at >= 85% of maxmemory (critical), failed RDB/AOF persistence, client input/output
  buffer peaks >= 16 MiB, average eviction rate since start; `node_memory` gains `findings`. Thresholds are listed in the
  README ("Finding thresholds"). `persistence` is part of the per-section `INFO` fallback.
- Memcached: evictions with a low hit ratio, evictions far below `limit_maxbytes` (slab imbalance), near-full nodes of huge
  items, auto-discovery endpoint listed in `MEMCACHED_NODES`; `aws_cache_clusters` flags Memcached < 1.6, retired
  Memcached versions (missing from `DescribeCacheEngineVersions`) and the discovery endpoint vs node endpoints.
- Failures are structured: `aws_*` errors carry a `hint` for AccessDenied, throttling and connect timeouts; node and
  Memcached connection, timeout and TLS handshake failures return `{error, message, hint}` instead of raising.
- Tests: README table and tool count must match the registry, every aws/node/memcached tool under injected failures,
  cluster-health integration test. `scripts/release-check.sh` (CHANGELOG entry for the pyproject version, README tool
  count) runs in CI.

## Earlier work: round 04

### Added
- `node_triage`: one-call snapshot (health, memory, replication, clients, failed commandstats, slowlog, latency),
  findings merged worst-first (max 30), a failing section never kills the rest.
- `aws_alarms`: CloudWatch alarm coverage (`DescribeAlarms`, read-only); IAM policy gains `cloudwatch:DescribeAlarms`.
- `memcached_cluster_stats` and `MEMCACHED_NODES`: fan-out with bounded concurrency, slab/item analysis, outlier findings.
- `node_keyspace_sample` / `node_cluster_keyspace_sample`: `prefixes` grouped by normalised key prefix, `top_prefixes`.
- `node_cluster_nodes` / `node_cluster_health`: `topology_findings` (fail/handshake/noaddr, resharding, primaries without
  replica, slot imbalance) and a `CLUSTER SHARDS` cross-check on 7.0+ with a fallback note on older engines.
- `MCP_MAX_OUTPUT_CHARS` (default 60000): every tool result is capped; lists are cut to their head, findings and
  summaries stay, `truncated`/`omitted` are set.

### Changed
- Tool count is now 37 (was 34).

## Earlier work: round 01

### Security
- `SafeRedis`: strict command parsing (no whitespace, newlines or extra tokens in command names) and a
  `CONFIG GET` allowlist; `*`, `requirepass`, `masterauth`, `tls-*` and glob patterns are refused.
- `node_info` redacts password-like fields.

### Added
- `node_cluster_nodes`, `node_cluster_health` (fan-out with bounded concurrency and per-node timeout).
- `aws_snapshots`, `aws_users`, `aws_user_groups`, `aws_global_replication_groups`, `aws_reserved_nodes`,
  `aws_service_updates`, `aws_subnet_groups` (findings first); per-group findings in `aws_replication_groups`.
- `aws_metrics`: findings, ascending series gated by `include_series`, `replication_group_id` fan-out,
  period validation (multiple of 60), chunking at 500 queries per call.
- `node_keyspace_sample`: `max_seconds` deadline (default 10, cap 60) with `partial` reporting and a cluster-mode note.
- Config: `ELASTICACHE_TLS_CA_FILE`, `ELASTICACHE_TLS_CHECK_HOSTNAME`, `ELASTICACHE_USE_IAM_AUTH`,
  `ELASTICACHE_IAM_CACHE_NAME`, `ELASTICACHE_READER_HOST`; validation of ports and timeouts.
- Tests: fake-redis unit tests for the data plane, Stubber tests for every control-plane tool, 80% coverage gate.
- CI: separate lint job, `uv build` smoke test, Memcached service, coverage.

### Changed
- Tool count is now 26 (was 17).

## 0.1.0
- Initial read-only ElastiCache ops MCP server.
