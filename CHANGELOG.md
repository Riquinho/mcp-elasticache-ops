# Changelog

## Unreleased (round 05)

### Added
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

## Unreleased (round 04)

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

## Unreleased (round 01)

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
