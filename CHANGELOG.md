# Changelog

## 0.2.0 - 2026-11-12

### Added
- Round 17 (0.2.0 cut): `dataplane.py` is now the `dataplane/` package (`_core`, `health`, `doctor`, `config_stats`,
  `keyspace`, `replication`, `topology`, `fanout`, `acl_pubsub`, `triage_report`; no module over 470 lines, every
  name re-exported; `tests/test_dataplane_package.py` pins the public and helper names and a 1300-line cap); the only
  test edit is the monkeypatch target of one triage test, now `dataplane.triage_report`; `tests/test_readonly_audit.py`
  scans every module of `controlplane/` and `dataplane/` (AST): only `describe_*`, `list_*`, `get_metric_data` and
  paginators over them on boto3 clients, no raw Redis constructor, `SafeRedis` outside `connection.py`, no wire bypass
  (`connection_pool`, `send_command`), and a new module fails until it is added to the audited list; findings-first
  contract in `tests/test_output_budget.py` runs every registered tool on the recording fake planes (top-level
  `findings`, at most 100, critical before warning before info; seven raw-view tools exempt with a stated reason,
  three legacy tools keep sentence findings); `tests/test_release.py` checks version, CHANGELOG heading and README
  count, table and registry (removing a tool from the README fails it); `scripts/integration.sh` gets a reduced
  footprint mode (one small Valkey container, no cluster) above `REDUCED_MIN_FREE_GB=2` and runs the cluster suite only
  in the full mode; `scripts/cluster-integration.sh` has its own 3G gate; `scripts/integration.ps1` mirrors both.
  Integration run on 2026-11-12 against `valkey/valkey:8-alpine` in WSL Docker: reduced mode at 4G free on C: and
  full mode at 7.2G free, both with 0 failures (1271 passed, 5 skipped without the cluster; cluster suite 4 passed,
  1 skipped), no `prova-elasticache-*` container left.
- Round 16: `controlplane.py` is now the `controlplane/` package (core plumbing, shared helpers, inventory, monitoring,
  cost, security, triage; every module under 1200 lines, all names re-exported so `server.py` and the tests import
  unchanged; the two AST scans over the former single file now walk the package); mypy in the dev group and in CI
  (`uv run mypy src`, baseline without strict, `ignore_missing_imports` for boto3/botocore/moto); `node_doctor` adds
  engine-quirk findings from `INFO` gated by the parsed engine version (Valkey 8 io-threads idle on a busy event loop,
  lazyfree backlog, dict rehash memory, replica serving stale data on a down link, Lua/functions memory with the
  functions heap only counted from 7.0); output-budget audit `tests/test_output_budget.py` calls every registered
  tool through the server layer with oversized backends and fails when a tool has no fixture. Integration gate: C:
  read 6.8G free at the start of the round and 890M at the end, so `scripts/integration.sh` exited at the gate
  (5G, unchanged) and no containers were started.
- Round 15: `node_doctor` (`MEMORY DOCTOR` / `LATENCY DOCTOR` as findings first, `not available` note when rejected,
  also a section of `node_triage`); `node_keyspace_sample(include_access=true)` access summary (cold keys, share idle
  over 7 days, eviction-risk hint; the existing `OBJECT FREQ`/`IDLETIME` reads of the sampling pipeline are kept because
  `coldest_keys_by_idle` and `hot_keys_by_lfu` depend on them, so the flag gates the summary, not the reads);
  `CLUSTER SHARDS` cross-check in `node_cluster_health` and `node_cluster_triage` (offset gaps, loading or failed
  replicas, shard without a healthy replica, `CLUSTER NODES` fallback, deduplicated against topology findings);
  `aws_capacity_forecast` (days until memory is full from 14 days of hourly metrics, one `GetMetricData` batch,
  ranked, <7 days critical, <30 warning). Tool count is now 53. Integration gate: C: showed 3.6G free (99% used) during
  the round, so the integration run was not started; `scripts/integration.sh` and `.ps1` now print the exact prune and
  `fstrim` steps when the gate trips (gate unchanged at 5G; df later read 6.9G free). Splitting `controlplane.py` into a
  package was deferred.
- Round 14: `aws_shard_balance` (per-shard CPU/memory/items/traffic skew, hot-key and hot-shard findings); failover/event correlation in `aws_triage` and `aws_serverless_triage` (category `failover-correlation`); serverless limits/throttling findings with p95 and a recommendation; `aws_parameters(diff_engine_defaults=True)` plus risky-setting findings (README IAM adds `elasticache:DescribeEngineDefaultParameters`, guarded by a README-policy test); `node_latency_events` (LATENCY LATEST/HISTORY/DOCTOR, MEMORY DOCTOR). 51 tools. Local integration run skipped: only 3.6G free on C: (gate needs 5G), docker cleanup freed 0B and fstrim is unavailable in the WSL distro; gate not weakened.
- Round 13: `node_connectivity` (staged DNS, TCP, TLS with plaintext fallback probe, PING, AUTH; stops at the first
  failure, findings first, secrets never echoed); `aws_security_audit` (fleet hardening roll-up with region fan-out:
  severity counts, findings grouped by category, capped pass/fail matrix; AccessDenied degrades to `partial`);
  `aws_cost_overview` adds an info-level Valkey savings hint (assumed list-price discount, version >= 5.0.6, never
  memcached or Valkey, no new IAM); stdio smoke test over the real transport; `py.typed`, classifiers and a wheel and
  sdist content check (no `.env*`, `.coverage`, `.lotes`, `*.pem`, `*.key`) in CI and `scripts/release-check.sh`.
  Tool count is now 49.
- Round 12: every control-plane pagination loop stops at 50 pages or on a repeated token and reports `partial` with a
  note; `memcached_discovery` (`config get cluster` joins the memcached allowlist); `aws_cost_overview`; Valkey quirks
  in data-plane findings and EOL findings only for engine redis; botocore connection errors in every `aws_*` tool
  return `error` and `hint`; integration job reachable via `workflow_dispatch` and a PR label, `integration.ps1` marks SKIPPED.
- Round 11: `node_pubsub` (`PUBSUB CHANNELS`/`NUMSUB`/`NUMPAT`/`SHARDCHANNELS` added to the `SafeRedis` allowlist with
  bounds: one glob of at most 128 chars, at most 100 channels per `NUMSUB`) reports channel and pattern-subscription
  counts, top channels by subscribers and findings for many patterns, large pubsub output buffers and idle
  subscribers, aggregated across shards in cluster mode. `node_clients` flags clients idle over an hour.
- Round 11: `node_keyspace_sample` / `node_cluster_keyspace_sample` return a TTL histogram (no TTL, < 1m, < 1h, < 1d,
  >= 1d) per prefix and per type plus the keyspace hit rate, from the existing sample and `INFO` reply (no extra
  round trips); findings for no-TTL dominance under an eviction policy and for a low hit rate.
- Round 11: `aws_maintenance` (`DescribeUpdateActions`, `DescribeServiceUpdates`, `DescribeCacheClusters`, no new IAM
  actions) flags overdue required updates, maintenance windows overlapping the snapshot window and end-of-life
  engines, with region fan-out like `aws_alarms`.
- Round 11: `node_cluster_triage` fans `node_triage` plus pub/sub out over every shard primary under one shared
  deadline, with per-node error isolation and one ranked, deduplicated findings list naming node and shard. Tool count
  is now 45.
- Round 11: `scripts/integration.ps1`, a disk-gated integration run (>= 5G free) that always ends with `down -v`,
  `image prune -f` and fstrim (never `prune -a`).
- Round 09: optional `region` argument on every `aws_*` tool (validated against a region pattern) and
  `ELASTICACHE_REGIONS` fan-out for `aws_replication_groups` / `aws_triage`; global datastore findings
  (`GlobalDatastoreReplicationLag`, secondary node type / engine version mismatch, member status); sustained-vs-spike
  analysis with `p95` and a memory trend / time-to-full hint; tags and ownership via `ListTagsForResource` (new IAM
  action `elasticache:ListTagsForResource`) in `aws_cluster_overview`, `aws_triage`, `aws_serverless_triage`; four
  on-call MCP prompts (`oncall_high_cpu`, `oncall_evictions_memory`, `oncall_replication_lag`,
  `oncall_connection_storm`).
- `aws_serverless_triage`: one-call incident summary for a serverless cache (configuration findings, snapshot health,
  `ThrottledCmds`/ECPU/storage against the usage limits), sections with per-section `unavailable` on errors such as
  `AccessDenied`, findings worst-first. Describe/GetMetricData calls only, no new IAM actions. Tool count is now 42.
- Burstable node types: `aws_cluster_overview` and `aws_triage` request `CPUCreditBalance` / `CPUCreditUsage` only for
  `cache.t*` groups and report low balance (< 20 credits warning, 0 critical) with a right-sizing hint towards a
  non-burstable type; `aws_alarms` recommends a `CPUCreditBalance` alarm for them.
- `node_health` / `node_triage` findings for fork latency (`latest_fork_usec` > 1 s warning, > 5 s critical),
  replication resync trouble (`sync_partial_err`, `sync_full` rate), `evicted_clients` and the `total_error_replies`
  share. `node_health` echoes `latest_fork_usec`, `rdb_last_bgsave_time_sec`, `sync_*`, `evicted_clients`,
  `total_error_replies`, `expired_stale_perc` and `active_defrag_running` when the engine reports them; absent
  fields (older engines) produce no finding.
- `SafeRedis` bounds expensive reads: `SCAN COUNT` <= 1000, `MEMORY USAGE SAMPLES` 1..100 (0 walks the whole key),
  `CLIENT LIST ID` <= 100 ids, `ACL LOG` count <= 128, and `COMMAND DOCS` needs a command name. The `scan_count`
  tool argument is now capped at 1000 (was 5000).
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
