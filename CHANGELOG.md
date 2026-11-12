# Changelog

## Round 48

Round 48. Tool count unchanged.

### Added
- `tests/test_readonly_sweep.py`: every registered tool runs through the recording `AuditRedis` and `AwsAudit` fakes.
  It asserts that each Redis command is in `READ_ONLY_COMMANDS`, that each AWS operation is `Describe*`, `List*` or
  `GetMetricData`, and that no write-named operation was issued. A self-test shows the checker rejects `SET` and
  `ModifyCacheCluster`.
- `tests/test_iam_coverage.py`: AST scan of the boto3 calls in `src/mcp_elasticache_ops/controlplane/`. Each operation
  must appear in `tests/iam_actions.json` and must carry a read-only prefix.
- `tests/test_regen_check.py`: `scripts/regen.py --check` runs against a copy of the repo with a stale file, and must
  exit 1 and leave the tree unchanged.

### Changed
- `scripts/regen.py --check` is read-only. It regenerates inside a temporary copy of the repo, compares the two
  generated files with the tree, exits 1 on a difference and writes nothing into the repo.
- `tests/test_server.py` `AUDIT_CALLS` adds `aws_parameters` with `diff_engine_defaults=True`. That path calls
  `DescribeEngineDefaultParameters` and was missing from the IAM pin. The pin and `docs/iam-matrix.md` were regenerated.

### Verified
- `uv run ruff check .`, `uv run ruff format --check .` and `uv run pytest -q` pass: 2160 passed, 24 skipped.
- `scripts/integration.sh` in full cluster mode (6.4G free on C:) exits 0: 2177 passed, 7 skipped for the single
  container, then 6 passed, 2 skipped for the 3-primary cluster. The first two attempts failed on the local port
  relay (ECONNREFUSED on 127.0.0.1:16379) and WSL was not reachable for a time because `ext4.vhdx` was locked; the
  third run was clean. Its containers and volumes were removed by the script's trap and `down -v`.
- Not touched: `prova-ghost-1805` (a `golang:1.26` container from another session) still shows in
  `docker ps -a --filter name=prova-`. Named volumes `gocache-agente-fix`, `gomodcache`, `stackops-*` were left alone.

## Round 45 (0.3.0)

Round 45. Tool count unchanged at 65.

### Verified
- Integration against Valkey 8 (`valkey/valkey:8-alpine`, WSL Docker): `scripts/integration.sh` exits 0 with 2167 passed
  and 7 skipped. It ran in reduced-footprint mode (2G free, below the 5G full gate): one container, no cluster run.
  Full-mode and cluster integration are still pending: C: has 2.7G free, `fstrim` is missing in the WSL distro, and
  freeing more space needs the user's OK (named volumes or vhdx compaction).
- Wheel 0.3.0 built with `uv build`. A clean venv install lists 65 tools, matching `tests/tool_schemas.json`.

### Fixed
- `scripts/regen.py` regenerated `docs/iam-matrix.md` and `tests/tool_schemas.json`. The committed snapshot was missing
  `aws_global_datastore_failover_readiness`, which CI's drift check would have flagged.

## Round 44 (0.3.0)

Round 44. Tool count unchanged at 65.

### Added
- Skip-budget gate: `tests/skip_budget.txt` holds the skip ceiling (24). `scripts/check-skip-budget.py junit.xml` fails
  when the junit report has more skips than the ceiling. The CI test job runs `pytest -rs` and calls the checker after
  the pass-floor check. Covered by `tests/test_skip_budget.py`.
- `tests/test_replica_cluster_coverage.py`: a hung shard in cluster fan-out gives a partial result with a findings
  line (`shard <ep> unreachable: no answer within the time budget`) while the other shards' answers survive; reader
  endpoint names classify as `reader`; writes, `READONLY` and `READWRITE` are refused by the allowlist; no allowlisted
  command is a write or a connection-mode switch. Mutating the timeout branch in `dataplane/fanout.py` makes two of
  these tests fail (checked, then reverted).

### Changed
- Generated files regenerated (`scripts/regen.py`): `aws_global_datastore_failover_readiness` was missing from
  `docs/iam-matrix.md` and `tests/tool_schemas.json`, left stale by round 41.
- `tests/pass_floor.txt` raised to the new passing count.

### Not run
- Docker integration (`scripts/integration.sh`) was skipped: `C:` had 2.7 GB free, below the 5 GB needed. Pruning
  untagged images and build cache older than 24 h freed nothing. Only a broader prune or a vhdx compaction (both need
  the user's OK) would free enough space.
- `prova-ghost-1805` (image `golang:1.26`, not created by this repo's scripts) is running in the WSL Docker daemon. It
  was left alone, so the `prova-` filter check is not empty.

## Round 41 (0.3.0)

Round 41. 65 tools (one new tool, `aws_global_datastore_failover_readiness`).

### Added
- `aws_global_datastore_failover_readiness` (`controlplane/inventory.py`, `controlplane/inventory_views.py`): read-only
  failover readiness per Global Datastore from `DescribeGlobalReplicationGroups`, `DescribeReplicationGroups`,
  `DescribeCacheClusters` and CloudWatch `GlobalDatastoreReplicationLag`. Findings first (worst first). Flags a lagging
  secondary (warning at 1 s, critical at 10 s), engine or node mismatch, and a secondary that is associating or
  disassociated. No new IAM actions beyond those already in `docs/iam-matrix.md`.
- `limit_reply` also caps mappings (`TruncatedDict`, `truncated` and `total`). `node_doctor` (MEMORY DOCTOR),
  `node_info` (INFO), `node_slowlog`, `node_clients`, the keyspace sample and `server_info` report a cut reply: the
  text says `reply cut at N characters by the read-only client guard`, and the other outputs carry `truncated`/`total`.
- Tests: `tests/test_global_datastore.py` (15 tests), reply-truncation consumer tests in
  `tests/test_reply_truncation.py`, and reserved-node cross-check tests in `tests/test_cost_overview.py`.

### Changed
- `aws_cost_overview` idle and oversized findings name the reservation when the group's nodes are covered by one, and
  point to `aws_reserved_nodes` before any downsize or delete. Before this, the advice could contradict the reserved-node
  output.
- `tests/test_tool_surface.py` byte budget raised from 54_000 to 55_000: 65 tools measure 54_734 bytes with the new
  tool, and the budget leaves headroom for descriptions to grow.

### Verification
- Mutation check on `limit_reply` (replaced by `return reply`): 11 reply-truncation tests fail; restored and green.
- Mutation check on the reserved-node cross-check: 2 cost-overview tests fail; restored and green.
- Docker integration against Valkey 8 skipped: 2.8 GB free on C: is under the 5 GB floor.

## Round 38 (0.3.0)

Round 38. Still 64 tools; no new tool this round.

### Added
- Reply-truncation coverage (`tests/test_reply_truncation.py`): huge-reply fakes for `limit_reply`, pipelines,
  `client_summary` and `commandlog`; every cut reply is reported as `truncated`.
- Reserved-node boundary tests (`tests/test_cost_overview.py`): expiry at 29, 30, 60, 89 and 90 days, and an
  uncovered node type next to a reserved one. Runbook 6 notes the reservation check before a node-type change.
- 200-user budget test (`tests/test_security_rbac.py`) for `aws_user_access_map`.

### Changed
- `aws_user_access_map` caps each group row at 10 users and 10 attached caches (with `users_more` and
  `replication_groups_more` counts), shows 15 group rows, and says `trimmed N finding(s) and M map row(s)` in
  `notes` plus a `trimmed` object.
- `SafePipeline.execute` runs every pipelined reply through `limit_reply`. `node_commandlog` sections and the
  keyspace sample carry `truncated: true` when a reply was cut.

## Round 28 additions to 0.3.0

Round 28. 64 tools (one new tool, `aws_user_access_map`).

### Added
- `aws_user_access_map` (`controlplane/security.py`): read-only RBAC join of `DescribeUsers`, `DescribeUserGroups`
  and the replication groups, serverless caches and Memcached clusters that use each group (no new IAM actions beyond
  `Describe*`). Findings first, each with `resource`, `category`, `next`.

### Changed
- `MAX_TOOLS_LIST_BYTES` raised from 53_400 to 54_000: the 64th tool (measured 53_804).

## Round 27 additions to 0.3.0

Round 27. 63 tools (one new tool, `aws_replication_group_audit`).

### Added
- `aws_replication_group_audit` (`controlplane/group_audit.py`, `inventory.py`): per-group posture from
  `DescribeReplicationGroups` and `DescribeCacheClusters` (no new IAM actions): Multi-AZ, automatic failover, zero
  replicas, single-AZ replicas, big node without cluster mode, auto minor upgrade, no snapshots, log delivery,
  encryption mix, network type. Capped at 60 findings, each with `resource`, `category`, `next`.
- Log delivery (`_shared.log_delivery_findings`): slow-log and engine-log missing (warning / info), failing status
  (warning) and split destination types (info), in `aws_triage`, `aws_replication_groups` and the group audit.
  Pointers to `node_slowlog` / `node_commandlog`. Serverless is not judged: the API does not expose log delivery.
- Memcached depth (`memcached.py`): slab calcification warning, eviction-rate finding, `accepting_conns` critical,
  `reclaimed` / `get_hits` in `node_report`, `NumCacheNodes` vs discovered node count mismatch warning.
- `tests/test_findings_pointers.py`: cross-tool pointer contract (severity vocabulary, ordering, actionable findings, every
  referenced tool exists); legacy state-describing findings are grandfathered in an explicit, ratcheted list.

### Changed
- `MAX_TOOLS_LIST_BYTES` raised from 52_300 to 53_400: the 63rd tool (measured 53_069).
- Log delivery went into `aws_triage`, not `aws_security_audit`: a new category there breaks the category-order test.

Integration: skipped. `df -h /c` showed 4.4G free (under the 5G floor).

## Round 26 additions to 0.3.0

Round 26. 62 tools (one new tool, `aws_backup_audit`).

### Added
- `aws_backup_audit` (`controlplane/restore.py`, `inventory.py`): fleet-wide backup hygiene from
  `DescribeReplicationGroups`, `DescribeCacheClusters` and `DescribeSnapshots` (no new IAM actions). Findings:
  retention off, stale latest automatic snapshot, latest failed, old manual snapshots (aggregated, with size) and
  orphan snapshots of deleted sources. Capped at 40 findings. Tests in `tests/test_backup_audit.py`.
- Memory breakdown (`dataplane/memory_breakdown.py`): one `memory-breakdown` warning in `node_memory`, `node_doctor`,
  `node_triage` and `node_cluster_triage` when allocator fragmentation, hashtable or client and replication buffers
  are large (`MEMORY STATS`, `INFO` fallback; silent under 32 MiB). Tests in `tests/test_memory_breakdown.py`.
- Serverless right-sizing in `aws_cost_overview`: ECPU and storage near-limit, over-limit, tight and over-provisioned
  findings, and an `idle` cost hint stating the billed floor in GB-hours (not dollars). Same single `GetMetricData`
  call. Tests in `tests/test_serverless_cost.py`.
- `aws_security_audit` RBAC hygiene: non-default user with `+@all`, IAM-auth user on a cache without TLS in transit,
  user in no group, group attached to no cache. Tests in `tests/test_security_rbac.py`.

### Changed
- `MAX_TOOLS_LIST_BYTES` raised from 51_200 to 52_300 in `tests/test_tool_surface.py`: the 62nd tool adds its schema
  and description to `tools/list` (measured 52_253 before trimming the docstring).
- `MEMORY STATS` was already on the SafeRedis allowlist; the audited fake now answers it with a dict.

Integration: `scripts/integration.sh` ran with 5.2G free on `/c` (full mode): 1931 passed, 7 skipped. Own `prova-elasticache-*` containers removed; dangling volumes, untagged images and old build cache pruned (`fstrim` not available in the WSL distro).

## Round 25 additions to 0.3.0

Round 25. 61 tools (no new tool; existing tools gain findings).

### Added
- Data tiering (r6gd): `DatabaseCapacityUsagePercentage` is read for tiered groups in `aws_metrics`, `aws_triage` and
  `aws_capacity_forecast`. Memory percentage understates fullness there (memory plus SSD); critical above 90, warning
  above 80, plus a warning when memory max is under 50. Forecast falls back to memory when no capacity data exists.
  Tests in `tests/test_data_tiering.py`.
- `aws_alarms` quality audit (`controlplane/alarm_quality.py`): no actions, missing-data not breaching, threshold that
  never fires, slow evaluation, host CPU instead of EngineCPU, wrong or missing dimension. Tests in
  `tests/test_alarm_quality.py`.
- `aws_shard_balance`: `replica-lag-outlier` finding from `ReplicationLag` (ratio 3x median and at least 1 s, at most 3
  reported). Tests in `tests/test_shard_outliers.py`.
- `aws_maintenance`: transport hygiene findings (TLS off, auth token age). No CA rule: the botocore model has no
  certificate field. Tests in `tests/test_tls_hygiene.py`.

### Changed
- Tree hygiene: stale `__pycache__` removed locally (none tracked); tool-count consistency pinned by
  `tests/test_surface_pin.py`.

## Round 24 additions to 0.3.0

Round 24. 61 tools.

### Added
- `aws_reader_endpoint_audit`: replicas against reader-endpoint use, from `DescribeReplicationGroups`,
  `DescribeCacheClusters` and a 1-hour `ReplicationLag` read (no new IAM actions). Findings: clients likely on the
  primary endpoint (info, a pointer: describe data cannot show client config), no reader endpoint, single-replica
  shards, replicas in the primary's AZ, replicas not available, high replica lag. Rules in
  `controlplane/failover.py`; tests in `tests/test_reader_endpoint.py`.
- `aws_parameter_groups` settings audit (`audit_settings`, default on): `DescribeCacheParameters` with `Source=user`
  for in-use custom redis/valkey groups (all custom groups when the cluster listing is unavailable), at most 25
  groups, stops with a partial note on the first denial. Rules in `quirks.PARAM_RULES` (noeviction, short timeout,
  tcp-keepalive 0, cluster-require-full-coverage, reserved-memory-percent low or unset, lazyfree off, replica-lazy-flush
  off, slowlog threshold too high); each finding names group, parameter, value and recommended value. Tests in
  `tests/test_parameter_groups.py`. `aws_parameter_groups` now also needs `DescribeCacheParameters` and
  `DescribeCacheEngineVersions` (already in the policy).
- `node_cluster_triage`: explicit "reached N/M nodes" for the COMMANDLOG and CLUSTER LINKS fan-out, with failure-mode
  tests (aggregation, hanging node, shard down, pre-Valkey-8 node).
- Real Valkey 8 integration tests for COMMANDLOG (large-request and large-reply with the size thresholds lowered,
  restored afterwards), LATENCY HISTOGRAM and CLUSTER LINKS (standalone note, 3-primary cluster links, cluster triage
  "reached 3/3"). A test skips only when the server version lacks the command, and the skip message names the
  command, the version found and the version needed. Result: `scripts/integration.sh` 1830 passed, 7 skipped
  (the skips are the cluster-only tests, run by the cluster stage: 6 passed there); free disk on `C:` was 5.2G before
  and after; no `prova-*` containers left, no dangling volumes. `fstrim` is not installed in the WSL distro, so it
  was not run. Offline suite: 1813 passed; `tests/pass_floor.txt` set to 1813.
- 0.4.0 is not cut: rounds 21-24 stay under "additions to 0.3.0" until a release is decided.
- `tools/list` byte budget raised from 50_500 to 51_200 for the 61st tool (docstring already trimmed).

## Round 23 additions to 0.3.0

Round 23. 60 tools.

### Added
- `node_commandlog`: Valkey 8 `COMMANDLOG` (`slow`, `large-request`, `large-reply`) as findings first, with top
  commands and client addresses. Arguments and values are never returned. Older engines get a note. Also a section of
  `node_doctor`.
- `node_latency` and `node_triage`: per-command p50/p99/p99.9 from `LATENCY HISTOGRAM` (busiest 8 commands, bucket
  upper bounds) and a warning when p99.9 is 100x the p50 and at least 1 ms.
- `node_cluster_health` and `node_cluster_triage`: `CLUSTER LINKS` send-buffer pressure (warning 16 MiB, critical
  128 MiB) and a finding for a node with no link to a peer. Unsupported engines give a note.
- Allowlist: `COMMANDLOG GET`, `COMMANDLOG LEN` (bounded count and type), `LATENCY HISTOGRAM` (up to 16 plain command
  names), `CLUSTER LINKS`. `COMMANDLOG RESET` and `COMMANDLOG HELP` are self-tested as refused. 53 commands.
- Runbook 8: large payload or tail latency.

### Changed
- tools/list byte budget 49_500 to 50_500: one new tool and longer `node_latency` text.

## Round 22 additions to 0.3.0

Round 22. 59 tools.

### Added
- `node_hot_slots`: read-only shard skew and hot slots for cluster-mode groups. Per shard `DBSIZE`, `used_memory` and
  `instantaneous_ops_per_sec`, plus `CLUSTER COUNTKEYSINSLOT` on an evenly spread, capped slot sample (default 64,
  max 256 per shard). Hot shards (1.5x the shard average, critical at 3x) and hot slots (8x the sampled median)
  come first; "reached N/M shards", per-node isolation and one shared deadline.
- `CLUSTER COUNTKEYSINSLOT` joins the SafeRedis allowlist with a single-slot, 0-16383 bound; `CLUSTER GETKEYSINSLOT`,
  `DELSLOTS`, `SETSLOT` and `ADDSLOTS` stay refused (tests prove it).
- `aws_security_audit` covers Memcached clusters and a new "network exposure" category (security groups open to the
  world, legacy cache security groups) and flags legacy or AUTH-only Redis groups (TLS off, default user open).
- `aws_cost_overview` flags idle groups and names the next smaller node type of the same family
  (`suggested_node_type`); the Valkey savings finding stays a single fleet-level note.
- `tests/test_hot_slots.py`, `tests/test_security_audit.py`, `tests/test_cost_overview.py`, and hanging-node tests
  for `node_cluster_triage`, the cluster keyspace sample and `node_doctor` in `tests/test_failure_modes.py`.

### Fixed
- `aws_metrics` is Memcached-aware: for a Memcached cluster the default metric list is `MEMCACHED_METRICS`
  (resolved with `DescribeCacheClusters`, falling back to the Redis list when that call is denied) and memcached
  findings are added. `aws_metrics` now needs `DescribeCacheClusters` (see `docs/iam-matrix.md`). Closes the round 21
  known gap.
- `node_doctor` had no deadline: it now returns a partial result plus a critical finding after 10 s instead of hanging
  on a node that stops answering.

### Changed
- tools/list text trimmed (about 20 tool descriptions shortened) so the new tool fits the unchanged 49,500 byte budget.
- Right-sizing reuses the existing single 14-day GetMetricData call per group (it covers the requested 7 days and keeps
  the one-call-per-group contract that existing tests pin).
- Integration run (`scripts/integration.sh`): ran (5.9G free on C:): 1702 passed, 5 skipped, containers cleaned up (no `prova-` left). One timing assertion in `test_fan_out_splits_budget_across_waves` compares a float budget to exactly 9.0 and failed once under load (8.984); it passes alone and in the plain run.

## 0.3.0 - 2026-11-12

Round 21. 58 tools.

### Added
- `aws_upgrade_plan`: one read-only `go` or `no-go` verdict for an engine upgrade (Redis OSS to a newer version or to
  Valkey), blockers first: version path, target parameter group family, failover and snapshot gates, pending service
  updates, maintenance window. A gate it cannot read is a blocker (no new IAM actions beyond existing Describe ones).
- `node_cluster_triage` cross-node consistency checks: config drift, ACL user names and engine version against the
  majority, with a "compared N/M nodes" summary. Per-node isolation, no secrets.
- `ACL USERS` (user names only) joins the SafeRedis allowlist; `ACL LIST` and `ACL GETUSER` stay refused.
- `tests/test_surface_pin.py`, `tests/test_failure_modes.py`, `tests/test_cluster_consistency.py`,
  `tests/test_upgrade_plan.py`, `tests/test_metric_catalogue.py` and a CI pass-floor step (`tests/pass_floor.txt`).

### Fixed
- CloudWatch counters `GetHits`, `GetMisses`, `CacheHits` and `CacheMisses` are now requested with the `Sum`
  statistic instead of `Average`.

### Changed
- tools/list byte budget raised from 48,500 to 49,500: one new tool (57 to 58), about 1 KB of description.
- Release hygiene: duplicate `0.2.0` headings merged under one `0.3.0` entry; version bumped to 0.3.0.

## Earlier in 0.3.0: round 20 additions

### Added
- `aws_scale_readiness`: read-only scale-in projection, scale-out advice and node-type change risk (no new IAM actions).
- `node_clients_summary`: bounded `CLIENT LIST` aggregate (no commands or key names); `node_doctor` includes its
  warnings only up to 500 connections.
- `mcp_elasticache_ops/quirks.py`: single table of Valkey, Redis OSS and Memcached version quirks, each with a
  remediation, used by `node_doctor`, `aws_engine_versions` (per upgrade target) and `aws_parameter_drift`.
- `scripts/regen.py` and a CI drift check for `docs/iam-matrix.md` and `tests/tool_schemas.json`.
- Runbooks for scale, client storm and failover readiness.

### Changed
- tools/list byte budget raised from 47,000 to 48,500: two new tools (55 to 57), 1.4 KB of descriptions.

## Earlier in 0.3.0: round 19 additions

### Added
- `docs/iam-matrix.md`: per-tool IAM actions and the reverse view (tools affected per withheld action), generated by
  running every tool against a recording botocore session; `tests/test_iam_policy.py` also AST-scans `controlplane/`
  and fails when a boto3 call is missing from the README policy or the matrix, or the policy grants more than the code
  calls.
- Cluster-mode replies during failover or resharding (MOVED, ASK, CLUSTERDOWN, LOADING, TRYAGAIN) become per-node
  findings with what they mean (`kind` on the shard or node row; CLUSTERDOWN critical, the rest warning) instead of
  an opaque error. Fan-out results and `node_cluster_health` carry `reached` ("reached 2/3 shards", with "(1 partial)"
  when a shard answered incompletely), and `per_shard` order is sorted by endpoint. `tests/test_cluster_quirks.py`.

### Changed
- `scripts/integration.sh`: Docker detection falls back to `wsl -d <distro> -e docker` and otherwise stops with a
  message naming the cause; it waits for a real PING through the published port and keeps a WSL session open for the
  run (without one the WSL localhost forward refused connections mid-run, failing the two server end-to-end tests).
  `integration.ps1` checks `docker info` first with the same message.
- Coverage floor raised from 90 to 93 (measured 95.9%) in `pyproject.toml` and CI.
- Round 18 work (readiness tools, split `server_*`, runbooks, pinned tool schemas) reviewed: ruff, ruff format, mypy
  and pytest clean; `tests/tool_schemas.json` holds only tool names and input schemas (no secrets).
- Integration run, 12 Nov 2026 (WSL Docker, valkey 8-alpine, then the 3-primary cluster): 1388 passed, 5 skipped
  (4 cluster and 1 Memcached tests, which the cluster script and `MEMCACHED_TEST_HOST` cover); no `prova-elasticache*`
  container or dangling volume left behind.

## 0.2.0 - 2026-11-12

### Added
- Round 18: two read-only tools (53 to 55). `aws_snapshot_restore_readiness` (replication group or serverless cache:
  failed or missing backups, no snapshot inside `stale_hours`, retention, no manual snapshot before a pending engine
  upgrade, KMS mismatch, restore target smaller than the data) and `aws_failover_readiness` (single node, automatic
  failover or Multi-AZ off, replicas in one AZ, uneven or unavailable replicas, `recovery_risk`); no new IAM actions.
  `node_keyspace_sample` takes `include_sizes` (default off) and `size_threshold`: key prefixes with collections over the
  threshold from the same SCAN sample (type-specific length command only, prefixes never full keys, no value read).
  `server.py` is split into `server.py` (plumbing, prompts, `main`), `server_node.py` and `server_aws.py`; names stay
  importable from `server`. `tools/list` was 49.9 KB before the shrink (long descriptions and the repeated `region`
  description) and is 46.3 KB after with 55 tools; `tests/test_tool_surface.py` enforces a 47 KB budget and pins tool
  names and input schemas in `tests/tool_schemas.json`. `docs/runbooks.md` has five playbooks (CPU, evictions,
  replication lag, connection storm, failover and restore readiness), linked from the README and checked against the
  tool registry by `tests/test_docs_runbooks.py`.
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
