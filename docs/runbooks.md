# Runbooks

Seven playbooks for the most common ElastiCache pages. Every step uses a read-only tool; nothing here writes,
flushes, fails over or restores. Four of them are also available as MCP prompts (`oncall_high_cpu`,
`oncall_evictions_memory`, `oncall_replication_lag`, `oncall_connection_storm`) that chain the same tools for the model.
Tools named `node_*` talk to one endpoint: set `ELASTICACHE_HOST` to the node you suspect before calling them.

Rule of thumb: read `findings` first, they are sorted worst-first and already say whether a signal is a
transient spike or sustained.

## 1. High CPU (EngineCPUUtilization alarm)

1. `aws_triage` with the replication group id. A "transient spike" finding is not an incident: report it and stop.
   Note `ownership` to know whom to page.
2. `aws_cluster_overview`. One node far above the peer median is a hot shard or hot key; all nodes high is load or sizing.
3. `aws_shard_balance` to confirm the skew from CloudWatch alone (no data-plane connection needed).
4. `node_triage` on the hot node, then `node_cluster_slowlog` and `node_commandstats` for the commands that burn the most time.
5. `node_clients` for huge output buffers or blocked clients; `node_cluster_health` if the cluster state is not ok.
6. `aws_metrics` with EngineCPUUtilization, CPUUtilization, CurrConnections, NewConnections for 360 minutes.
   EngineCPUUtilization high with CPUUtilization low means the single Redis thread is saturated: add shards or fix
   the command, a bigger host will not help.

Conclude: sustained or spike, one node or all, top slow command, next step.

## 2. Evictions or memory pressure

1. `aws_triage`: DatabaseMemoryUsagePercentage and Evictions findings, and the "reached in about Nh" trend hint.
2. `aws_capacity_forecast` for days until full across the fleet, soonest first.
3. `aws_metrics` with DatabaseMemoryUsagePercentage, BytesUsedForCache, Evictions, CurrItems, CacheHitRate for 1440
   minutes. Evictions with a falling CacheHitRate hurt users now; high memory without evictions means noeviction.
4. `node_memory` for fragmentation, maxmemory and policy; `node_cluster_memory` to compare shards.
5. `node_keyspace_sample` (or `node_cluster_keyspace_sample`) for big keys and missing TTLs. Add `include_sizes` to
   list key prefixes whose lists, sets, hashes or streams exceed a threshold (unbounded-growth candidates; prefixes only).
6. `aws_parameters` to confirm maxmemory-policy and reserved-memory-percent.

Conclude: leak or burst, which keys or shard, policy in force, hours until full, and the choice (TTLs, policy,
shards, node type).

## 3. Replication lag

1. `aws_triage`: ReplicationLag findings, recent failover or replacement events, pending service updates.
2. `aws_events` for the group over 24 hours: a failover or replacement just before the lag explains a resync.
3. `node_replication` on the primary: replica offsets, link status, backlog. `node_cluster_nodes` shows which shard.
4. `aws_metrics` with ReplicationLag, ReplicationBytes, EngineCPUUtilization and the network allowance metrics.
5. Global datastore: `aws_global_replication_groups`, also with `region` set to the secondary region.
6. `aws_failover_readiness` before anyone talks about failing over: it states the recovery risk (high, medium, low),
   replicas sharing an AZ, and replicas that are not available.

Conclude: which replica or region lags, since when, whether load, network or a resync explains it, and whether a
failover would lose data.

## 4. Connection storm

1. `aws_triage`: CurrConnections findings. "Transient spike" means a client restarted; "sustained" means a leak or a
   missing pool.
2. `aws_metrics` with CurrConnections, NewConnections, EngineCPUUtilization. NewConnections high with CurrConnections
   flat is churn; CurrConnections climbing is a leak.
3. `node_clients_summary` on the busiest node: top source IPs, client names or libraries, idle clients, big buffers
   and the use against `maxclients`, with no commands or key names. One address owning thousands of connections is
   the offender; then `node_clients` for the per-client detail.
4. `node_latency` and `node_cluster_slowlog` to see whether every command suffers; `node_acl_log` for retry storms
   after authentication failures.
5. `aws_alarms` to check that a CurrConnections alarm exists.

Conclude: responsible client, churn or leak, distance to maxclients, fix (pool, idle timeout, backoff).

## 5. Failover or restore readiness (before a drill, an upgrade or a maintenance window)

1. `aws_failover_readiness` for the replication group: single-node or no replicas, automatic failover or Multi-AZ off,
   replicas in the primary's AZ, uneven replica counts per shard, replicas not available. The result carries one
   `recovery_risk` (high, medium, low).
2. `aws_snapshot_restore_readiness` with the replication group id (or `serverless_cache_name`): backups disabled, no
   snapshot inside `stale_hours`, retention shorter than the history you need, no manual snapshot before a pending
   engine upgrade, KMS key mismatch, and a restore target smaller than the data.
3. `aws_scale_readiness` when the window includes a node-type change: its node-type-change risk and reasons
   (Multi-AZ off, replica lag, pending modification, burstable credits).
4. `aws_maintenance` for updates past their apply-by date that will force a failover on their own.
5. `aws_snapshots` or `aws_serverless_snapshots` for the raw snapshot list behind the findings.
6. `aws_alarms` to confirm replication lag and memory alarms exist before the window.

Conclude: recovery risk, newest restorable snapshot and its age, and the gaps to close before the change.

## 6. Scale (add or remove shards, change node type)

1. `aws_scale_readiness` for the replication group: scale-in fit (projected memory and CPU on the surviving shards),
   scale-out advice (memory, CPU, network allowance, shard skew) and node-type change risk with its reasons.
2. `aws_shard_balance`: one hot shard is a resharding problem, not a capacity one; adding shards helps only after the
   skew is understood.
3. `aws_failover_readiness`: a node-type change replaces nodes through failover, so replicas and Multi-AZ must be in
   place first.
4. `aws_metrics` with DatabaseMemoryUsagePercentage and EngineCPUUtilization over the same 7 days for the shape
   behind the projection.

Conclude: safe or not to scale in, whether to scale out, the risk of the node-type change and what to fix first.

## 7. Snapshot fork latency (latency spikes at backup time)

1. `aws_snapshots` for the snapshot times, then `aws_metrics` with EngineCPUUtilization and
   DatabaseMemoryUsagePercentage around them: a spike at each backup is the fork.
2. `node_latency` and `node_memory` on the node taking the snapshot: fragmentation and copy-on-write growth.
3. `aws_snapshot_restore_readiness`: backup window and retention, and whether a replica could take the snapshot.

Conclude: whether the spikes line up with the backup window, headroom for the copy-on-write memory, and the window
or node to move the backup to.
