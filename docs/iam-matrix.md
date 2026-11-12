# IAM matrix

Generated from the code by `tests/test_iam_policy.py` (do not edit by hand; regenerate with
`UPDATE_IAM_MATRIX=1 uv run python -I -m pytest tests/test_iam_policy.py`). Every call is `Describe*`,
`List*` or `cloudwatch:GetMetricData`, all with `Resource: "*"`. Tools not listed here make no AWS call and
need no IAM permission (they reach the node directly).

## Actions each tool needs

A tool whose action is missing from the role returns `{"error": "AccessDenied", ...}` for that call; tools
with several actions degrade to a partial answer when only some are denied.

| Tool | Actions |
| --- | --- |
| `aws_alarms` | `cloudwatch:DescribeAlarms`, `elasticache:DescribeCacheClusters`, `elasticache:DescribeReplicationGroups`, `elasticache:DescribeServerlessCaches` |
| `aws_cache_clusters` | `elasticache:DescribeCacheClusters`, `elasticache:DescribeCacheEngineVersions`, `elasticache:DescribeCacheParameterGroups` |
| `aws_capacity_forecast` | `cloudwatch:GetMetricData`, `elasticache:DescribeCacheClusters`, `elasticache:DescribeReplicationGroups`, `elasticache:DescribeServerlessCaches` |
| `aws_cluster_overview` | `cloudwatch:GetMetricData`, `elasticache:DescribeCacheClusters`, `elasticache:DescribeReplicationGroups`, `elasticache:ListTagsForResource` |
| `aws_cost_overview` | `cloudwatch:GetMetricData`, `elasticache:DescribeCacheClusters`, `elasticache:DescribeReplicationGroups`, `elasticache:DescribeReservedCacheNodes`, `elasticache:DescribeServerlessCaches`, `elasticache:DescribeSnapshots` |
| `aws_engine_versions` | `elasticache:DescribeCacheEngineVersions` |
| `aws_events` | `elasticache:DescribeEvents` |
| `aws_failover_readiness` | `elasticache:DescribeCacheClusters`, `elasticache:DescribeReplicationGroups` |
| `aws_global_replication_groups` | `elasticache:DescribeGlobalReplicationGroups` |
| `aws_maintenance` | `elasticache:DescribeCacheClusters`, `elasticache:DescribeServiceUpdates`, `elasticache:DescribeUpdateActions` |
| `aws_metrics` | `cloudwatch:GetMetricData`, `elasticache:DescribeCacheClusters`, `elasticache:DescribeReplicationGroups`, `elasticache:DescribeServerlessCaches` |
| `aws_parameter_drift` | `elasticache:DescribeCacheParameterGroups`, `elasticache:DescribeCacheParameters` |
| `aws_parameter_groups` | `elasticache:DescribeCacheClusters`, `elasticache:DescribeCacheParameterGroups` |
| `aws_parameters` | `elasticache:DescribeCacheParameters` |
| `aws_reader_endpoint_audit` | `elasticache:DescribeCacheClusters`, `elasticache:DescribeReplicationGroups` |
| `aws_replication_groups` | `elasticache:DescribeCacheClusters`, `elasticache:DescribeCacheEngineVersions`, `elasticache:DescribeReplicationGroups` |
| `aws_reserved_nodes` | `elasticache:DescribeCacheClusters`, `elasticache:DescribeReservedCacheNodes` |
| `aws_reserved_offerings` | `elasticache:DescribeCacheClusters`, `elasticache:DescribeReservedCacheNodes`, `elasticache:DescribeReservedCacheNodesOfferings` |
| `aws_scale_readiness` | `cloudwatch:GetMetricData`, `elasticache:DescribeCacheClusters`, `elasticache:DescribeReplicationGroups` |
| `aws_security_audit` | `elasticache:DescribeCacheClusters`, `elasticache:DescribeCacheEngineVersions`, `elasticache:DescribeReplicationGroups`, `elasticache:DescribeServerlessCaches`, `elasticache:DescribeUserGroups`, `elasticache:DescribeUsers` |
| `aws_serverless_caches` | `elasticache:DescribeServerlessCaches` |
| `aws_serverless_snapshots` | `elasticache:DescribeServerlessCacheSnapshots`, `elasticache:DescribeServerlessCaches` |
| `aws_serverless_triage` | `cloudwatch:GetMetricData`, `elasticache:DescribeEvents`, `elasticache:DescribeServerlessCacheSnapshots`, `elasticache:DescribeServerlessCaches` |
| `aws_service_updates` | `elasticache:DescribeServiceUpdates` |
| `aws_shard_balance` | `cloudwatch:GetMetricData`, `elasticache:DescribeReplicationGroups` |
| `aws_snapshot_restore_readiness` | `elasticache:DescribeCacheClusters`, `elasticache:DescribeReplicationGroups`, `elasticache:DescribeServerlessCacheSnapshots`, `elasticache:DescribeServerlessCaches`, `elasticache:DescribeSnapshots` |
| `aws_snapshots` | `elasticache:DescribeSnapshots` |
| `aws_subnet_groups` | `elasticache:DescribeCacheSubnetGroups` |
| `aws_triage` | `cloudwatch:GetMetricData`, `elasticache:DescribeCacheClusters`, `elasticache:DescribeCacheEngineVersions`, `elasticache:DescribeEvents`, `elasticache:DescribeReplicationGroups`, `elasticache:DescribeSnapshots`, `elasticache:DescribeUpdateActions`, `elasticache:ListTagsForResource` |
| `aws_upgrade_plan` | `elasticache:DescribeCacheClusters`, `elasticache:DescribeCacheEngineVersions`, `elasticache:DescribeCacheParameterGroups`, `elasticache:DescribeReplicationGroups`, `elasticache:DescribeSnapshots`, `elasticache:DescribeUpdateActions` |
| `aws_user_groups` | `elasticache:DescribeUserGroups`, `elasticache:DescribeUsers` |
| `aws_users` | `elasticache:DescribeUserGroups`, `elasticache:DescribeUsers` |
| `memcached_discovery` | `elasticache:DescribeCacheClusters` |

## Tools affected when one action is not granted

| Action | Tools that lose data |
| --- | --- |
| `cloudwatch:DescribeAlarms` | `aws_alarms` |
| `cloudwatch:GetMetricData` | `aws_capacity_forecast`, `aws_cluster_overview`, `aws_cost_overview`, `aws_metrics`, `aws_scale_readiness`, `aws_serverless_triage`, `aws_shard_balance`, `aws_triage` |
| `elasticache:DescribeCacheClusters` | `aws_alarms`, `aws_cache_clusters`, `aws_capacity_forecast`, `aws_cluster_overview`, `aws_cost_overview`, `aws_failover_readiness`, `aws_maintenance`, `aws_metrics`, `aws_parameter_groups`, `aws_reader_endpoint_audit`, `aws_replication_groups`, `aws_reserved_nodes`, `aws_reserved_offerings`, `aws_scale_readiness`, `aws_security_audit`, `aws_snapshot_restore_readiness`, `aws_triage`, `aws_upgrade_plan`, `memcached_discovery` |
| `elasticache:DescribeCacheEngineVersions` | `aws_cache_clusters`, `aws_engine_versions`, `aws_replication_groups`, `aws_security_audit`, `aws_triage`, `aws_upgrade_plan` |
| `elasticache:DescribeCacheParameterGroups` | `aws_cache_clusters`, `aws_parameter_drift`, `aws_parameter_groups`, `aws_upgrade_plan` |
| `elasticache:DescribeCacheParameters` | `aws_parameter_drift`, `aws_parameters` |
| `elasticache:DescribeCacheSubnetGroups` | `aws_subnet_groups` |
| `elasticache:DescribeEvents` | `aws_events`, `aws_serverless_triage`, `aws_triage` |
| `elasticache:DescribeGlobalReplicationGroups` | `aws_global_replication_groups` |
| `elasticache:DescribeReplicationGroups` | `aws_alarms`, `aws_capacity_forecast`, `aws_cluster_overview`, `aws_cost_overview`, `aws_failover_readiness`, `aws_metrics`, `aws_reader_endpoint_audit`, `aws_replication_groups`, `aws_scale_readiness`, `aws_security_audit`, `aws_shard_balance`, `aws_snapshot_restore_readiness`, `aws_triage`, `aws_upgrade_plan` |
| `elasticache:DescribeReservedCacheNodes` | `aws_cost_overview`, `aws_reserved_nodes`, `aws_reserved_offerings` |
| `elasticache:DescribeReservedCacheNodesOfferings` | `aws_reserved_offerings` |
| `elasticache:DescribeServerlessCacheSnapshots` | `aws_serverless_snapshots`, `aws_serverless_triage`, `aws_snapshot_restore_readiness` |
| `elasticache:DescribeServerlessCaches` | `aws_alarms`, `aws_capacity_forecast`, `aws_cost_overview`, `aws_metrics`, `aws_security_audit`, `aws_serverless_caches`, `aws_serverless_snapshots`, `aws_serverless_triage`, `aws_snapshot_restore_readiness` |
| `elasticache:DescribeServiceUpdates` | `aws_maintenance`, `aws_service_updates` |
| `elasticache:DescribeSnapshots` | `aws_cost_overview`, `aws_snapshot_restore_readiness`, `aws_snapshots`, `aws_triage`, `aws_upgrade_plan` |
| `elasticache:DescribeUpdateActions` | `aws_maintenance`, `aws_triage`, `aws_upgrade_plan` |
| `elasticache:DescribeUserGroups` | `aws_security_audit`, `aws_user_groups`, `aws_users` |
| `elasticache:DescribeUsers` | `aws_security_audit`, `aws_user_groups`, `aws_users` |
| `elasticache:ListTagsForResource` | `aws_cluster_overview`, `aws_triage` |
