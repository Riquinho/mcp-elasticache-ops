# Security

## Read-only guarantee

This server cannot change data or configuration, by construction:

- **Data plane.** Every Redis command passes through `SafeRedis` / `SafePipeline` (`safe_client.py`), an
  allowlist of read-only commands. Anything else, including `GET`, `SET`, `DEL`, `FLUSHALL`, `CONFIG SET`,
  `CLIENT KILL`, `EVAL`, `MULTI`, raises `ReadOnlyViolation` before reaching the network. Command names must be
  one or two alphabetic tokens, so whitespace or newline smuggling is rejected. `CONFIG GET` is limited to an
  explicit set of non-sensitive parameters; `*`, `requirepass`, `masterauth`, `tls-*` and glob patterns are refused.
  `KEYS` is refused. Values are never read.
- **Control plane.** `ControlPlane._paginate` refuses any operation not starting with `describe_`, `list_` or
  `get_metric_data`. Grant the IAM role only `elasticache:Describe*` and `cloudwatch:GetMetricData`.
- **Secrets.** Passwords, AUTH tokens and IAM tokens come from the environment (or a file) and are never returned
  by tools. `node_info` redacts password-like fields; `node_slowlog` hides arguments unless `include_args=true`;
  `aws_users` returns no credential material. IAM auth tokens are signed locally (SigV4) and sent only to the
  cache endpoint.
- Use TLS (`ELASTICACHE_TLS=true`) with certificate verification on; `ELASTICACHE_TLS_VERIFY=false` is for tests only.

Tests enforcing this: `tests/test_safe_client.py`, `tests/test_controlplane_tools.py` (recording client),
`tests/test_server.py` (all tools annotated read-only).

## Reporting a vulnerability

Use GitHub private vulnerability reporting:
<https://github.com/Riquinho/mcp-elasticache-ops/security/advisories/new>.
Please do not file public issues for bypasses of the read-only guard. Expect an acknowledgement within a few days.

## Supported versions

Only the latest release receives security fixes.
