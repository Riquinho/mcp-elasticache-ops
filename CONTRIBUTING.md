# Contributing

Core rule: this server is **read-only**. Changes must not add write commands to the SafeRedis allowlist or call AWS APIs other than `describe_*`, `list_*` and `get_metric_data`. See SECURITY.md.

## Setup

```bash
uv sync --locked
```

## Checks (CI runs the same)

```bash
uv run ruff check . && uv run ruff format --check .
uv run mypy src
uv run pytest -q
uv run python -I scripts/regen.py   # must leave no diff
bash scripts/release-check.sh
```

Live-server integration tests need `REDIS_TEST_URL`, `MEMCACHED_TEST_HOST` and, for cluster, `CLUSTER_TEST_HOST` (see `scripts/` and `tests/docker-compose.cluster.yml`).

## Pull requests

- Small, focused changes with tests. Coverage floor is 93%.
- Update CHANGELOG.md when behavior changes.
- Never commit secrets, tokens or real endpoints. CI scans history with gitleaks.
