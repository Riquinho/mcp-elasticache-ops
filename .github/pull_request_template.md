## What and why

## Checklist

- [ ] Stays read-only: no write command added to the SafeRedis allowlist, no non-`describe_`/`list_`/`get_metric_data` AWS call
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy src && uv run pytest -q` pass
- [ ] `uv run python -I scripts/regen.py` leaves no diff (docs/iam-matrix.md, tests/tool_schemas.json)
- [ ] CHANGELOG entry added when behavior changes
- [ ] No secrets, tokens or real endpoints in code, tests or logs
