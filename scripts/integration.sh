#!/usr/bin/env bash
# Run the full test suite against a throwaway Redis/Valkey container.
# The container is started with --rm and removed on EXIT, even on failure.
#
#   scripts/integration.sh                         # docker on PATH
#   DOCKER="wsl -d Ubuntu -e docker" scripts/integration.sh
#   IMAGE=redis:7-alpine scripts/integration.sh
set -euo pipefail

DOCKER=${DOCKER:-docker}
IMAGE=${IMAGE:-valkey/valkey:8-alpine}
NAME=${NAME:-prova-elasticache-ops-redis}
PORT=${PORT:-16379}

cleanup() {
  $DOCKER rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup
$DOCKER run --rm -d --name "$NAME" -p "127.0.0.1:${PORT}:6379" "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  if $DOCKER exec "$NAME" sh -c 'redis-cli ping 2>/dev/null || valkey-cli ping' 2>/dev/null | grep -q PONG; then
    break
  fi
  sleep 1
done

REDIS_TEST_URL="redis://127.0.0.1:${PORT}/0" uv run pytest -q "$@"
