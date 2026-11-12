#!/usr/bin/env bash
# Run the full test suite against a throwaway Redis/Valkey container.
# The container is started with --rm and removed on EXIT, even on failure.
#
#   scripts/integration.sh                         # docker on PATH
#   DOCKER="wsl -d Ubuntu -e docker" scripts/integration.sh
#   IMAGE=redis:7-alpine scripts/integration.sh
set -euo pipefail

MIN_FREE_GB=${MIN_FREE_GB:-5}
FREE_GB=$(df -Pk "${DISK_PATH:-.}" | awk 'NR==2 {printf "%d", $4/1048576}')
if [ "$FREE_GB" -lt "$MIN_FREE_GB" ]; then
  echo "disk gate: ${FREE_GB}G free (< ${MIN_FREE_GB}G required)"
  echo "INTEGRATION SKIPPED: nothing was started. Free only what tests created, then re-run (the gate is not lowered):"
  echo "  1. wsl -d Ubuntu -e docker image prune -f"
  echo "  2. wsl -d Ubuntu -e docker volume ls -q -f dangling=true   (remove only 64-hex anonymous names)"
  echo "  3. wsl -d Ubuntu -e docker builder prune -f --filter until=24h"
  echo "  4. wsl -d Ubuntu -u root -e fstrim -v /"
  exit 0
fi

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
