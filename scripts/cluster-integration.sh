#!/usr/bin/env bash
# Run the cluster integration tests against a throwaway 3-primary valkey cluster.
# Everything is removed on EXIT (`down -v`), even on failure.
#
#   scripts/cluster-integration.sh
#   DOCKER="wsl -d Ubuntu -e docker" scripts/cluster-integration.sh
set -euo pipefail

MIN_FREE_GB=${MIN_FREE_GB:-3}
FREE_GB=$(df -Pk "${DISK_PATH:-.}" | awk 'NR==2 {printf "%d", $4/1048576}')
if [ "$FREE_GB" -lt "$MIN_FREE_GB" ]; then
  echo "disk gate: ${FREE_GB}G free (< ${MIN_FREE_GB}G required): CLUSTER INTEGRATION SKIPPED, nothing was started"
  exit 0
fi

DOCKER=${DOCKER:-docker}
COMPOSE_FILE=${COMPOSE_FILE:-tests/docker-compose.cluster.yml}
HERE=$(cd "$(dirname "$0")/.." && pwd)

# With WSL docker the compose file path must be a Linux path.
if [[ "$DOCKER" == wsl* ]]; then
  FILE=$(wsl -d Ubuntu -e wslpath -a "$(cd "$HERE" && pwd -W 2>/dev/null || pwd)/$COMPOSE_FILE")
else
  FILE="$HERE/$COMPOSE_FILE"
fi

cleanup() {
  $DOCKER compose -f "$FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup
$DOCKER compose -f "$FILE" up -d --wait --wait-timeout 90

CLUSTER_TEST_HOST=127.0.0.1 CLUSTER_TEST_PORT=7001 uv run pytest -q -m integration tests/test_dataplane_integration.py -k cluster "$@"
