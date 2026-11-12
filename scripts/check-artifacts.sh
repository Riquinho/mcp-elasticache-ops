#!/usr/bin/env bash
# Build the sdist and wheel into a temp dir and fail if either ships secrets or local state:
# .env*, .coverage, .lotes, *.pem, *.key. Also requires py.typed in the wheel.
set -euo pipefail
cd "$(dirname "$0")/.."
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
uv build --out-dir "$out" >/dev/null
bad=0
for f in "$out"/*.tar.gz; do
  tar -tzf "$f" > "$out/sdist.lst"
done
unzip -Z1 "$out"/*.whl > "$out/wheel.lst"
for lst in "$out/sdist.lst" "$out/wheel.lst"; do
  if grep -Eq '(^|/)(\.env[^/]*|\.coverage[^/]*|\.lotes(/.*)?|[^/]*\.pem|[^/]*\.key)$' "$lst"; then
    echo "forbidden file in $(basename "$lst" .lst):" >&2
    grep -E '(^|/)(\.env[^/]*|\.coverage[^/]*|\.lotes(/.*)?|[^/]*\.pem|[^/]*\.key)$' "$lst" >&2
    bad=1
  fi
done
grep -q 'mcp_elasticache_ops/py.typed$' "$out/wheel.lst" || { echo "py.typed missing from wheel" >&2; bad=1; }
[ "$bad" = 0 ] && echo "artifact check ok"
exit "$bad"
