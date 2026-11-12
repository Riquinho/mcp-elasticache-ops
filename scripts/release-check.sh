#!/usr/bin/env bash
# Release consistency checks, run in CI and locally:
#   1. CHANGELOG.md has a section for the version in pyproject.toml (or an "Unreleased" section);
#   2. the tool count in README.md equals the number of tools the server registers;
#   3. every registered tool has a row in the README tool table;
#   4. every registered tool name appears somewhere in README.md (derived from the server registry);
#   5. every environment variable named in config.py is documented in README.md.
set -euo pipefail
cd "$(dirname "$0")/.."

version=$(uv run python -I -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')
if ! grep -Eq "^## (\[?v?${version//./\.}\]?|Unreleased)" CHANGELOG.md; then
  echo "CHANGELOG.md has no entry for version ${version} (and no Unreleased section)" >&2
  exit 1
fi

uv run python -I - <<'PY'
import asyncio
import re
import sys
from pathlib import Path

from mcp_elasticache_ops.server import mcp

registered = {t.name for t in asyncio.run(mcp.list_tools())}
readme = Path("README.md").read_text(encoding="utf-8") + "\n" + Path("docs/tools.md").read_text(encoding="utf-8")
claimed = re.search(r"All (\d+) tools are annotated", readme)
documented = set(re.findall(r"^\| `([a-z_]+)` \|", readme, flags=re.MULTILINE))
problems = []
if not claimed or int(claimed.group(1)) != len(registered):
    problems.append(f"README claims {claimed.group(1) if claimed else 'no'} tools, server registers {len(registered)}")
config_src = Path("src/mcp_elasticache_ops/config.py").read_text(encoding="utf-8")
env_vars = set(re.findall(r'"((?:ELASTICACHE|MEMCACHED|MCP|AWS)_[A-Z0-9_]+)"', config_src))
problems += [f"environment variable {n} (config.py) is not documented in README.md" for n in sorted(env_vars) if not re.search(rf"(?<![A-Z0-9_]){n}(?![A-Z0-9_])", readme)]
problems += [
    f"tool {n} is registered but its name does not appear in README.md"
    for n in sorted(registered)
    if not re.search(rf"(?<![a-z_]){n}(?![a-z_])", readme)
]
problems += [f"tool {n} missing from the README table" for n in sorted(registered - documented)]
problems += [f"README table lists unknown tool {n}" for n in sorted(documented - registered)]
if problems:
    print("\n".join(problems), file=sys.stderr)
    sys.exit(1)
print(f"release check ok: {len(registered)} tools")
PY
echo "release check ok: CHANGELOG has an entry for ${version} or Unreleased"
bash scripts/check-artifacts.sh
