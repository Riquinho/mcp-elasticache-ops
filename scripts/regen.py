"""Regenerate the checked-in generated files: docs/iam-matrix.md and tests/tool_schemas.json.

Run from anywhere: ``uv run python -I scripts/regen.py``. CI runs it and fails on ``git diff`` (drift check)."""

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    env = {**os.environ, "UPDATE_IAM_MATRIX": "1"}
    cmd = [sys.executable, "-I", "-m", "pytest", "-q", "--no-cov", "-p", "no:cacheprovider", "tests/test_iam_policy.py"]
    done = subprocess.run(cmd, cwd=ROOT, env=env, check=False)
    if done.returncode:
        return done.returncode
    sys.path.insert(0, str(ROOT))
    from tests import test_tool_surface as surface

    tools = asyncio.run(surface._dumped())
    surface.SNAPSHOT.write_text(
        json.dumps(surface._schemas(tools), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"regenerated docs/iam-matrix.md and {surface.SNAPSHOT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
