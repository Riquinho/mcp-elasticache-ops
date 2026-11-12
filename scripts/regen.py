"""Regenerate the checked-in generated files: docs/iam-matrix.md and tests/tool_schemas.json.

Run from anywhere: ``uv run python -I scripts/regen.py``. CI runs it and fails on ``git diff`` (drift check).

``--check`` is read-only: it regenerates inside a temporary copy of the repository, compares the result with the
files on disk, exits 1 on any difference and leaves the working tree untouched."""

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GENERATED = ("docs/iam-matrix.md", "tests/tool_schemas.json")
COPY_IGNORE = shutil.ignore_patterns(
    ".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis", "dist", ".coverage*"
)


def _pytest(root: Path, env_extra: dict[str, str], target: str) -> int:
    env = {**os.environ, **env_extra, "PYTHONPATH": str(root / "src")}
    cmd = [sys.executable, "-I", "-m", "pytest", "-q", "--no-cov", "-p", "no:cacheprovider", target]
    return subprocess.run(cmd, cwd=root, env=env, check=False).returncode


def _generate(root: Path) -> int:
    if _pytest(root, {"UPDATE_IAM_MATRIX": "1"}, "tests/test_iam_policy.py"):
        return 1
    sys.path.insert(0, str(root))
    sys.path.insert(0, str(root / "src"))
    from tests import test_tool_surface as surface

    tools = asyncio.run(surface._dumped())
    (root / "tests/tool_schemas.json").write_text(
        json.dumps(surface._schemas(tools), indent=1, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    if _pytest(root, {"UPDATE_IAM_PIN": "1"}, "tests/test_surface_pin.py") not in (0, 1):
        return 1
    return 0


def check() -> int:
    with tempfile.TemporaryDirectory(prefix="regen-check-") as tmp:
        work = Path(tmp) / "repo"
        shutil.copytree(ROOT, work, ignore=COPY_IGNORE)
        if _generate(work):
            return 1
        stale = [rel for rel in GENERATED if (work / rel).read_bytes() != (ROOT / rel).read_bytes()]
    if stale:
        print(f"stale generated files (run scripts/regen.py): {', '.join(stale)}", file=sys.stderr)
        return 1
    print("generated files are up to date")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if "--check" in args:
        return check()
    if _generate(ROOT):
        return 1
    print(f"regenerated {', '.join(GENERATED)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
