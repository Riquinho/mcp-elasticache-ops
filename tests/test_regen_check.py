"""``scripts/regen.py --check`` must be read-only: it reports drift with exit 1 and never rewrites the tree."""

import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def test_check_fails_on_a_stale_file_and_writes_nothing(tmp_path: Path):
    copy = tmp_path / "repo"
    shutil.copytree(
        REPO,
        copy,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis", "dist"
        ),
    )
    stale = copy / "tests" / "tool_schemas.json"
    stale.write_text(stale.read_text(encoding="utf-8") + "\n// stale\n", encoding="utf-8", newline="\n")
    before = {p: p.read_bytes() for p in copy.rglob("*") if p.is_file() and "__pycache__" not in p.parts}

    done = subprocess.run(
        [sys.executable, "-I", str(copy / "scripts" / "regen.py"), "--check"],
        cwd=copy,
        capture_output=True,
        text=True,
        check=False,
    )

    assert done.returncode == 1, done.stdout + done.stderr
    assert "tests/tool_schemas.json" in done.stderr
    after = {p: p.read_bytes() for p in copy.rglob("*") if p.is_file() and "__pycache__" not in p.parts}
    assert after == before, "--check must not write to the tree"
