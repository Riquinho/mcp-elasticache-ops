"""Release readiness: one version everywhere, a CHANGELOG entry, and a README catalogue that matches the registry."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from mcp_elasticache_ops import __version__, server

ROOT = Path(__file__).resolve().parent.parent
TABLE_ROW = re.compile(r"^\| `([a-z_]+)` \|", flags=re.MULTILINE)


def readme_problems(readme: str, registered: set[str]) -> list[str]:
    """Count claim, table rows and prose mentions of the README, compared with the tool registry."""
    problems: list[str] = []
    claimed = re.search(r"All (\d+) tools are annotated", readme)
    if not claimed or int(claimed.group(1)) != len(registered):
        problems.append(f"README claims {claimed.group(1) if claimed else 'no'} tools, registry has {len(registered)}")
    documented = set(TABLE_ROW.findall(readme))
    problems += [f"tool {n} missing from the README table" for n in sorted(registered - documented)]
    problems += [f"README table lists unknown tool {n}" for n in sorted(documented - registered)]
    return problems


async def _registered() -> set[str]:
    return {t.name for t in await server.mcp.list_tools()}


async def test_readme_catalogue_matches_registry():
    assert readme_problems((ROOT / "README.md").read_text(encoding="utf-8"), await _registered()) == []


async def test_removing_a_tool_from_the_readme_fails_the_check():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    registered = await _registered()
    victim = sorted(registered)[0]
    without_row = "\n".join(line for line in readme.splitlines() if not line.startswith(f"| `{victim}` |"))
    assert readme_problems(without_row, registered) == [f"tool {victim} missing from the README table"]


async def test_stale_tool_count_or_phantom_row_fails_the_check():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    registered = await _registered()
    wrong_count = readme.replace(f"All {len(registered)} tools", f"All {len(registered) + 1} tools")
    assert any("claims" in p for p in readme_problems(wrong_count, registered))
    phantom = readme + "\n| `node_does_not_exist` | nothing |\n"
    assert readme_problems(phantom, registered) == ["README table lists unknown tool node_does_not_exist"]


def test_version_is_the_same_in_pyproject_and_package():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == __version__


def test_changelog_has_a_dated_section_for_the_current_version():
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert re.search(rf"^## {re.escape(__version__)}( |$)", changelog, flags=re.MULTILINE), __version__
    assert "## Unreleased" not in changelog, "cut the release: Unreleased was turned into the version heading"


def test_changelog_has_a_single_heading_per_released_version():
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"^## (\d+\.\d+\.\d+)\b", changelog, flags=re.MULTILINE)
    assert len(headings) == len(set(headings)), f"duplicate version headings: {headings}"
