"""docs/runbooks.md stays honest: every tool it names exists in the registry, and the README links it."""

import re
from pathlib import Path

from mcp_elasticache_ops import server

ROOT = Path(__file__).resolve().parent.parent
RUNBOOKS = ROOT / "docs" / "runbooks.md"
TOOL_NAME = re.compile(r"`((?:aws|node|memcached)_[a-z_]+)`")


async def test_docs_runbooks_name_only_registered_tools():
    registered = {t.name for t in await server.mcp.list_tools()}
    named = set(TOOL_NAME.findall(RUNBOOKS.read_text(encoding="utf-8")))
    assert named, "the runbooks should reference tools"
    assert named <= registered, f"runbooks name tools that do not exist: {sorted(named - registered)}"


def test_docs_runbooks_have_seven_playbooks():
    headings = re.findall(r"^## \d+\. ", RUNBOOKS.read_text(encoding="utf-8"), re.M)
    assert len(headings) == 7


def test_docs_runbooks_are_read_only_and_linked_from_the_readme():
    assert "docs/runbooks.md" in (ROOT / "README.md").read_text(encoding="utf-8")
    text = RUNBOOKS.read_text(encoding="utf-8").lower()
    assert "read-only" in text


async def test_docs_runbooks_cover_the_round_18_readiness_tools():
    named = set(TOOL_NAME.findall(RUNBOOKS.read_text(encoding="utf-8")))
    assert {"aws_failover_readiness", "aws_snapshot_restore_readiness"} <= named


def test_every_incident_class_lists_at_least_two_tools():
    sections = re.split(r"^## (?=\d+\. )", RUNBOOKS.read_text(encoding="utf-8"), flags=re.M)[1:]
    assert len(sections) == 7
    for section in sections:
        title = section.splitlines()[0]
        assert len(set(TOOL_NAME.findall(section))) >= 2, f"playbook {title!r} lists fewer than 2 tools"


async def test_docs_runbooks_cover_the_round_20_tools():
    named = set(TOOL_NAME.findall(RUNBOOKS.read_text(encoding="utf-8")))
    assert {"aws_scale_readiness", "node_clients_summary"} <= named
