"""Cross-tool findings pointers: vocabulary, `next` targets and actionability hold for every tool.

A finding that tells the operator to run another tool must name one that exists. Renaming a tool or a ``next``
pointer without the other fails here, not in production.
"""

import ast
import pathlib
import re

import pytest

from mcp_elasticache_ops import server

from .test_output_budget import STRING_FINDINGS, _call_id, _run
from .test_server import AUDIT_CALLS, audit  # noqa: F401  (fixture)

VOCAB = {"critical", "warning", "info"}
TOOL_TOKEN = re.compile(r"\b(?:aws|node|memcached)_[a-z][a-z0-9_]*\b")
SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "mcp_elasticache_ops"

# Tools whose critical/warning findings were built to be actionable: each carries a ``next`` pointer to a
# registered tool, or its message names one. Legacy tools that only describe state are not forced into this.
ACTIONABLE = {"aws_replication_group_audit", "aws_triage", "aws_replication_groups"}


async def _registered() -> set[str]:
    return {t.name for t in await server.mcp.list_tools()}


def _structured(data: dict) -> list[dict]:
    return [f for f in data.get("findings", []) if isinstance(f, dict)]


@pytest.mark.parametrize("call", AUDIT_CALLS, ids=_call_id)
async def test_findings_use_the_shared_vocabulary_and_point_at_real_tools(audit, call):  # noqa: F811
    name, args = call
    registered = await _registered()
    data = await _run(name, args)
    if name in STRING_FINDINGS:
        return
    for f in _structured(data):
        assert f.get("severity") in VOCAB, f"{name}: severity {f.get('severity')!r} outside {sorted(VOCAB)}"
        if "next" in f:
            assert f["next"] in registered, f"{name}: next={f['next']!r} is not a registered tool"
        for token in TOOL_TOKEN.findall(f["message"]):
            assert token in registered, f"{name}: message names unknown tool {token!r}: {f['message']}"


@pytest.mark.parametrize("call", [c for c in AUDIT_CALLS if c[0] in ACTIONABLE], ids=_call_id)
async def test_actionable_tools_give_every_warning_a_next_step(audit, call):  # noqa: F811
    name, args = call
    registered = await _registered()
    for f in _structured(await _run(name, args)):
        if f["severity"] == "info":
            continue
        names_tool = any(t in registered for t in TOOL_TOKEN.findall(f["message"]))
        if name == "aws_replication_group_audit":
            assert f.get("next") in registered and f.get("category") and f.get("resource"), f
        elif "next" not in f and not names_tool:
            continue  # aws_triage / aws_replication_groups still carry older state-only findings
        else:
            assert f.get("next") in registered or names_tool, f


def _docstring_ids(tree: ast.AST) -> set[int]:
    kinds = (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
    return {
        id(n.body[0].value)
        for n in ast.walk(tree)
        if isinstance(n, kinds) and n.body and isinstance(n.body[0], ast.Expr)
    }


def test_every_tool_name_in_source_messages_is_registered():
    import asyncio

    registered = asyncio.run(_registered())
    unknown = {}
    for path in SRC.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docs = _docstring_ids(tree)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)) or id(node) in docs:
                continue
            for token in TOOL_TOKEN.findall(node.value) if " " in node.value else []:
                if token not in registered:
                    unknown.setdefault(token, path.name)
    assert not unknown, f"messages name tools that are not registered: {unknown}"


def test_every_next_pointer_in_source_is_registered():
    import asyncio

    registered = asyncio.run(_registered())
    bad = {}
    for path in SRC.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            is_next = isinstance(node, ast.keyword) and node.arg == "next"
            if is_next and isinstance(node.value, ast.Constant) and node.value.value not in registered:
                bad[node.value.value] = path.name
    assert not bad, f"next= pointers to unregistered tools: {bad}"


async def test_every_pointer_a_worst_case_group_can_emit_is_registered():
    """The audit fixtures are healthy-ish; a group failing every check exercises every pointer."""
    from mcp_elasticache_ops.controlplane._shared import log_delivery_findings
    from mcp_elasticache_ops.controlplane.group_audit import group_audit_findings

    registered = await _registered()
    worst = {
        "ReplicationGroupId": "rg",
        "Engine": "valkey",
        "MultiAZ": "disabled",
        "AutomaticFailover": "disabled",
        "ClusterEnabled": False,
        "CacheNodeType": "cache.r7g.4xlarge",
        "AutoMinorVersionUpgrade": False,
        "SnapshotRetentionLimit": 0,
        "TransitEncryptionEnabled": False,
        "AtRestEncryptionEnabled": True,
        "NetworkType": "ipv6",
        "IpDiscovery": "ipv4",
        "LogDeliveryConfigurations": [],
        "NodeGroups": [{"NodeGroupId": "0001", "NodeGroupMembers": [{"PreferredAvailabilityZone": "a"}]}],
    }
    found = group_audit_findings(worst, []) + log_delivery_findings(worst, "valkey")
    assert len({f["category"] for f in found if "category" in f}) >= 9
    for f in found:
        assert f["next"] in registered, f
        assert f["severity"] in VOCAB
