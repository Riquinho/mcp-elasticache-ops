"""Per-tool IAM matrix generated from the code, checked against docs/iam-matrix.md and the README policy.

Two independent sources of truth: (1) every tool is run once per ``AUDIT_CALLS`` entry against a recording
botocore session, giving the exact actions each tool issues; (2) an AST scan of ``controlplane/`` lists every
boto3 call the code can make, including branches the canned replies never reach. A new boto3 call that is
missing from the README policy or from the matrix fails here. Regenerate the matrix with
``UPDATE_IAM_MATRIX=1 uv run python -I -m pytest tests/test_iam_policy.py``.
"""

from __future__ import annotations

import ast
import contextlib
import json
import os
import re
from collections import defaultdict
from pathlib import Path

from fastmcp import Client
from fastmcp.exceptions import ToolError

from mcp_elasticache_ops import server
from tests.test_server import AUDIT_CALLS, audit  # noqa: F401  (audit is a fixture)

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "docs" / "iam-matrix.md"
README = ROOT / "README.md"
CONTROLPLANE = ROOT / "src" / "mcp_elasticache_ops" / "controlplane"


def _pascal(snake: str) -> str:
    return "".join(part.capitalize() for part in snake.split("_"))


OPERATION = re.compile(r"^(describe|list)_[a-z_]+[a-z]$|^get_metric_data$")
CLOUDWATCH_OPERATIONS = {"describe_alarms", "get_metric_data"}


def static_actions() -> set[str]:
    """Every ``service:Operation`` the controlplane code can call.

    The code reaches boto3 through ``self._paginate("describe_x", ...)``, ``client.describe_x(...)``,
    ``cw.get_metric_data(...)`` and ``get_paginator("describe_x")``, so the scan takes every string constant and
    every called attribute that is shaped like a read operation name. A call style that hides the name entirely
    is caught by the runtime-versus-AST test below. An operation not in ``CLOUDWATCH_OPERATIONS`` is attributed to
    ElastiCache, so a new CloudWatch call fails the policy test until it is classified here."""
    names: set[str] = set()
    for path in sorted(CONTROLPLANE.glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and OPERATION.match(node.value):
                names.add(node.value)
            elif (
                isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and OPERATION.match(node.func.attr)
            ):
                names.add(node.func.attr)
    return {f"{'cloudwatch' if n in CLOUDWATCH_OPERATIONS else 'elasticache'}:{_pascal(n)}" for n in names}


def readme_policy_actions() -> set[str]:
    text = README.read_text(encoding="utf-8")
    block = text.split("### Minimal IAM policy", 1)[1].split("```json", 1)[1].split("```", 1)[0]
    actions = json.loads(block)["Statement"][0]["Action"]
    return set(actions)


async def _collect(audit_ns) -> tuple[dict[str, set[str]], set[str]]:
    per_tool: dict[str, set[str]] = defaultdict(set)
    async with Client(server.mcp) as c:
        registered = {t.name for t in await c.list_tools()}
        for name, args in AUDIT_CALLS:
            before = len(audit_ns.aws.operations)
            with contextlib.suppress(ToolError):
                await c.call_tool(name, args)
            per_tool[name] |= {f"{svc}:{op}" for svc, op in audit_ns.aws.operations[before:]}
    return per_tool, registered


def render(per_tool: dict[str, set[str]], registered: set[str]) -> str:
    aws_tools = sorted(t for t in registered if per_tool.get(t) or t.startswith("aws_"))
    lines = [
        "# IAM matrix",
        "",
        "Generated from the code by `tests/test_iam_policy.py` (do not edit by hand; regenerate with",
        "`UPDATE_IAM_MATRIX=1 uv run python -I -m pytest tests/test_iam_policy.py`). Every call is `Describe*`,",
        '`List*` or `cloudwatch:GetMetricData`, all with `Resource: "*"`. Tools not listed here make no AWS call and',
        "need no IAM permission (they reach the node directly).",
        "",
        "## Actions each tool needs",
        "",
        'A tool whose action is missing from the role returns `{"error": "AccessDenied", ...}` for that call; tools',
        "with several actions degrade to a partial answer when only some are denied.",
        "",
        "| Tool | Actions |",
        "| --- | --- |",
    ]
    for tool in aws_tools:
        acts = sorted(per_tool.get(tool, set()))
        lines.append(f"| `{tool}` | {', '.join(f'`{a}`' for a in acts) if acts else 'none recorded'} |")
    by_action: dict[str, list[str]] = defaultdict(list)
    for tool in aws_tools:
        for act in per_tool.get(tool, set()):
            by_action[act].append(tool)
    lines += [
        "",
        "## Tools affected when one action is not granted",
        "",
        "| Action | Tools that lose data |",
        "| --- | --- |",
    ]
    for act in sorted(by_action):
        lines.append(f"| `{act}` | {', '.join(f'`{t}`' for t in sorted(by_action[act]))} |")
    return "\n".join(lines) + "\n"


async def test_matrix_is_generated_from_the_code_and_lists_every_aws_tool(audit):  # noqa: F811
    per_tool, registered = await _collect(audit)
    text = render(per_tool, registered)
    if os.environ.get("UPDATE_IAM_MATRIX"):
        MATRIX.write_text(text, encoding="utf-8")
    assert MATRIX.exists(), "docs/iam-matrix.md is missing; run with UPDATE_IAM_MATRIX=1"
    assert MATRIX.read_text(encoding="utf-8") == text, "docs/iam-matrix.md is stale; run with UPDATE_IAM_MATRIX=1"
    listed = set(re.findall(r"^\| `([a-z_]+)` \|", text, flags=re.MULTILINE))
    assert {t for t in registered if t.startswith("aws_")} <= listed
    for tool in (t for t in registered if t.startswith("aws_")):
        assert per_tool[tool], f"{tool} recorded no AWS operation"


async def test_every_recorded_action_is_in_the_readme_policy(audit):  # noqa: F811
    per_tool, _ = await _collect(audit)
    recorded = set().union(*per_tool.values())
    missing = recorded - readme_policy_actions()
    assert not missing, f"README minimal IAM policy lacks: {sorted(missing)}"


def test_every_boto3_call_in_the_code_is_in_the_readme_policy():
    missing = static_actions() - readme_policy_actions()
    assert not missing, f"README minimal IAM policy lacks: {sorted(missing)}"


def test_readme_policy_has_no_action_the_code_never_calls():
    extra = readme_policy_actions() - static_actions()
    assert not extra, f"README policy grants more than the code needs: {sorted(extra)}"


async def test_the_ast_scan_sees_every_action_the_runtime_recording_saw(audit):  # noqa: F811
    per_tool, _ = await _collect(audit)
    assert set().union(*per_tool.values()) <= static_actions()


def test_static_scan_sees_the_known_calls():
    seen = static_actions()
    assert {"elasticache:DescribeReplicationGroups", "cloudwatch:GetMetricData", "cloudwatch:DescribeAlarms"} <= seen


def test_pascal_conversion_matches_aws_operation_names():
    assert _pascal("describe_cache_parameter_groups") == "DescribeCacheParameterGroups"
    assert _pascal("get_metric_data") == "GetMetricData"
