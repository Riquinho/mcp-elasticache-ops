"""Cross-check the boto3 calls found in ``src/`` against ``tests/iam_actions.json`` and the read-only prefixes.

An AST scan collects every ``<client>.<operation>(...)`` call on a boto3 client (variables holding a
``.client(...)`` result plus the conventional client names). Each operation must be listed in the IAM action
pin, and must be a read operation (``describe_*``, ``list_*`` or ``get_metric_data``). Only ``controlplane/`` is
scanned: ``dataplane/`` is Redis-only (``test_readonly_audit`` forbids boto there), and its ``r.info()`` or
``client.execute_command`` calls would otherwise be mistaken for AWS operations.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

from tests.test_readonly_audit import CLIENT_PARAM_NAMES, _client_names

SRC = Path(__file__).resolve().parent.parent / "src" / "mcp_elasticache_ops"
IAM_PIN = Path(__file__).with_name("iam_actions.json")
READ_ONLY_PREFIXES = ("describe_", "list_", "get_metric_data")
# botocore client helpers that look like calls on a client but are not AWS operations.
CLIENT_HELPERS = {"get_paginator", "get_waiter", "can_paginate", "close"}
CLOUDWATCH_OPERATIONS = {"describe_alarms", "get_metric_data"}


def _pascal(snake: str) -> str:
    return "".join(part.capitalize() for part in snake.split("_"))


def client_operations(source: str) -> set[str]:
    """Snake-case operation names invoked on a boto3 client in ``source``."""
    tree = ast.parse(source)
    names = _client_names(tree) | CLIENT_PARAM_NAMES
    ops: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        receiver = node.func.value
        if not (isinstance(receiver, ast.Name) and receiver.id in names):
            continue
        if node.func.attr == "get_paginator":
            first = node.args[0] if node.args else None
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                ops.add(first.value)
        elif node.func.attr not in CLIENT_HELPERS:
            ops.add(node.func.attr)
    return ops


def scanned_operations() -> dict[str, set[str]]:
    """Map each boto3 operation found under ``src/controlplane`` to the relative paths that call it."""
    found: dict[str, set[str]] = {}
    for path in sorted((SRC / "controlplane").rglob("*.py")):
        for op in client_operations(path.read_text(encoding="utf-8")):
            found.setdefault(op, set()).add(path.relative_to(SRC).as_posix())
    return found


def pinned_actions() -> set[str]:
    pinned: dict[str, list[str]] = json.loads(IAM_PIN.read_text(encoding="utf-8"))
    return {action for actions in pinned.values() for action in actions}


def test_scanner_sees_known_operations():
    ops = set(scanned_operations())
    assert {"describe_engine_default_parameters", "get_metric_data", "describe_alarms"} <= ops


def test_every_client_operation_is_in_the_iam_pin():
    pinned = pinned_actions()
    missing = {
        op
        for op in scanned_operations()
        if f"{'cloudwatch' if op in CLOUDWATCH_OPERATIONS else 'elasticache'}:{_pascal(op)}" not in pinned
    }
    assert not missing, f"src/ calls operations missing from tests/iam_actions.json: {sorted(missing)}"


def test_no_client_operation_is_outside_the_read_only_prefixes():
    writes = {op: paths for op, paths in scanned_operations().items() if not op.startswith(READ_ONLY_PREFIXES)}
    assert not writes, f"write-capable boto3 operations in src/: {writes}"


def test_pinned_actions_are_all_read_operations():
    bad = sorted(
        a for a in pinned_actions() if not a.split(":", 1)[1].startswith(("Describe", "List", "GetMetricData"))
    )
    assert not bad, f"pinned IAM actions that are not read operations: {bad}"


def test_scanner_flags_a_write_call_and_ignores_paginator_helpers():
    source = (
        "def f(client):\n"
        "    client.modify_cache_cluster(CacheClusterId='x')\n"
        "    client.get_paginator('describe_cache_clusters')\n"
    )
    assert client_operations(source) == {"modify_cache_cluster", "describe_cache_clusters"}
