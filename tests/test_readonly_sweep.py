"""Read-only sweep over every registered MCP tool.

Every tool runs once through its ``AUDIT_CALLS`` entry against the recording fakes from ``tests/test_server.py``:
``AuditRedis`` (which validates each command with the real ``SafeRedis`` allowlist) and ``AwsAudit`` (a botocore
``before-call`` hook that answers without touching the network and records each operation). The sweep then asserts:

* every Redis command issued is in ``READ_ONLY_COMMANDS`` and none was rejected;
* every AWS operation is a read: ``Describe*``, ``List*`` or ``GetMetricData``;
* no write method was invoked, on Redis or on boto3.

``test_the_checker_rejects_writes`` proves the checker fails on a SET or a write operation, so a future tool that
writes cannot pass the sweep silently.
"""

from __future__ import annotations

import contextlib
import re

from fastmcp import Client
from fastmcp.exceptions import ToolError

from mcp_elasticache_ops import server
from mcp_elasticache_ops.safe_client import READ_ONLY_COMMANDS
from tests.test_server import AUDIT_CALLS, audit  # noqa: F401  (audit is a fixture)

AWS_READ_OPERATION = re.compile(r"^(Describe|List)[A-Za-z]+$|^GetMetricData$")
WRITE_WORDS = (
    "Create",
    "Delete",
    "Modify",
    "Reboot",
    "Reset",
    "Update",
    "Put",
    "Set",
    "Add",
    "Remove",
    "Start",
    "Stop",
)


def sweep_findings(
    redis_commands: list[str], redis_violations: list[str], aws_operations: list[tuple[str, str]]
) -> list[str]:
    """Human-readable list of every read-only violation; empty when the run was read-only."""
    findings = [f"rejected Redis command: {v}" for v in redis_violations]
    findings += [f"Redis command outside the allowlist: {c}" for c in redis_commands if c not in READ_ONLY_COMMANDS]
    for service, op in aws_operations:
        if service not in {"elasticache", "cloudwatch"}:
            findings.append(f"unexpected AWS service {service}:{op}")
        if not AWS_READ_OPERATION.match(op):
            findings.append(f"AWS operation is not a read: {service}:{op}")
        if any(op.startswith(word) for word in WRITE_WORDS):
            findings.append(f"write-named AWS operation: {service}:{op}")
    return findings


async def test_every_registered_tool_is_read_only(audit):  # noqa: F811
    async with Client(server.mcp) as client:
        registered = {t.name for t in await client.list_tools()}
        for name, args in AUDIT_CALLS:
            with contextlib.suppress(ToolError):  # canned replies are thin; only the attempted calls matter
                await client.call_tool(name, args)
    exercised = {name for name, _ in AUDIT_CALLS}
    assert registered <= exercised, f"tools never swept: {sorted(registered - exercised)}"
    assert audit.aws.operations, "the sweep recorded no AWS operation at all"
    assert audit.redis.commands, "the sweep recorded no Redis command at all"
    findings = sweep_findings(audit.redis.commands, audit.redis.violations, audit.aws.operations)
    assert not findings, findings


def test_the_checker_rejects_writes():
    assert sweep_findings(["SET"], [], []) == ["Redis command outside the allowlist: SET"]
    assert sweep_findings(["INFO"], ["FLUSHALL"], []) == ["rejected Redis command: FLUSHALL"]
    assert sweep_findings([], [], [("elasticache", "ModifyCacheCluster")]) == [
        "AWS operation is not a read: elasticache:ModifyCacheCluster",
        "write-named AWS operation: elasticache:ModifyCacheCluster",
    ]
    assert sweep_findings([], [], [("cloudwatch", "GetMetricData")]) == []
    assert sweep_findings(["PUBSUB NUMPAT", "INFO"], [], [("elasticache", "DescribeCacheClusters")]) == []
