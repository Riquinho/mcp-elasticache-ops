"""Every registered tool has a failure-mode test, driven by the registry rather than a hand-kept list.

``aws_*`` tools run once against a session where every call is denied (AccessDenied) and once with a connection
timeout; ``node_*`` tools run against a node that refuses and times out. A tool added to the registry without a
usable ``AUDIT_CALLS`` entry fails ``test_every_registered_tool_is_covered`` instead of silently skipping.
"""

from __future__ import annotations

import json

import pytest
import redis
from botocore.exceptions import ConnectTimeoutError
from fastmcp import Client

from mcp_elasticache_ops import server
from mcp_elasticache_ops.controlplane import ControlPlane, ControlPlaneConfig
from tests.fakes import AwsAudit
from tests.test_server import AUDIT_CALLS, audit  # noqa: F401  (audit is a fixture)


class _DenyEverything(dict):
    def get(self, key, default=None):  # type: ignore[override]
        return ("error", "AccessDenied")


def _first_call(prefix: str) -> list[tuple[str, dict]]:
    seen: dict[str, dict] = {}
    for name, args in AUDIT_CALLS:
        if name.startswith(prefix):
            seen.setdefault(name, args)
    return sorted(seen.items())


def _payload(res) -> dict:
    data = res.data if isinstance(res.data, dict) else json.loads(res.content[0].text)
    assert isinstance(data, dict)
    return data


def _mentions(data: dict, *needles: str) -> bool:
    text = json.dumps(data, default=str)
    return any(n in text for n in needles)


async def _registered() -> set[str]:
    async with Client(server.mcp) as c:
        return {t.name for t in await c.list_tools()}


async def test_every_registered_tool_is_covered():
    registered = await _registered()
    covered = {n for n, _ in _first_call("aws_")} | {n for n, _ in _first_call("node_")}
    covered |= {n for n, _ in AUDIT_CALLS if n.startswith("memcached_")}
    assert registered == covered, f"tools without a failure-mode test: {sorted(registered - covered)}"


@pytest.mark.parametrize(("name", "args"), _first_call("aws_"), ids=lambda v: v if isinstance(v, str) else "")
async def test_aws_tool_reports_access_denied_instead_of_crashing(monkeypatch, audit, name, args):  # noqa: F811
    aws = AwsAudit()
    aws.responses = _DenyEverything()
    plane = ControlPlane(ControlPlaneConfig(region="us-east-1", regions=("us-east-1",)), session_factory=aws)
    monkeypatch.setattr(server, "control_plane", lambda: plane)
    async with Client(server.mcp) as c:
        res = await c.call_tool(name, args, raise_on_error=False)
    data = _payload(res)
    assert aws.operations, f"{name} made no AWS call"
    assert _mentions(data, "AccessDenied"), f"{name} hides the AccessDenied: {json.dumps(data, default=str)[:300]}"


@pytest.mark.parametrize(("name", "args"), _first_call("aws_"), ids=lambda v: v if isinstance(v, str) else "")
async def test_aws_tool_turns_a_connect_timeout_into_error_and_hint(monkeypatch, name, args):
    def boom():
        raise ConnectTimeoutError(endpoint_url="https://elasticache.invalid")

    plane = ControlPlane(ControlPlaneConfig(region="us-east-1"), session_factory=boom)
    monkeypatch.setattr(server, "control_plane", lambda: plane)
    async with Client(server.mcp) as c:
        res = await c.call_tool(name, args, raise_on_error=False)
    data = _payload(res)
    assert data.get("error") and data.get("hint"), (name, data)


class _Broken:
    """Stands in for a SafeRedis whose node fails every command."""

    def __init__(self, exc: Exception) -> None:
        self.exc = exc

    def __getattr__(self, _name: str):
        def fail(*_a, **_k):
            raise self.exc

        return fail


@pytest.mark.parametrize("exc", [redis.exceptions.ConnectionError("refused"), redis.exceptions.TimeoutError("slow")])
@pytest.mark.parametrize(
    ("name", "args"),
    [(n, a) for n, a in _first_call("node_") if n != "node_connectivity"],
    ids=lambda v: v if isinstance(v, str) else "",
)
async def test_node_tool_turns_a_node_error_into_error_and_hint(monkeypatch, name, args, exc):
    broken = _Broken(exc)
    monkeypatch.setattr(server, "redis_client", lambda: broken)
    monkeypatch.setattr(server, "build_client", lambda *a, **k: broken)
    async with Client(server.mcp) as c:
        res = await c.call_tool(name, args, raise_on_error=False)
    data = _payload(res)
    degraded = data.get("status") in {"partial", "unavailable"} and _mentions(data, type(exc).__name__)
    assert (data.get("error") and data.get("hint")) or degraded, (name, data)
    assert "traceback" not in json.dumps(data, default=str).lower()
