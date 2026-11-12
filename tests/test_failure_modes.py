"""Every registered tool has a failure-mode test, driven by the registry rather than a hand-kept list.

``aws_*`` tools run once against a session where every call is denied (AccessDenied) and once with a connection
timeout; ``node_*`` tools run against a node that refuses and times out. A tool added to the registry without a
usable ``AUDIT_CALLS`` entry fails ``test_every_registered_tool_is_covered`` instead of silently skipping.
"""

from __future__ import annotations

import json
import time

import pytest
import redis
from botocore.exceptions import ConnectTimeoutError
from fastmcp import Client

from mcp_elasticache_ops import dataplane, server
from mcp_elasticache_ops.config import DEFAULT_MAX_OUTPUT_CHARS
from mcp_elasticache_ops.controlplane import ControlPlane, ControlPlaneConfig
from tests.fakes import AwsAudit, FakeRedis
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


# ------------------------------------------------------- hanging nodes: partial result inside the budget


def _hang_fan(hang_for: float = 3.0):
    """Three shard primaries where the middle one blocks; returns (seed, factory)."""
    from tests.test_dataplane_unit import _fan_factory, _seed, _shard_client

    def hang():
        time.sleep(hang_for)
        return _shard_client("b")

    clients = {"10.0.0.1:6379": _shard_client("a"), "10.0.0.2:6379": hang, "10.0.0.3:6379": _shard_client("c")}
    factory, _ = _fan_factory(clients)
    return _seed(), factory


def test_cluster_triage_hanging_node_is_a_critical_entry_within_budget():
    seed, factory = _hang_fan()
    started = time.monotonic()
    out = dataplane.cluster_triage(seed, factory, max_seconds=0.6, per_node_timeout=0.3)
    assert time.monotonic() - started < 3.0
    assert out["per_node"]["10.0.0.2:6379"]["status"] == "unreachable"
    assert out["per_node"]["10.0.0.1:6379"]["status"] != "unreachable"
    assert any(f["severity"] == "critical" and "10.0.0.2:6379" in f["message"] for f in out["findings"])
    assert len(out["findings"]) <= dataplane.CLUSTER_TRIAGE_MAX_FINDINGS


def test_cluster_keyspace_sample_hanging_node_returns_partial_with_error_entry():
    seed, factory = _hang_fan()
    started = time.monotonic()
    out = dataplane.cluster_keyspace_sample(seed, factory, sample_size=60, max_seconds=0.6, per_node_timeout=0.3)
    assert time.monotonic() - started < 3.0
    assert out["per_shard"]["10.0.0.2:6379"]["status"] == "unreachable"
    assert out["per_shard"]["10.0.0.2:6379"]["error"]
    assert out["partial"] is True and out["shards_ok"] == 2
    assert out["sampled_keys"] > 0


def test_node_doctor_hanging_node_returns_partial_with_error_within_budget():
    class Stuck(FakeRedis):
        def info(self, section=None):
            time.sleep(3)
            return {}

    started = time.monotonic()
    out = dataplane.node_doctor(Stuck(), max_seconds=0.4)
    assert time.monotonic() - started < 2.0
    assert out["partial"] is True and "did not answer" in out["error"]
    assert out["findings"][0]["severity"] == "critical"


def test_node_doctor_without_a_budget_is_unchanged():
    out = dataplane.node_doctor(FakeRedis(infos={"server": {"redis_version": "7.1.0"}}))
    assert "partial" not in out and "error" not in out


# ------------------------------------- COMMANDLOG and CLUSTER LINKS sections of node_cluster_triage

_NODE_IDS = {"10.0.0.1:6379": "p1", "10.0.0.2:6379": "p2", "10.0.0.3:6379": "p3"}
_VALKEY8 = {"valkey_version": "8.0.1", "redis_version": "7.2.4"}
_PRE_VALKEY8 = {"redis_version": "7.1.0"}


def _bus_client(endpoint: str, server: dict, *, big_reply: bool = False, buffer: int = 0, hang_for: float = 0.0):
    """A shard primary with a CLUSTER LINKS reply to its peers and, on Valkey 8, a COMMANDLOG."""
    from tests.test_dataplane_unit import _mem_info, _shard_data

    me = _NODE_IDS[endpoint]
    peers = [i for i in ("p1", "p2", "p3", "r1") if i != me]
    client = FakeRedis(infos={"memory": _mem_info(), "server": server}, data=_shard_data(me, 20, 100))
    client.commands["CLUSTER LINKS"] = [
        ["direction", "to", "node", peer, "send-buffer-allocated", buffer, "send-buffer-used", 0] for peer in peers
    ]
    if server is _VALKEY8:
        for kind in ("slow", "large-request", "large-reply"):
            rows = [[1, 1700000000, 20 * 1024 * 1024, ["GET", "k"], "10.1.1.1:5000", "app"]] if big_reply else []
            client.commands[f"COMMANDLOG GET 5 {kind}"] = rows if kind == "large-reply" else []
            client.commands[f"COMMANDLOG LEN {kind}"] = len(rows) if kind == "large-reply" else 0
    if hang_for:
        original = client.info

        def slow_info(section=None):
            time.sleep(hang_for)
            return original(section)

        client.info = slow_info  # type: ignore[method-assign]
    return client


def _triage(clients, **kw):
    from tests.test_dataplane_unit import _fan_factory, _seed

    factory, _ = _fan_factory(clients)
    started = time.monotonic()
    out = dataplane.cluster_triage(_seed(), factory, **kw)
    return out, time.monotonic() - started


def _assert_bounded(out: dict) -> None:
    assert len(out["findings"]) <= dataplane.CLUSTER_TRIAGE_MAX_FINDINGS
    assert len(json.dumps(server.cap_output(out, DEFAULT_MAX_OUTPUT_CHARS), default=str)) <= DEFAULT_MAX_OUTPUT_CHARS


def test_cluster_triage_aggregates_commandlog_and_links_across_shards():
    clients = {ep: _bus_client(ep, _VALKEY8, big_reply=ep != "10.0.0.2:6379") for ep in _NODE_IDS}
    clients["10.0.0.3:6379"] = _bus_client("10.0.0.3:6379", _VALKEY8, big_reply=True, buffer=200 * 1024 * 1024)
    out, _ = _triage(clients, max_seconds=5)
    assert out["commandlog"]["reached"] == "reached 3/3 nodes"
    assert out["cluster_links"] == {"reached": "reached 3/3 nodes", "max_send_buffer_bytes": 200 * 1024 * 1024}
    big = [f for f in out["findings"] if f.get("source") == "commandlog" and f["severity"] == "critical"]
    assert big and sorted(big[0]["nodes"]) == ["10.0.0.1:6379", "10.0.0.3:6379"]  # merged, not repeated per node
    assert any(f.get("source") == "cluster links" for f in out["findings"])
    _assert_bounded(out)


def test_cluster_triage_hanging_node_keeps_reached_line_for_new_sections():
    clients = {ep: _bus_client(ep, _VALKEY8) for ep in _NODE_IDS}
    clients["10.0.0.2:6379"] = lambda: _bus_client("10.0.0.2:6379", _VALKEY8, hang_for=3.0)
    out, elapsed = _triage(clients, max_seconds=0.8, per_node_timeout=0.4)
    assert elapsed < 3.0
    assert out["per_node"]["10.0.0.2:6379"]["status"] == "unreachable"
    assert out["commandlog"]["reached"] == "reached 2/3 nodes"
    assert out["cluster_links"]["reached"] == "reached 2/3 nodes"
    assert out["reached"].startswith("reached 2/3 shards")
    _assert_bounded(out)


def test_cluster_triage_one_shard_down_is_isolated_from_commandlog_and_links():
    clients = {ep: _bus_client(ep, _VALKEY8, big_reply=True) for ep in _NODE_IDS}
    clients["10.0.0.3:6379"] = redis.ConnectionError("connection refused")
    out, _ = _triage(clients, max_seconds=5)
    assert out["per_node"]["10.0.0.3:6379"]["status"] == "unreachable"
    assert out["commandlog"]["reached"] == "reached 2/3 nodes"
    assert out["cluster_links"]["reached"] == "reached 2/3 nodes"
    assert out["reached"].startswith("reached 2/3 shards") and out["partial"] is True
    assert any(f["severity"] == "critical" and "10.0.0.3:6379" in f["message"] for f in out["findings"])
    assert any(f.get("source") == "commandlog" for f in out["findings"])
    _assert_bounded(out)


def test_cluster_triage_pre_valkey8_node_has_no_commandlog_and_no_error():
    clients = {ep: _bus_client(ep, _VALKEY8, big_reply=True) for ep in _NODE_IDS}
    clients["10.0.0.2:6379"] = _bus_client("10.0.0.2:6379", _PRE_VALKEY8)
    out, _ = _triage(clients, max_seconds=5)
    assert out["commandlog"]["reached"] == "reached 2/3 nodes"
    assert out["cluster_links"]["reached"] == "reached 3/3 nodes"
    assert out["per_node"]["10.0.0.2:6379"]["status"] != "unreachable"
    assert not any("COMMANDLOG" in f["message"] and "10.0.0.2:6379" in f.get("nodes", []) for f in out["findings"])
    assert out["reached"].startswith("reached 3/3 shards")
    _assert_bounded(out)
