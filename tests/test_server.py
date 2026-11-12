import contextlib
import json
from urllib.parse import urlparse

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from mcp_elasticache_ops import server


@pytest.fixture()
def env(monkeypatch, seeded):
    u = urlparse(seeded)
    monkeypatch.setenv("ELASTICACHE_HOST", u.hostname)
    monkeypatch.setenv("ELASTICACHE_PORT", str(u.port or 6379))
    monkeypatch.setenv("ELASTICACHE_CONTROL_PLANE", "false")
    server.redis_client.cache_clear()
    server.control_plane.cache_clear()
    yield
    server.redis_client.cache_clear()
    server.control_plane.cache_clear()


def _data(result):
    if result.structured_content is not None:
        return result.structured_content.get("result", result.structured_content)
    return json.loads(result.content[0].text)


async def test_all_tools_read_only():
    async with Client(server.mcp) as c:
        tools = await c.list_tools()
    names = {t.name for t in tools}
    assert len(tools) == 65
    assert {
        "node_health",
        "node_info",
        "node_memory",
        "node_slowlog",
        "node_clients",
        "node_latency",
        "node_commandstats",
        "node_keyspace_sample",
        "node_replication",
        "node_cluster",
        "memcached_stats",
        "aws_replication_groups",
        "aws_cache_clusters",
        "aws_serverless_caches",
        "aws_events",
        "aws_parameters",
        "aws_metrics",
    } <= names  # the original 17
    assert {
        "node_cluster_nodes",
        "node_cluster_health",
        "aws_snapshots",
        "aws_users",
        "aws_user_groups",
        "aws_user_access_map",
        "aws_global_replication_groups",
        "aws_reserved_nodes",
        "aws_service_updates",
        "aws_subnet_groups",
    } <= names
    assert {"node_config", "aws_triage", "aws_parameter_drift"} <= names  # round 02
    assert {
        "node_cluster_keyspace_sample",
        "node_cluster_slowlog",
        "node_cluster_memory",
        "node_acl_log",
        "aws_cluster_overview",
    } <= names  # round 03
    assert {"node_triage", "aws_alarms", "memcached_cluster_stats"} <= names  # round 04
    assert {"aws_engine_versions", "aws_parameter_groups"} <= names  # round 06
    assert {"node_pubsub", "node_cluster_triage", "aws_maintenance"} <= names  # round 11
    assert {"memcached_discovery", "aws_cost_overview"} <= names  # round 12
    assert {"node_latency_events", "aws_shard_balance"} <= names  # round 14
    for t in tools:
        assert t.annotations.read_only_hint is True, t.name
        assert t.annotations.destructive_hint is False, t.name


async def test_validation_rejects_out_of_range():
    async with Client(server.mcp) as c:
        with pytest.raises(ToolError):
            await c.call_tool("node_slowlog", {"count": 5000})


def test_main_help(capsys):
    with pytest.raises(SystemExit) as exc:
        server.main(["--help"])
    assert exc.value.code == 0
    assert "--transport" in capsys.readouterr().out


@pytest.mark.integration
async def test_tools_end_to_end(env):
    async with Client(server.mcp) as c:
        health = _data(await c.call_tool("node_health", {}))
        assert health["role"] == "master"
        ks = _data(await c.call_tool("node_keyspace_sample", {"sample_size": 50, "top": 3}))
        assert ks["sampled_keys"] == 50
        slow = _data(await c.call_tool("node_slowlog", {"count": 5}))
        assert slow["returned"] <= 5
        aws = _data(await c.call_tool("aws_replication_groups", {}))
        assert "unavailable" in aws


@pytest.mark.integration
async def test_node_config_end_to_end(env):
    async with Client(server.mcp) as c:
        cfg = _data(await c.call_tool("node_config", {}))
    assert "findings" in cfg and "available" in cfg
    assert "requirepass" not in cfg.get("config", {})


# ------------------------------------------------------------------ output cap


async def test_every_registered_tool_is_wrapped_with_the_output_cap():
    tools = await server.mcp.list_tools()
    assert len(tools) == 65
    unwrapped = [t.name for t in tools if not getattr(t.fn, "__capped__", False)]
    assert unwrapped == []


def test_cap_output_small_result_is_returned_untouched():
    small = {"findings": [{"severity": "info", "message": "x"}], "rows": list(range(10))}
    assert server.cap_output(small, 60000) is small
    assert server.cap_output(["not", "a", "dict"], 5) == ["not", "a", "dict"]


def _big():
    return {
        "status": "ok",
        "count": 3000,
        "findings": [{"severity": "warning", "message": f"finding {i}"} for i in range(5)],
        "summary": {"nodes": 3000},
        "notes": ["keep me"],
        "rows": [{"id": i, "payload": "x" * 40} for i in range(3000)],
        "nested": {"a": {"series": list(range(5000))}},
    }


def test_cap_output_trims_lists_keeps_findings_and_does_not_mutate():
    import copy

    original = _big()
    snapshot = copy.deepcopy(original)
    out = server.cap_output(original, 8000)
    assert original == snapshot  # input untouched
    assert out is not original
    assert out["truncated"] is True and out["omitted"] > 0
    assert out["original_chars"] > 8000
    assert "MCP_MAX_OUTPUT_CHARS=8000" in out["truncation_hint"]
    assert out["findings"] == snapshot["findings"] and out["summary"] == snapshot["summary"]
    assert out["notes"] == ["keep me"] and out["count"] == 3000 and out["status"] == "ok"
    assert out["rows"] == snapshot["rows"][: len(out["rows"])]  # head of the list
    assert len(out["rows"]) < 3000
    assert len(json.dumps(out)) <= 8000 + 400  # the added keys are the only overshoot


def test_cap_output_adds_no_flags_when_it_fits():
    out = server.cap_output(_big(), 10_000_000)
    assert "truncated" not in out


def test_tool_wrapper_reads_limit_from_env(monkeypatch):
    monkeypatch.setattr(server.dataplane, "triage", lambda *a, **k: _big())
    monkeypatch.setattr(server, "redis_client", lambda: object())
    monkeypatch.setattr(server, "_serverless", lambda: False)
    monkeypatch.setenv("MCP_MAX_OUTPUT_CHARS", "6000")
    out = server.node_triage()
    assert out["truncated"] is True and len(out["rows"]) < 3000
    monkeypatch.setenv("MCP_MAX_OUTPUT_CHARS", "5000000")
    assert "truncated" not in server.node_triage()


def test_tool_wrapper_rejects_invalid_limit(monkeypatch):
    from mcp_elasticache_ops.config import ConfigError

    monkeypatch.setattr(server.dataplane, "triage", lambda *a, **k: {})
    monkeypatch.setattr(server, "redis_client", lambda: object())
    monkeypatch.setattr(server, "_serverless", lambda: False)
    monkeypatch.setenv("MCP_MAX_OUTPUT_CHARS", "lots")
    with pytest.raises(ConfigError, match="MCP_MAX_OUTPUT_CHARS"):
        server.node_triage()


# ------------------------------------------------------------------ README / registry sync


def _readme_text() -> str:
    from pathlib import Path

    return (
        (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
        + "\n"
        + (Path(__file__).resolve().parent.parent / "docs" / "tools.md").read_text(encoding="utf-8")
    )


async def test_readme_tool_table_lists_exactly_the_registered_tools():
    import re

    registered = {t.name for t in await server.mcp.list_tools()}
    documented = set(re.findall(r"^\| `([a-z_]+)` \|", _readme_text(), flags=re.MULTILINE))
    assert registered - documented == set(), "tools missing from the README table"
    assert documented - registered == set(), "README lists tools that are not registered"


async def test_readme_tool_count_matches_registry():
    import re

    match = re.search(r"All (\d+) tools are annotated", _readme_text())
    assert match is not None
    assert int(match.group(1)) == len(await server.mcp.list_tools())


def test_capped_wrapper_keeps_findings_first_and_marks_truncation(monkeypatch):
    monkeypatch.setenv("MCP_MAX_OUTPUT_CHARS", "4000")

    @server._capped
    def fake_tool() -> dict:
        return _big()

    out = fake_tool()
    assert list(out)[: len(_big())] == list(_big())  # original key order, findings stay before bulky lists
    keys = list(out)
    assert keys.index("findings") < keys.index("rows")
    assert out["truncated"] is True and out["omitted"] > 0
    assert len(out["findings"]) == 5


# ------------------------------------------------------------------ failure modes (node_* and memcached_*)


class _Unreachable:
    """Stands in for a redis client whose every call fails with ``make()``."""

    def __init__(self, make):
        self._make = make

    def __getattr__(self, name):
        def call(*args, **kwargs):
            raise self._make()

        return call


def _redis_failures():
    import redis

    return {
        "timeout": (lambda: redis.TimeoutError("Timeout reading from socket"), "did not answer"),
        "refused": (
            lambda: redis.ConnectionError("Error 111 connecting to h:6379. Connection refused."),
            "Cannot reach",
        ),
        "tls": (
            lambda: redis.ConnectionError("Error 1 connecting to h:6379. [SSL: WRONG_VERSION_NUMBER] wrong version"),
            "ELASTICACHE_TLS",
        ),
        "auth": (lambda: redis.AuthenticationError("invalid username-password pair"), "credentials"),
    }


@pytest.mark.parametrize("failure", ["timeout", "refused", "tls", "auth"])
async def test_every_node_tool_returns_a_structured_failure_with_a_hint(monkeypatch, failure):
    make, hint_part = _redis_failures()[failure]
    monkeypatch.setenv("ELASTICACHE_HOST", "node.example.invalid")
    monkeypatch.setattr(server, "redis_client", lambda: _Unreachable(make))
    monkeypatch.setattr(server, "_node_client", lambda host, port: _Unreachable(make))
    async with Client(server.mcp) as client:
        tools = [t for t in await client.list_tools() if t.name.startswith("node_")]
        assert len(tools) >= 18
        for tool in tools:
            args = dict.fromkeys(tool.input_schema.get("required", []), "x")
            result = await client.call_tool(tool.name, args, raise_on_error=False)
            assert not result.is_error, f"{tool.name} raised: {result.content}"
            data = _data(result)
            text = json.dumps(data, default=str)
            assert "Traceback" not in text, tool.name
            top_level_error = isinstance(data, dict) and "error" in data and "hint" in data
            degraded = isinstance(data, dict) and (
                data.get("status") in {"partial", "error"}
                or data.get("unavailable")
                or data.get("notes")
                or data.get("findings")
                or data.get("shards_unreachable") is not None
            )
            assert top_level_error or degraded, f"{tool.name}: {text[:300]}"
            if top_level_error:
                assert hint_part in data["hint"], f"{tool.name}: {data['hint']}"


def test_tls_handshake_error_hints_at_tls_and_endpoint_settings():
    import redis

    out = server.connection_error_result(redis.ConnectionError("[SSL: CERTIFICATE_VERIFY_FAILED] hostname mismatch"))
    assert "ELASTICACHE_TLS" in out["hint"] and "ELASTICACHE_HOST" in out["hint"]
    assert out["error"] == "ConnectionError"


@pytest.mark.parametrize("tool", ["memcached_stats", "memcached_cluster_stats"])
async def test_memcached_tools_survive_socket_timeouts(monkeypatch, tool):
    import socket

    def timeout(*args, **kwargs):
        raise TimeoutError("timed out")

    monkeypatch.setattr(socket, "create_connection", timeout)
    monkeypatch.setenv("MEMCACHED_HOST", "mc.example.invalid")
    monkeypatch.setenv("MEMCACHED_NODES", "mc1.example.invalid:11211,mc2.example.invalid:11211")
    async with Client(server.mcp) as client:
        result = await client.call_tool(tool, {}, raise_on_error=False)
    assert not result.is_error
    data = _data(result)
    assert data.get("hint") or data.get("status") in {"partial", "error"}


async def test_every_tool_has_a_short_docstring_and_readme_rows_match_registry():
    import re
    from pathlib import Path

    async with Client(server.mcp) as c:
        tools = await c.list_tools()
    for t in tools:
        assert t.description and t.description.strip(), t.name
        assert len(t.description) < 400, f"{t.name}: description is {len(t.description)} chars"
    readme = (
        (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
        + "\n"
        + (Path(__file__).resolve().parent.parent / "docs" / "tools.md").read_text(encoding="utf-8")
    )
    rows = re.findall(r"^\| `((?:node|aws|memcached)_[a-z_]+)` \|", readme, flags=re.M)
    assert len(rows) == len(set(rows)), "duplicate README tool rows"
    assert set(rows) == {t.name for t in tools}


# ------------------------------------------------------------- on-call prompts

RUNBOOKS = {"oncall_high_cpu", "oncall_evictions_memory", "oncall_replication_lag", "oncall_connection_storm"}


async def test_oncall_prompts_are_registered_and_do_not_change_the_tool_count():
    prompts = await server.mcp.list_prompts()
    assert {p.name for p in prompts} == RUNBOOKS
    async with Client(server.mcp) as c:
        assert {p.name for p in await c.list_prompts()} == RUNBOOKS
        assert len(await c.list_tools()) == 65  # prompts are not tools


@pytest.mark.parametrize("name", sorted(RUNBOOKS))
async def test_oncall_prompt_only_names_tools_that_exist_and_chains_several(name):
    import re

    async with Client(server.mcp) as c:
        tool_names = {t.name for t in await c.list_tools()}
        result = await c.get_prompt(name, {"replication_group_id": "orders-prod"})
    text = "\n".join(m.content.text for m in result.messages)
    assert "orders-prod" in text
    named = set(re.findall(r"`((?:aws|node|memcached)_[a-z_]+)`", text))
    assert len(named) >= 4
    assert named <= tool_names, sorted(named - tool_names)
    assert "aws_triage" in named and "aws_metrics" in named


async def test_oncall_high_cpu_runs_the_documented_sequence():
    async with Client(server.mcp) as c:
        result = await c.get_prompt("oncall_high_cpu", {"replication_group_id": "rg"})
    text = result.messages[0].content.text
    order = ["`aws_triage`", "`node_triage`", "`node_cluster_slowlog`", "`aws_metrics`"]
    positions = [text.index(t) for t in order]
    assert positions == sorted(positions)


# ------------------------------------------------------------ runtime read-only audit

AUDIT_CALLS: list[tuple[str, dict]] = [
    ("node_health", {}),
    ("node_triage", {}),
    ("node_cluster_triage", {}),
    ("node_hot_slots", {}),
    ("node_pubsub", {}),
    ("aws_maintenance", {}),
    ("aws_maintenance", {"replication_group_id": "audit-rg"}),
    ("node_info", {}),
    ("node_memory", {}),
    ("node_config", {}),
    ("node_slowlog", {}),
    ("node_clients", {}),
    ("node_clients_summary", {}),
    ("node_latency", {}),
    ("node_commandlog", {}),
    ("node_commandstats", {}),
    ("node_latency_events", {}),
    ("node_keyspace_sample", {"sample_size": 10}),
    ("node_keyspace_sample", {"sample_size": 10, "include_access": True}),
    ("node_keyspace_sample", {"sample_size": 10, "include_sizes": True, "size_threshold": 1}),
    ("node_doctor", {}),
    ("node_replication", {}),
    ("node_acl_log", {}),
    ("node_cluster", {}),
    ("node_cluster_nodes", {}),
    ("node_cluster_health", {}),
    ("node_cluster_keyspace_sample", {"sample_size": 10}),
    ("node_cluster_slowlog", {}),
    ("node_cluster_memory", {}),
    ("memcached_stats", {}),
    ("memcached_stats", {"group": "slabs"}),
    ("memcached_cluster_stats", {}),
    ("memcached_discovery", {"cache_cluster_id": "audit-mc"}),
    ("aws_replication_groups", {}),
    ("aws_replication_groups", {"replication_group_id": "audit-rg", "region": "eu-west-1"}),
    ("aws_cache_clusters", {}),
    ("aws_serverless_caches", {}),
    ("aws_events", {"source_type": "replication-group", "source_identifier": "audit-rg"}),
    ("aws_parameters", {"parameter_group": "default.redis7"}),
    ("aws_parameters", {"parameter_group": "default.redis7", "diff_engine_defaults": True}),
    ("aws_snapshots", {}),
    ("aws_serverless_snapshots", {}),
    ("aws_users", {}),
    ("aws_user_groups", {}),
    ("aws_user_access_map", {}),
    ("aws_global_replication_groups", {}),
    ("aws_global_datastore_failover_readiness", {}),
    ("aws_reserved_nodes", {}),
    ("aws_reserved_offerings", {"node_type": "cache.r6g.large", "engine": "redis"}),
    ("aws_engine_versions", {"engine": "redis"}),
    ("aws_parameter_groups", {}),
    ("aws_service_updates", {}),
    ("aws_subnet_groups", {}),
    ("aws_backup_audit", {}),
    ("aws_replication_group_audit", {}),
    ("aws_replication_group_audit", {}),
    ("aws_metrics", {"replication_group_id": "audit-rg"}),
    ("aws_metrics", {"cache_cluster_id": "sc", "serverless": True}),
    ("aws_metrics", {"cache_cluster_id": "audit-mc"}),
    ("aws_parameter_drift", {"group_a": "a", "group_b": "b"}),
    ("aws_triage", {"replication_group_id": "audit-rg"}),
    ("aws_serverless_triage", {"serverless_cache_name": "audit-sc"}),
    ("aws_shard_balance", {"replication_group_id": "audit-rg"}),
    ("aws_snapshot_restore_readiness", {"replication_group_id": "audit-rg"}),
    ("aws_snapshot_restore_readiness", {"serverless_cache_name": "audit-sc"}),
    ("aws_failover_readiness", {"replication_group_id": "audit-rg"}),
    ("aws_reader_endpoint_audit", {"replication_group_id": "audit-rg"}),
    ("aws_scale_readiness", {"replication_group_id": "audit-rg"}),
    ("aws_upgrade_plan", {"replication_group_id": "audit-rg"}),
    ("aws_alarms", {}),  # fleet mode over both configured regions
    ("aws_alarms", {"replication_group_id": "audit-rg"}),
    ("aws_cluster_overview", {}),  # fleet mode
    ("aws_cluster_overview", {"replication_group_id": "audit-rg"}),
    ("aws_cost_overview", {}),
    ("aws_capacity_forecast", {}),
    ("aws_security_audit", {}),
    ("node_connectivity", {}),
]


@pytest.fixture()
def audit(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from mcp_elasticache_ops import memcached
    from mcp_elasticache_ops.config import ControlPlaneConfig
    from mcp_elasticache_ops.controlplane import ControlPlane

    from .fakes import AuditRedis, AuditSocket, AwsAudit

    for var in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "none"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("MEMCACHED_HOST", "10.0.0.9")
    monkeypatch.setenv("MEMCACHED_NODES", "10.0.0.9:11211,10.0.0.10:11211")
    aws, redis_audit, memcached_sent = AwsAudit(), AuditRedis(), []
    plane = ControlPlane(
        ControlPlaneConfig(region="us-east-1", regions=("us-east-1", "eu-west-1")), session_factory=aws
    )
    client = redis_audit.build()
    monkeypatch.setattr(server, "control_plane", lambda: plane)
    monkeypatch.setattr(server, "redis_client", lambda: client)
    monkeypatch.setattr(server, "build_client", lambda *a, **k: redis_audit.build())
    monkeypatch.setattr(
        memcached, "socket", SimpleNamespace(create_connection=lambda *a, **k: AuditSocket(memcached_sent))
    )
    # node_connectivity: no real DNS or sockets; PING goes through the recording Redis
    import ssl

    from mcp_elasticache_ops import connection

    class _Sock(AuditSocket):
        def close(self) -> None:
            return None

        def settimeout(self, _t: float) -> None:
            return None

        def recv(self, _size: int) -> bytes:
            return b"+PONG\r\n"

        def sendall(self, _data: bytes) -> None:
            return None

    class _PlainOnly:
        def wrap_socket(self, *_a: object, **_k: object):
            raise ssl.SSLError("plaintext server")

    fake_socket = SimpleNamespace(
        AF_INET=2,
        SOCK_STREAM=1,
        getaddrinfo=lambda host, port, **k: [(2, 1, 6, "", ("10.0.0.5", port))],
        create_connection=lambda *a, **k: _Sock([]),
    )
    monkeypatch.setattr(connection, "socket", fake_socket)
    monkeypatch.setattr(connection, "_tls_context", lambda cfg, verify: _PlainOnly())
    monkeypatch.setattr(connection, "build_client", lambda *a, **k: redis_audit.build())
    return SimpleNamespace(aws=aws, redis=redis_audit, memcached=memcached_sent)


async def test_every_tool_only_issues_read_operations(audit):
    import re

    from mcp_elasticache_ops import memcached
    from mcp_elasticache_ops.safe_client import READ_ONLY_COMMANDS

    async with Client(server.mcp) as c:
        registered = {t.name for t in await c.list_tools()}
        exercised = {name for name, _ in AUDIT_CALLS}
        assert registered == exercised, (
            f"tools missing from AUDIT_CALLS: {sorted(registered - exercised)}; "
            f"stale entries: {sorted(exercised - registered)}"
        )
        for name, args in AUDIT_CALLS:
            with contextlib.suppress(ToolError):  # thin canned replies; only attempted calls matter
                await c.call_tool(name, args)
    assert audit.aws.operations, "no AWS operation was recorded at all"
    for service, op in audit.aws.operations:
        assert service in {"elasticache", "cloudwatch"}, (service, op)
        assert re.match(r"^(Describe|List|GetMetricData)", op), f"{service}:{op} is not a read operation"
    assert {op for _, op in audit.aws.operations} >= {"DescribeReplicationGroups", "GetMetricData", "DescribeAlarms"}
    regions_hit = {op for _, op in audit.aws.operations}
    assert regions_hit  # fleet mode ran through the recording session as well
    assert audit.redis.violations == []
    assert audit.redis.commands, "no Redis command was recorded at all"
    assert set(audit.redis.commands) <= READ_ONLY_COMMANDS
    assert {"PUBSUB CHANNELS", "PUBSUB NUMSUB", "PUBSUB NUMPAT"} <= set(audit.redis.commands)
    assert {"DescribeUpdateActions", "DescribeServiceUpdates", "DescribeCacheClusters"} <= {
        op for _, op in audit.aws.operations
    }
    assert audit.memcached, "no memcached command was recorded at all"
    assert set(audit.memcached) <= memcached.ALLOWED_COMMANDS


def _boto_errors():
    from botocore.exceptions import EndpointConnectionError, NoCredentialsError

    return [NoCredentialsError(), EndpointConnectionError(endpoint_url="https://elasticache.invalid")]


@pytest.mark.parametrize("exc", _boto_errors(), ids=lambda e: type(e).__name__)
async def test_every_aws_tool_turns_botocore_connection_errors_into_error_and_hint(monkeypatch, exc):
    from mcp_elasticache_ops.controlplane import ControlPlane, ControlPlaneConfig

    def boom():
        raise exc

    plane = ControlPlane(ControlPlaneConfig(region="us-east-1"), session_factory=boom)
    monkeypatch.setattr(server, "control_plane", lambda: plane)
    calls = [(n, a) for n, a in AUDIT_CALLS if n.startswith("aws_")]
    assert len(calls) >= 20
    async with Client(server.mcp) as c:
        for name, args in calls:
            res = await c.call_tool(name, args, raise_on_error=False)
            data = res.data if isinstance(res.data, dict) else json.loads(res.content[0].text)
            assert isinstance(data, dict) and data.get("error"), (name, data)
            assert data.get("hint"), (name, data)


# ------------------------------------------------------------------ node_connectivity registration


async def test_node_connectivity_is_read_only_and_never_echoes_the_secret(monkeypatch):
    import socket

    def no_dns(*a, **k):
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", no_dns)
    monkeypatch.setenv("ELASTICACHE_HOST", "missing.example.invalid")
    monkeypatch.setenv("ELASTICACHE_PASSWORD", "hunter2-secret")
    tools = {t.name: t for t in await server.mcp.list_tools()}
    assert tools["node_connectivity"].annotations.read_only_hint is True
    assert getattr(tools["node_connectivity"].fn, "__capped__", False)
    async with Client(server.mcp) as c:
        out = await c.call_tool("node_connectivity", {})
    data = _data(out)
    assert data["failed_stage"] == "dns" and data["findings"]
    assert "hunter2-secret" not in json.dumps(data)
