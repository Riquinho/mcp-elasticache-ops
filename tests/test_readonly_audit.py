"""Read-only invariant audit over the split ``controlplane/`` and ``dataplane/`` packages.

Static (AST) scan of every module: AWS calls are limited to ``describe_*``, ``list_*``,
``get_metric_data`` and paginators over those, and nothing reaches Redis except through a
``SafeRedis`` handed in by ``connection.py``. A module added to either package must be listed in
``AUDITED_MODULES`` below, which forces a human look at it.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parent.parent / "src" / "mcp_elasticache_ops"
PACKAGES = ("controlplane", "dataplane")

AUDITED_MODULES = {
    "controlplane/__init__.py",
    "controlplane/_core.py",
    "controlplane/_shared.py",
    "controlplane/cost.py",
    "controlplane/cost_rules.py",
    "controlplane/failover.py",
    "controlplane/inventory.py",
    "controlplane/inventory_views.py",
    "controlplane/upgrade.py",
    "controlplane/monitoring.py",
    "controlplane/plane.py",
    "controlplane/restore.py",
    "controlplane/scale.py",
    "controlplane/scale_view.py",
    "controlplane/security.py",
    "controlplane/triage.py",
    "controlplane/triage_events.py",
    "controlplane/triage_overview.py",
    "controlplane/alarm_quality.py",
    "controlplane/group_audit.py",
    "controlplane/triage_shards.py",
    "dataplane/__init__.py",
    "dataplane/_core.py",
    "dataplane/acl_pubsub.py",
    "dataplane/clients.py",
    "dataplane/config_stats.py",
    "dataplane/doctor.py",
    "dataplane/fanout.py",
    "dataplane/hot_slots.py",
    "dataplane/health.py",
    "dataplane/keyspace.py",
    "dataplane/memory_breakdown.py",
    "dataplane/replication.py",
    "dataplane/topology.py",
    "dataplane/triage_report.py",
}

READ_ONLY_PREFIXES = ("describe_", "list_", "get_metric_data")
CLIENT_PARAM_NAMES = {"client", "cw", "ec", "cloudwatch", "elasticache"}
RAW_REDIS_NAMES = {
    "Redis",
    "StrictRedis",
    "RedisCluster",
    "ConnectionPool",
    "BlockingConnectionPool",
    "Sentinel",
    "from_url",
}
# Attributes that talk to the wire without going through SafeRedis.execute_command's allowlist.
WIRE_BYPASS_ATTRS = {"connection_pool", "get_connection", "send_command", "send_packed_command", "parse_response"}


def _modules() -> dict[str, Path]:
    return {p.relative_to(SRC).as_posix(): p for pkg in PACKAGES for p in sorted((SRC / pkg).rglob("*.py"))}


def _client_names(tree: ast.AST, params: bool = True) -> set[str]:
    """Variables that hold a boto3 client: ``x = <anything>.client(...)`` plus conventional parameter names."""
    names = set(CLIENT_PARAM_NAMES) if params else set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            f = node.value.func
            if isinstance(f, ast.Attribute) and f.attr == "client":
                names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
    return names


def _enclosing_functions(tree: ast.AST) -> dict[int, ast.AST]:
    owner: dict[int, ast.AST] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for child in ast.walk(fn):
                owner[id(child)] = fn  # ast.walk is breadth-first: inner functions overwrite outer ones
    return owner


def _guards_with_allowlist(fn: ast.AST | None) -> bool:
    """True when the function refuses non-read-only operation names (``op.startswith(ALLOWED_PREFIXES)``)."""
    if fn is None:
        return False
    return any(
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "startswith"
        and any(isinstance(a, ast.Name) and a.id == "ALLOWED_PREFIXES" for a in n.args)
        for n in ast.walk(fn)
    )


def aws_violations(source: str, params: bool = True) -> list[str]:
    tree = ast.parse(source)
    clients = _client_names(tree, params)
    owner = _enclosing_functions(tree)
    bad: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in clients:
            if f.attr == "get_paginator":
                op = node.args[0].value if node.args and isinstance(node.args[0], ast.Constant) else None
                if not (isinstance(op, str) and op.startswith(READ_ONLY_PREFIXES)):
                    bad.append(f"line {node.lineno}: get_paginator({op!r})")
            elif not f.attr.startswith(READ_ONLY_PREFIXES):
                bad.append(f"line {node.lineno}: {f.value.id}.{f.attr}()")
        elif isinstance(f, ast.Name) and f.id == "getattr" and node.args:
            target = node.args[0]
            if (
                isinstance(target, ast.Name)
                and target.id in clients
                and not _guards_with_allowlist(owner.get(id(node)))
            ):
                bad.append(f"line {node.lineno}: unguarded getattr on client {target.id!r}")
    return bad


def redis_violations(source: str) -> list[str]:
    tree = ast.parse(source)
    bad: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] == "redis":
            bad += [f"line {node.lineno}: import {a.name}" for a in node.names if a.name in RAW_REDIS_NAMES]
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
            if name in RAW_REDIS_NAMES or name == "SafeRedis":
                bad.append(f"line {node.lineno}: builds {name}")
        if isinstance(node, ast.Attribute) and node.attr in WIRE_BYPASS_ATTRS:
            bad.append(f"line {node.lineno}: .{node.attr}")
    return bad


def test_every_module_in_the_packages_is_audited():
    assert set(_modules()) == AUDITED_MODULES, "add new modules to AUDITED_MODULES after checking they stay read-only"


@pytest.mark.parametrize("module", sorted(AUDITED_MODULES))
def test_aws_calls_are_read_only(module):
    # In dataplane/ a parameter called ``client`` is a Redis client, so only bound boto3 clients count there.
    source = _modules()[module].read_text(encoding="utf-8")
    assert aws_violations(source, params=module.startswith("controlplane/")) == []


@pytest.mark.parametrize("module", sorted(m for m in AUDITED_MODULES if m.startswith("dataplane/")))
def test_dataplane_never_imports_boto(module):
    imported = {
        (a.name if isinstance(n, ast.Import) else n.module or "").split(".")[0]
        for n in ast.walk(ast.parse(_modules()[module].read_text(encoding="utf-8")))
        if isinstance(n, (ast.Import, ast.ImportFrom))
        for a in (n.names if isinstance(n, ast.Import) else [n])
    }
    assert not imported & {"boto3", "botocore"}


@pytest.mark.parametrize("module", sorted(AUDITED_MODULES))
def test_redis_is_only_reached_through_safe_redis(module):
    assert redis_violations(_modules()[module].read_text(encoding="utf-8")) == []


def test_audit_actually_sees_the_real_aws_calls():
    """Guards against a checker that silently matches nothing."""
    text = (SRC / "controlplane" / "_core.py").read_text(encoding="utf-8")
    tree = ast.parse(text)
    assert "ec" in _client_names(tree) and "cw" in _client_names(tree)
    assert any(isinstance(n, ast.Call) and getattr(n.func, "id", None) == "getattr" for n in ast.walk(tree))


@pytest.mark.parametrize(
    "source",
    [
        "def f(client):\n    client.modify_cache_cluster(CacheClusterId='x')",
        "def f(self):\n    ec = self.client('elasticache')\n    ec.delete_cache_cluster(CacheClusterId='x')",
        "def f(client):\n    client.get_paginator('reboot_cache_cluster')",
        "def f(client, op):\n    return getattr(client, op)()",
        "def f(self):\n    boto = self.client('x')\n    boto.create_snapshot()",
    ],
)
def test_checker_flags_write_calls(source):
    assert aws_violations(source)


@pytest.mark.parametrize(
    "source",
    [
        "def f(client):\n    client.describe_cache_clusters()\n    client.get_paginator('describe_events')",
        "def f(cw):\n    cw.get_metric_data()\n    cw.list_metrics()",
        "def f(client, op):\n    if not op.startswith(ALLOWED_PREFIXES):\n        raise ValueError\n"
        "    return getattr(client, op)()",
    ],
)
def test_checker_accepts_read_calls(source):
    assert aws_violations(source) == []


@pytest.mark.parametrize(
    "source",
    [
        "import redis\nr = redis.Redis()",
        "from redis import Redis\n",
        "r = SafeRedis()",
        "def f(r):\n    r.connection_pool.get_connection('GET')",
        "def f(r):\n    r.send_command('FLUSHALL')",
    ],
)
def test_checker_flags_redis_bypass(source):
    assert redis_violations(source)


def test_checker_ignores_annotations_and_plain_use():
    assert redis_violations("import redis\ndef f(r: redis.Redis) -> dict:\n    return r.info()") == []
