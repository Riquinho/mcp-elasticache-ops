"""In-memory stand-ins for redis-py so dataplane logic is unit-testable without a server."""

from __future__ import annotations

import time
from typing import Any

import redis


class FakePipeline:
    def __init__(self, client: FakeRedis) -> None:
        self.client = client
        self.cmds: list[tuple] = []

    def type(self, k):
        self.cmds.append(("TYPE", k))
        return self

    def memory_usage(self, k, samples=None):
        self.cmds.append(("MEMORY USAGE", k))
        return self

    def pttl(self, k):
        self.cmds.append(("PTTL", k))
        return self

    def object(self, sub, k):
        self.cmds.append(("OBJECT", sub, k))
        return self

    def execute_command(self, *args):
        self.cmds.append(args)
        return self

    def execute(self, raise_on_error=True):
        self.client.pipeline_runs += 1
        if self.client.pipeline_delay:
            time.sleep(self.client.pipeline_delay)
        out = [self.client.run(c) for c in self.cmds]
        self.cmds = []
        return out


class FakeRedis:
    """Just enough of redis.Redis for dataplane.py. ``data`` maps key -> (type, bytes, pttl, length)."""

    def __init__(
        self,
        infos: dict[str, dict] | None = None,
        data: dict[str, tuple] | None = None,
        scan_batch: int = 10,
        scan_delay: float = 0.0,
        pipeline_delay: float = 0.0,
    ) -> None:
        self.infos = infos or {}
        self.data = data or {}
        self.scan_batch = scan_batch
        self.scan_delay = scan_delay
        self.pipeline_delay = pipeline_delay
        self.pipeline_runs = 0
        self.scan_calls = 0
        self.slowlog_entries: list[dict] = []
        self.clients: list[dict] = []
        self.commands: dict[str, Any] = {}
        self.closed = False
        self.object_values: dict[str, int] = {}  # key -> OBJECT FREQ/IDLETIME reply (default 5)
        self.sent: list[tuple] = []  # every pipelined command, for allowlist assertions

    def info(self, section: str | None = None) -> dict:
        if section is None:
            merged: dict = {}
            for v in self.infos.values():
                merged.update(v)
            return merged
        if section not in self.infos and section != "cluster":
            raise redis.ResponseError(f"unknown section {section}")
        return self.infos.get(section, {"cluster_enabled": 0})

    def dbsize(self) -> int:
        return len(self.data)

    def ping(self):
        return True

    def close(self):
        self.closed = True

    def scan(self, cursor=0, match=None, count=10):
        self.scan_calls += 1
        if self.scan_delay:
            time.sleep(self.scan_delay)
        keys = sorted(self.data)
        nxt = cursor + self.scan_batch
        return (0 if nxt >= len(keys) else nxt), keys[cursor:nxt]

    def pipeline(self):
        return FakePipeline(self)

    def run(self, cmd: tuple):
        name = cmd[0]
        self.sent.append(cmd)
        if name == "OBJECT":
            return self.object_values.get(cmd[-1], 5)
        key = cmd[-1] if name in {"TYPE", "MEMORY USAGE", "PTTL"} else cmd[1]
        typ, size, pttl, length = self.data[key]
        return {"TYPE": typ, "MEMORY USAGE": size, "PTTL": pttl}.get(name, length)

    def slowlog_get(self, count):
        return self.slowlog_entries[:count]

    def slowlog_len(self):
        return len(self.slowlog_entries)

    def client_list(self, _type=None):
        if _type:
            return [c for c in self.clients if c.get("flags") == "P" or c.get("type") == _type]
        return self.clients

    def memory_stats(self):
        return {"peak.allocated": 1}

    def latency_latest(self):
        return [["command", 1700000000, 12, 40]]

    def config_get(self, pattern):
        return {"latency-monitor-threshold": "100"}

    def execute_command(self, *args):
        key = " ".join(str(a) for a in args)
        if key not in self.commands:
            raise redis.ResponseError(f"unknown command {key}")
        value = self.commands[key]
        if isinstance(value, Exception):
            raise value
        if callable(value):
            return value()
        return value


# --------------------------------------------------------------------------- runtime read-only audit
# Recording fakes used by tests/test_server.py to prove, tool by tool, that nothing but read calls leaves
# the process: AWS operations are recorded at botocore level, Redis commands at the SafeRedis level and
# Memcached commands at the socket level.

AUDIT_AWS_RESPONSES: dict[str, dict[str, Any]] = {
    "DescribeReplicationGroups": {
        "ReplicationGroups": [
            {
                "ReplicationGroupId": "audit-rg",
                "Status": "available",
                "MemberClusters": ["audit-rg-001"],
                "CacheNodeType": "cache.r6g.large",
                "ClusterEnabled": False,
                "MultiAZ": "disabled",
                "AutomaticFailover": "disabled",
                "ARN": "arn:aws:elasticache:us-east-1:123456789012:replicationgroup:audit-rg",
                "NodeGroups": [
                    {
                        "NodeGroupId": "0001",
                        "Status": "available",
                        "NodeGroupMembers": [
                            {
                                "CacheClusterId": "audit-rg-001",
                                "PreferredAvailabilityZone": "us-east-1a",
                                "CurrentRole": "primary",
                            }
                        ],
                    }
                ],
            }
        ]
    },
    "DescribeCacheClusters": {
        "CacheClusters": [
            {
                "CacheClusterId": "audit-rg-001",
                "ReplicationGroupId": "audit-rg",
                "Engine": "redis",
                "EngineVersion": "7.1.0",
                "CacheNodeType": "cache.r6g.large",
                "CacheClusterStatus": "available",
            },
            {
                "CacheClusterId": "audit-mc",
                "Engine": "memcached",
                "EngineVersion": "1.6.21",
                "CacheNodeType": "cache.r6g.large",
                "CacheClusterStatus": "available",
                "ConfigurationEndpoint": {"Address": "audit-mc.cfg.use1.cache.amazonaws.com", "Port": 11211},
                "CacheNodes": [
                    {
                        "CacheNodeId": "0001",
                        "CacheNodeStatus": "available",
                        "Endpoint": {"Address": "audit-mc.0001.use1.cache.amazonaws.com", "Port": 11211},
                    }
                ],
            },
        ]
    },
    "DescribeServerlessCaches": {
        "ServerlessCaches": [{"ServerlessCacheName": "audit-sc", "Status": "available", "Engine": "valkey"}]
    },
    "GetMetricData": {"MetricDataResults": []},
}


class AwsAudit:
    """boto3 session factory whose clients never touch the network and record every operation name."""

    def __init__(self, responses: dict[str, Any] | None = None) -> None:
        self.operations: list[tuple[str, str]] = []  # (service, OperationName as sent to AWS)
        # per-operation overrides of AUDIT_AWS_RESPONSES; ``("error", "AccessDenied")`` makes the call fail with it
        self.responses = {**AUDIT_AWS_RESPONSES, **(responses or {})}

    def __call__(self) -> Any:
        audit = self

        class Session:
            def client(self, service, region_name=None, config=None):
                import boto3
                from botocore.awsrequest import AWSResponse

                client = boto3.client(service, region_name=region_name or "us-east-1", config=config)

                def before_call(model, **_kwargs):
                    audit.operations.append((service, model.name))
                    http = AWSResponse("https://audit.invalid", 200, {}, None)
                    reply = audit.responses.get(model.name, {})
                    if isinstance(reply, tuple) and reply[0] == "error":
                        denied = AWSResponse("https://audit.invalid", 403, {}, None)
                        return denied, {"Error": {"Code": reply[1], "Message": "denied by the test"}}
                    return http, dict(reply)

                client.meta.events.register("before-call", before_call)
                return client

        return Session()


def _audit_reply(args: tuple) -> Any:
    name = str(args[0]).upper()
    key = (
        f"{name} {args[1]}".upper()
        if len(args) > 1 and name in {"CONFIG", "CLIENT", "SLOWLOG", "ACL", "LATENCY"}
        else name
    )
    if name == "INFO" and len(args) > 1 and str(args[1]).lower() == "commandstats":
        return {"cmdstat_get": {"calls": 10, "usec": 100, "usec_per_call": 10.0}}
    if name == "INFO":
        return {
            "redis_version": "7.1.0",
            "redis_mode": "standalone",
            "role": "master",
            "used_memory": 1_000_000,
            "maxmemory": 0,
            "connected_clients": 1,
            "cluster_enabled": 0,
            "total_connections_received": 1,
            "total_commands_processed": 1,
        }
    if name == "SCAN":
        return (0, [b"audit:key"])
    if name.startswith("PUBSUB"):
        sub = name.split(" ", 1)[1] if " " in name else str(args[1]).upper()
        if sub in {"CHANNELS", "SHARDCHANNELS"}:
            return [b"audit:chan"]
        if sub == "NUMSUB":
            return [(b"audit:chan", 1)]
        return 0
    return {
        "PING": True,
        "DBSIZE": 1,
        "TYPE": "string",
        "PTTL": -1,
        "TTL": -1,
        "MEMORY USAGE": 64,
        "SLOWLOG GET": [],
        "SLOWLOG LEN": 0,
        "CLIENT LIST": [],
        "ACL LOG": [],
        "ACL USERS": ["default"],
        "LATENCY LATEST": [],
        "LATENCY HISTORY": [],
        "LATENCY DOCTOR": "Dave, no latency spikes.",
        "CONFIG GET": {},
        "CLUSTER INFO": {"cluster_state": "ok"},
        "CLUSTER NODES": {},
        "CLUSTER COUNTKEYSINSLOT": 0,
        "ROLE": ["master", 0, []],
    }.get(key, 1)


class AuditRedis:
    """Factory for SafeRedis clients that validate (via the real allowlist) and record every command."""

    def __init__(self) -> None:
        self.commands: list[str] = []
        self.violations: list[str] = []

    def build(self, *_args: Any, **_kwargs: Any) -> Any:
        from mcp_elasticache_ops.safe_client import SafePipeline, SafeRedis, check, command_key

        audit = self

        def record(args: tuple) -> None:
            try:
                check(args)
            except PermissionError:
                audit.violations.append(" ".join(str(a) for a in args))
                raise
            audit.commands.append(command_key(args))

        class AuditPipeline(SafePipeline):
            def execute(self, raise_on_error: bool = True):
                stack = list(self.command_stack)
                self.reset()
                for args, _ in stack:
                    record(args)
                return [_audit_reply(args) for args, _ in stack]

        class Client(SafeRedis):
            def execute_command(self, *args, **options):
                record(args)
                return _audit_reply(args)

            def pipeline(self, transaction: bool = False, shard_hint=None):
                return AuditPipeline(self.connection_pool, self.response_callbacks, False, shard_hint)

        return Client()


class AuditSocket:
    """Memcached socket stand-in: records each command line and answers like a tiny server."""

    def __init__(self, sent: list[str]) -> None:
        self.sent = sent
        self._reply = b""

    def __enter__(self) -> AuditSocket:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def sendall(self, data: bytes) -> None:
        command = data.decode("ascii").strip()
        self.sent.append(command)
        if command == "version":
            self._reply = b"VERSION 1.6.21\r\n"
        elif command == "config get cluster":
            self._reply = (
                b"CONFIG cluster 0 60\r\n2\naudit-mc.0001.use1.cache.amazonaws.com|10.0.0.9|11211 \n\r\nEND\r\n"
            )
        else:
            self._reply = b"STAT pid 1\r\nSTAT curr_connections 3\r\nSTAT limit_maxbytes 1048576\r\nEND\r\n"

    def recv(self, _size: int) -> bytes:
        reply, self._reply = self._reply, b""
        return reply
