"""A redis-py client that refuses anything outside a read-only allowlist.

Every tool in this server is read-only by construction, but the guard makes it
a property of the client rather than of code review: a future tool that tries
to send FLUSHALL, CONFIG SET, CLIENT KILL, DEL, SET, DEBUG, etc. fails before
it reaches the wire.
"""

from __future__ import annotations

import redis
from redis.client import Pipeline

# Commands that carry a subcommand we must inspect.
_CONTAINERS = {"CLIENT", "CLUSTER", "COMMAND", "CONFIG", "LATENCY", "MEMORY", "OBJECT", "SLOWLOG"}

READ_ONLY_COMMANDS: frozenset[str] = frozenset(
    {
        # server / introspection
        "PING",
        "INFO",
        "ROLE",
        "DBSIZE",
        "TIME",
        "LASTSAVE",
        "CLIENT LIST",
        "CLIENT INFO",
        "CLIENT GETNAME",
        "CLIENT ID",
        "SLOWLOG GET",
        "SLOWLOG LEN",
        "LATENCY LATEST",
        "LATENCY HISTORY",
        "LATENCY DOCTOR",
        "MEMORY STATS",
        "MEMORY USAGE",
        "MEMORY DOCTOR",
        "OBJECT FREQ",
        "OBJECT IDLETIME",
        "OBJECT ENCODING",
        "CLUSTER INFO",
        "CLUSTER SLOTS",
        "CLUSTER SHARDS",
        "CLUSTER NODES",
        "CLUSTER MYID",
        "CONFIG GET",
        "COMMAND COUNT",
        "COMMAND DOCS",
        # keyspace sampling (metadata only, never values)
        "SCAN",
        "TYPE",
        "TTL",
        "PTTL",
        "EXISTS",
        "STRLEN",
        "LLEN",
        "HLEN",
        "SCARD",
        "ZCARD",
        "XLEN",
        "PFCOUNT",
    }
)


class ReadOnlyViolation(PermissionError):
    """Raised when code tries to send a command outside the allowlist."""


def command_key(args: tuple) -> str:
    if not args:
        raise ReadOnlyViolation("empty command")
    head = args[0]
    head = head.decode() if isinstance(head, bytes) else str(head)
    parts = head.upper().split()
    name = parts[0]
    if name in _CONTAINERS:
        sub = parts[1] if len(parts) > 1 else (args[1] if len(args) > 1 else "")
        sub = sub.decode() if isinstance(sub, bytes) else str(sub)
        return f"{name} {sub.upper()}".strip()
    return name


def check(args: tuple) -> None:
    key = command_key(args)
    if key not in READ_ONLY_COMMANDS:
        raise ReadOnlyViolation(f"command {key!r} is not in the read-only allowlist")


class SafePipeline(Pipeline):
    def execute_command(self, *args, **kwargs):
        check(args)
        return super().execute_command(*args, **kwargs)


class SafeRedis(redis.Redis):
    def execute_command(self, *args, **options):
        check(args)
        return super().execute_command(*args, **options)

    def pipeline(self, transaction: bool = False, shard_hint=None) -> SafePipeline:
        if transaction:
            raise ReadOnlyViolation("MULTI/EXEC transactions are not allowed")
        return SafePipeline(self.connection_pool, self.response_callbacks, False, shard_hint)
