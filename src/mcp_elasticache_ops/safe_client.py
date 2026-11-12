"""A redis-py client that refuses anything outside a read-only allowlist.

Every tool in this server is read-only by construction, but the guard makes it
a property of the client rather than of code review: a future tool that tries
to send FLUSHALL, CONFIG SET, CLIENT KILL, DEL, SET, DEBUG, etc. fails before
it reaches the wire.
"""

from __future__ import annotations

import re

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


# CONFIG GET reveals secrets (requirepass, masterauth, masteruser, tls key paths)
# on self-hosted nodes, so only these parameters may be asked for, by exact name
# or by a trailing-``*`` prefix that is at least as specific as an allowed prefix.
CONFIG_GET_EXACT: frozenset[str] = frozenset(
    {
        "maxclients",
        "timeout",
        "tcp-keepalive",
        "databases",
        "appendonly",
        "appendfsync",
        "save",
        "notify-keyspace-events",
        "cluster-enabled",
        "cluster-node-timeout",
        "cluster-require-full-coverage",
        "cluster-allow-reads-when-down",
        "hz",
        "dynamic-hz",
        "lfu-log-factor",
        "lfu-decay-time",
        "rdbcompression",
        "replica-read-only",
        "min-replicas-to-write",
        "min-replicas-max-lag",
        "repl-backlog-size",
        "repl-backlog-ttl",
        "repl-diskless-sync",
        "client-query-buffer-limit",
        "proto-max-bulk-len",
        "io-threads",
    }
)
CONFIG_GET_PREFIXES: tuple[str, ...] = (
    "maxmemory",
    "slowlog-",
    "latency-",
    "activedefrag",
    "active-defrag-",
    "lazyfree-",
    "hash-max-",
    "list-max-",
    "set-max-",
    "zset-max-",
    "client-output-buffer-limit",
)
_GLOB_CHARS = set("*?[]\\")
_HEAD_RE = re.compile(r"[A-Za-z]+(?: [A-Za-z]+)?")


def _text(value: object, what: str) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    raise ReadOnlyViolation(f"{what} must be str or bytes, got {type(value).__name__}")


def _split(args: tuple) -> tuple[str, str, tuple]:
    """Return (command name, subcommand or "", remaining arguments)."""
    if not args:
        raise ReadOnlyViolation("empty command")
    head = _text(args[0], "command name")
    # One word, or "CONTAINER SUB" with a single space. Anything else (extra tokens,
    # newlines, tabs, leading/trailing blanks) could smuggle a second command.
    if not _HEAD_RE.fullmatch(head):
        raise ReadOnlyViolation(f"malformed command name {head!r}")
    parts = head.upper().split(" ")
    name = parts[0]
    rest = args[1:]
    if name not in _CONTAINERS:
        if len(parts) > 1:
            raise ReadOnlyViolation(f"command {name!r} does not take a subcommand in its name")
        return name, "", rest
    if len(parts) > 1:
        return name, parts[1], rest
    if not rest:
        return name, "", rest
    sub = _text(rest[0], "subcommand")
    if not re.fullmatch(r"[A-Za-z]+", sub):
        raise ReadOnlyViolation(f"malformed subcommand {sub!r}")
    return name, sub.upper(), rest[1:]


def command_key(args: tuple) -> str:
    name, sub, _ = _split(args)
    return f"{name} {sub}".strip()


def _check_config_get(patterns: tuple) -> None:
    if not patterns:
        raise ReadOnlyViolation("CONFIG GET needs an explicit parameter name")
    for raw in patterns:
        pat = _text(raw, "CONFIG GET parameter").lower()
        body = pat[:-1] if pat.endswith("*") else pat
        if not body or _GLOB_CHARS & set(body):
            raise ReadOnlyViolation(f"CONFIG GET pattern {pat!r} is too broad")
        if pat in CONFIG_GET_EXACT:
            continue
        if pat.endswith("*") and body.startswith(CONFIG_GET_PREFIXES):
            continue
        if not pat.endswith("*") and pat.startswith(CONFIG_GET_PREFIXES):
            continue
        raise ReadOnlyViolation(f"CONFIG GET {pat!r} is not in the allowed parameter list")


def check(args: tuple) -> None:
    name, sub, rest = _split(args)
    key = f"{name} {sub}".strip()
    if key not in READ_ONLY_COMMANDS:
        raise ReadOnlyViolation(f"command {key!r} is not in the read-only allowlist")
    if key == "CONFIG GET":
        _check_config_get(rest)


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
