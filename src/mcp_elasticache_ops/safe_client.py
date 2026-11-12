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
    if not re.fullmatch(r"[A-Za-z_]+", sub):
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


# Commands redis-py itself sends while (re)connecting; they only touch connection state.
_HANDSHAKE_COMMANDS: frozenset[str] = frozenset(
    {"AUTH", "HELLO", "SELECT", "CLIENT SETNAME", "CLIENT SETINFO", "CLIENT MAINT_NOTIFICATIONS"}
)

# Never allowed in the allowlist, whatever the future holds. Used by the self-test below.
FORBIDDEN_COMMANDS: frozenset[str] = frozenset(
    {
        "SET", "GET", "MGET", "HGET", "HGETALL", "LRANGE", "SMEMBERS", "ZRANGE", "DEL", "UNLINK", "EXPIRE",
        "FLUSHALL", "FLUSHDB", "KEYS", "CONFIG SET", "CONFIG REWRITE", "CONFIG RESETSTAT", "CLIENT KILL",
        "CLIENT PAUSE", "CLIENT UNPAUSE", "CLIENT REPLY", "CLIENT TRACKING", "DEBUG", "EVAL", "EVALSHA",
        "FCALL", "SCRIPT", "SCRIPT LOAD", "SCRIPT FLUSH", "FUNCTION", "ACL", "ACL LIST", "ACL GETUSER",
        "ACL SETUSER", "MONITOR", "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE", "PUBLISH", "XREAD", "XREADGROUP",
        "XRANGE", "MULTI", "EXEC", "WATCH", "SHUTDOWN", "SLAVEOF", "REPLICAOF", "FAILOVER", "SAVE", "BGSAVE",
        "BGREWRITEAOF", "SLOWLOG RESET", "CLUSTER FAILOVER", "CLUSTER RESET", "MIGRATE", "RESTORE", "DUMP",
        "MODULE LOAD", "SYNC", "PSYNC", "SORT", "OBJECT HELP", "MEMORY PURGE", "LATENCY RESET", "AUTH", "HELLO",
    }
)  # fmt: skip


def assert_allowlist_is_readonly() -> None:
    """Self-test: fail loudly if a forbidden command ever lands in ``READ_ONLY_COMMANDS``."""
    leaked = FORBIDDEN_COMMANDS & READ_ONLY_COMMANDS
    if leaked:
        raise ReadOnlyViolation(f"allowlist contains forbidden commands: {sorted(leaked)}")
    for key in READ_ONLY_COMMANDS:
        if key != key.upper() or key != key.strip() or key.count(" ") > 1:
            raise ReadOnlyViolation(f"allowlist entry {key!r} is not in canonical form")
        if " " in key and key.split(" ")[0] not in _CONTAINERS:
            raise ReadOnlyViolation(f"allowlist entry {key!r} has a subcommand on a non-container command")


assert_allowlist_is_readonly()


def _check_handshake_or_allowed(args: tuple) -> None:
    if command_key(args) in _HANDSHAKE_COMMANDS:
        return
    check(args)


class _GuardedConnectionMixin:
    """Mixed into the pool's connection class so raw ``send_command`` calls are checked too."""

    _safe_packed_ok = False

    def send_command(self, *args, **kwargs):
        _check_handshake_or_allowed(args)
        previous, self._safe_packed_ok = self._safe_packed_ok, True  # checked above
        try:
            return super().send_command(*args, **kwargs)  # type: ignore[misc]
        finally:
            self._safe_packed_ok = previous

    def send_packed_command(self, command, check_health=True):
        # Pre-packed bytes cannot be inspected; only SafePipeline (which re-checks every
        # queued command first) may use them.
        if not self._safe_packed_ok:
            raise ReadOnlyViolation("raw packed commands are not allowed")
        return super().send_packed_command(command, check_health=check_health)  # type: ignore[misc]


def _guarded_class(cls: type) -> type:
    if issubclass(cls, _GuardedConnectionMixin):
        return cls
    return type(f"Guarded{cls.__name__}", (_GuardedConnectionMixin, cls), {})


class _BlockedHelpers:
    """redis-py helpers that reach the wire without going through ``execute_command``."""

    def _blocked(self, what: str):
        raise ReadOnlyViolation(f"{what} is not allowed on a read-only client")

    def pubsub(self, **kwargs):
        self._blocked("pubsub (SUBSCRIBE/PSUBSCRIBE would expose live traffic)")

    def monitor(self):
        self._blocked("MONITOR (would expose live traffic, values included)")

    def register_script(self, script):
        self._blocked("register_script/EVALSHA")

    def lock(self, *args, **kwargs):
        self._blocked("lock (writes keys)")

    def transaction(self, *args, **kwargs):
        self._blocked("transaction (WATCH/MULTI/EXEC)")


class SafePipeline(_BlockedHelpers, Pipeline):
    def execute_command(self, *args, **kwargs):
        check(args)
        return super().execute_command(*args, **kwargs)

    def pipeline_execute_command(self, *args, **options):
        check(args)
        return super().pipeline_execute_command(*args, **options)

    def immediate_execute_command(self, *args, **options):
        check(args)
        return super().immediate_execute_command(*args, **options)

    def multi(self):
        raise ReadOnlyViolation("MULTI/EXEC transactions are not allowed")

    def execute(self, raise_on_error: bool = True):
        for args, _ in self.command_stack:
            check(args)  # refuse before any connection is opened
        return super().execute(raise_on_error)

    def _execute_pipeline(self, connection, commands, raise_on_error):
        for args, _ in commands:
            check(args)
        connection._safe_packed_ok = True
        try:
            return super()._execute_pipeline(connection, commands, raise_on_error)
        finally:
            connection._safe_packed_ok = False


class SafeRedis(_BlockedHelpers, redis.Redis):
    def __init__(self, *args, **kwargs):
        if kwargs.get("single_connection_client"):
            raise ReadOnlyViolation("single_connection_client is not supported")
        super().__init__(*args, **kwargs)
        pool = self.connection_pool
        pool.connection_class = _guarded_class(pool.connection_class)

    def execute_command(self, *args, **options):
        check(args)
        return super().execute_command(*args, **options)

    def pipeline(self, transaction: bool = False, shard_hint=None) -> SafePipeline:
        if transaction:
            raise ReadOnlyViolation("MULTI/EXEC transactions are not allowed")
        return SafePipeline(self.connection_pool, self.response_callbacks, False, shard_hint)
