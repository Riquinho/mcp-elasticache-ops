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
_CONTAINERS = {"ACL", "CLIENT", "CLUSTER", "COMMAND", "CONFIG", "LATENCY", "MEMORY", "OBJECT", "PUBSUB", "SLOWLOG"}

READ_ONLY_COMMANDS: frozenset[str] = frozenset(
    {
        # server / introspection
        "PING",
        "INFO",
        # ACL visibility without password hashes: ACL LIST/GETUSER stay refused
        "ACL LOG",
        "ACL USERS",
        "ACL WHOAMI",
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
        "CLUSTER COUNTKEYSINSLOT",
        "CONFIG GET",
        # pub/sub introspection: counts only, never message payloads
        "PUBSUB CHANNELS",
        "PUBSUB NUMSUB",
        "PUBSUB NUMPAT",
        "PUBSUB SHARDCHANNELS",
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


# Upper bounds so no caller can issue an expensive read, whatever it passes.
MAX_SCAN_COUNT = 1000
MAX_MEMORY_USAGE_SAMPLES = 100
MAX_CLIENT_LIST_IDS = 100
MAX_ACL_LOG_COUNT = 128
MAX_PUBSUB_PATTERN_LEN = 128
MAX_PUBSUB_NUMSUB_CHANNELS = 100
LAST_CLUSTER_SLOT = 16383  # slots are 0..16383

_CLIENT_LIST_TYPES = frozenset({"NORMAL", "MASTER", "REPLICA", "SLAVE", "PUBSUB"})
_SCAN_OPTIONS = frozenset({"MATCH", "COUNT", "TYPE"})


def _int_arg(value: object, what: str) -> int:
    """A non-negative integer given as int, or as digits in str/bytes (never bool)."""
    if isinstance(value, bool):
        raise ReadOnlyViolation(f"{what} must be an integer")
    if isinstance(value, int):
        number = value
    else:
        text = _text(value, what)
        if not text.isascii() or not text.isdigit():
            raise ReadOnlyViolation(f"{what} must be a non-negative integer, got {text!r}")
        number = int(text)
    if number < 0:
        raise ReadOnlyViolation(f"{what} must be a non-negative integer")
    return number


def _check_acl_log(rest: tuple) -> None:
    # ACL LOG [count]; the only other form is ACL LOG RESET, which clears server state.
    if len(rest) > 1:
        raise ReadOnlyViolation("ACL LOG accepts at most a count")
    if rest and _int_arg(rest[0], "ACL LOG count") > MAX_ACL_LOG_COUNT:
        raise ReadOnlyViolation(f"ACL LOG count is capped at {MAX_ACL_LOG_COUNT}")


def _check_memory_usage(rest: tuple) -> None:
    if len(rest) not in (0, 1, 3):
        raise ReadOnlyViolation("MEMORY USAGE takes a key and an optional SAMPLES count")
    if len(rest) == 3:
        if _text(rest[1], "MEMORY USAGE option").upper() != "SAMPLES":
            raise ReadOnlyViolation("MEMORY USAGE only supports the SAMPLES option")
        samples = _int_arg(rest[2], "MEMORY USAGE SAMPLES")
        # SAMPLES 0 walks every element of the key, which blocks the node on a huge key.
        if not 1 <= samples <= MAX_MEMORY_USAGE_SAMPLES:
            raise ReadOnlyViolation(f"MEMORY USAGE SAMPLES must be between 1 and {MAX_MEMORY_USAGE_SAMPLES}")


def _check_scan(rest: tuple) -> None:
    if not rest:
        return
    _int_arg(rest[0], "SCAN cursor")
    options = rest[1:]
    if len(options) % 2:
        raise ReadOnlyViolation("SCAN options come in name/value pairs")
    for opt, value in zip(options[0::2], options[1::2], strict=True):
        name = _text(opt, "SCAN option").upper()
        if name not in _SCAN_OPTIONS:
            raise ReadOnlyViolation(f"SCAN option {name!r} is not allowed")
        if name == "COUNT":
            if _int_arg(value, "SCAN COUNT") > MAX_SCAN_COUNT:
                raise ReadOnlyViolation(f"SCAN COUNT is capped at {MAX_SCAN_COUNT}")
        else:  # MATCH takes a glob and TYPE a type name; both are server-side filters only
            _text(value, f"SCAN {name} value")


def _check_client_list(rest: tuple) -> None:
    if not rest:
        return
    option = _text(rest[0], "CLIENT LIST option").upper()
    if option == "TYPE" and len(rest) == 2:
        if _text(rest[1], "CLIENT LIST TYPE").upper() not in _CLIENT_LIST_TYPES:
            raise ReadOnlyViolation("CLIENT LIST TYPE must be normal, master, replica or pubsub")
    elif option == "ID" and len(rest) >= 2:
        if len(rest) - 1 > MAX_CLIENT_LIST_IDS:
            raise ReadOnlyViolation(f"CLIENT LIST ID accepts at most {MAX_CLIENT_LIST_IDS} ids")
        for client_id in rest[1:]:
            _int_arg(client_id, "CLIENT LIST ID")
    else:
        raise ReadOnlyViolation("CLIENT LIST only accepts TYPE <type> or ID <id> [id ...]")


def _check_pubsub(sub: str, rest: tuple) -> None:
    if sub in ("CHANNELS", "SHARDCHANNELS"):
        if len(rest) > 1:
            raise ReadOnlyViolation(f"PUBSUB {sub} takes at most one pattern")
        if rest:
            pattern = _text(rest[0], f"PUBSUB {sub} pattern")
            if len(pattern) > MAX_PUBSUB_PATTERN_LEN:
                raise ReadOnlyViolation(f"PUBSUB {sub} pattern is capped at {MAX_PUBSUB_PATTERN_LEN} characters")
    elif sub == "NUMSUB":
        if len(rest) > MAX_PUBSUB_NUMSUB_CHANNELS:
            raise ReadOnlyViolation(f"PUBSUB NUMSUB accepts at most {MAX_PUBSUB_NUMSUB_CHANNELS} channels")
        for channel in rest:
            if len(_text(channel, "PUBSUB NUMSUB channel")) > MAX_PUBSUB_PATTERN_LEN:
                raise ReadOnlyViolation(f"PUBSUB NUMSUB channel is capped at {MAX_PUBSUB_PATTERN_LEN} characters")
    elif rest:  # NUMPAT
        raise ReadOnlyViolation("PUBSUB NUMPAT takes no arguments")


def _check_countkeysinslot(rest: tuple) -> None:
    # One slot per call: a count, never keys (CLUSTER GETKEYSINSLOT stays refused).
    if len(rest) != 1:
        raise ReadOnlyViolation("CLUSTER COUNTKEYSINSLOT takes exactly one slot")
    if _int_arg(rest[0], "CLUSTER COUNTKEYSINSLOT slot") > LAST_CLUSTER_SLOT:
        raise ReadOnlyViolation(f"CLUSTER COUNTKEYSINSLOT slot must be between 0 and {LAST_CLUSTER_SLOT}")


def _check_single_key(key: str, rest: tuple) -> None:
    if len(rest) > 1:
        raise ReadOnlyViolation(f"{key} takes a single key")


def check(args: tuple) -> None:
    name, sub, rest = _split(args)
    key = f"{name} {sub}".strip()
    if key not in READ_ONLY_COMMANDS:
        raise ReadOnlyViolation(f"command {key!r} is not in the read-only allowlist")
    if key == "CONFIG GET":
        _check_config_get(rest)
    elif key == "ACL LOG":
        _check_acl_log(rest)
    elif key == "ACL WHOAMI" and rest:
        raise ReadOnlyViolation("ACL WHOAMI takes no arguments")
    elif key == "MEMORY USAGE":
        _check_memory_usage(rest)
    elif key == "SCAN":
        _check_scan(rest)
    elif key == "CLIENT LIST":
        _check_client_list(rest)
    elif key == "COMMAND DOCS" and not rest:
        raise ReadOnlyViolation("COMMAND DOCS needs at least one command name (the full dump is large)")
    elif key == "CLUSTER COUNTKEYSINSLOT":
        _check_countkeysinslot(rest)
    elif name == "PUBSUB":
        _check_pubsub(sub, rest)
    elif key.startswith("OBJECT "):
        _check_single_key(key, rest)


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
        "ACL SETUSER", "ACL DELUSER", "ACL LOG RESET", "MONITOR", "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE",
                "PUBLISH", "PUBSUB", "PUBSUB HELP", "PUBSUB SHARDNUMSUB", "XREAD", "XREADGROUP",
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
            return super().send_command(*args, **kwargs)
        finally:
            self._safe_packed_ok = previous

    def send_packed_command(self, command, check_health=True):
        # Pre-packed bytes cannot be inspected; only SafePipeline (which re-checks every
        # queued command first) may use them.
        if not self._safe_packed_ok:
            raise ReadOnlyViolation("raw packed commands are not allowed")
        return super().send_packed_command(command, check_health=check_health)


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
