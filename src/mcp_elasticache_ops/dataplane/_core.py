"""Shared helpers, thresholds and INFO plumbing for the data-plane modules."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

import redis

LENGTH_COMMAND = {
    "string": "STRLEN",
    "list": "LLEN",
    "hash": "HLEN",
    "set": "SCARD",
    "zset": "ZCARD",
    "stream": "XLEN",
}


def _try(fn, *args, **kwargs) -> tuple[Any, str | None]:
    try:
        return fn(*args, **kwargs), None
    except redis.ResponseError as exc:  # command disabled/renamed/unknown
        return None, str(exc)


_SERVERLESS_HOST = re.compile(r"\.serverless\.[a-z0-9-]+\.cache\.amazonaws\.com\.?$", re.IGNORECASE)


def is_serverless_host(host: str | None) -> bool:
    """True for ElastiCache Serverless endpoints (``<name>.serverless.<region>.cache.amazonaws.com``)."""
    return bool(host and _SERVERLESS_HOST.search(host.strip()))


def _unsupported(what: str, err: str | None, serverless: bool) -> str:
    if serverless:
        return f"{what}: serverless: command not supported ({err})"
    return f"{what}: unavailable ({err})"


def _num(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def engine_of(info_server: dict) -> dict:
    """Valkey reports ``server_name: valkey`` and ``valkey_version``.

    Valkey also keeps ``redis_version`` (7.2.4) as a compatibility value; it is surfaced as
    ``redis_compat_version`` and never used as the engine version."""
    if info_server.get("server_name") == "valkey" or "valkey_version" in info_server:
        version = str(info_server.get("valkey_version", ""))
        out = {"engine": "valkey", "version": version, "version_label": f"Valkey {version}".strip()}
        if info_server.get("redis_version"):
            out["redis_compat_version"] = str(info_server["redis_version"])
        return out
    version = str(info_server.get("redis_version", ""))
    return {"engine": "redis", "version": version, "version_label": f"Redis OSS {version}".strip()}


# Oldest engine version that has each command (Valkey 7.2+ has all of them). A refusal on an older
# engine is an expected quirk, so it is reported as a note that names the engine, never an error.
MIN_ENGINE_VERSION: dict[str, tuple[int, ...]] = {
    "CLUSTER SHARDS": (7, 0),
    "ACL LOG": (6, 0),
    "ACL WHOAMI": (6, 0),
    "MEMORY DOCTOR": (4, 0),
    "LATENCY LATEST": (2, 8, 13),
    "INFO ERRORSTATS": (6, 2),
    "INFO LATENCYSTATS": (7, 0),
    "LATENCY HISTOGRAM": (7, 0),
    "CLUSTER LINKS": (7, 0),
}


def version_tuple(version: Any) -> tuple[int, ...]:
    """``"7.2.4"`` -> ``(7, 2, 4)``; parsing stops at the first non-numeric part, unknown -> ``()``."""
    parts: list[int] = []
    for token in str(version or "").split("."):
        digits = re.match(r"\d+", token)
        if not digits:
            break
        parts.append(int(digits.group()))
    return tuple(parts)


def command_support_note(command: str, info_server: dict | None, err: str | None) -> str:
    """Explain a refused command, naming the engine version when it is simply too old."""
    engine = engine_of(info_server or {})
    version = version_tuple(engine["version"])
    needed = MIN_ENGINE_VERSION.get(command)
    if needed and version and version < needed:
        return (
            f"{command}: not supported by {engine['engine']} {engine['version']} "
            f"(needs {'.'.join(map(str, needed))}+); skipped"
        )
    return f"{command}: unavailable ({err})"


_SECRET_KEY = re.compile(r"pass(word)?|secret|token|masterauth|masteruser|requirepass", re.IGNORECASE)


REDACTED = "***REDACTED***"


def redact(value: Any) -> Any:
    """Mask values of password-like keys (masterauth, requirepass, ...) recursively."""
    if isinstance(value, dict):
        return {k: REDACTED if _SECRET_KEY.search(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def server_info(r: redis.Redis, section: str | None = None) -> dict:
    """Raw INFO, optionally a single section (server, clients, memory, stats, ...)."""
    data = r.info(section) if section else r.info()
    return {"section": section or "default", "info": redact(data)}


INFO_SECTIONS = ("server", "clients", "memory", "persistence", "stats", "replication", "keyspace")


# Documented in the README ("Finding thresholds"); all bounded, none configurable on purpose.
MEMORY_HIGH_RATIO = 0.9  # used / maxmemory above this is critical


NOEVICTION_USAGE_RATIO = 0.85  # noeviction at this fill level means OOM errors are close


FRAGMENTATION_HIGH = 1.5


FRAGMENTATION_LOW = 1.0


CLIENT_BUFFER_WARN_BYTES = 16 * 1024 * 1024  # client_recent_max_output_buffer / input buffer


CONNECTIONS_WARN_RATIO = 0.80  # connected_clients / maxclients above this is a warning


CONNECTIONS_CRIT_RATIO = 0.95  # ... and above this a critical


CLIENT_MEMORY_SHARE = 0.10  # mem_clients_normal / used_memory above this is a warning


CLIENT_MEMORY_FLOOR_BYTES = 8 * 1024 * 1024  # ... but only when client buffers hold at least this much


CHURN_MIN_UPTIME_SECONDS = 600  # too early to average the connection rate before this


CHURN_PER_SECOND = 20.0  # average new connections per second that hints at a missing connection pool


FORK_WARN_USEC = 1_000_000  # latest_fork_usec above this stalls the main thread for over a second


FORK_CRIT_USEC = 5_000_000


SYNC_MIN_UPTIME_SECONDS = 600  # too early to judge full-resync frequency before this


SYNC_FULL_MIN = 3  # at least this many full syncs ...


SYNC_FULL_PER_HOUR = 1.0  # ... at this average rate per hour of uptime is a resync storm


ERROR_REPLIES_MIN_COMMANDS = 1000  # ignore the error share on a barely used node


ERROR_REPLIES_SHARE = 0.05  # total_error_replies / total_commands_processed above this is a warning


# Raw INFO fields echoed by health_summary when the engine reports them (absent on older engines).
HEALTH_EXTRA_FIELDS = (
    "latest_fork_usec",
    "rdb_last_bgsave_time_sec",
    "sync_full",
    "sync_partial_ok",
    "sync_partial_err",
    "evicted_clients",
    "total_error_replies",
    "total_commands_processed",
    "expired_stale_perc",
    "active_defrag_running",
)


def _s(v: Any) -> Any:
    return v.decode("utf-8", "backslashreplace") if isinstance(v, bytes) else v


IDLE_CLIENTS_WARN = 20  # clients idle for over an hour that make timeout=0 worth flagging


_SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}


def _finding(severity: str, message: str, **extra: Any) -> dict:
    return {"severity": severity, "message": message, **extra}


# Cluster-mode replies a node can give while slots move or a failover is under way. They are a state of that node
# right now, not a reason to abort a fan-out: each one becomes a per-node finding with what it means.
_CLUSTER_REPLIES: dict[str, tuple[str, str]] = {
    "MOVED": ("warning", "slot ownership changed (failover or resharding); the seed's topology view is stale, re-run"),
    "ASK": ("warning", "a slot is migrating and this node redirected the request; resharding in progress, re-run"),
    "CLUSTERDOWN": ("critical", "the cluster reports itself down (uncovered slots or no quorum)"),
    "LOADING": ("warning", "the node is loading its dataset (restart or full resync after a failover); retry shortly"),
    "TRYAGAIN": ("warning", "multi-key operation hit a slot that is mid-migration or mid-failover; retry shortly"),
}


def _node_error(exc: BaseException) -> tuple[str, str, str]:
    """``(kind, severity, text)`` for an exception raised by one node of a fan-out.

    ``kind`` is MOVED, ASK, CLUSTERDOWN, LOADING or TRYAGAIN for those replies and ``error`` for anything else."""
    head = str(exc).strip().split(" ", 1)[0].upper() if str(exc).strip() else ""
    by_type = {
        redis.exceptions.MovedError: "MOVED",
        redis.exceptions.AskError: "ASK",
        redis.exceptions.ClusterDownError: "CLUSTERDOWN",
        redis.exceptions.BusyLoadingError: "LOADING",
        redis.exceptions.TryAgainError: "TRYAGAIN",
    }
    kind = next((name for cls, name in by_type.items() if isinstance(exc, cls)), head)
    if kind in _CLUSTER_REPLIES:
        severity, meaning = _CLUSTER_REPLIES[kind]
        return kind, severity, f"{kind} reply ({meaning}): {exc}"
    return "error", "critical", f"{type(exc).__name__}: {exc}"


def _pairs(raw: Any) -> dict[str, Any]:
    """CLUSTER SHARDS entries arrive as dicts (RESP3, newer redis-py) or flat key/value lists (RESP2)."""
    if isinstance(raw, dict):
        return {str(_s(k)): v for k, v in raw.items()}
    items = list(raw)
    return {str(_s(items[i])): items[i + 1] for i in range(0, len(items) - 1, 2)}


def _endpoint(n: dict) -> str:
    return f"{n.get('hostname') or n['ip']}:{n['port']}"


def _jsonable(v: Any) -> Any:
    if isinstance(v, bytes):
        return v.decode("utf-8", "backslashreplace")
    if isinstance(v, dict):
        return {str(_jsonable(k)): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: _SEVERITY_RANK.get(f["severity"], 3))


def _safe(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, str | None]:
    """``_try`` that also absorbs connection and timeout errors, so one section never kills the call."""
    try:
        return _try(fn, *args, **kwargs)
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
