"""Data-plane diagnostics for Redis OSS / Valkey nodes (ElastiCache or self-hosted).

Every function takes a connected client (normally a ``SafeRedis``) and returns
plain JSON-serialisable dicts. Nothing here writes, flushes or reads values:
keyspace sampling only touches metadata (TYPE, MEMORY USAGE, OBJECT, lengths).

ElastiCache restricts some admin commands (CONFIG, DEBUG, some MEMORY/LATENCY
subcommands depending on engine version). Those are attempted and, if refused,
reported as ``unavailable`` instead of failing the whole tool.
"""

from __future__ import annotations

import math
import re
import statistics
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any

import redis

from .safe_client import CONFIG_GET_EXACT, CONFIG_GET_PREFIXES

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
    """Valkey reports ``server_name: valkey`` and ``valkey_version``."""
    if info_server.get("server_name") == "valkey" or "valkey_version" in info_server:
        return {"engine": "valkey", "version": str(info_server.get("valkey_version", ""))}
    return {"engine": "redis", "version": str(info_server.get("redis_version", ""))}


# Oldest engine version that has each command (Valkey 7.2+ has all of them). A refusal on an older
# engine is an expected quirk, so it is reported as a note that names the engine, never an error.
MIN_ENGINE_VERSION: dict[str, tuple[int, ...]] = {
    "CLUSTER SHARDS": (7, 0),
    "ACL LOG": (6, 0),
    "ACL WHOAMI": (6, 0),
    "MEMORY DOCTOR": (4, 0),
    "LATENCY LATEST": (2, 8, 13),
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


# --------------------------------------------------------------------------- INFO


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


def _persistence_findings(info: dict) -> list[str]:
    out: list[str] = []
    if str(info.get("rdb_last_bgsave_status", "ok")).lower() not in ("ok", ""):
        out.append(
            "persistence: last RDB background save failed (rdb_last_bgsave_status=err); backups and full resyncs "
            "may fail, and writes are refused when stop-writes-on-bgsave-error is yes"
        )
    if str(info.get("aof_last_write_status", "ok")).lower() not in ("ok", ""):
        out.append(f"persistence: last AOF write failed (aof_last_write_status={info.get('aof_last_write_status')})")
    return out


def _buffer_findings(info: dict) -> list[str]:
    out: list[str] = []
    for key, label in (("client_recent_max_output_buffer", "output"), ("client_recent_max_input_buffer", "input")):
        size = _num(info.get(key))
        if size >= CLIENT_BUFFER_WARN_BYTES:
            out.append(
                f"client {label} buffer peaked at {int(size) // (1024 * 1024)} MiB ({key}); "
                "slow consumers or huge replies, see node_clients"
            )
    return out


def _eviction_rate_text(info: dict) -> str:
    uptime = _num(info.get("uptime_in_seconds"))
    evicted = _num(info.get("evicted_keys"))
    if uptime <= 0 or evicted <= 0:
        return ""
    return f", about {evicted * 60 / uptime:.1f}/min on average"


def _info_all(r: redis.Redis, serverless: bool) -> tuple[dict, list[str]]:
    """``INFO`` with a per-section fallback for endpoints that refuse the bare command."""
    info, err = _try(r.info)
    if info is not None:
        return info, []
    merged: dict = {}
    notes = [_unsupported("INFO", err, serverless)]
    for section in INFO_SECTIONS:
        part, part_err = _try(r.info, section)
        if part is None:
            notes.append(_unsupported(f"INFO {section}", part_err, serverless))
        else:
            merged.update(part)
    return merged, notes


def health_summary(r: redis.Redis, serverless: bool = False) -> dict:
    info, notes = _info_all(r, serverless)
    if not info and notes:
        return {"serverless": serverless, "findings": ["INFO is not available on this endpoint"], "notes": notes}
    hits, misses = _num(info.get("keyspace_hits")), _num(info.get("keyspace_misses"))
    maxmemory = _num(info.get("maxmemory"))
    used = _num(info.get("used_memory"))
    frag = _num(info.get("mem_fragmentation_ratio"), default=1.0)
    findings: list[str] = []
    if maxmemory and used / maxmemory > MEMORY_HIGH_RATIO:
        findings.append(f"memory at {used / maxmemory:.0%} of maxmemory")
    if info.get("maxmemory_policy") == "noeviction" and maxmemory and used / maxmemory >= NOEVICTION_USAGE_RATIO:
        findings.append(
            f"noeviction at {used / maxmemory:.0%} of maxmemory: writes fail with OOM once memory is full "
            "(switch to an eviction policy or add memory)"
        )
    if _num(info.get("evicted_keys")) > 0:
        findings.append(f"{int(_num(info.get('evicted_keys')))} keys evicted since restart{_eviction_rate_text(info)}")
    if frag > FRAGMENTATION_HIGH:
        findings.append(f"high fragmentation ratio {frag:.2f}")
    elif frag < FRAGMENTATION_LOW and used > 0:
        findings.append(f"fragmentation ratio {frag:.2f} < 1: possible swapping")
    if _num(info.get("rejected_connections")) > 0:
        findings.append(f"{int(_num(info.get('rejected_connections')))} rejected connections (maxclients)")
    if _num(info.get("blocked_clients")) > 0:
        findings.append(f"{int(_num(info.get('blocked_clients')))} blocked clients")
    if info.get("role") == "slave" and info.get("master_link_status") != "up":
        findings.append(f"replica link is {info.get('master_link_status')}")
    findings += _persistence_findings(info)
    findings += _buffer_findings(info)
    return {
        **engine_of(info),
        "role": info.get("role"),
        "uptime_seconds": info.get("uptime_in_seconds"),
        "connected_clients": info.get("connected_clients"),
        "blocked_clients": info.get("blocked_clients"),
        "ops_per_sec": info.get("instantaneous_ops_per_sec"),
        "hit_ratio": round(hits / (hits + misses), 4) if hits + misses else None,
        "used_memory": int(used),
        "maxmemory": int(maxmemory),
        "maxmemory_policy": info.get("maxmemory_policy"),
        "mem_fragmentation_ratio": frag,
        "evicted_keys": info.get("evicted_keys"),
        "expired_keys": info.get("expired_keys"),
        "keyspace": {k: v for k, v in info.items() if k.startswith("db")},
        "findings": findings or ["no issues detected by basic thresholds"],
        **({"serverless": serverless} if serverless else {}),
        **({"notes": notes} if notes else {}),
    }


# ------------------------------------------------------------------------- memory


def memory_report(r: redis.Redis, serverless: bool = False) -> dict:
    mem, mem_err = _try(r.info, "memory")
    stats, stats_info_err = _try(r.info, "stats")
    if mem is None:
        return {
            "serverless": serverless,
            "notes": [_unsupported("INFO memory", mem_err, serverless), *_serverless_hint(serverless)],
        }
    stats = stats or {}
    used = _num(mem.get("used_memory"))
    maxmemory = _num(mem.get("maxmemory"))
    rss = _num(mem.get("used_memory_rss"))
    frag = _num(mem.get("mem_fragmentation_ratio"), default=1.0)
    memory_stats, stats_err = _try(r.memory_stats)
    doctor, doctor_err = _try(r.execute_command, "MEMORY", "DOCTOR")

    if frag > FRAGMENTATION_HIGH:
        frag_verdict = "high: RSS well above dataset; consider activedefrag (Redis 4+/Valkey) or node replacement"
    elif frag < FRAGMENTATION_LOW and used > 0:
        frag_verdict = "below 1.0: memory may be swapped; check SwapUsage in CloudWatch"
    else:
        frag_verdict = "normal"

    findings = _memory_findings(mem, stats, used, maxmemory, frag)
    return {
        "findings": findings,
        "used_memory": int(used),
        "used_memory_human": mem.get("used_memory_human"),
        "used_memory_rss": int(rss),
        "used_memory_peak": mem.get("used_memory_peak"),
        "used_memory_dataset": mem.get("used_memory_dataset"),
        "used_memory_overhead": mem.get("used_memory_overhead"),
        "maxmemory": int(maxmemory),
        "maxmemory_policy": mem.get("maxmemory_policy"),
        "usage_of_maxmemory": round(used / maxmemory, 4) if maxmemory else None,
        "mem_fragmentation_ratio": frag,
        "allocator_frag_ratio": mem.get("allocator_frag_ratio"),
        "fragmentation_verdict": frag_verdict,
        "evicted_keys": stats.get("evicted_keys"),
        "memory_stats": memory_stats if memory_stats is not None else {"unavailable": stats_err},
        "memory_doctor": doctor if doctor is not None else {"unavailable": doctor_err},
        **(
            {
                "notes": [
                    *([_unsupported("INFO stats", stats_info_err, serverless)] if stats_info_err else []),
                    *_serverless_hint(serverless),
                ]
            }
            if stats_info_err or serverless
            else {}
        ),
        "note": (
            "On ElastiCache, maxmemory already excludes reserved-memory-percent; "
            "compare with the BytesUsedForCache and DatabaseMemoryUsagePercentage metrics."
        ),
    }


def _memory_findings(mem: dict, stats: dict, used: float, maxmemory: float, frag: float) -> list[dict]:
    out: list[dict] = []
    ratio = used / maxmemory if maxmemory else None
    if ratio is not None and ratio > MEMORY_HIGH_RATIO:
        out.append(_finding("critical", f"memory at {ratio:.0%} of maxmemory"))
    if mem.get("maxmemory_policy") == "noeviction" and ratio is not None and ratio >= NOEVICTION_USAGE_RATIO:
        out.append(
            _finding(
                "critical",
                f"maxmemory-policy is noeviction at {ratio:.0%} of maxmemory: writes fail with OOM once memory is full",
            )
        )
    if frag > FRAGMENTATION_HIGH:
        out.append(
            _finding("warning", f"mem_fragmentation_ratio {frag:.2f} > {FRAGMENTATION_HIGH}: RSS well above data")
        )
    elif frag < FRAGMENTATION_LOW and used > 0:
        out.append(_finding("warning", f"mem_fragmentation_ratio {frag:.2f} < 1: memory may be swapped"))
    evicted = int(_num(stats.get("evicted_keys")))
    if evicted > 0:
        out.append(_finding("warning", f"{evicted} keys evicted since restart"))
    return out


def _serverless_hint(serverless: bool) -> list[str]:
    if not serverless:
        return []
    return [
        "ElastiCache Serverless manages memory and eviction itself; use aws_metrics with serverless=true "
        "(BytesUsedForCache, ElastiCacheProcessingUnits) for capacity."
    ]


# ------------------------------------------------------------------------ slowlog


def slowlog(r: redis.Redis, count: int = 25, include_args: bool = False, serverless: bool = False) -> dict:
    """SLOWLOG GET with per-command aggregation.

    By default only the command name and the first argument (usually the key)
    are returned, so values passed to SET/HSET etc. never leave the server.
    """
    count = max(1, min(int(count), 1024))
    entries, err = _try(r.slowlog_get, count)
    if entries is None:
        return {
            "slowlog_len": None,
            "returned": 0,
            "by_command": [],
            "entries": [],
            "notes": [_unsupported("SLOWLOG GET", err, serverless)],
        }
    total_len, _ = _try(r.slowlog_len)
    out = []
    by_cmd: dict[str, list[int]] = defaultdict(list)
    for e in entries:
        raw = e.get("command", "")
        raw = raw.decode("utf-8", "backslashreplace") if isinstance(raw, bytes) else str(raw)
        parts = raw.split()
        name = parts[0].upper() if parts else "?"
        shown = raw if include_args else " ".join(parts[:2]) + (" ..." if len(parts) > 2 else "")
        by_cmd[name].append(int(e.get("duration", 0)))
        out.append(
            {
                "id": e.get("id"),
                "start_time": e.get("start_time"),
                "duration_us": e.get("duration"),
                "command": shown,
                "client_address": _s(e.get("client_address")),
                "client_name": _s(e.get("client_name")),
            }
        )
    summary = sorted(
        ({"command": k, "count": len(v), "total_us": sum(v), "max_us": max(v)} for k, v in by_cmd.items()),
        key=lambda x: x["total_us"],
        reverse=True,
    )
    return {"slowlog_len": total_len, "returned": len(out), "by_command": summary, "entries": out}


def _s(v: Any) -> Any:
    return v.decode("utf-8", "backslashreplace") if isinstance(v, bytes) else v


# ---------------------------------------------------------------------- clients


def client_list(r: redis.Redis, top: int = 20) -> dict:
    clients = r.client_list()
    by_ip: Counter[str] = Counter()
    by_name: Counter[str] = Counter()
    by_user: Counter[str] = Counter()
    by_cmd: Counter[str] = Counter()
    idle = []
    for c in clients:
        by_ip[str(c.get("addr", "?")).rsplit(":", 1)[0]] += 1
        by_name[c.get("name") or "(unnamed)"] += 1
        by_user[c.get("user") or "default"] += 1
        by_cmd[c.get("cmd") or "?"] += 1
        idle.append(int(_num(c.get("idle"))))

    def heavy(c: dict) -> int:
        return int(_num(c.get("omem"))) + int(_num(c.get("qbuf"))) + int(_num(c.get("tot-mem")))

    top_mem = sorted(clients, key=heavy, reverse=True)[: max(1, int(top))]
    fields = ("id", "addr", "name", "user", "age", "idle", "db", "cmd", "qbuf", "omem", "tot-mem", "flags")
    return {
        "total": len(clients),
        "by_source_ip": by_ip.most_common(top),
        "by_name": by_name.most_common(top),
        "by_user": by_user.most_common(top),
        "by_last_command": by_cmd.most_common(top),
        "idle_seconds": {
            "max": max(idle) if idle else 0,
            "median": statistics.median(idle) if idle else 0,
            "over_1h": sum(1 for i in idle if i > 3600),
        },
        "top_by_buffer_memory": [{k: c.get(k) for k in fields} for c in top_mem],
    }


# ---------------------------------------------------------------------- latency


def latency(r: redis.Redis, ping_samples: int = 20) -> dict:
    """Client-side PING round-trip plus the server latency monitor, if enabled."""
    samples = []
    for _ in range(max(1, min(int(ping_samples), 500))):
        t0 = time.perf_counter()
        r.ping()
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    latest, latest_err = _try(r.latency_latest)
    threshold_cfg, _ = _try(r.config_get, "latency-monitor-threshold")
    threshold = (threshold_cfg or {}).get("latency-monitor-threshold")
    events = []
    for row in latest or []:
        # [event, timestamp, latest_ms, max_ms]
        events.append({"event": _s(row[0]), "timestamp": row[1], "latest_ms": row[2], "max_ms": row[3]})
    return {
        "ping_rtt_ms": {
            "samples": len(samples),
            "min": round(samples[0], 3),
            "p50": round(samples[len(samples) // 2], 3),
            "p99": round(samples[min(len(samples) - 1, int(len(samples) * 0.99))], 3),
            "max": round(samples[-1], 3),
        },
        "latency_monitor_threshold": threshold
        if threshold
        else "unavailable (CONFIG GET refused; see parameter group)",
        "latency_latest": events if latest is not None else {"unavailable": latest_err},
        "hint": "Empty latency_latest usually means latency-monitor-threshold is 0 in the parameter group.",
    }


def commandstats(r: redis.Redis, top: int = 20) -> dict:
    stats = r.info("commandstats")
    rows = []
    for key, v in stats.items():
        name = key.removeprefix("cmdstat_")
        rows.append(
            {
                "command": name,
                "calls": int(_num(v.get("calls"))),
                "usec": int(_num(v.get("usec"))),
                "usec_per_call": _num(v.get("usec_per_call")),
                "rejected_calls": int(_num(v.get("rejected_calls"))),
                "failed_calls": int(_num(v.get("failed_calls"))),
            }
        )
    rows.sort(key=lambda x: x["usec"], reverse=True)
    return {"commands": len(rows), "top_by_total_time": rows[: max(1, int(top))]}


# ----------------------------------------------------------------------- config

CONFIG_FALLBACK_NOTE = (
    "CONFIG GET is refused by this endpoint (managed services restrict it); read the effective values "
    "from the parameter group with aws_parameters."
)
IDLE_CLIENTS_WARN = 20  # clients idle for over an hour that make timeout=0 worth flagging
_KEYSPACE_CLASSES = set("gl$szxetd")  # event classes besides K/E; A is the alias for all of them
_SEVERITY_RANK = {"critical": 0, "warning": 1, "info": 2}


def config_patterns() -> list[str]:
    """CONFIG GET patterns requested by ``config_view``: only allowlisted names and prefixes."""
    return [*sorted(CONFIG_GET_EXACT), *(f"{p}*" for p in CONFIG_GET_PREFIXES)]


def _cfg_finding(severity: str, message: str, parameter: str) -> dict:
    return {"severity": severity, "message": message, "parameter": parameter}


def config_findings(cfg: dict[str, str], idle_clients: int | None = None) -> list[dict]:
    out: list[dict] = []
    if cfg.get("maxmemory-policy") == "noeviction" and _num(cfg.get("maxmemory")) != 0:
        out.append(
            _cfg_finding(
                "warning",
                "maxmemory-policy is noeviction: writes fail with OOM once memory is full. "
                "Fine for a datastore, wrong for a cache (use allkeys-lru, allkeys-lfu or volatile-ttl).",
                "maxmemory-policy",
            )
        )
    if cfg.get("timeout") is not None and _num(cfg["timeout"]) == 0 and (idle_clients or 0) >= IDLE_CLIENTS_WARN:
        out.append(
            _cfg_finding(
                "warning",
                f"timeout is 0 (idle connections are never closed) and {idle_clients} clients have been idle for "
                "over an hour: leaked connections count against maxclients. Set timeout or fix client pooling.",
                "timeout",
            )
        )
    if str(cfg.get("appendonly", "")).lower() == "yes":
        out.append(
            _cfg_finding(
                "warning",
                "appendonly is yes: AOF adds fsync latency and ElastiCache does not support AOF persistence "
                "(use snapshots and Multi-AZ replicas).",
                "appendonly",
            )
        )
    if cfg.get("latency-monitor-threshold") is not None and _num(cfg["latency-monitor-threshold"]) == 0:
        out.append(
            _cfg_finding(
                "info",
                "latency-monitor-threshold is 0: LATENCY LATEST stays empty. "
                "Set it (for example 100 ms) in the parameter group.",
                "latency-monitor-threshold",
            )
        )
    slower = cfg.get("slowlog-log-slower-than")
    if slower is not None and _num(slower) < 0:
        out.append(
            _cfg_finding(
                "warning", "slowlog-log-slower-than is negative: the slow log is disabled", "slowlog-log-slower-than"
            )
        )
    elif slower is not None and _num(slower) == 0:
        out.append(
            _cfg_finding(
                "warning",
                "slowlog-log-slower-than is 0: every command is logged, which pushes out real slow entries "
                "and costs CPU",
                "slowlog-log-slower-than",
            )
        )
    events = cfg.get("notify-keyspace-events") or ""
    if events:
        classes = set(events.replace("A", "gl$szxetd")) & _KEYSPACE_CLASSES
        if len(classes) >= 4:
            out.append(
                _cfg_finding(
                    "warning",
                    f"notify-keyspace-events is {events!r}: broad keyspace notifications publish an event per "
                    "write and add CPU and output-buffer load. Enable only the classes you consume.",
                    "notify-keyspace-events",
                )
            )
        else:
            out.append(
                _cfg_finding(
                    "info",
                    f"notify-keyspace-events is {events!r}: each matching event is published to Pub/Sub; "
                    "cost grows with the write rate.",
                    "notify-keyspace-events",
                )
            )
    return out


def config_view(r: redis.Redis) -> dict:
    """Allowlisted ``CONFIG GET`` parameters with ElastiCache-aware findings.

    Only names in ``CONFIG_GET_EXACT`` and prefixes in ``CONFIG_GET_PREFIXES`` are requested, so secrets
    (``requirepass``, ``masterauth``, TLS paths) are never asked for. When the endpoint refuses CONFIG
    (ElastiCache and Serverless do), the result is a note pointing at ``aws_parameters``.
    """
    cfg: dict[str, str] = {}
    refused: list[str] = []
    first_error: str | None = None
    for pattern in config_patterns():
        got, err = _try(r.config_get, pattern)
        if got is None:
            refused.append(pattern)
            first_error = first_error or err
            continue
        cfg.update({str(_s(k)): str(_s(v)) for k, v in got.items()})
    if not cfg:
        return {
            "available": False,
            "config": {},
            "findings": [],
            "notes": [CONFIG_FALLBACK_NOTE, f"first error: {first_error}"],
        }
    clients, _ = _try(r.client_list)
    idle = sum(1 for c in clients if _num(c.get("idle")) > 3600) if clients is not None else None
    findings = sorted(config_findings(cfg, idle), key=lambda f: _SEVERITY_RANK.get(f["severity"], 3))
    out: dict[str, Any] = {"available": True, "config": redact(dict(sorted(cfg.items()))), "findings": findings}
    if refused:
        out["notes"] = [CONFIG_FALLBACK_NOTE]
        out["refused_patterns"] = refused
    return out


# --------------------------------------------------------------------- keyspace


DEFAULT_SAMPLE_SECONDS = 10.0
MAX_SAMPLE_SECONDS = 60.0
PIPELINE_CHUNK = 100
DEFAULT_TOP_PREFIXES = 10
MAX_TOP_PREFIXES = 50
PREFIX_PRESSURE_RATIO = 0.8  # memory share of maxmemory at which a no-TTL prefix becomes a finding
PREFIX_SHARE_PCT = 10.0  # a prefix must hold at least this share of sampled memory to be flagged
PREFIX_NO_TTL_PCT = 90.0

_KEY_SEPARATORS = re.compile(r"([:/.])")
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_HEX_ID = re.compile(r"[0-9a-fA-F]{8,}")


def _is_variable_segment(segment: str) -> bool:
    if segment.isdigit() or _UUID.fullmatch(segment):
        return True
    # long hex tokens (object ids, hashes); needing a digit keeps plain words such as "defaced" intact
    return bool(_HEX_ID.fullmatch(segment)) and any(c.isdigit() for c in segment)


def normalize_key(key: Any) -> str:
    """Collapse the variable parts of a key: ``user:123:cart`` -> ``user:*:cart``.

    The key is split on ``:``, ``/`` and ``.`` (separators are kept); a segment that is all digits, a UUID or a
    hex token of 8+ characters becomes ``*``. Redis Cluster hash-tag braces around a segment are preserved.
    """
    out = []
    for part in _KEY_SEPARATORS.split(str(_s(key))):
        core = part.strip("{}")
        out.append(part.replace(core, "*", 1) if core and _is_variable_segment(core) else part)
    return "".join(out)


def _prefix_entries(rows: list[dict], dbsize: int) -> list[dict]:
    """Aggregate sampled rows by normalised prefix; bytes and key counts are scaled up to ``dbsize``."""
    scale = dbsize / len(rows) if rows and dbsize > len(rows) else 1.0
    agg: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = agg.setdefault(
            normalize_key(row["key"]),
            {"sampled_keys": 0, "sampled_bytes": 0, "no_ttl_keys": 0, "types": Counter()},
        )
        entry["sampled_keys"] += 1
        entry["sampled_bytes"] += row["bytes"] or 0
        entry["no_ttl_keys"] += 1 if row["ttl_ms"] == -1 else 0
        entry["types"][row["type"]] += 1
    return [
        {
            "prefix": prefix,
            "sampled_keys": e["sampled_keys"],
            "est_keys": round(e["sampled_keys"] * scale),
            "est_bytes": round(e["sampled_bytes"] * scale),
            "no_ttl_keys": e["no_ttl_keys"],
            "types": dict(e["types"]),
        }
        for prefix, e in agg.items()
    ]


def _merge_prefix_entries(groups: list[list[dict]]) -> list[dict]:
    """Sum prefix entries produced by several shards (inputs are not modified)."""
    merged: dict[str, dict[str, Any]] = {}
    for group in groups:
        for e in group:
            m = merged.setdefault(
                e["prefix"],
                {
                    "prefix": e["prefix"],
                    "sampled_keys": 0,
                    "est_keys": 0,
                    "est_bytes": 0,
                    "no_ttl_keys": 0,
                    "types": {},
                },
            )
            for field_name in ("sampled_keys", "est_keys", "est_bytes", "no_ttl_keys"):
                m[field_name] += e[field_name]
            for t, n in e["types"].items():
                m["types"][t] = m["types"].get(t, 0) + n
    return list(merged.values())


def _prefix_report(
    entries: list[dict], top_prefixes: int, policy: str, usage: float | None, total_bytes: int | None = None
) -> dict[str, Any]:
    """Top prefixes by estimated bytes plus findings when no-TTL data sits under memory pressure."""
    top_prefixes = max(1, min(int(top_prefixes), MAX_TOP_PREFIXES))
    ranked = sorted(entries, key=lambda e: (e["est_bytes"], e["sampled_keys"]), reverse=True)
    total = total_bytes if total_bytes is not None else sum(e["est_bytes"] for e in ranked)

    def view(e: dict) -> dict:
        return {
            "prefix": e["prefix"],
            "sampled_keys": e["sampled_keys"],
            "est_keys": e["est_keys"],
            "est_bytes": e["est_bytes"],
            "pct_of_memory": round(100 * e["est_bytes"] / total, 1) if total else 0.0,
            "no_ttl_keys": e["no_ttl_keys"],
            "no_ttl_pct": round(100 * e["no_ttl_keys"] / e["sampled_keys"], 1) if e["sampled_keys"] else 0.0,
            "types": dict(sorted(e["types"].items())),
        }

    rows = [view(e) for e in ranked]
    pressure = policy == "noeviction" or (usage is not None and usage >= PREFIX_PRESSURE_RATIO)
    findings = []
    if pressure:
        why = f"maxmemory-policy {policy or '?'}" + (f", memory at {usage:.0%} of maxmemory" if usage else "")
        for row in rows:
            if row["pct_of_memory"] >= PREFIX_SHARE_PCT and row["no_ttl_pct"] >= PREFIX_NO_TTL_PCT:
                findings.append(
                    _finding(
                        "critical" if usage is not None and usage >= 0.9 else "warning",
                        f"prefix {row['prefix']} has {row['pct_of_memory']:g}% of sampled memory and "
                        f"{row['no_ttl_pct']:g}% of its keys have no TTL ({why})",
                        prefix=row["prefix"],
                    )
                )
    return {
        "prefixes": rows[:top_prefixes],
        "prefixes_summary": {"distinct": len(rows), "shown": min(len(rows), top_prefixes), "est_bytes_total": total},
        "findings": findings,
    }


def keyspace_sample(
    r: redis.Redis,
    sample_size: int = 1000,
    match: str | None = None,
    top: int = 20,
    scan_count: int = 250,
    pause_ms: int = 0,
    max_seconds: float = DEFAULT_SAMPLE_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    top_prefixes: int = DEFAULT_TOP_PREFIXES,
) -> dict:
    """Big/hot key finder based on a bounded SCAN.

    Cost control: at most ``sample_size`` keys are inspected (so at most four
    pipelined metadata commands per key plus one length command), SCAN uses COUNT
    ``scan_count`` and an optional pause between batches, and the whole call
    stops at the ``max_seconds`` wall-clock budget (hard cap 60 s), returning
    what it has with ``partial=True``. Hot keys need an LFU ``maxmemory-policy``
    (OBJECT FREQ); otherwise idle time is reported. Only the connected node is
    sampled, which in cluster mode means only that node's slots. ``prefixes`` groups the sampled keys by
    normalised prefix (see ``normalize_key``) from data already fetched, so it costs no extra commands.
    """
    sample_size = max(1, min(int(sample_size), 100_000))
    max_seconds = max(0.01, min(float(max_seconds), MAX_SAMPLE_SECONDS))
    started = clock()
    deadline = started + max_seconds
    partial_reason: str | None = None
    mem_info = r.info("memory")
    policy = str(mem_info.get("maxmemory_policy", ""))
    lfu = "lfu" in policy
    keys: list[str] = []
    cursor = 0
    while True:
        cursor, batch = r.scan(cursor=cursor, match=match, count=scan_count)
        keys.extend(batch)
        if cursor == 0 or len(keys) >= sample_size:
            break
        if clock() >= deadline:
            partial_reason = f"time budget of {max_seconds:g}s exhausted while scanning"
            break
        if pause_ms:
            time.sleep(pause_ms / 1000)
    keys = keys[:sample_size]

    rows = []
    for i in range(0, len(keys), PIPELINE_CHUNK):
        if clock() >= deadline:
            partial_reason = partial_reason or f"time budget of {max_seconds:g}s exhausted while inspecting keys"
            break
        chunk = keys[i : i + PIPELINE_CHUNK]
        pipe = r.pipeline()
        for k in chunk:
            pipe.type(k)
            pipe.memory_usage(k, samples=5)
            pipe.pttl(k)
            pipe.object("FREQ" if lfu else "IDLETIME", k)
        res = pipe.execute(raise_on_error=False)
        types = res[0::4]
        lengths_pipe = r.pipeline()
        for k, t in zip(chunk, types, strict=True):
            cmd = LENGTH_COMMAND.get(_s(t) if not isinstance(t, Exception) else "", "EXISTS")
            lengths_pipe.execute_command(cmd, k)
        lengths = lengths_pipe.execute(raise_on_error=False)
        for j, k in enumerate(chunk):
            t, mem, pttl, obj = res[4 * j : 4 * j + 4]
            tname = _s(t) if not isinstance(t, Exception) else "?"
            length = lengths[j] if tname in LENGTH_COMMAND and isinstance(lengths[j], int) else None
            rows.append(
                {
                    "key": _s(k),
                    "type": tname,
                    "bytes": mem if isinstance(mem, int) else None,
                    "length": length,
                    "ttl_ms": pttl if isinstance(pttl, int) else None,
                    ("lfu_freq" if lfu else "idle_seconds"): obj if isinstance(obj, int) else None,
                }
            )

    by_type: dict[str, dict[str, int]] = defaultdict(lambda: {"keys": 0, "bytes": 0})
    for row in rows:
        by_type[row["type"]]["keys"] += 1
        by_type[row["type"]]["bytes"] += row["bytes"] or 0
    no_ttl = sum(1 for row in rows if row["ttl_ms"] == -1)
    top = max(1, int(top))
    partial = partial_reason is not None
    dbsize = r.dbsize()
    maxmemory = _num(mem_info.get("maxmemory"))
    usage = round(_num(mem_info.get("used_memory")) / maxmemory, 4) if maxmemory else None
    prefix_report = _prefix_report(_prefix_entries(rows, dbsize), top_prefixes, policy, usage)
    result: dict[str, Any] = {
        "sampled_keys": len(rows),
        "dbsize": dbsize,
        "complete_scan": cursor == 0 and len(keys) < sample_size and not partial,
        "partial": partial,
        "partial_reason": partial_reason,
        "max_seconds": max_seconds,
        "elapsed_seconds": round(clock() - started, 3),
        "scope": "connected node only",
        "maxmemory_policy": policy,
        "by_type": dict(by_type),
        "keys_without_ttl": no_ttl,
        "usage_of_maxmemory": usage,
        **prefix_report,
        "big_keys_by_bytes": sorted(rows, key=lambda x: x["bytes"] or 0, reverse=True)[:top],
        # STRLEN is bytes, so strings rank in big_keys_by_bytes; length ranks collection elements.
        "big_keys_by_length": sorted(
            (x for x in rows if x["type"] != "string"), key=lambda x: x["length"] or 0, reverse=True
        )[:top],
    }
    cluster_info, _ = _try(r.info, "cluster")
    if int(_num((cluster_info or {}).get("cluster_enabled"))):
        result["cluster_mode"] = True
        result["cluster_note"] = (
            "cluster mode is enabled: only the slots owned by this node were sampled. "
            "Run node_cluster_nodes for per-shard endpoints and repeat with ELASTICACHE_HOST "
            "pointing at each shard primary."
        )
    else:
        result["cluster_mode"] = False
    if lfu:
        result["hot_keys_by_lfu"] = sorted(rows, key=lambda x: x["lfu_freq"] or 0, reverse=True)[:top]
    else:
        result["coldest_keys_by_idle"] = sorted(rows, key=lambda x: x["idle_seconds"] or 0, reverse=True)[:top]
        result["hot_keys_note"] = "set maxmemory-policy to an *-lfu policy to rank hot keys (OBJECT FREQ)"
    return result


# ------------------------------------------------------------ replication/cluster


REPL_LAG_BYTES_WARN = 1_000_000
REPL_LAG_SECONDS_WARN = 10
REPL_IO_SECONDS_WARN = 10
REPLICA_SETTINGS = (
    "replica-read-only",
    "min-replicas-to-write",
    "min-replicas-max-lag",
    "cluster-allow-reads-when-down",
)


def _finding(severity: str, message: str, **extra: Any) -> dict:
    return {"severity": severity, "message": message, **extra}


def _primary_offset(
    info: dict, client_factory: Callable[[str, int], redis.Redis] | None
) -> tuple[int | None, str | None]:
    """Replication offset of this replica's primary, read from the primary itself."""
    host, port = info.get("master_host"), info.get("master_port")
    if client_factory is None or not host or not port:
        return None, None
    client = None
    try:
        client = client_factory(str(host), int(port))
        return int(_num(client.info("replication").get("master_repl_offset"))), None
    except Exception as exc:
        return None, f"primary {host}:{port} unreachable for offset comparison: {type(exc).__name__}: {exc}"
    finally:
        close = getattr(client, "close", None)
        if close:
            close()


def replication(
    r: redis.Redis,
    client_factory: Callable[[str, int], redis.Redis] | None = None,
    lag_bytes_threshold: int = REPL_LAG_BYTES_WARN,
) -> dict:
    """Replication state with findings: down links, lagging replicas, risky replica settings.

    On a replica, ``client_factory`` (a ``SafeRedis`` builder) lets the offset be compared with the
    primary's. Commands an older engine lacks become notes, never exceptions.
    """
    info = r.info("replication")
    role, role_err = _try(r.execute_command, "ROLE")
    server, _ = _try(r.info, "server")
    findings: list[dict] = []
    notes: list[str] = []
    replicas = []
    master_offset = int(_num(info.get("master_repl_offset")))
    is_replica = info.get("role") == "slave"
    for k, v in info.items():
        if not (k.startswith("slave") and isinstance(v, dict)):
            continue
        row = {**v, "lag_bytes": master_offset - int(_num(v.get("offset")))}
        replicas.append(row)
        addr = f"{v.get('ip')}:{v.get('port')}"
        if v.get("state") not in (None, "online"):
            findings.append(_finding("critical", f"replica {addr} link is {v.get('state')}, not online", replica=addr))
        if row["lag_bytes"] > lag_bytes_threshold:
            findings.append(_finding("warning", f"replica {addr} is {row['lag_bytes']} bytes behind", replica=addr))
        if _num(v.get("lag")) > REPL_LAG_SECONDS_WARN:
            findings.append(_finding("warning", f"replica {addr} last acknowledged {v.get('lag')}s ago", replica=addr))
    connected = int(_num(info.get("connected_slaves")))
    if not is_replica and connected == 0:
        findings.append(_finding("warning", "no replicas connected: there is no failover target and no read scaling"))
    if is_replica:
        if info.get("master_link_status") not in (None, "up"):
            down = info.get("master_link_down_since_seconds")
            findings.append(
                _finding(
                    "critical",
                    f"replication link to the primary is {info.get('master_link_status')}"
                    + (f" for {down}s" if down is not None else ""),
                )
            )
        last_io = _num(info.get("master_last_io_seconds_ago"), default=-1)
        if last_io > REPL_IO_SECONDS_WARN:
            findings.append(_finding("warning", f"last I/O with the primary was {int(last_io)}s ago"))
        if int(_num(info.get("master_sync_in_progress"))):
            findings.append(_finding("info", "a full resync with the primary is in progress"))
        own = int(_num(info.get("slave_repl_offset", info.get("master_repl_offset"))))
        primary_offset, offset_err = _primary_offset(info, client_factory)
        if offset_err:
            notes.append(offset_err)
        elif primary_offset is not None and primary_offset - own > lag_bytes_threshold:
            findings.append(_finding("warning", f"this replica is {primary_offset - own} bytes behind the primary"))
    settings: dict[str, str] = {}
    refused = 0
    for name in REPLICA_SETTINGS:
        got, _ = _try(r.config_get, name)
        if got is None:
            refused += 1
        elif name in got:
            settings[name] = str(_s(got[name]))
    if refused == len(REPLICA_SETTINGS):
        notes.append(CONFIG_FALLBACK_NOTE)
    if is_replica and settings.get("replica-read-only", "yes").lower() == "no":
        findings.append(_finding("warning", "replica-read-only is no: writes to this replica diverge from the primary"))
    min_write = int(_num(settings.get("min-replicas-to-write")))
    if not is_replica and replicas and min_write == 0 and "min-replicas-to-write" in settings:
        findings.append(_finding("info", "min-replicas-to-write is 0: writes are accepted with every replica gone"))
    elif not is_replica and min_write > connected:
        findings.append(
            _finding("critical", f"min-replicas-to-write is {min_write} but only {connected} replicas are connected")
        )
    if settings.get("cluster-allow-reads-when-down", "").lower() == "yes":
        findings.append(_finding("info", "cluster-allow-reads-when-down is yes: reads may be stale during an outage"))
    if role is None and server:
        notes.append(command_support_note("ROLE", server, role_err))
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f["severity"], 3))
    return {
        "role": info.get("role"),
        "connected_replicas": info.get("connected_slaves"),
        "replicas": replicas,
        "master_repl_offset": master_offset,
        "slave_repl_offset": info.get("slave_repl_offset"),
        "master_link_status": info.get("master_link_status"),
        "master_last_io_seconds_ago": info.get("master_last_io_seconds_ago"),
        "master_sync_in_progress": info.get("master_sync_in_progress"),
        "repl_backlog_size": info.get("repl_backlog_size"),
        "role_command": _jsonable(role) if role is not None else {"unavailable": role_err},
        "settings": settings,
        "findings": findings,
        **engine_of(server or {}),
        **({"notes": notes} if notes else {}),
    }


def cluster(r: redis.Redis, serverless: bool = False) -> dict:
    cluster_info, info_err = _try(r.info, "cluster")
    notes: list[str] = []
    if cluster_info is None:
        notes.append(_unsupported("INFO cluster", info_err, serverless))
        enabled = serverless  # Serverless endpoints use cluster-mode client semantics
    else:
        enabled = bool(int(_num(cluster_info.get("cluster_enabled"))))
    if not enabled:
        return {
            "cluster_enabled": False,
            "note": "cluster mode disabled (single shard)",
            **({"notes": notes} if notes else {}),
        }
    info, cinfo_err = _try(r.execute_command, "CLUSTER INFO")
    if info is None:
        notes.append(_unsupported("CLUSTER INFO", cinfo_err, serverless))
    elif isinstance(info, (bytes, str)):
        info = dict(line.split(":", 1) for line in _s(info).splitlines() if ":" in line)
    shards, shards_err = _try(r.execute_command, "CLUSTER", "SHARDS")
    if shards is None:
        server, _ = _try(r.info, "server")
        notes.append(command_support_note("CLUSTER SHARDS", server, shards_err) + "; use node_cluster_nodes instead")
    slots, slots_err = _try(r.execute_command, "CLUSTER", "SLOTS")
    if slots is None:
        notes.append(_unsupported("CLUSTER SLOTS", slots_err, serverless))
    coverage: dict[str, int] = Counter()
    for row in slots or []:
        start, end, master = row[0], row[1], row[2]
        host = _s(master[0]) if master else "?"
        coverage[f"{host}:{master[1]}"] += int(end) - int(start) + 1
    notes += _serverless_hint(serverless)
    return {
        "cluster_enabled": True,
        "cluster_info": _jsonable(info) if info is not None else {"unavailable": cinfo_err},
        "slots_per_primary": dict(coverage),
        "slots_covered": sum(coverage.values()),
        "shards": _jsonable(shards) if shards is not None else {"unavailable": shards_err},
        **({"notes": notes} if notes else {}),
    }


TOTAL_SLOTS = 16384
_BAD_FLAGS = {"fail", "fail?", "handshake", "noaddr"}
SLOT_IMBALANCE_RATIO = 0.10  # a shard whose slot count is off the average by more than this is flagged
_MIGRATING = re.compile(r"\[(\d+)->-([0-9a-f]+)\]")
_IMPORTING = re.compile(r"\[(\d+)-<-([0-9a-f]+)\]")


def parse_cluster_nodes(text: str) -> list[dict]:
    """Parse CLUSTER NODES output into one dict per node."""
    nodes = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 8:
            continue
        node_id, addr, flags, master_id = parts[0], parts[1], parts[2].split(","), parts[3]
        hostport, _, hostname = addr.partition(",")
        hostport = hostport.split("@", 1)[0]
        ip, _, port = hostport.rpartition(":")
        slots = [t for t in parts[8:] if not t.startswith("[")]
        migrating = [{"slot": int(m[1]), "to": m[2]} for t in parts[8:] if (m := _MIGRATING.fullmatch(t))]
        importing = [{"slot": int(m[1]), "from": m[2]} for t in parts[8:] if (m := _IMPORTING.fullmatch(t))]
        slot_count = 0
        for tok in slots:
            lo, _, hi = tok.partition("-")
            slot_count += int(hi or lo) - int(lo) + 1
        nodes.append(
            {
                "id": node_id,
                "ip": ip,
                "port": int(port) if port.isdigit() else None,
                "hostname": hostname or None,
                "flags": flags,
                "role": "primary" if "master" in flags else "replica",
                "master_id": None if master_id == "-" else master_id,
                "link_state": parts[7],
                "slots": slots,
                "slot_count": slot_count,
                "migrating": migrating,
                "importing": importing,
                "myself": "myself" in flags,
                "failing": bool(_BAD_FLAGS & set(flags)) or parts[7] != "connected",
            }
        )
    return nodes


def cluster_topology_findings(nodes: list[dict]) -> list[dict]:
    """Severity-ranked topology findings from parsed CLUSTER NODES entries.

    Flags fail/fail?/handshake/noaddr nodes and disconnected links, slots being migrated or imported
    (resharding in progress), primaries without a replica once replication is in use, and shards whose slot
    count is more than ``SLOT_IMBALANCE_RATIO`` away from the average.
    """
    findings: list[dict] = []

    def label(n: dict) -> str:
        return _endpoint(n) if n["port"] else n["id"]

    for n in nodes:
        flags = set(n["flags"])
        ep = label(n)
        if "fail" in flags:
            findings.append(_finding("critical", f"node {ep} is flagged fail: the cluster considers it down", node=ep))
        if "fail?" in flags:
            findings.append(
                _finding("warning", f"node {ep} is flagged fail? (possible failure, not yet confirmed)", node=ep)
            )
        if "handshake" in flags:
            findings.append(
                _finding("warning", f"node {ep} is still in handshake: not yet part of the cluster", node=ep)
            )
        if "noaddr" in flags:
            findings.append(_finding("warning", f"node {ep} has no known address (noaddr)", node=ep))
        if n["link_state"] != "connected" and "fail" not in flags:
            findings.append(_finding("warning", f"node {ep} link state is {n['link_state']}", node=ep))
        if n.get("migrating") or n.get("importing"):
            out, into = n.get("migrating", []), n.get("importing", [])
            first = ", ".join(str(m["slot"]) for m in [*out, *into][:5])
            findings.append(
                _finding(
                    "info",
                    f"resharding in progress on {ep}: {len(out)} slot(s) migrating out, "
                    f"{len(into)} importing (slots {first})",
                    node=ep,
                )
            )
    primaries = [n for n in nodes if n["role"] == "primary" and n["slot_count"] > 0]
    replica_of = Counter(n["master_id"] for n in nodes if n["role"] == "replica")
    if replica_of:
        for p in primaries:
            if not replica_of[p["id"]]:
                findings.append(
                    _finding(
                        "warning",
                        f"primary {label(p)} has no replica: no failover target for its {p['slot_count']} slots",
                        node=label(p),
                    )
                )
    elif primaries:
        findings.append(_finding("info", "no shard has a replica: node failure loses data and slots until replaced"))
    if len(primaries) > 1:
        avg = statistics.mean(p["slot_count"] for p in primaries)
        for p in primaries:
            if abs(p["slot_count"] - avg) / avg > SLOT_IMBALANCE_RATIO:
                findings.append(
                    _finding(
                        "warning",
                        f"shard {label(p)} owns {p['slot_count']} slots, "
                        f"{p['slot_count'] / avg:.0%} of the average {avg:.0f}",
                        node=label(p),
                    )
                )
    return _sorted_findings(findings)


def _pairs(raw: Any) -> dict[str, Any]:
    """CLUSTER SHARDS entries arrive as dicts (RESP3, newer redis-py) or flat key/value lists (RESP2)."""
    if isinstance(raw, dict):
        return {str(_s(k)): v for k, v in raw.items()}
    items = list(raw)
    return {str(_s(items[i])): items[i + 1] for i in range(0, len(items) - 1, 2)}


def cluster_shards_check(raw: Any, lag_bytes_threshold: int = REPL_LAG_BYTES_WARN) -> tuple[list[dict], list[dict]]:
    """Cross-check CLUSTER SHARDS (7.0+): node health and replication offset lag per replica.

    Returns ``(findings, shards)``; ``shards`` lists slot count, primary and each replica's health and byte lag.
    """
    findings: list[dict] = []
    shards: list[dict] = []

    def endpoint(n: dict) -> str:
        host = _s(n.get("endpoint") or n.get("hostname") or n.get("ip"))
        return f"{host}:{n.get('port') or n.get('tls-port')}"

    for entry in raw or []:
        shard = _pairs(entry)
        nodes = [_pairs(n) for n in shard.get("nodes") or []]
        slots = [int(x) for x in shard.get("slots") or []]
        slot_count = sum(slots[i + 1] - slots[i] + 1 for i in range(0, len(slots) - 1, 2))
        primary = next((n for n in nodes if _s(n.get("role")) == "master"), None)
        primary_offset = int(_num(primary.get("replication-offset"))) if primary else None
        replicas = []
        for n in nodes:
            health = str(_s(n.get("health", "online")))
            ep = endpoint(n)
            if health != "online":
                findings.append(
                    _finding(
                        "critical" if health == "fail" else "warning",
                        f"CLUSTER SHARDS: node {ep} health is {health}",
                        node=ep,
                    )
                )
            if n is primary:
                continue
            lag = primary_offset - int(_num(n.get("replication-offset"))) if primary_offset is not None else None
            replicas.append({"endpoint": ep, "health": health, "lag_bytes": lag})
            if lag is not None and lag > lag_bytes_threshold:
                findings.append(_finding("warning", f"replica {ep} is {lag} bytes behind its primary", node=ep))
        shards.append(
            {
                "slot_count": slot_count,
                "primary": endpoint(primary) if primary else None,
                "replicas": replicas,
            }
        )
    return findings, shards


def _endpoint(n: dict) -> str:
    return f"{n.get('hostname') or n['ip']}:{n['port']}"


def cluster_nodes(r: redis.Redis, serverless: bool = False, cross_check: bool = True) -> dict:
    """Per-shard endpoints from CLUSTER NODES, with a recommendation for fan-out.

    ``topology_findings`` ranks node flags, resharding, replica coverage and slot imbalance. With
    ``cross_check`` CLUSTER SHARDS (7.0+) adds replica offset lag; older engines get a note instead.
    """
    cluster_info, info_err = _try(r.info, "cluster")
    if cluster_info is not None and not int(_num(cluster_info.get("cluster_enabled"))):
        return {"cluster_enabled": False, "note": "cluster mode disabled (single shard); use the primary endpoint"}
    raw, err = _try(r.execute_command, "CLUSTER", "NODES")
    if raw is None:
        notes = [_unsupported("CLUSTER NODES", err, serverless)]
        if cluster_info is None:
            notes.append(_unsupported("INFO cluster", info_err, serverless))
        if serverless:
            notes.append(
                "ElastiCache Serverless exposes one TLS endpoint and hides node topology; "
                "connect with a cluster-aware client to that endpoint."
            )
        return {
            "cluster_enabled": True if cluster_info is not None or serverless else None,
            "unavailable": err,
            "notes": notes,
        }
    nodes = parse_cluster_nodes(_s(raw))
    primaries = [n for n in nodes if n["role"] == "primary"]
    shards = []
    for p in sorted(primaries, key=lambda n: int((n["slots"] or ["99999"])[0].split("-")[0])):
        replicas = [n for n in nodes if n["master_id"] == p["id"]]
        shards.append(
            {
                "primary": _endpoint(p),
                "replicas": [_endpoint(n) for n in replicas],
                "slot_count": p["slot_count"],
                "slots": p["slots"],
                "failing": [_endpoint(n) for n in [p, *replicas] if n["failing"]],
            }
        )
    covered = sum(n["slot_count"] for n in primaries)
    findings = []
    if covered != TOTAL_SLOTS:
        findings.append(f"{covered} of {TOTAL_SLOTS} slots covered by primaries")
    findings += [f"node {_endpoint(n)} is {','.join(n['flags'])}/{n['link_state']}" for n in nodes if n["failing"]]
    topology = cluster_topology_findings(nodes)
    notes: list[str] = []
    shards_check = None
    if cross_check:
        raw_shards, shards_err = _try(r.execute_command, "CLUSTER", "SHARDS")
        if raw_shards is None:
            server, _ = _try(r.info, "server")
            notes.append(
                command_support_note("CLUSTER SHARDS", server, shards_err) + "; topology from CLUSTER NODES only"
            )
        else:
            check_findings, shards_check = cluster_shards_check(raw_shards)
            topology = _sorted_findings([*topology, *check_findings])
    return {
        "cluster_enabled": True,
        "nodes": nodes,
        "shards": shards,
        "slots_covered": covered,
        "findings": findings,
        "topology_findings": topology,
        **({"shards_check": shards_check} if shards_check is not None else {}),
        **({"notes": notes} if notes else {}),
        "recommendation": (
            "Per-key tools only see the connected node. To inspect each shard, set ELASTICACHE_HOST to each "
            "primary endpoint above (and replicas for read-side checks), or use node_cluster_health for a fan-out."
        ),
    }


def _node_snapshot(info: dict) -> dict:
    return {
        "role": info.get("role"),
        "used_memory": int(_num(info.get("used_memory"))),
        "maxmemory": int(_num(info.get("maxmemory"))),
        "ops_per_sec": int(_num(info.get("instantaneous_ops_per_sec"))),
        "connected_clients": int(_num(info.get("connected_clients"))),
        "evicted_keys": int(_num(info.get("evicted_keys"))),
        "master_link_status": info.get("master_link_status"),
        "master_repl_offset": int(_num(info.get("master_repl_offset"))),
        "replicas": [
            {"addr": f"{v.get('ip')}:{v.get('port')}", "offset": int(_num(v.get("offset"))), "lag": _num(v.get("lag"))}
            for k, v in info.items()
            if k.startswith("slave") and isinstance(v, dict)
        ],
    }


def cluster_health(
    r: redis.Redis,
    client_factory: Callable[[str, int], redis.Redis],
    max_workers: int = 8,
    per_node_timeout: float = 5.0,
    skew_ratio: float = 1.5,
    lag_bytes_threshold: int = 1_000_000,
) -> dict:
    """INFO on every cluster node (bounded concurrency, per-node timeout) with skew findings."""
    topo = cluster_nodes(r)
    if not topo.get("cluster_enabled") or "nodes" not in topo:
        return topo
    nodes = [n for n in topo["nodes"] if n["port"]]
    results: dict[str, dict] = {}

    def probe(n: dict) -> dict:
        client = client_factory(n.get("hostname") or n["ip"], n["port"])
        try:
            return _node_snapshot(client.info())
        finally:
            close = getattr(client, "close", None)
            if close:
                close()

    pool = ThreadPoolExecutor(max_workers=max(1, min(int(max_workers), 32)))
    try:
        futures = {_endpoint(n): pool.submit(probe, n) for n in nodes if not n["failing"]}
        for ep, fut in futures.items():
            try:
                results[ep] = fut.result(timeout=per_node_timeout)
            except FutureTimeout:
                results[ep] = {"error": f"timeout after {per_node_timeout:g}s"}
            except Exception as exc:  # one dead node must not hide the others
                results[ep] = {"error": f"{type(exc).__name__}: {exc}"}
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    findings: list[str] = list(topo["findings"])
    for ep, res in results.items():
        if "error" in res:
            findings.append(f"node {ep} unreachable: {res['error']}")
    primaries = {ep: res for ep, res in results.items() if res.get("role") == "master"}
    for label, key, floor in (("memory", "used_memory", 1), ("ops/sec", "ops_per_sec", 100)):
        vals = [res[key] for res in primaries.values()]
        if len(vals) > 1 and statistics.mean(vals) >= floor:
            avg = statistics.mean(vals)
            for ep, res in primaries.items():
                if res[key] > avg * skew_ratio:
                    findings.append(f"shard primary {ep} {label} is {res[key] / avg:.1f}x the shard average (skew)")
    for ep, res in primaries.items():
        for rep in res.get("replicas", []):
            lag = res["master_repl_offset"] - rep["offset"]
            if lag > lag_bytes_threshold:
                findings.append(f"replica {rep['addr']} of {ep} lags {lag} bytes")
    for ep, res in results.items():
        if res.get("role") == "slave" and res.get("master_link_status") not in (None, "up"):
            findings.append(f"replica {ep} link is {res['master_link_status']}")
    return {
        "cluster_enabled": True,
        "nodes_probed": len(results),
        "slots_covered": topo["slots_covered"],
        "shards": topo["shards"],
        "topology_findings": topo["topology_findings"],
        "per_node": results,
        "findings": findings or ["no skew, lag or coverage problems detected"],
    }


def _jsonable(v: Any) -> Any:
    if isinstance(v, bytes):
        return v.decode("utf-8", "backslashreplace")
    if isinstance(v, dict):
        return {str(_jsonable(k)): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v


# ------------------------------------------------------------- cluster-wide fan-out

ClientFactory = Callable[[str, int], redis.Redis]
SKEW_RATIO = 1.5


def _fan_out_primaries(
    r: redis.Redis,
    client_factory: ClientFactory,
    work: Callable[[redis.Redis, float, int], dict],
    max_workers: int,
    total_seconds: float,
    per_node_timeout: float,
) -> tuple[dict, dict[str, dict]]:
    """Run ``work(client, shard_budget_seconds, shard_count)`` on every shard primary.

    Returns ``(topology, outcomes)``; ``outcomes`` maps ``host:port`` to ``{"status": "ok", "data": ...}``
    or ``{"status": "unreachable", "error": ...}``. The wall-clock budget is split across the waves of
    primaries the worker pool needs (``ceil(primaries / workers)``), so the sum of all shard budgets stays
    within ``total_seconds``; a shard that hangs is abandoned ``per_node_timeout`` seconds after that,
    and a dead shard never fails the call. Clients come from ``client_factory`` (``SafeRedis`` only).
    """
    topo = cluster_nodes(r, cross_check=False)
    if not topo.get("cluster_enabled") or "nodes" not in topo:
        return topo, {}
    primaries = [n for n in topo["nodes"] if n["role"] == "primary" and n["port"]]
    workers = max(1, min(int(max_workers), 32, len(primaries) or 1))
    shard_budget = total_seconds / math.ceil(len(primaries) / workers) if primaries else total_seconds
    deadline = time.monotonic() + total_seconds
    hard_deadline = deadline + per_node_timeout
    outcomes: dict[str, dict] = {}

    def run(node: dict) -> dict:
        # A shard that only gets a worker after earlier shards stalled must not outlive the shared deadline:
        # it gets what is left of it, or never starts.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("not started before the overall time budget ran out")
        client = client_factory(node.get("hostname") or node["ip"], node["port"])
        try:
            return work(client, min(shard_budget, remaining), len(primaries))
        finally:
            close = getattr(client, "close", None)
            if close:
                close()

    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {}
        for node in sorted(primaries, key=_endpoint):
            ep = _endpoint(node)
            if node["failing"]:
                outcomes[ep] = {"status": "unreachable", "error": "flagged as failing in CLUSTER NODES; not contacted"}
            else:
                futures[ep] = pool.submit(run, node)
        for ep, fut in futures.items():
            try:
                outcomes[ep] = {"status": "ok", "data": fut.result(timeout=max(0.0, hard_deadline - time.monotonic()))}
            except FutureTimeout:
                outcomes[ep] = {"status": "unreachable", "error": "no answer within the time budget"}
            except Exception as exc:  # one dead shard must not hide the others
                outcomes[ep] = {"status": "unreachable", "error": f"{type(exc).__name__}: {exc}"}
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return topo, outcomes


def _shard_counts(outcomes: dict[str, dict]) -> dict[str, int]:
    return {
        "shards_total": len(outcomes),
        "shards_ok": sum(1 for o in outcomes.values() if o["status"] == "ok"),
        "shards_partial": sum(1 for o in outcomes.values() if o["status"] == "partial"),
        "shards_unreachable": sum(1 for o in outcomes.values() if o["status"] == "unreachable"),
    }


MAX_MERGED_ROWS = 5_000  # rows kept from all shards together before the final top-N cut


def _partial_nodes(outcomes: dict[str, dict]) -> list[dict]:
    """Nodes whose answer is incomplete (budget ran out, hung, failed), for a top-level ``partial_nodes`` list."""
    out: list[dict] = []
    for ep, o in outcomes.items():
        if o["status"] == "unreachable":
            out.append({"node": ep, "status": "unreachable", "reason": o["error"]})
        elif o["status"] == "partial":
            data = o.get("data") or {}
            reason = data.get("partial_reason") or (data.get("notes") or ["incomplete answer"])[0]
            out.append({"node": ep, "status": "partial", "reason": reason})
    return out


def _unreachable_findings(outcomes: dict[str, dict]) -> list[dict]:
    return [
        _finding("critical", f"shard {ep} unreachable: {o['error']}", shard=ep)
        for ep, o in outcomes.items()
        if o["status"] == "unreachable"
    ]


def _skew_findings(values: dict[str, float], label: str, ratio: float = SKEW_RATIO) -> list[dict]:
    if len(values) < 2:
        return []
    mean = statistics.mean(values.values())
    if mean <= 0:
        return []
    return [
        _finding("warning", f"shard {ep} {label} is {v / mean:.1f}x the shard average (skew)", shard=ep)
        for ep, v in values.items()
        if v > mean * ratio
    ]


def _sorted_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: _SEVERITY_RANK.get(f["severity"], 3))


def _labelled(rows: list[dict], shard: str) -> list[dict]:
    return [{**row, "shard": shard} for row in rows]


def cluster_keyspace_sample(
    r: redis.Redis,
    client_factory: ClientFactory,
    sample_size: int = 1000,
    match: str | None = None,
    top: int = 20,
    scan_count: int = 250,
    pause_ms: int = 0,
    max_seconds: float = DEFAULT_SAMPLE_SECONDS,
    max_workers: int = 8,
    per_node_timeout: float = 5.0,
    top_prefixes: int = DEFAULT_TOP_PREFIXES,
) -> dict:
    """``keyspace_sample`` on every shard primary, merged with a ``shard`` label on each key.

    ``sample_size`` and the ``max_seconds`` wall-clock budget are split across the primaries (the budget
    by the waves of the worker pool), so the whole call returns within ``max_seconds`` plus at most
    ``per_node_timeout`` for a stuck shard. Each shard reports ``ok``, ``partial`` (its own budget ran out)
    or ``unreachable``; the merged top-N lists come from whatever the reachable shards returned. Prefix
    aggregates are summed across shards (each shard reports its 50 largest prefixes, the merge keeps ``top_prefixes``).
    """
    started = time.monotonic()
    max_seconds = max(0.01, min(float(max_seconds), MAX_SAMPLE_SECONDS))
    top = max(1, int(top))

    def work(client: redis.Redis, budget: float, shards: int) -> dict:
        per_shard = max(1, math.ceil(max(1, min(int(sample_size), 100_000)) / shards))
        return keyspace_sample(
            client, per_shard, match, top, scan_count, pause_ms, budget, top_prefixes=MAX_TOP_PREFIXES
        )

    topo, outcomes = _fan_out_primaries(r, client_factory, work, max_workers, max_seconds, per_node_timeout)
    if not outcomes:
        if topo.get("cluster_enabled") is False:
            single = keyspace_sample(
                r, sample_size, match, top, scan_count, pause_ms, max_seconds, top_prefixes=top_prefixes
            )
            return {**single, "cluster_enabled": False, "note": "cluster mode disabled; sampled the single node"}
        return topo
    for o in outcomes.values():
        if o["status"] == "ok" and o["data"]["partial"]:
            o["status"] = "partial"
    findings = _unreachable_findings(outcomes)
    merged: dict[str, list[dict]] = defaultdict(list)
    by_type: dict[str, dict[str, int]] = defaultdict(lambda: {"keys": 0, "bytes": 0})
    per_shard: dict[str, dict] = {}
    totals = {"sampled_keys": 0, "dbsize": 0, "keys_without_ttl": 0}
    policy = ""
    prefix_groups: list[list[dict]] = []
    prefix_total = 0
    usage: float | None = None
    for ep, o in outcomes.items():
        if o["status"] == "unreachable":
            per_shard[ep] = o
            continue
        d = o["data"]
        policy = policy or d["maxmemory_policy"]
        prefix_groups.append(d["prefixes"])
        prefix_total += d["prefixes_summary"]["est_bytes_total"]
        if d["usage_of_maxmemory"] is not None:
            usage = max(usage or 0.0, d["usage_of_maxmemory"])
        for name in ("big_keys_by_bytes", "big_keys_by_length", "hot_keys_by_lfu", "coldest_keys_by_idle"):
            merged[name] += _labelled(d.get(name, [])[:top], ep)[: max(0, MAX_MERGED_ROWS - len(merged[name]))]
        for t, v in d["by_type"].items():
            by_type[t]["keys"] += v["keys"]
            by_type[t]["bytes"] += v["bytes"]
        for k in totals:
            totals[k] += d[k]
        per_shard[ep] = {
            "status": o["status"],
            "sampled_keys": d["sampled_keys"],
            "dbsize": d["dbsize"],
            "elapsed_seconds": d["elapsed_seconds"],
            "complete_scan": d["complete_scan"],
            **({"partial_reason": d["partial_reason"]} if d["partial"] else {}),
        }
        if d["partial"]:
            findings.append(_finding("warning", f"shard {ep} sample is partial: {d['partial_reason']}", shard=ep))
    findings += _skew_findings({ep: s["dbsize"] for ep, s in per_shard.items() if "dbsize" in s}, "key count")
    if topo["findings"]:
        findings += [_finding("warning", f) for f in topo["findings"]]
    prefix_report = _prefix_report(_merge_prefix_entries(prefix_groups), top_prefixes, policy, usage, prefix_total)
    findings += prefix_report.pop("findings")
    counts = _shard_counts(outcomes)
    result: dict[str, Any] = {
        "cluster_enabled": True,
        "scope": "all shard primaries",
        **counts,
        "partial": counts["shards_total"] != counts["shards_ok"],
        "partial_nodes": _partial_nodes(outcomes),
        "max_seconds": max_seconds,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "maxmemory_policy": policy,
        **totals,
        "by_type": dict(by_type),
        **prefix_report,
        "big_keys_by_bytes": sorted(merged["big_keys_by_bytes"], key=lambda x: x["bytes"] or 0, reverse=True)[:top],
        "big_keys_by_length": sorted(merged["big_keys_by_length"], key=lambda x: x["length"] or 0, reverse=True)[:top],
        "per_shard": per_shard,
        "findings": _sorted_findings(findings),
    }
    if merged["hot_keys_by_lfu"]:
        result["hot_keys_by_lfu"] = sorted(merged["hot_keys_by_lfu"], key=lambda x: x["lfu_freq"] or 0, reverse=True)[
            :top
        ]
    elif merged["coldest_keys_by_idle"]:
        result["coldest_keys_by_idle"] = sorted(
            merged["coldest_keys_by_idle"], key=lambda x: x["idle_seconds"] or 0, reverse=True
        )[:top]
        result["hot_keys_note"] = "set maxmemory-policy to an *-lfu policy to rank hot keys (OBJECT FREQ)"
    return result


def cluster_slowlog(
    r: redis.Redis,
    client_factory: ClientFactory,
    count: int = 25,
    include_args: bool = False,
    max_workers: int = 8,
    per_node_timeout: float = 5.0,
    max_seconds: float = 10.0,
) -> dict:
    """``slowlog`` on every shard primary: the slowest ``count`` entries overall, each labelled by shard."""
    count = max(1, min(int(count), 1024))
    started = time.monotonic()

    def work(client: redis.Redis, budget: float, shards: int) -> dict:
        return slowlog(client, count, include_args)

    topo, outcomes = _fan_out_primaries(r, client_factory, work, max_workers, max_seconds, per_node_timeout)
    if not outcomes:
        if topo.get("cluster_enabled") is False:
            return {**slowlog(r, count, include_args), "cluster_enabled": False, "note": "cluster mode disabled"}
        return topo
    findings = _unreachable_findings(outcomes)
    entries: list[dict] = []
    by_cmd: dict[str, dict[str, int]] = defaultdict(lambda: {"count": 0, "total_us": 0, "max_us": 0})
    per_shard: dict[str, dict] = {}
    for ep, o in outcomes.items():
        if o["status"] == "unreachable":
            per_shard[ep] = o
            continue
        d = o["data"]
        if d.get("notes"):
            o["status"] = "partial"
            findings.append(_finding("warning", f"shard {ep} slowlog unavailable: {d['notes'][0]}", shard=ep))
        entries += _labelled(d["entries"][:count], ep)[: max(0, MAX_MERGED_ROWS - len(entries))]
        for row in d["by_command"]:
            agg = by_cmd[row["command"]]
            agg["count"] += row["count"]
            agg["total_us"] += row["total_us"]
            agg["max_us"] = max(agg["max_us"], row["max_us"])
        per_shard[ep] = {
            "status": o["status"],
            "slowlog_len": d["slowlog_len"],
            "returned": d["returned"],
            **({"notes": d["notes"]} if d.get("notes") else {}),
        }
    entries.sort(key=lambda e: _num(e["duration_us"]), reverse=True)
    counts = _shard_counts(outcomes)
    by_command = sorted(({"command": k, **v} for k, v in by_cmd.items()), key=lambda x: x["total_us"], reverse=True)
    if entries:
        worst = entries[0]
        findings.append(
            _finding(
                "info",
                f"slowest entry: {worst['command']} took {worst['duration_us']} us on shard {worst['shard']}",
                shard=worst["shard"],
            )
        )
    return {
        "cluster_enabled": True,
        "scope": "all shard primaries",
        **counts,
        "partial": counts["shards_total"] != counts["shards_ok"],
        "partial_nodes": _partial_nodes(outcomes),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "returned": min(len(entries), count),
        "by_command": by_command,
        "entries": entries[:count],
        "per_shard": per_shard,
        "findings": _sorted_findings(findings),
    }


def cluster_memory(
    r: redis.Redis,
    client_factory: ClientFactory,
    max_workers: int = 8,
    per_node_timeout: float = 5.0,
    max_seconds: float = 10.0,
) -> dict:
    """Memory headline of every shard primary with skew, pressure and fragmentation findings."""
    started = time.monotonic()

    def work(client: redis.Redis, budget: float, shards: int) -> dict:
        return memory_report(client)

    topo, outcomes = _fan_out_primaries(r, client_factory, work, max_workers, max_seconds, per_node_timeout)
    if not outcomes:
        if topo.get("cluster_enabled") is False:
            return {**memory_report(r), "cluster_enabled": False, "note": "cluster mode disabled"}
        return topo
    findings = _unreachable_findings(outcomes)
    per_shard: dict[str, dict] = {}
    used: dict[str, float] = {}
    keep = (
        "used_memory",
        "used_memory_rss",
        "maxmemory",
        "usage_of_maxmemory",
        "mem_fragmentation_ratio",
        "fragmentation_verdict",
        "evicted_keys",
        "notes",
    )
    for ep, o in outcomes.items():
        if o["status"] == "unreachable":
            per_shard[ep] = o
            continue
        d = o["data"]
        if "used_memory" not in d:
            o["status"] = "partial"
            findings.append(
                _finding("warning", f"shard {ep} memory unavailable: {(d.get('notes') or ['?'])[0]}", shard=ep)
            )
        else:
            used[ep] = d["used_memory"]
            if (d.get("usage_of_maxmemory") or 0) > 0.9:
                findings.append(
                    _finding("critical", f"shard {ep} at {d['usage_of_maxmemory']:.0%} of maxmemory", shard=ep)
                )
            if _num(d.get("evicted_keys")) > 0:
                findings.append(
                    _finding("warning", f"shard {ep} evicted {int(_num(d['evicted_keys']))} keys", shard=ep)
                )
            if _num(d.get("mem_fragmentation_ratio"), 1.0) > 1.5:
                findings.append(
                    _finding("warning", f"shard {ep} fragmentation ratio {d['mem_fragmentation_ratio']}", shard=ep)
                )
        per_shard[ep] = {"status": o["status"], **{k: d[k] for k in keep if k in d}}
    findings += _skew_findings(used, "memory")
    counts = _shard_counts(outcomes)
    return {
        "cluster_enabled": True,
        "scope": "all shard primaries",
        **counts,
        "partial": counts["shards_total"] != counts["shards_ok"],
        "partial_nodes": _partial_nodes(outcomes),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "total_used_memory": int(sum(used.values())),
        "max_shard_used_memory": int(max(used.values())) if used else 0,
        "per_shard": per_shard,
        "findings": _sorted_findings(findings),
    }


# --------------------------------------------------------------------------- ACL LOG

ACL_AUTH_FAILURES_WARN = 5
ACL_DENIED_WARN = 20
ACL_RECENT_SECONDS = 300
_CLIENT_INFO_FIELDS = ("addr", "name", "user", "lib-name", "lib-ver", "cmd")


def _client_info(raw: Any) -> dict[str, str]:
    """Reduce ACL LOG's ``client-info`` (string or dict) to a few non-sensitive fields."""
    if isinstance(raw, dict):
        fields = {str(_s(k)): str(_s(v)) for k, v in raw.items()}
    else:
        fields = dict(tok.split("=", 1) for tok in str(_s(raw) or "").split() if "=" in tok)
    return {k: fields[k] for k in _CLIENT_INFO_FIELDS if k in fields}


def acl_log(r: redis.Redis, count: int = 25) -> dict:
    """Recent ACL failures from ``ACL LOG`` plus ``ACL WHOAMI``; never ``ACL LIST``/``GETUSER`` (password hashes).

    Key and channel names in ``object`` are hidden, client info is cut to address, name, user and
    library, and any password-like field is redacted. ``ACL LOG RESET`` is refused by the client guard.
    """
    count = max(1, min(int(count), 128))
    server, _ = _try(r.info, "server")
    me, me_err = _try(r.execute_command, "ACL WHOAMI")
    raw, err = _try(r.execute_command, "ACL LOG", count)
    if raw is None:
        return {
            "whoami": _s(me),
            "entries": [],
            "findings": [],
            "notes": [command_support_note("ACL LOG", server, err)],
        }
    entries = []
    by_reason: Counter[str] = Counter()
    by_user: Counter[str] = Counter()
    auth_failures = denied_commands = recent_denied = 0
    failing_users: set[str] = set()
    for e in raw:
        e = _jsonable(e)
        reason = str(e.get("reason", "?"))
        user = str(e.get("username", "?"))
        n = int(_num(e.get("count"), 1))
        by_reason[reason] += n
        by_user[user] += n
        if reason == "auth":
            auth_failures += n
            failing_users.add(user)
        elif reason == "command":
            denied_commands += n
            if _num(e.get("age-seconds"), ACL_RECENT_SECONDS + 1) <= ACL_RECENT_SECONDS:
                recent_denied += n
        hidden = reason in ("key", "channel")
        entries.append(
            redact(
                {
                    "reason": reason,
                    "context": e.get("context"),
                    "object": "(name hidden)" if hidden else e.get("object"),
                    "username": user,
                    "count": n,
                    "age_seconds": e.get("age-seconds"),
                    "client": _client_info(e.get("client-info")),
                }
            )
        )
    entries.sort(key=lambda x: x["count"], reverse=True)
    findings = []
    if auth_failures >= ACL_AUTH_FAILURES_WARN:
        who = ", ".join(sorted(failing_users))
        findings.append(_finding("warning", f"{auth_failures} failed authentications for users: {who}"))
    if recent_denied >= ACL_DENIED_WARN:
        findings.append(
            _finding("warning", f"{recent_denied} denied commands in the last {ACL_RECENT_SECONDS}s (ACL spike)")
        )
    elif denied_commands:
        findings.append(_finding("info", f"{denied_commands} commands denied by ACL rules"))
    return {
        "whoami": _s(me) if me is not None else {"unavailable": me_err},
        "entries_returned": len(entries),
        "by_reason": dict(by_reason),
        "by_user": dict(by_user),
        "entries": entries,
        "findings": _sorted_findings(findings),
    }


# ------------------------------------------------------------------------- triage

TRIAGE_MAX_FINDINGS = 30
TRIAGE_BIG_BUFFER_BYTES = 10 * 1024 * 1024
TRIAGE_SLOW_US = 100_000
TRIAGE_PING_P99_MS = 50.0
TRIAGE_LATENCY_EVENT_MS = 100


def _safe(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[Any, str | None]:
    """``_try`` that also absorbs connection and timeout errors, so one section never kills the call."""
    try:
        return _try(fn, *args, **kwargs)
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _health_severity(message: str) -> str:
    if message.startswith(("replica link", "memory at", "noeviction at")):
        return "critical"
    return "warning"


def _triage_health(d: dict) -> tuple[dict, list[dict]]:
    if "role" not in d:
        return {"status": "unavailable", "notes": d.get("notes", [])}, []
    keys = ("engine", "version", "role", "connected_clients", "hit_ratio", "ops_per_sec", "evicted_keys")
    findings = [_finding(_health_severity(f), f) for f in d["findings"] if not f.startswith("no issues detected")]
    return {k: d[k] for k in keys if k in d}, findings


def _triage_memory(d: dict) -> tuple[dict, list[dict]]:
    if "used_memory" not in d:
        return {"status": "unavailable", "notes": d.get("notes", [])}, []
    keys = ("used_memory", "maxmemory", "usage_of_maxmemory", "mem_fragmentation_ratio", "fragmentation_verdict")
    return {k: d[k] for k in keys}, []  # usage, eviction and fragmentation findings come from the health section


def _triage_replication(d: dict) -> tuple[dict, list[dict]]:
    summary = {
        "role": d["role"],
        "connected_replicas": d["connected_replicas"],
        "master_link_status": d["master_link_status"],
    }
    return summary, list(d["findings"])


def _triage_clients(d: dict) -> tuple[dict, list[dict]]:
    findings = []
    over_1h = d["idle_seconds"]["over_1h"]
    if over_1h >= IDLE_CLIENTS_WARN:
        findings.append(
            _finding("info", f"{over_1h} clients idle for over an hour (connection leak or missing timeout)")
        )
    heavy = [
        c for c in d["top_by_buffer_memory"] if _num(c.get("omem")) + _num(c.get("qbuf")) >= TRIAGE_BIG_BUFFER_BYTES
    ]
    for c in heavy[:3]:
        findings.append(
            _finding(
                "warning",
                f"client id={c.get('id')} ({c.get('addr')}) holds {int(_num(c.get('omem')) + _num(c.get('qbuf')))} "
                "bytes of query/output buffer",
            )
        )
    return {"total": d["total"], "idle_over_1h": over_1h}, findings


def _triage_commandstats(d: dict) -> tuple[dict, list[dict]]:
    rows = [c for c in d["top_by_total_time"] if c["failed_calls"] or c["rejected_calls"]]
    rows.sort(key=lambda c: c["failed_calls"] + c["rejected_calls"], reverse=True)
    findings = []
    for c in rows[:5]:
        total = max(c["calls"], 1)
        bad = c["failed_calls"] + c["rejected_calls"]
        severity = "warning" if c["rejected_calls"] or bad / total > 0.05 else "info"
        findings.append(
            _finding(
                severity,
                f"{c['command']}: {c['failed_calls']} failed and {c['rejected_calls']} rejected of {c['calls']} calls",
                command=c["command"],
            )
        )
    summary = {
        "commands": d["commands"],
        "failed_calls": sum(c["failed_calls"] for c in rows),
        "rejected_calls": sum(c["rejected_calls"] for c in rows),
    }
    return summary, findings


def _triage_slowlog(d: dict) -> tuple[dict, list[dict]]:
    if d.get("notes"):
        return {"status": "unavailable", "notes": d["notes"]}, []
    entries = d["entries"]
    findings = []
    if entries:
        worst = max(entries, key=lambda e: _num(e["duration_us"]))
        slow = _num(worst["duration_us"])
        findings.append(
            _finding(
                "warning" if slow >= TRIAGE_SLOW_US else "info",
                f"slowest recent command: {worst['command']} took {int(slow)} us "
                f"({d['slowlog_len']} entries in slowlog)",
            )
        )
    return {
        "slowlog_len": d["slowlog_len"],
        "top": [{"command": e["command"], "duration_us": e["duration_us"]} for e in entries],
    }, findings


def _triage_latency(d: dict) -> tuple[dict, list[dict]]:
    rtt = d["ping_rtt_ms"]
    findings = []
    if rtt["p99"] >= TRIAGE_PING_P99_MS:
        findings.append(_finding("warning", f"PING p99 is {rtt['p99']} ms (p50 {rtt['p50']} ms)"))
    events = d["latency_latest"] if isinstance(d["latency_latest"], list) else []
    for e in sorted(events, key=lambda e: _num(e["max_ms"]), reverse=True)[:3]:
        severity = "warning" if _num(e["max_ms"]) >= TRIAGE_LATENCY_EVENT_MS else "info"
        findings.append(
            _finding(severity, f"latency event {e['event']}: latest {e['latest_ms']} ms, max {e['max_ms']} ms")
        )
    return {"ping_p50_ms": rtt["p50"], "ping_p99_ms": rtt["p99"], "events": len(events)}, findings


def triage(
    r: redis.Redis, client_factory: Callable[[str, int], redis.Redis] | None = None, serverless: bool = False
) -> dict:
    """One-call data-plane on-call snapshot.

    Runs health, memory, replication, clients, commandstats, slowlog (top 5) and latency by reusing the
    section functions (no extra Redis commands). A section that fails becomes ``unavailable`` and the
    result ``partial``; findings from every section are merged, severity-sorted and capped at
    ``TRIAGE_MAX_FINDINGS``. On Serverless an unavailable section is an info finding, not a warning.
    """
    plan: list[tuple[str, Callable[[], Any], Callable[[Any], tuple[dict, list[dict]]]]] = [
        ("health", lambda: health_summary(r, serverless), _triage_health),
        ("memory", lambda: memory_report(r, serverless), _triage_memory),
        ("replication", lambda: replication(r, client_factory), _triage_replication),
        ("clients", lambda: client_list(r, 5), _triage_clients),
        ("commandstats", lambda: commandstats(r, 500), _triage_commandstats),
        ("slowlog", lambda: slowlog(r, 5, False, serverless), _triage_slowlog),
        ("latency", lambda: latency(r, 5), _triage_latency),
    ]
    sections: dict[str, dict] = {}
    findings: list[dict] = []
    for name, fetch, summarize in plan:
        data, err = _safe(fetch)
        if data is None:
            summary: dict[str, Any] = {"status": "unavailable", "error": err}
            section_findings: list[dict] = []
        else:
            summary, section_findings = summarize(data)
            summary = {"status": "ok", **summary}
        if summary["status"] == "unavailable":
            detail = err or "; ".join(summary.get("notes") or []) or "no data"
            section_findings = [_finding("info" if serverless else "warning", f"{name} section unavailable: {detail}")]
        sections[name] = summary
        findings += [{**f, "section": name} for f in section_findings]
    findings = _sorted_findings(findings)
    total = len(findings)
    partial = any(s["status"] != "ok" for s in sections.values())
    if not findings:
        findings = [_finding("info", "no issues detected by the triage sections", section="triage")]
    return {
        "status": "partial" if partial else "ok",
        "serverless": serverless,
        "findings": findings[:TRIAGE_MAX_FINDINGS],
        "findings_total": total,
        **({"findings_omitted": total - TRIAGE_MAX_FINDINGS} if total > TRIAGE_MAX_FINDINGS else {}),
        "sections": sections,
    }
