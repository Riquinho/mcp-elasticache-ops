"""COMMANDSTATS/ERRORSTATS rollup and CONFIG GET review."""

from __future__ import annotations

from typing import Any

import redis

from .. import quirks
from ..safe_client import CONFIG_GET_EXACT, CONFIG_GET_PREFIXES
from ._core import (
    _SEVERITY_RANK,
    IDLE_CLIENTS_WARN,
    _num,
    _s,
    _try,
    command_support_note,
    engine_of,
    redact,
    version_tuple,
)

COMMANDSTATS_P99_WARN_USEC = 10_000  # a top-by-time command whose p99 exceeds 10 ms is worth a look


MAX_ERROR_PREFIXES = 20  # errorstats rows returned


# Error prefixes that point at a specific, fixable cause (INFO errorstats, Redis 6.2+/Valkey).
_ERROR_CAUSES = {
    "OOM": "maxmemory is reached with a noeviction-like policy: raise memory, evict, or shorten TTLs",
    "READONLY": "writes reached a replica (failover or a client pinned to a replica): check endpoints and failovers",
    "NOPERM": "an ACL user lacks permission for the command or key: check ACL LOG with node_acl_log",
}


_LATENCY_PREFIX = "latency_percentiles_usec_"


def _error_rows(stats: dict) -> list[dict]:
    rows = [
        {"error": key.removeprefix("errorstat_"), "count": int(_num((v or {}).get("count")))}
        for key, v in stats.items()
        if isinstance(v, dict)
    ]
    rows.sort(key=lambda row: row["count"], reverse=True)
    return rows


def _latency_rows(stats: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for key, v in stats.items():
        if key.startswith(_LATENCY_PREFIX) and isinstance(v, dict):
            out[key.removeprefix(_LATENCY_PREFIX)] = {
                "p50_usec": _num(v.get("p50")),
                "p99_usec": _num(v.get("p99")),
                "p99_9_usec": _num(v.get("p99.9")),
            }
    return out


def commandstats(r: redis.Redis, top: int = 20) -> dict:
    """Commands ranked by CPU time, plus error prefix counts and per-command latency percentiles.

    ``INFO errorstats`` (Redis 6.2+/Valkey) and ``INFO latencystats`` (7.0+/Valkey) are optional: an older
    engine or a managed endpoint that refuses them yields a note, never an error. Output is capped at ``top``.
    """
    stats = r.info("commandstats")
    top = max(1, int(top))
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
    rows.sort(key=lambda x: _num(x["usec"]), reverse=True)
    top_rows = rows[:top]

    notes: list[str] = []
    server, _ = _try(r.info, "server")
    errors, errors_err = _try(r.info, "errorstats")
    if errors is None:
        notes.append(command_support_note("INFO ERRORSTATS", server, errors_err))
    error_rows = _error_rows(errors or {})
    latency_stats, latency_err = _try(r.info, "latencystats")
    if latency_stats is None:
        notes.append(command_support_note("INFO LATENCYSTATS", server, latency_err))
    latency = _latency_rows(latency_stats or {})

    findings: list[str] = []
    for row in error_rows:
        cause = _ERROR_CAUSES.get(str(row["error"]).upper())
        if cause and row["count"] > 0:
            findings.append(f"{row['count']} {row['error']} error replies since start: {cause}")
    for row in top_rows:
        p99 = (latency.get(str(row["command"])) or {}).get("p99_usec", 0.0)
        if p99 > COMMANDSTATS_P99_WARN_USEC:
            findings.append(
                f"{row['command']} p99 latency is {p99 / 1000:.1f} ms (above {COMMANDSTATS_P99_WARN_USEC // 1000} ms) "
                f"over {row['calls']} calls; see node_slowlog for the arguments"
            )
    shown = {row["command"] for row in top_rows}
    return {
        "commands": len(rows),
        "top_by_total_time": top_rows,
        "errorstats": error_rows[: min(top, MAX_ERROR_PREFIXES)],
        "latencystats": {k: v for k, v in sorted(latency.items(), key=lambda kv: -kv[1]["p99_usec"]) if k in shown},
        "findings": findings,
        **({"notes": notes} if notes else {}),
    }


CONFIG_FALLBACK_NOTE = (
    "CONFIG GET is refused by this endpoint (managed services restrict it); read the effective values "
    "from the parameter group with aws_parameters."
)


_KEYSPACE_CLASSES = set("gl$szxetd")  # event classes besides K/E; A is the alias for all of them


def config_patterns() -> list[str]:
    """CONFIG GET patterns requested by ``config_view``: only allowlisted names and prefixes."""
    return [*sorted(CONFIG_GET_EXACT), *(f"{p}*" for p in CONFIG_GET_PREFIXES)]


def _cfg_finding(severity: str, message: str, parameter: str) -> dict:
    return {"severity": severity, "message": message, "parameter": parameter}


def _valkey_config_findings(cfg: dict[str, str], server: dict) -> list[dict]:
    """Valkey 8+ quirks: single-threaded I/O by default, lazyfree tuning."""
    out: list[dict] = []
    engine = engine_of(server)
    if engine["engine"] != "valkey":
        return out
    if version_tuple(engine["version"]) >= (8,) and str(cfg.get("io-threads", "")).strip() == "1":
        out.append(
            _cfg_finding(
                "info",
                f"io-threads is 1 on Valkey 8+: {quirks.text('valkey-io-threads')}",
                "io-threads",
            )
        )
    off = sorted(k for k, v in cfg.items() if k.startswith("lazyfree-lazy-") and str(v).lower() == "no")
    if off:
        out.append(
            _cfg_finding(
                "info",
                f"{', '.join(off)} is off: {quirks.text('valkey-lazyfree')}",
                off[0],
            )
        )
    return out


def config_findings(cfg: dict[str, str], idle_clients: int | None = None, server: dict | None = None) -> list[dict]:
    out: list[dict] = _valkey_config_findings(cfg, server or {})
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
    server, _ = _try(r.info, "server")
    findings = sorted(config_findings(cfg, idle, server or {}), key=lambda f: _SEVERITY_RANK.get(f["severity"], 3))
    out: dict[str, Any] = {"available": True, "config": redact(dict(sorted(cfg.items()))), "findings": findings}
    if refused:
        out["notes"] = [CONFIG_FALLBACK_NOTE]
        out["refused_patterns"] = refused
    return out
