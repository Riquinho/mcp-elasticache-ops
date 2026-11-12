"""Node health summary, memory report, slowlog, client list and latency probe."""

from __future__ import annotations

import statistics
import time
from collections import Counter, defaultdict
from typing import Any

import redis

from .. import quirks
from ._core import (
    CHURN_MIN_UPTIME_SECONDS,
    CHURN_PER_SECOND,
    CLIENT_BUFFER_WARN_BYTES,
    CLIENT_MEMORY_FLOOR_BYTES,
    CLIENT_MEMORY_SHARE,
    CONNECTIONS_CRIT_RATIO,
    CONNECTIONS_WARN_RATIO,
    ERROR_REPLIES_MIN_COMMANDS,
    ERROR_REPLIES_SHARE,
    FORK_WARN_USEC,
    FRAGMENTATION_HIGH,
    FRAGMENTATION_LOW,
    HEALTH_EXTRA_FIELDS,
    IDLE_CLIENTS_WARN,
    INFO_SECTIONS,
    MEMORY_HIGH_RATIO,
    NOEVICTION_USAGE_RATIO,
    SYNC_FULL_MIN,
    SYNC_FULL_PER_HOUR,
    SYNC_MIN_UPTIME_SECONDS,
    _finding,
    _num,
    _s,
    _sorted_findings,
    _try,
    _unsupported,
    command_support_note,
    engine_of,
    version_tuple,
)
from .memory_breakdown import memory_breakdown, memory_breakdown_findings


def _fork_findings(info: dict) -> list[str]:
    fork = _num(info.get("latest_fork_usec"))
    if fork <= FORK_WARN_USEC:
        return []
    tail = "the main thread blocks while forking (large heap or slow host); expect latency spikes during saves"
    return [f"fork latency {fork / 1_000_000:.1f}s (latest_fork_usec={int(fork)}): {tail}"]


def _sync_findings(info: dict) -> list[str]:
    out: list[str] = []
    partial_err = int(_num(info.get("sync_partial_err")))
    if partial_err > 0:
        out.append(
            f"{partial_err} partial resync requests refused (sync_partial_err): the replication backlog is too small "
            "or replicas fall too far behind, so replicas fall back to full resyncs (see repl-backlog-size)"
        )
    full = _num(info.get("sync_full"))
    uptime = _num(info.get("uptime_in_seconds"))
    if uptime >= SYNC_MIN_UPTIME_SECONDS and full >= SYNC_FULL_MIN and full * 3600 / uptime >= SYNC_FULL_PER_HOUR:
        out.append(
            f"{int(full)} full resyncs served since start (about {full * 3600 / uptime:.1f}/hour, sync_full): "
            "replicas keep resyncing, each one forks and ships a full RDB"
        )
    return out


def _error_findings(info: dict) -> list[str]:
    out: list[str] = []
    evicted_clients = int(_num(info.get("evicted_clients")))
    if evicted_clients > 0:
        out.append(
            f"{evicted_clients} clients evicted since restart (evicted_clients): maxmemory-clients was reached; "
            "look for clients with large buffers, see node_clients"
        )
    errors = _num(info.get("total_error_replies"))
    commands = _num(info.get("total_commands_processed"))
    if commands >= ERROR_REPLIES_MIN_COMMANDS and errors / commands > ERROR_REPLIES_SHARE:
        out.append(
            f"{errors / commands:.0%} of commands ended in an error reply ({int(errors)} of {int(commands)}, "
            "total_error_replies); see node_commandstats for the commands and error prefixes"
        )
    return out


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


def _connection_findings(info: dict, maxclients: float) -> list[str]:
    out: list[str] = []
    clients = _num(info.get("connected_clients"))
    if maxclients > 0 and clients / maxclients > CONNECTIONS_WARN_RATIO:
        ratio = clients / maxclients
        tail = "new clients are about to be refused" if ratio > CONNECTIONS_CRIT_RATIO else "headroom is shrinking"
        out.append(f"connections at {ratio:.0%} of maxclients ({int(clients)}/{int(maxclients)}): {tail}")
    used = _num(info.get("used_memory"))
    buffers = _num(info.get("mem_clients_normal"))
    if used > 0 and buffers >= CLIENT_MEMORY_FLOOR_BYTES and buffers / used > CLIENT_MEMORY_SHARE:
        out.append(
            f"client buffers hold {buffers / used:.0%} of used_memory ({int(buffers) // (1024 * 1024)} MiB "
            "in mem_clients_normal); look for slow consumers, see node_clients"
        )
    uptime = _num(info.get("uptime_in_seconds"))
    received = _num(info.get("total_connections_received"))
    if uptime >= CHURN_MIN_UPTIME_SECONDS and received / uptime >= CHURN_PER_SECOND:
        out.append(
            f"connection churn: {received / uptime:.0f} new connections/s on average since start "
            f"(total_connections_received={int(received)}); clients are probably not pooling connections"
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
    findings += _fork_findings(info)
    findings += _sync_findings(info)
    findings += _error_findings(info)
    findings += _buffer_findings(info)
    maxclients = _num(info.get("maxclients"))
    if not maxclients and _num(info.get("connected_clients")) > 0:
        cfg, _ = _try(r.config_get, "maxclients")
        maxclients = _num((cfg or {}).get("maxclients"))
    findings += _connection_findings(info, maxclients)
    return {
        **engine_of(info),
        "role": info.get("role"),
        "uptime_seconds": info.get("uptime_in_seconds"),
        "connected_clients": info.get("connected_clients"),
        "maxclients": int(maxclients) or None,
        "blocked_clients": info.get("blocked_clients"),
        "ops_per_sec": info.get("instantaneous_ops_per_sec"),
        "hit_ratio": round(hits / (hits + misses), 4) if hits + misses else None,
        "used_memory": int(used),
        "maxmemory": int(maxmemory),
        "maxmemory_policy": info.get("maxmemory_policy"),
        "mem_fragmentation_ratio": frag,
        "evicted_keys": info.get("evicted_keys"),
        "expired_keys": info.get("expired_keys"),
        **{k: info[k] for k in HEALTH_EXTRA_FIELDS if k in info},
        "keyspace": {k: v for k, v in info.items() if k.startswith("db")},
        "findings": findings or ["no issues detected by basic thresholds"],
        **({"serverless": serverless} if serverless else {}),
        **({"notes": notes} if notes else {}),
    }


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
    breakdown_findings = memory_breakdown_findings(mem, memory_stats)
    findings += breakdown_findings
    return {
        "findings": findings,
        "breakdown_findings": breakdown_findings,
        "breakdown": memory_breakdown(mem, memory_stats),
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
            f"{quirks.get('reserved-memory-percent').remediation}; "
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
        key=lambda x: _num(x["total_us"]),
        reverse=True,
    )
    return {"slowlog_len": total_len, "returned": len(out), "by_command": summary, "entries": out}


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
    over_1h = sum(1 for i in idle if i > 3600)
    findings = []
    if over_1h >= IDLE_CLIENTS_WARN:
        findings.append(
            _finding(
                "info" if over_1h < 10 * IDLE_CLIENTS_WARN else "warning",
                f"{over_1h} of {len(clients)} clients have been idle for over an hour "
                "(connection leak, or timeout 0 with no idle reaping)",
            )
        )
    return {
        "findings": findings,
        "total": len(clients),
        "by_source_ip": by_ip.most_common(top),
        "by_name": by_name.most_common(top),
        "by_user": by_user.most_common(top),
        "by_last_command": by_cmd.most_common(top),
        "idle_seconds": {
            "max": max(idle) if idle else 0,
            "median": statistics.median(idle) if idle else 0,
            "over_1h": over_1h,
        },
        "top_by_buffer_memory": [{k: c.get(k) for k in fields} for c in top_mem],
    }


HISTOGRAM_COMMANDS = 8  # busiest commands (by total time) whose LATENCY HISTOGRAM is fetched
HISTOGRAM_TOP = 5  # rows returned in command_tail
HISTOGRAM_MIN_CALLS = 100  # fewer calls than this make a percentile meaningless
HISTOGRAM_TAIL_FACTOR = 100.0  # p99.9 this many times the p50 means a heavy tail
HISTOGRAM_TAIL_FLOOR_US = 1_000  # ... and only when the tail itself is at least 1 ms
_HISTOGRAM_QUANTILES = (("p50_usec", 0.5), ("p99_usec", 0.99), ("p99_9_usec", 0.999))


def _flat_pairs(value: Any) -> list[tuple[Any, Any]]:
    """A RESP3 map or a RESP2 flat ``[k1, v1, k2, v2]`` list as ``(key, value)`` pairs."""
    if isinstance(value, dict):
        return list(value.items())
    if isinstance(value, list | tuple):
        return list(zip(value[0::2], value[1::2], strict=False))
    return []


def _histogram_row(name: str, body: Any) -> dict | None:
    """p50/p99/p99.9 from one command's cumulative ``histogram_usec`` buckets (bucket upper bounds, in microseconds)."""
    fields = {str(_s(k)): v for k, v in _flat_pairs(body)}
    calls = int(_num(fields.get("calls")))
    buckets = sorted((_num(_s(k)), _num(v)) for k, v in _flat_pairs(fields.get("histogram_usec")))
    if calls <= 0 or not buckets:
        return None
    row: dict[str, Any] = {"command": name, "calls": calls}
    for label, quantile in _HISTOGRAM_QUANTILES:
        row[label] = next((bound for bound, cumulative in buckets if cumulative >= quantile * calls), buckets[-1][0])
    p50 = _num(row["p50_usec"])
    row["tail_ratio"] = round(_num(row["p99_9_usec"]) / p50, 1) if p50 > 0 else None
    return row


def command_tail(r: redis.Redis, serverless: bool = False) -> dict:
    """Per-command p50/p99/p99.9 from ``LATENCY HISTOGRAM`` for the busiest commands, widest tail first.

    Needs Redis 7.0+/Valkey; an older engine or a managed endpoint that refuses it yields a note, not an error.
    Percentiles are histogram bucket upper bounds (powers of two), so they overstate by up to 2x."""
    stats, stats_err = _try(r.info, "commandstats")
    if stats is None:
        return {"findings": [], "rows": [], "notes": [_unsupported("INFO commandstats", stats_err, serverless)]}
    busiest = sorted(
        (
            (str(k).removeprefix("cmdstat_"), _num((v or {}).get("usec")))
            for k, v in stats.items()
            if isinstance(v, dict)
        ),
        key=lambda item: -item[1],
    )
    names = [name for name, _ in busiest[:HISTOGRAM_COMMANDS]]
    if not names:
        return {"findings": [], "rows": []}
    reply, err = _try(r.execute_command, "LATENCY", "HISTOGRAM", *names)
    if err is not None:
        if serverless:
            return {"findings": [], "rows": [], "notes": [_unsupported("LATENCY HISTOGRAM", err, True)]}
        server, _ = _try(r.info, "server")
        return {"findings": [], "rows": [], "notes": [command_support_note("LATENCY HISTOGRAM", server, err)]}
    rows = [
        row
        for key, body in _flat_pairs(reply)
        if (row := _histogram_row(str(_s(key)), body)) is not None and row["calls"] >= HISTOGRAM_MIN_CALLS
    ]
    rows.sort(key=lambda row: -(row["tail_ratio"] or 0.0))
    findings = [
        _finding(
            "warning",
            f"{str(row['command']).upper()} p99.9 is {row['tail_ratio']:.0f}x its p50 "
            f"({_num(row['p99_9_usec']) / 1000:.1f} ms vs {_num(row['p50_usec']) / 1000:.2f} ms over {row['calls']} "
            "calls): suspect big keys or a blocking command; see node_commandlog and node_slowlog",
            command=row["command"],
        )
        for row in rows[:HISTOGRAM_TOP]
        if (row["tail_ratio"] or 0.0) >= HISTOGRAM_TAIL_FACTOR and _num(row["p99_9_usec"]) >= HISTOGRAM_TAIL_FLOOR_US
    ]
    return {"findings": findings, "rows": rows[:HISTOGRAM_TOP]}


def latency(r: redis.Redis, ping_samples: int = 20, serverless: bool = False) -> dict:
    """Client-side PING round-trip, the server latency monitor and the per-command slow tail (LATENCY HISTOGRAM)."""
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
    tail = command_tail(r, serverless)
    return {
        "findings": tail["findings"],
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
        "command_tail": tail["rows"],
        **({"notes": tail["notes"]} if tail.get("notes") else {}),
        "hint": "Empty latency_latest usually means latency-monitor-threshold is 0 in the parameter group.",
    }


COMMANDLOG_TYPES = ("slow", "large-request", "large-reply")
COMMANDLOG_TOP = 5  # command and client rows returned per type
COMMANDLOG_LARGE_WARN_BYTES = 1024 * 1024  # the server logs from 1 MiB by default
COMMANDLOG_LARGE_CRIT_BYTES = 16 * 1024 * 1024
COMMANDLOG_SLOW_WARN_US = 100_000
_COMMANDLOG_MIN_VERSION = (8, 0)


def _commandlog_entries(reply: Any) -> list[dict]:
    """Entries as ``[id, time, value, args, client_addr, client_name]``; the arguments are dropped on purpose
    (only the command name is kept), because a large request or reply is exactly where values live."""
    out = []
    for entry in reply if isinstance(reply, list | tuple) else []:
        if not isinstance(entry, list | tuple) or len(entry) < 3:
            continue
        args = entry[3] if len(entry) > 3 and isinstance(entry[3], list | tuple) else []
        out.append(
            {
                "id": entry[0],
                "timestamp": entry[1],
                "value": int(_num(entry[2])),
                "command": str(_s(args[0])).upper()[:32] if args else "?",
                "client_address": _s(entry[4]) if len(entry) > 4 else None,
                "client_name": _s(entry[5]) if len(entry) > 5 else None,
            }
        )
    return out


def _commandlog_section(kind: str, entries: list[dict], total: Any) -> dict:
    unit = "duration_us" if kind == "slow" else "size_bytes"
    by_command: dict[str, dict[str, int]] = defaultdict(lambda: {"entries": 0, "max": 0})
    by_client: Counter[str] = Counter()
    for e in entries:
        agg = by_command[e["command"]]
        agg["entries"] += 1
        agg["max"] = max(agg["max"], e["value"])
        by_client[str(e["client_address"] or "?")] += 1
    ranked = sorted(by_command.items(), key=lambda item: -item[1]["max"])
    return {
        "len": total,
        "returned": len(entries),
        "top_commands": [{"command": name, f"max_{unit}": a["max"], "entries": a["entries"]} for name, a in ranked][
            :COMMANDLOG_TOP
        ],
        "top_clients": [{"client_address": addr, "entries": n} for addr, n in by_client.most_common(COMMANDLOG_TOP)],
        "entries": [
            {
                "id": e["id"],
                "timestamp": e["timestamp"],
                unit: e["value"],
                "command": e["command"],
                "client_address": e["client_address"],
                "client_name": e["client_name"],
            }
            for e in sorted(entries, key=lambda e: -e["value"])[:COMMANDLOG_TOP]
        ],
    }


def _commandlog_findings(sections: dict[str, dict]) -> list[dict]:
    out: list[dict] = []
    for kind, section in sections.items():
        if not section["entries"]:
            continue
        top = section["entries"][0]
        who = f" from {top['client_address']}" if top["client_address"] else ""
        if kind == "slow":
            us = top["duration_us"]
            out.append(
                _finding(
                    "warning" if us >= COMMANDLOG_SLOW_WARN_US else "info",
                    f"slowest command in the commandlog is {top['command']} at {us / 1000:.1f} ms{who} "
                    f"({section['len']} logged); node_slowlog has the same view on every engine",
                    source="commandlog",
                    kind=kind,
                )
            )
            continue
        size = top["size_bytes"]
        if size >= COMMANDLOG_LARGE_CRIT_BYTES:
            severity = "critical"
        elif size >= COMMANDLOG_LARGE_WARN_BYTES:
            severity = "warning"
        else:
            severity = "info"
        if kind == "large-request":
            what, fix = "request", "split the write (smaller pipeline batches or a smaller value)"
        else:
            what, fix = (
                "reply",
                "page the read (HSCAN/SSCAN/LRANGE ranges) or cap the collection; big replies fill buffers",
            )
        out.append(
            _finding(
                severity,
                f"largest {what} is {size / 1024 / 1024:.1f} MiB ({top['command']}){who}, "
                f"{section['len']} logged: {fix}",
                source="commandlog",
                kind=kind,
            )
        )
    return out


def commandlog(r: redis.Redis, count: int = 10, serverless: bool = False, info_server: dict | None = None) -> dict:
    """Valkey 8 COMMANDLOG for ``slow``, ``large-request`` and ``large-reply``: the oversized payloads SLOWLOG misses.

    Findings first, then top commands by size and client addresses. Arguments and values are never returned.
    Redis and Valkey before 8.0 have no COMMANDLOG: that is a note naming the engine, never an error."""
    count = max(1, min(int(count), 128))
    server = info_server if info_server is not None else _try(r.info, "server")[0]
    engine = engine_of(server or {})
    if server and not (engine["engine"] == "valkey" and version_tuple(engine["version"]) >= _COMMANDLOG_MIN_VERSION):
        reason = f"{engine['version_label']} has no COMMANDLOG; it needs Valkey 8.0+"
        return {"findings": [], "supported": False, "notes": [_unsupported("COMMANDLOG GET", reason, serverless)]}
    sections: dict[str, dict] = {}
    notes: list[str] = []
    for kind in COMMANDLOG_TYPES:
        reply, err = _try(r.execute_command, "COMMANDLOG", "GET", count, kind)
        if err is not None:
            notes.append(_unsupported(f"COMMANDLOG GET {kind}", err, serverless))
            if not sections:  # the first type failing means the command itself is missing or refused
                break
            continue
        total, _ = _try(r.execute_command, "COMMANDLOG", "LEN", kind)
        sections[kind] = _commandlog_section(kind, _commandlog_entries(reply), total)
    return {
        "findings": _sorted_findings(_commandlog_findings(sections)),
        "supported": bool(sections),
        **sections,
        **({"notes": notes} if notes else {}),
    }
