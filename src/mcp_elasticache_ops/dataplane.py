"""Data-plane diagnostics for Redis OSS / Valkey nodes (ElastiCache or self-hosted).

Every function takes a connected client (normally a ``SafeRedis``) and returns
plain JSON-serialisable dicts. Nothing here writes, flushes or reads values:
keyspace sampling only touches metadata (TYPE, MEMORY USAGE, OBJECT, lengths).

ElastiCache restricts some admin commands (CONFIG, DEBUG, some MEMORY/LATENCY
subcommands depending on engine version). Those are attempted and, if refused,
reported as ``unavailable`` instead of failing the whole tool.
"""

from __future__ import annotations

import statistics
import time
from collections import Counter, defaultdict
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


# --------------------------------------------------------------------------- INFO


def server_info(r: redis.Redis, section: str | None = None) -> dict:
    """Raw INFO, optionally a single section (server, clients, memory, stats, ...)."""
    data = r.info(section) if section else r.info()
    return {"section": section or "default", "info": data}


def health_summary(r: redis.Redis) -> dict:
    info = r.info()
    hits, misses = _num(info.get("keyspace_hits")), _num(info.get("keyspace_misses"))
    maxmemory = _num(info.get("maxmemory"))
    used = _num(info.get("used_memory"))
    frag = _num(info.get("mem_fragmentation_ratio"), default=1.0)
    findings: list[str] = []
    if maxmemory and used / maxmemory > 0.9:
        findings.append(f"memory at {used / maxmemory:.0%} of maxmemory")
    if _num(info.get("evicted_keys")) > 0:
        findings.append(f"{int(_num(info.get('evicted_keys')))} keys evicted since restart")
    if frag > 1.5:
        findings.append(f"high fragmentation ratio {frag:.2f}")
    elif frag < 1.0 and used > 0:
        findings.append(f"fragmentation ratio {frag:.2f} < 1: possible swapping")
    if _num(info.get("rejected_connections")) > 0:
        findings.append(f"{int(_num(info.get('rejected_connections')))} rejected connections (maxclients)")
    if _num(info.get("blocked_clients")) > 0:
        findings.append(f"{int(_num(info.get('blocked_clients')))} blocked clients")
    if info.get("role") == "slave" and info.get("master_link_status") != "up":
        findings.append(f"replica link is {info.get('master_link_status')}")
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
    }


# ------------------------------------------------------------------------- memory


def memory_report(r: redis.Redis) -> dict:
    mem = r.info("memory")
    stats = r.info("stats")
    used = _num(mem.get("used_memory"))
    maxmemory = _num(mem.get("maxmemory"))
    rss = _num(mem.get("used_memory_rss"))
    frag = _num(mem.get("mem_fragmentation_ratio"), default=1.0)
    memory_stats, stats_err = _try(r.memory_stats)
    doctor, doctor_err = _try(r.execute_command, "MEMORY", "DOCTOR")

    if frag > 1.5:
        frag_verdict = "high: RSS well above dataset; consider activedefrag (Redis 4+/Valkey) or node replacement"
    elif frag < 1.0 and used > 0:
        frag_verdict = "below 1.0: memory may be swapped; check SwapUsage in CloudWatch"
    else:
        frag_verdict = "normal"

    return {
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
        "note": (
            "On ElastiCache, maxmemory already excludes reserved-memory-percent; "
            "compare with the BytesUsedForCache and DatabaseMemoryUsagePercentage metrics."
        ),
    }


# ------------------------------------------------------------------------ slowlog


def slowlog(r: redis.Redis, count: int = 25, include_args: bool = False) -> dict:
    """SLOWLOG GET with per-command aggregation.

    By default only the command name and the first argument (usually the key)
    are returned, so values passed to SET/HSET etc. never leave the server.
    """
    count = max(1, min(int(count), 1024))
    entries = r.slowlog_get(count)
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


# --------------------------------------------------------------------- keyspace


def keyspace_sample(
    r: redis.Redis,
    sample_size: int = 1000,
    match: str | None = None,
    top: int = 20,
    scan_count: int = 250,
    pause_ms: int = 0,
) -> dict:
    """Big/hot key finder based on a bounded SCAN.

    Cost control: at most ``sample_size`` keys are inspected, SCAN uses COUNT
    ``scan_count`` and an optional pause between batches. Hot keys need an LFU
    ``maxmemory-policy`` (OBJECT FREQ); otherwise idle time is reported.
    """
    sample_size = max(1, min(int(sample_size), 100_000))
    policy = str(r.info("memory").get("maxmemory_policy", ""))
    lfu = "lfu" in policy
    keys: list[str] = []
    cursor = 0
    while True:
        cursor, batch = r.scan(cursor=cursor, match=match, count=scan_count)
        keys.extend(batch)
        if cursor == 0 or len(keys) >= sample_size:
            break
        if pause_ms:
            time.sleep(pause_ms / 1000)
    keys = keys[:sample_size]

    rows = []
    for i in range(0, len(keys), 200):
        chunk = keys[i : i + 200]
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
    result = {
        "sampled_keys": len(rows),
        "dbsize": r.dbsize(),
        "complete_scan": cursor == 0 and len(keys) < sample_size,
        "maxmemory_policy": policy,
        "by_type": dict(by_type),
        "keys_without_ttl": no_ttl,
        "big_keys_by_bytes": sorted(rows, key=lambda x: x["bytes"] or 0, reverse=True)[:top],
        # STRLEN is bytes, so strings rank in big_keys_by_bytes; length ranks collection elements.
        "big_keys_by_length": sorted(
            (x for x in rows if x["type"] != "string"), key=lambda x: x["length"] or 0, reverse=True
        )[:top],
    }
    if lfu:
        result["hot_keys_by_lfu"] = sorted(rows, key=lambda x: x["lfu_freq"] or 0, reverse=True)[:top]
    else:
        result["coldest_keys_by_idle"] = sorted(rows, key=lambda x: x["idle_seconds"] or 0, reverse=True)[:top]
        result["hot_keys_note"] = "set maxmemory-policy to an *-lfu policy to rank hot keys (OBJECT FREQ)"
    return result


# ------------------------------------------------------------ replication/cluster


def replication(r: redis.Redis) -> dict:
    info = r.info("replication")
    role, role_err = _try(r.execute_command, "ROLE")
    replicas = []
    master_offset = int(_num(info.get("master_repl_offset")))
    for k, v in info.items():
        if k.startswith("slave") and isinstance(v, dict):
            off = int(_num(v.get("offset")))
            replicas.append({**v, "lag_bytes": master_offset - off})
    return {
        "role": info.get("role"),
        "connected_replicas": info.get("connected_slaves"),
        "replicas": replicas,
        "master_repl_offset": master_offset,
        "master_link_status": info.get("master_link_status"),
        "master_last_io_seconds_ago": info.get("master_last_io_seconds_ago"),
        "master_sync_in_progress": info.get("master_sync_in_progress"),
        "repl_backlog_size": info.get("repl_backlog_size"),
        "role_command": _jsonable(role) if role is not None else {"unavailable": role_err},
    }


def cluster(r: redis.Redis) -> dict:
    enabled = int(_num(r.info("cluster").get("cluster_enabled")))
    if not enabled:
        return {"cluster_enabled": False, "note": "cluster mode disabled (single shard)"}
    info = r.execute_command("CLUSTER INFO")
    if isinstance(info, (bytes, str)):
        info = dict(line.split(":", 1) for line in _s(info).splitlines() if ":" in line)
    shards, shards_err = _try(r.execute_command, "CLUSTER", "SHARDS")
    slots, _ = _try(r.execute_command, "CLUSTER", "SLOTS")
    coverage: dict[str, int] = Counter()
    for row in slots or []:
        start, end, master = row[0], row[1], row[2]
        host = _s(master[0]) if master else "?"
        coverage[f"{host}:{master[1]}"] += int(end) - int(start) + 1
    return {
        "cluster_enabled": True,
        "cluster_info": _jsonable(info),
        "slots_per_primary": dict(coverage),
        "slots_covered": sum(coverage.values()),
        "shards": _jsonable(shards) if shards is not None else {"unavailable": shards_err},
    }


def _jsonable(v: Any) -> Any:
    if isinstance(v, bytes):
        return v.decode("utf-8", "backslashreplace")
    if isinstance(v, dict):
        return {str(_jsonable(k)): _jsonable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [_jsonable(x) for x in v]
    return v
