"""Metadata-only keyspace sampling: prefixes, TTL histograms, access recency."""

from __future__ import annotations

import re
import time
from collections import Counter, defaultdict
from collections.abc import Callable
from typing import Any

import redis

from ..safe_client import MAX_SCAN_COUNT
from ._core import (
    LENGTH_COMMAND,
    _finding,
    _num,
    _s,
    _try,
)

DEFAULT_SAMPLE_SECONDS = 10.0


MAX_SAMPLE_SECONDS = 60.0


PIPELINE_CHUNK = 100


DEFAULT_TOP_PREFIXES = 10


MAX_TOP_PREFIXES = 50


ACCESS_IDLE_SECONDS = 7 * 24 * 3600  # OBJECT IDLETIME above this counts as untouched


ACCESS_LFU_COLD_FREQ = 1  # OBJECT FREQ (logarithmic counter, decays when untouched) at or below this is cold


ACCESS_FINDING_PCT = 20.0  # share of cold sampled keys that becomes a finding


PREFIX_PRESSURE_RATIO = 0.8  # memory share of maxmemory at which a no-TTL prefix becomes a finding


PREFIX_SHARE_PCT = 10.0  # a prefix must hold at least this share of sampled memory to be flagged


PREFIX_NO_TTL_PCT = 90.0


TTL_BUCKETS = ("no_ttl", "lt_1m", "lt_1h", "lt_1d", "gte_1d")


NO_TTL_DOMINANT_PCT = 90.0  # share of sampled keys without expiry that counts as dominant ...


NO_TTL_MIN_KEYS = 20  # ... once at least this many keys with a known TTL were sampled


HIT_RATE_WARN = 0.80  # keyspace_hits / (hits + misses) below this is a warning


HIT_RATE_CRIT = 0.50  # ... and below this a critical


HIT_RATE_MIN_LOOKUPS = 1000  # ignore the ratio on a barely used node


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


def ttl_bucket(ttl_ms: Any) -> str | None:
    """Histogram bucket of a PTTL reply; ``None`` for keys that vanished (-2) or could not be read."""
    if not isinstance(ttl_ms, int) or ttl_ms == -2:
        return None
    if ttl_ms < 0:
        return "no_ttl"
    if ttl_ms < 60_000:
        return "lt_1m"
    if ttl_ms < 3_600_000:
        return "lt_1h"
    if ttl_ms < 86_400_000:
        return "lt_1d"
    return "gte_1d"


def _empty_histogram() -> dict[str, int]:
    return dict.fromkeys(TTL_BUCKETS, 0)


def _add_histograms(into: dict[str, int], other: dict[str, int]) -> None:
    for bucket in TTL_BUCKETS:
        into[bucket] += other.get(bucket, 0)


def _ttl_histograms(rows: list[dict]) -> dict[str, Any]:
    """Overall and per-type TTL histograms from the PTTL values already fetched (no extra commands)."""
    overall = _empty_histogram()
    by_type: dict[str, dict[str, int]] = {}
    for row in rows:
        bucket = ttl_bucket(row["ttl_ms"])
        if bucket is None:
            continue
        overall[bucket] += 1
        by_type.setdefault(row["type"], _empty_histogram())[bucket] += 1
    return {"overall": overall, "by_type": dict(sorted(by_type.items()))}


def hit_rate(hits: Any, misses: Any) -> float | None:
    """keyspace_hits / (hits + misses), or ``None`` without enough lookups to mean anything."""
    total = _num(hits) + _num(misses)
    if total < HIT_RATE_MIN_LOOKUPS:
        return None
    return round(_num(hits) / total, 4)


def _ttl_findings(overall: dict[str, int], policy: str, rate: float | None) -> list[dict]:
    """Findings from the sampled TTL mix (expiry-less keys under an eviction policy) and the hit rate."""
    findings: list[dict] = []
    known = sum(overall.values())
    if policy and policy != "noeviction" and known >= NO_TTL_MIN_KEYS:
        pct = 100 * overall["no_ttl"] / known
        if pct >= NO_TTL_DOMINANT_PCT:
            volatile = policy.startswith("volatile-")
            findings.append(
                _finding(
                    "warning" if volatile else "info",
                    f"{pct:.0f}% of sampled keys have no TTL on a cache with maxmemory-policy {policy}"
                    + (
                        ": volatile-* policies can only evict keys with an expiry, so memory will not be reclaimed"
                        if volatile
                        else ": nothing ages out, so eviction alone decides what stays"
                    ),
                )
            )
    if rate is not None and rate < HIT_RATE_WARN:
        findings.append(
            _finding(
                "critical" if rate < HIT_RATE_CRIT else "warning",
                f"keyspace hit rate is {rate:.0%} (INFO keyspace_hits/keyspace_misses), below {HIT_RATE_WARN:.0%}",
            )
        )
    return findings


def _prefix_entries(rows: list[dict], dbsize: int) -> list[dict]:
    """Aggregate sampled rows by normalised prefix; bytes and key counts are scaled up to ``dbsize``."""
    scale = dbsize / len(rows) if rows and dbsize > len(rows) else 1.0
    agg: dict[str, dict[str, Any]] = {}
    for row in rows:
        entry = agg.setdefault(
            normalize_key(row["key"]),
            {
                "sampled_keys": 0,
                "sampled_bytes": 0,
                "no_ttl_keys": 0,
                "types": Counter(),
                "ttl_histogram": _empty_histogram(),
            },
        )
        bucket = ttl_bucket(row["ttl_ms"])
        if bucket is not None:
            entry["ttl_histogram"][bucket] += 1
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
            "ttl_histogram": e["ttl_histogram"],
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
                    "ttl_histogram": _empty_histogram(),
                },
            )
            _add_histograms(m["ttl_histogram"], e.get("ttl_histogram", {}))
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
            "ttl_histogram": e["ttl_histogram"],
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


def _access_report(rows: list[dict], lfu: bool, policy: str, usage: float | None) -> tuple[dict, list[dict]]:
    """Share of sampled keys that look untouched, from the OBJECT IDLETIME / OBJECT FREQ values already read.

    LRU-style policies report idle seconds (cold = idle over 7 days); LFU policies have no idle time, so cold
    means a frequency counter at or below ``ACCESS_LFU_COLD_FREQ``. Keys whose OBJECT reply failed are skipped.
    """
    field_name = "lfu_freq" if lfu else "idle_seconds"
    known = [row[field_name] for row in rows if isinstance(row.get(field_name), int)]
    cold = sum(1 for v in known if (v <= ACCESS_LFU_COLD_FREQ if lfu else v > ACCESS_IDLE_SECONDS))
    pct = round(100 * cold / len(known), 1) if known else 0.0
    basis = f"OBJECT FREQ <= {ACCESS_LFU_COLD_FREQ}" if lfu else "OBJECT IDLETIME > 7d"
    report: dict[str, Any] = {
        "command": "OBJECT FREQ" if lfu else "OBJECT IDLETIME",
        "keys_read": len(known),
        "cold_keys": cold,
        "cold_pct": pct,
        "basis": basis,
    }
    findings: list[dict] = []
    if known and pct >= ACCESS_FINDING_PCT:
        what = "of sampled keys have a low access frequency" if lfu else "of sampled keys untouched for >7d"
        report["eviction_risk_hint"] = f"{pct:g}% {what}, candidates for TTL or removal"
        pressure = policy == "noeviction" or (usage is not None and usage >= PREFIX_PRESSURE_RATIO)
        findings.append(_finding("warning" if pressure else "info", report["eviction_risk_hint"], section="access"))
    elif not known:
        report["note"] = "no OBJECT reply could be read for the sampled keys"
    return report, findings


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
    include_access: bool = False,
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
    ``include_access`` adds an ``access`` block (share of keys idle for over 7 days, or with a cold LFU counter)
    built from the same OBJECT replies and the same budget; it never issues extra commands.
    """
    sample_size = max(1, min(int(sample_size), 100_000))
    scan_count = max(1, min(int(scan_count), MAX_SCAN_COUNT))
    max_seconds = max(0.01, min(float(max_seconds), MAX_SAMPLE_SECONDS))
    started = clock()
    deadline = started + max_seconds
    partial_reason: str | None = None
    mem_info = r.info()  # default INFO carries memory, stats and cluster: one round trip for all three
    policy = str(mem_info.get("maxmemory_policy", ""))
    lfu = "lfu" in policy
    keys: list[str] = []
    cursor = 0
    while True:
        cursor, batch = r.scan(cursor=cursor, match=match, count=scan_count)
        keys.extend(k.decode() if isinstance(k, bytes) else k for k in batch)
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
    ttl_histogram = _ttl_histograms(rows)
    rate = hit_rate(mem_info.get("keyspace_hits"), mem_info.get("keyspace_misses"))
    prefix_report["findings"] += _ttl_findings(ttl_histogram["overall"], policy, rate)
    access: dict[str, Any] | None = None
    if include_access:
        access, access_findings = _access_report(rows, lfu, policy, usage)
        prefix_report["findings"] += access_findings
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
        "ttl_histogram": ttl_histogram,
        "keyspace_hits": int(_num(mem_info.get("keyspace_hits"))),
        "keyspace_misses": int(_num(mem_info.get("keyspace_misses"))),
        "keyspace_hit_rate": rate,
        "usage_of_maxmemory": usage,
        **prefix_report,
        "big_keys_by_bytes": sorted(rows, key=lambda x: x["bytes"] or 0, reverse=True)[:top],
        # STRLEN is bytes, so strings rank in big_keys_by_bytes; length ranks collection elements.
        "big_keys_by_length": sorted(
            (x for x in rows if x["type"] != "string"), key=lambda x: x["length"] or 0, reverse=True
        )[:top],
    }
    if access is not None:
        result["access"] = {**access, "partial": partial}
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
