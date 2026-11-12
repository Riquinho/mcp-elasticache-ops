"""Fan-out of a per-node probe to every shard primary, with a shared deadline."""

from __future__ import annotations

import math
import statistics
import time
from collections import defaultdict
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any

import redis

from ._core import (
    _endpoint,
    _finding,
    _num,
    _sorted_findings,
)
from .health import (
    memory_report,
    slowlog,
)
from .keyspace import (
    DEFAULT_SAMPLE_SECONDS,
    DEFAULT_TOP_PREFIXES,
    MAX_SAMPLE_SECONDS,
    MAX_TOP_PREFIXES,
    _add_histograms,
    _empty_histogram,
    _merge_prefix_entries,
    _prefix_report,
    _ttl_findings,
    hit_rate,
    keyspace_sample,
)
from .topology import (
    cluster_nodes,
)

ClientFactory = Callable[[str, int], redis.Redis]


SKEW_RATIO = 1.5


def _fan_out_primaries(
    r: redis.Redis,
    client_factory: ClientFactory,
    work: Callable[[redis.Redis, float, int], dict],
    max_workers: int,
    total_seconds: float,
    per_node_timeout: float,
    cross_check: bool = False,
) -> tuple[dict, dict[str, dict]]:
    """Run ``work(client, shard_budget_seconds, shard_count)`` on every shard primary.

    Returns ``(topology, outcomes)``; ``outcomes`` maps ``host:port`` to ``{"status": "ok", "data": ...}``
    or ``{"status": "unreachable", "error": ...}``. The wall-clock budget is split across the waves of
    primaries the worker pool needs (``ceil(primaries / workers)``), so the sum of all shard budgets stays
    within ``total_seconds``; a shard that hangs is abandoned ``per_node_timeout`` seconds after that,
    and a dead shard never fails the call. Clients come from ``client_factory`` (``SafeRedis`` only).
    ``cross_check`` also reads CLUSTER SHARDS (one extra command on the seed node) for ``topology_findings``.
    """
    topo = cluster_nodes(r, cross_check=cross_check)
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
    ttl_overall = _empty_histogram()
    ttl_by_type: dict[str, dict[str, int]] = {}
    hits = misses = 0
    for ep, o in outcomes.items():
        if o["status"] == "unreachable":
            per_shard[ep] = o
            continue
        d = o["data"]
        policy = policy or d["maxmemory_policy"]
        _add_histograms(ttl_overall, d["ttl_histogram"]["overall"])
        for t, hist in d["ttl_histogram"]["by_type"].items():
            _add_histograms(ttl_by_type.setdefault(t, _empty_histogram()), hist)
        hits += d["keyspace_hits"]
        misses += d["keyspace_misses"]
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
    rate = hit_rate(hits, misses)
    findings += _ttl_findings(ttl_overall, policy, rate)
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
        "ttl_histogram": {"overall": ttl_overall, "by_type": dict(sorted(ttl_by_type.items()))},
        "keyspace_hit_rate": rate,
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
    by_command = sorted(
        ({"command": k, **v} for k, v in by_cmd.items()), key=lambda x: _num(x["total_us"]), reverse=True
    )
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
