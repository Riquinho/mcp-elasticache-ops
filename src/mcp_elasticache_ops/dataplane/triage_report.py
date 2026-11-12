"""One-call triage snapshot, node and cluster-wide."""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from typing import Any

import redis

from ._core import (
    _SEVERITY_RANK,
    CONNECTIONS_CRIT_RATIO,
    FORK_CRIT_USEC,
    IDLE_CLIENTS_WARN,
    _endpoint,
    _finding,
    _num,
    _safe,
    _sorted_findings,
)
from .acl_pubsub import (
    pubsub_report,
)
from .config_stats import (
    commandstats,
)
from .doctor import (
    node_doctor,
)
from .fanout import (
    ClientFactory,
    _fan_out_primaries,
    _partial_nodes,
    _shard_counts,
)
from .health import (
    client_list,
    health_summary,
    latency,
    memory_report,
    slowlog,
)
from .hot_slots import offenders_text, top_offenders
from .replication import (
    replication,
)
from .topology import cluster_links, consistency_findings, consistency_snapshot, missing_link_findings

TRIAGE_MAX_FINDINGS = 30


TRIAGE_BIG_BUFFER_BYTES = 10 * 1024 * 1024


TRIAGE_SLOW_US = 100_000


TRIAGE_PING_P99_MS = 50.0


TRIAGE_LATENCY_EVENT_MS = 100


_CONNECTIONS_PCT = re.compile(r"connections at (\d+)%")


_FORK_USEC = re.compile(r"fork latency .*latest_fork_usec=(\d+)")


def _health_severity(message: str) -> str:
    if message.startswith(("replica link", "memory at", "noeviction at")):
        return "critical"
    fork = _FORK_USEC.match(message)
    if fork and int(fork.group(1)) > FORK_CRIT_USEC:
        return "critical"
    match = _CONNECTIONS_PCT.match(message)
    if match and int(match.group(1)) > CONNECTIONS_CRIT_RATIO * 100:
        return "critical"
    return "warning"


def _triage_health(d: dict) -> tuple[dict, list[dict]]:
    if "role" not in d:
        return {"status": "unavailable", "notes": d.get("notes", [])}, []
    keys = (
        "engine",
        "version",
        "version_label",
        "redis_compat_version",
        "role",
        "connected_clients",
        "hit_ratio",
        "ops_per_sec",
        "evicted_keys",
    )
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
    findings += [_finding("warning", f) for f in d.get("findings", [])]
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
    findings += d.get("findings", [])  # per-command slow tail from LATENCY HISTOGRAM
    return {"ping_p50_ms": rtt["p50"], "ping_p99_ms": rtt["p99"], "events": len(events)}, findings


def _triage_doctor(d: dict) -> tuple[dict, list[dict]]:
    """MEMORY/LATENCY DOCTOR advice: two cheap commands whose refusal is a note, never an unavailable section."""
    summary = {"memory": d["memory_doctor"]["status"], "latency": d["latency_doctor"]["status"]}
    return summary, list(d["findings"])


def triage(
    r: redis.Redis, client_factory: Callable[[str, int], redis.Redis] | None = None, serverless: bool = False
) -> dict:
    """One-call data-plane on-call snapshot.

    Runs health, memory, replication, clients, commandstats, slowlog (top 5), latency and the DOCTOR advice by
    reusing the
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
        ("latency", lambda: latency(r, 5, serverless), _triage_latency),
        ("doctor", lambda: node_doctor(r, serverless), _triage_doctor),
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


CLUSTER_TRIAGE_MAX_FINDINGS = 40


def _node_triage_work(client: redis.Redis, budget: float, shards: int) -> dict:
    """One shard's on-call snapshot: the regular triage sections plus the pub/sub section."""
    snapshot = triage(client, None)
    pubsub = pubsub_report(client, 5)
    consistency, _ = _safe(consistency_snapshot, client)
    links, _ = _safe(cluster_links, client)
    stats, _ = _safe(client.info, "commandstats")
    return {
        "triage": snapshot,
        "pubsub": pubsub,
        "consistency": consistency,
        "links": links,
        "offenders": top_offenders(stats),
    }


def cluster_triage(
    r: redis.Redis,
    client_factory: ClientFactory,
    max_workers: int = 8,
    per_node_timeout: float = 5.0,
    max_seconds: float = 20.0,
    serverless: bool = False,
) -> dict:
    """``triage`` (plus pub/sub pressure) on every shard primary with one ranked, deduplicated finding list.

    The shards share one wall-clock budget (``max_seconds``, split by worker waves) and a dead or stuck shard
    becomes a critical finding instead of failing the call. Findings carry ``node`` and ``shard``; identical
    findings from several nodes are merged into one that lists them in ``nodes``. Worst nodes (most critical, then
    warning findings) come first, and the list is capped at ``CLUSTER_TRIAGE_MAX_FINDINGS``.
    """
    started = time.monotonic()
    topo, outcomes = _fan_out_primaries(
        r, client_factory, _node_triage_work, max_workers, max_seconds, per_node_timeout, cross_check=True
    )
    if not outcomes:
        if topo.get("cluster_enabled") is False:
            return {**triage(r, client_factory, serverless), "cluster_enabled": False, "note": "cluster mode disabled"}
        return topo
    shard_names = {s["primary"]: f"shard-{i + 1}" for i, s in enumerate(topo.get("shards", []))}
    per_node: dict[str, dict] = {}
    raw: list[dict] = []
    snapshots: dict[str, dict] = {}
    link_notes: set[str] = set()
    for ep, o in outcomes.items():
        shard = shard_names.get(ep, "?")
        if o["status"] == "unreachable":
            per_node[ep] = {"status": "unreachable", "shard": shard, "error": o["error"]}
            raw.append(
                {
                    **_finding("critical", f"node {ep} unreachable: {o['error']}", section="cluster"),
                    "node": ep,
                    "shard": shard,
                }
            )
            continue
        data = o["data"]
        snapshot, pubsub = data["triage"], data["pubsub"]
        if data.get("consistency"):
            snapshots[ep] = data["consistency"]
        found = [{**f, "node": ep} for f in snapshot["findings"] if f.get("section") != "triage"]
        found += [{**f, "section": "pubsub", "node": ep} for f in pubsub["findings"]]
        links = data.get("links") or {}
        self_ids = {n["id"] for n in topo["nodes"] if _endpoint(n) == ep}
        expected = {n["id"] for n in topo["nodes"] if not n["failing"]} - self_ids
        found += [
            {**f, "section": "cluster", "node": ep}
            for f in links.get("findings", []) + missing_link_findings(links, expected, f"node {ep}")
        ]
        for note in links.get("notes", []):
            link_notes.add(note)
        raw += [{**f, "shard": shard} for f in found]
        per_node[ep] = {
            "status": snapshot["status"],
            "shard": shard,
            "findings": len(found),
            "sections": {name: s["status"] for name, s in snapshot["sections"].items()},
        }

    def severity_rank(f: dict) -> int:
        return _SEVERITY_RANK.get(f["severity"], 3)

    tally: dict[str, tuple[int, int]] = {}
    for ep in per_node:
        mine = [f for f in raw if f["node"] == ep]
        tally[ep] = (sum(f["severity"] == "critical" for f in mine), sum(f["severity"] == "warning" for f in mine))
    node_order = sorted(per_node, key=lambda ep: (-tally[ep][0], -tally[ep][1], ep))
    rank = {ep: i for i, ep in enumerate(node_order)}
    for ep in node_order:
        per_node[ep]["critical"], per_node[ep]["warning"] = tally[ep]

    merged: dict[tuple[str, str, str], dict] = {}
    for f in sorted(raw, key=lambda f: (severity_rank(f), rank[f["node"]])):
        key = (f["severity"], f["message"], f.get("section", ""))
        if key in merged:
            merged[key]["nodes"].append(f["node"])
            merged[key]["shards"].append(f["shard"])
        else:
            merged[key] = {**f, "nodes": [f["node"]], "shards": [f["shard"]]}
    findings = list(merged.values())
    for f in findings:
        f["count"] = len(f["nodes"])
    # CLUSTER SHARDS cross-check (already deduplicated against the CLUSTER NODES topology findings)
    for f in topo.get("topology_findings", []):
        if f.get("source") == "CLUSTER SHARDS":
            findings.append({**f, "section": "topology", "nodes": [f["node"]], "shards": [], "count": 1})
    consistency = consistency_findings(snapshots, {ep: p["shard"] for ep, p in per_node.items()}, len(outcomes))
    findings += consistency["findings"]
    findings.sort(key=severity_rank)
    worst = node_order[0] if node_order and tally[node_order[0]] != (0, 0) else None
    worst_offenders = (outcomes[worst].get("data") or {}).get("offenders") if worst else None
    if worst and worst_offenders:
        findings.append({**_finding("info", offenders_text(worst, worst_offenders), section="cluster"), "node": worst})
    total = len(findings)
    counts = _shard_counts(outcomes)
    if not findings:
        findings = [_finding("info", "no issues detected on any shard primary", section="cluster")]
    return {
        "cluster_enabled": True,
        "scope": "all shard primaries",
        **counts,
        "partial": counts["shards_total"] != counts["shards_ok"]
        or any(n["status"] not in ("ok", "unreachable") for n in per_node.values()),
        "partial_nodes": _partial_nodes(outcomes),
        **({"notes": [*topo.get("notes", []), *sorted(link_notes)]} if topo.get("notes") or link_notes else {}),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "consistency": {k: v for k, v in consistency.items() if k != "findings"},
        "worst_node": node_order[0] if node_order and tally[node_order[0]] != (0, 0) else None,
        "findings": findings[:CLUSTER_TRIAGE_MAX_FINDINGS],
        "findings_total": total,
        **({"findings_omitted": total - CLUSTER_TRIAGE_MAX_FINDINGS} if total > CLUSTER_TRIAGE_MAX_FINDINGS else {}),
        "per_node": {ep: per_node[ep] for ep in node_order},
    }
