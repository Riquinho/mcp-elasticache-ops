"""CLUSTER NODES / SHARDS parsing, topology findings and cluster health."""

from __future__ import annotations

import re
import statistics
from collections import Counter
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any

import redis

from ._core import (
    _endpoint,
    _finding,
    _node_error,
    _num,
    _pairs,
    _s,
    _sorted_findings,
    _try,
    _unsupported,
    command_support_note,
)
from .replication import (
    REPL_LAG_BYTES_WARN,
)

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
            findings.append(
                _finding(
                    "critical",
                    f"node {ep} is flagged fail: the cluster considers it down",
                    node=ep,
                    category="node-down",
                )
            )
        if "fail?" in flags:
            findings.append(
                _finding(
                    "warning",
                    f"node {ep} is flagged fail? (possible failure, not yet confirmed)",
                    node=ep,
                    category="node-down",
                )
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
                        category="no-replica",
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


def cluster_shards_check(raw: Any, lag_bytes_threshold: int = REPL_LAG_BYTES_WARN) -> tuple[list[dict], list[dict]]:
    """Cross-check CLUSTER SHARDS (7.0+): node health, replication offset gaps and replica coverage per shard.

    Returns ``(findings, shards)``; ``shards`` lists slot count, primary, each replica's health and byte lag, and
    how many replicas are online. Findings are tagged ``source`` ``CLUSTER SHARDS`` and a ``category`` so
    ``merge_shard_findings`` can drop the ones ``cluster_topology_findings`` already reports (``node-down``,
    ``no-replica``). A shard whose replicas are all failed or loading has no failover target and is critical;
    a ``loading`` replica (full sync in progress) is a warning.
    """
    findings: list[dict] = []
    shards: list[dict] = []
    parsed: list[tuple[dict | None, list[dict], int]] = []

    def endpoint(n: dict) -> str:
        host = _s(n.get("endpoint") or n.get("hostname") or n.get("ip"))
        return f"{host}:{n.get('port') or n.get('tls-port')}"

    def add(severity: str, message: str, node: str, category: str) -> None:
        findings.append(_finding(severity, message, node=node, category=category, source="CLUSTER SHARDS"))

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
                add(
                    "critical" if health == "fail" else "warning",
                    f"CLUSTER SHARDS: node {ep} health is {health}",
                    ep,
                    "node-down" if health == "fail" else "node-loading",
                )
            if n is primary:
                continue
            lag = primary_offset - int(_num(n.get("replication-offset"))) if primary_offset is not None else None
            replicas.append({"endpoint": ep, "health": health, "lag_bytes": lag})
            if lag is not None and lag > lag_bytes_threshold:
                add("warning", f"replica {ep} is {lag} bytes behind its primary", ep, "replica-lag")
        parsed.append((primary, replicas, slot_count))
        shards.append(
            {
                "slot_count": slot_count,
                "primary": endpoint(primary) if primary else None,
                "replicas": replicas,
            }
        )
    replication_in_use = any(replicas for _, replicas, _ in parsed)
    for primary, replicas, slot_count in parsed:
        if primary is None:
            continue
        pep = endpoint(primary)
        if not replicas and replication_in_use:
            add(
                "warning",
                f"shard {pep} has no replica: no failover target for its {slot_count} slots",
                pep,
                "no-replica",
            )
        elif replicas and not any(rep["health"] == "online" for rep in replicas):
            add(
                "critical",
                f"shard {pep} has no healthy replica ({len(replicas)} replica(s), none online): "
                f"failover has no target for its {slot_count} slots",
                pep,
                "no-healthy-replica",
            )
    return findings, shards


def merge_shard_findings(topology: list[dict], check: list[dict]) -> list[dict]:
    """Topology findings plus the CLUSTER SHARDS findings that add something new, severity-sorted.

    A CLUSTER SHARDS finding is dropped when a topology finding already covers the same ``(node, category)``,
    for example a node flagged ``fail`` in CLUSTER NODES or a primary without a replica.
    """
    seen = {(f.get("node"), f["category"]) for f in topology if f.get("category")}
    extra = [f for f in check if (f.get("node"), f.get("category")) not in seen]
    return _sorted_findings([*topology, *extra])


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
    notes = []
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
            topology = merge_shard_findings(topology, check_findings)
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
        "slave_repl_offset": int(_num(info["slave_repl_offset"])) if "slave_repl_offset" in info else None,
        "replicas": [
            {"addr": f"{v.get('ip')}:{v.get('port')}", "offset": int(_num(v.get("offset"))), "lag": _num(v.get("lag"))}
            for k, v in info.items()
            if k.startswith("slave") and isinstance(v, dict)
        ],
    }


def _shard_replication_check(
    shards: list[dict], results: dict[str, dict], lag_bytes_threshold: int, reported: list[str]
) -> tuple[list[dict], list[str]]:
    """Per shard: replica offset lag, nodes whose INFO role contradicts CLUSTER NODES, and replica count.

    Works on the INFO already fetched for every node; a node that errored is skipped (it is listed in
    ``partial_nodes``), so one dead node never hides the verdict on the rest of its shard. Shards without a
    replica are reported with ``replicas: 0`` (the topology findings carry the warning).
    """
    rows: list[dict] = []
    findings: list[str] = []
    for shard in shards:
        primary = shard["primary"]
        pres = results.get(primary, {})
        if pres.get("role") == "slave":
            findings.append(
                f"shard primary {primary} reports role:slave although CLUSTER NODES lists it as primary "
                "(failover in progress or stale topology)"
            )
        master_offset = pres["master_repl_offset"] if pres.get("role") == "master" else None
        lags: dict[str, int] = {}
        for ep in shard["replicas"]:
            rres = results.get(ep, {})
            if rres.get("role") == "master":
                findings.append(f"replica {ep} of {primary} reports role:master (split or failover in progress)")
                continue
            offset = rres.get("slave_repl_offset")
            if master_offset is None or offset is None:
                continue
            lags[ep] = master_offset - offset
            if lags[ep] > lag_bytes_threshold and not any(f"replica {ep} of {primary} lags" in f for f in reported):
                findings.append(
                    f"replica {ep} of {primary} lags {lags[ep]} bytes (master_repl_offset {master_offset} "
                    f"vs slave_repl_offset {offset})"
                )
        rows.append(
            {
                "primary": primary,
                "replicas": len(shard["replicas"]),
                "lag_bytes": lags,
                "max_lag_bytes": max(lags.values(), default=None),
            }
        )
    return rows, findings


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
            snap = _node_snapshot(client.info())
            snap["links"] = cluster_links(client)
            return snap
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
                kind, _severity, text = _node_error(exc)
                results[ep] = {"error": text, "kind": kind}
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
    ids = {n["id"] for n in nodes if not n["failing"]}
    for ep, res in results.items():
        links = res.get("links") or {}
        mine = {n["id"] for n in nodes if _endpoint(n) == ep}
        for f in links.get("findings", []) + missing_link_findings(links, ids - mine, f"node {ep}"):
            findings.append(f"node {ep}: {f['message']}")
    shard_rows, shard_findings = _shard_replication_check(topo["shards"], results, lag_bytes_threshold, findings)
    findings += shard_findings
    partial_nodes = [
        {"node": ep, "status": "unreachable", "reason": res["error"]} for ep, res in results.items() if "error" in res
    ] + [
        {"node": ep, "status": "unreachable", "reason": "flagged as failing in CLUSTER NODES; not contacted"}
        for ep in (_endpoint(n) for n in nodes if n["failing"])
    ]
    return {
        "cluster_enabled": True,
        "nodes_probed": len(results),
        "reached": f"reached {sum(1 for res in results.values() if 'error' not in res)}/{len(nodes)} nodes",
        "partial_nodes": partial_nodes,
        "shard_replication": shard_rows,
        "slots_covered": topo["slots_covered"],
        "shards": topo["shards"],
        "topology_findings": topo["topology_findings"],
        "per_node": results,
        "findings": findings or ["no skew, lag or coverage problems detected"],
    }


# --------------------------------------------------------------------------- cluster bus links

LINK_BUFFER_WARN_BYTES = 16 * 1024 * 1024  # a send buffer this big means a peer is not draining the cluster bus
LINK_BUFFER_CRIT_BYTES = 128 * 1024 * 1024
MAX_LINKS_KEPT = 256


def cluster_links(r: redis.Redis, serverless: bool = False) -> dict:
    """``CLUSTER LINKS`` (Redis 7+/Valkey): cluster bus send-buffer pressure per peer link.

    Returns ``{"supported", "links", "peers", "max_send_buffer_bytes", "findings", "rows", "notes"}``. ``peers`` is
    the set of node ids that have a link to this node, for the missing-link check (``missing_link_findings``).
    An engine without the command (Redis 6, refused managed endpoint) gives a note, never an error."""
    reply, err = _try(r.execute_command, "CLUSTER", "LINKS")
    if err is not None:
        server = None if serverless else _try(r.info, "server")[0]
        note = (
            _unsupported("CLUSTER LINKS", err, True)
            if serverless
            else command_support_note("CLUSTER LINKS", server, err)
        )
        return {"supported": False, "links": 0, "peers": [], "findings": [], "rows": [], "notes": [note]}
    rows: list[dict] = []
    for entry in reply if isinstance(reply, list | tuple) else []:
        link = {_s(k): v for k, v in _pairs(entry).items()}
        rows.append(
            {
                "node": _s(link.get("node")),
                "direction": _s(link.get("direction")),
                "send_buffer_allocated": int(_num(link.get("send-buffer-allocated"))),
                "send_buffer_used": int(_num(link.get("send-buffer-used"))),
            }
        )
    rows = rows[:MAX_LINKS_KEPT]
    findings: list[dict] = []
    worst = max(rows, key=lambda row: row["send_buffer_allocated"], default=None)
    top = worst["send_buffer_allocated"] if worst else 0
    if worst and top >= LINK_BUFFER_WARN_BYTES:
        findings.append(
            _finding(
                "critical" if top >= LINK_BUFFER_CRIT_BYTES else "warning",
                f"cluster bus send buffer to peer {worst['node'][:12]} ({worst['direction']}) "
                f"holds {top / 1024 / 1024:.0f} MiB: the peer is slow to read gossip "
                "(network stall, CPU-bound or blocked node); check that node first",
                source="cluster links",
            )
        )
    return {
        "supported": True,
        "links": len(rows),
        "peers": sorted({row["node"] for row in rows}),
        "max_send_buffer_bytes": top,
        "findings": findings,
        "rows": sorted(rows, key=lambda row: -row["send_buffer_allocated"])[:3],
    }


def missing_link_findings(links: dict, expected_ids: set[str], label: str) -> list[dict]:
    """A node that has no link to a peer the topology lists means the cluster bus is split from that peer."""
    if not links.get("supported"):
        return []
    missing = sorted(expected_ids - set(links["peers"]))
    if not missing:
        return []
    shown = ", ".join(i[:12] for i in missing[:3]) + (f" and {len(missing) - 3} more" if len(missing) > 3 else "")
    return [
        _finding(
            "warning",
            f"{label} has no cluster bus link to {len(missing)} peer(s) ({shown}): gossip is split, expect failover "
            "or slot-map disagreement; compare CLUSTER NODES on both sides",
            source="cluster links",
        )
    ]


# --------------------------------------------------------------------------- cross-node consistency

# Parameters compared across shard primaries. All are on the CONFIG GET allowlist and none is a secret.
CONSISTENCY_CONFIG: tuple[str, ...] = (
    "maxmemory-policy",
    "maxmemory",
    "timeout",
    "notify-keyspace-events",
    "cluster-require-full-coverage",
)
MAX_CONSISTENCY_ACL_USERS = 200
MAX_NAME_CHARS = 64


def consistency_snapshot(r: redis.Redis) -> dict:
    """What one node says about itself for the cross-node comparison; every probe fails on its own.

    CONFIG GET is limited to ``CONSISTENCY_CONFIG``, the ACL users come from ``ACL USERS`` (names only; ``ACL
    LIST`` carries password hashes and stays refused) and the engine version from ``INFO server``.
    """
    config: dict[str, str] = {}
    unavailable: list[str] = []
    for name in CONSISTENCY_CONFIG:
        try:
            got = r.config_get(name)
        except Exception:
            unavailable.append(name)
            continue
        if isinstance(got, dict) and name in {_s(k) for k in got}:
            value = next(v for k, v in got.items() if _s(k) == name)
            config[name] = _s(value)[:MAX_NAME_CHARS]
    users: list[str] | None = None
    try:
        raw = r.execute_command("ACL", "USERS")
        if isinstance(raw, (list, tuple)):
            users = sorted({_s(u)[:MAX_NAME_CHARS] for u in raw})[:MAX_CONSISTENCY_ACL_USERS]
    except Exception:
        unavailable.append("acl-users")
    version: str | None = None
    try:
        info = r.info("server")
        if isinstance(info, dict):
            raw_version = info.get("valkey_version") or info.get("redis_version")
            if raw_version:
                engine = "valkey" if info.get("valkey_version") else "redis"
                version = f"{engine} {_s(raw_version)}"
    except Exception:
        unavailable.append("version")
    return {"config": config, "acl_users": users, "version": version, "unavailable": unavailable}


def _majority(values: dict[str, Any]) -> tuple[Any, int] | None:
    """The value held by strictly more than half of the nodes that answered, with its count; None without one."""
    if not values:
        return None
    ranked = Counter(repr(v) for v in values.values()).most_common()
    top_repr, top = ranked[0]
    if top * 2 <= len(values):
        return None
    value = next(v for v in values.values() if repr(v) == top_repr)
    return value, top


def _drift(name: str, values: dict[str, Any], shards: dict[str, str], describe: Callable[[Any], str]) -> dict | None:
    if len(values) < 2 or len({repr(v) for v in values.values()}) == 1:
        return None
    maj = _majority(values)
    if maj is None:
        found = ", ".join(f"{ep}={describe(v)}" for ep, v in sorted(values.items()))
        nodes = sorted(values)
        message = f"{name} has no majority across {len(values)} nodes: {found}"
    else:
        value, count = maj
        nodes = sorted(ep for ep, v in values.items() if repr(v) != repr(value))
        found = ", ".join(f"{ep}={describe(values[ep])}" for ep in nodes)
        message = f"{name} differs from the majority {describe(value)} ({count}/{len(values)} nodes): {found}"
    return {
        **_finding("warning", message, section="consistency"),
        "category": "consistency",
        "parameter": name,
        "nodes": nodes,
        "shards": [shards.get(ep, "?") for ep in nodes],
        "count": len(nodes),
    }


def consistency_findings(snapshots: dict[str, dict], shards: dict[str, str], total_nodes: int) -> dict:
    """Compare per-node snapshots and return ``{"reached", "findings", "parameters"}``.

    ``snapshots`` maps ``host:port`` to ``consistency_snapshot`` output for the nodes that answered;
    ``total_nodes`` is how many were asked, so the result states how far the comparison reached.
    """
    findings: list[dict] = []
    parameters: dict[str, dict] = {}
    for name in CONSISTENCY_CONFIG:
        values = {ep: s["config"][name] for ep, s in snapshots.items() if name in s["config"]}
        parameters[name] = {"nodes_compared": len(values), "distinct_values": len({repr(v) for v in values.values()})}
        found = _drift(name, values, shards, repr)
        if found:
            findings.append(found)
    users = {ep: tuple(s["acl_users"]) for ep, s in snapshots.items() if s["acl_users"] is not None}
    parameters["acl-users"] = {"nodes_compared": len(users), "distinct_values": len(set(users.values()))}

    def users_text(value: tuple) -> str:
        return "[" + ", ".join(value) + "]"

    found = _drift("ACL user names", users, shards, users_text)
    if found:
        maj = _majority(users)
        if maj is not None:
            ref = set(maj[0])
            gaps = []
            for ep in found["nodes"]:
                mine = set(users[ep])
                gaps.append(f"{ep} missing {sorted(ref - mine) or '-'} extra {sorted(mine - ref) or '-'}")
            found["message"] = f"ACL user names differ from the majority ({maj[1]}/{len(users)} nodes): " + "; ".join(
                gaps
            )
        findings.append(found)
    versions = {ep: s["version"] for ep, s in snapshots.items() if s["version"]}
    parameters["engine-version"] = {"nodes_compared": len(versions), "distinct_values": len(set(versions.values()))}
    found = _drift("engine version", versions, shards, str)
    if found:
        found["message"] += " (rolling upgrade in progress or a stuck update)"
        findings.append(found)
    answered = sum(1 for s in snapshots.values() if s["config"] or s["acl_users"] is not None or s["version"])
    return {
        "reached": f"compared {answered}/{total_nodes} nodes",
        "nodes_compared": answered,
        "nodes_total": total_nodes,
        "findings": findings,
        "parameters": parameters,
    }
