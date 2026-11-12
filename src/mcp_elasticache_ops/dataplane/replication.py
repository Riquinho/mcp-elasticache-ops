"""Replication view and the CLUSTER INFO summary."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable

import redis

from ._core import (
    _SEVERITY_RANK,
    _finding,
    _jsonable,
    _num,
    _s,
    _try,
    _unsupported,
    command_support_note,
    engine_of,
)
from .config_stats import (
    CONFIG_FALLBACK_NOTE,
)
from .health import (
    _serverless_hint,
)

REPL_LAG_BYTES_WARN = 1_000_000


REPL_LAG_SECONDS_WARN = 10


REPL_IO_SECONDS_WARN = 10


REPLICA_SETTINGS = (
    "replica-read-only",
    "min-replicas-to-write",
    "min-replicas-max-lag",
    "cluster-allow-reads-when-down",
)


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
