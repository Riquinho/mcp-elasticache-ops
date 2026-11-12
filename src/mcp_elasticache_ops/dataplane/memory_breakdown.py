"""Where the memory goes: one merged finding from INFO memory and MEMORY STATS.

Fragmentation ratio and noeviction pressure have their own findings in ``health``; this adds the parts that
explain a high or odd ratio: allocator fragmentation, main hash table overhead, replication backlog and client
buffers (normal plus replica output). All thresholds are fixed and documented in the README."""

from __future__ import annotations

from typing import Any

from ._core import _finding, _num

ALLOCATOR_FRAG_HIGH = 1.5  # allocator_frag_ratio above this: the allocator holds pages the dataset cannot reuse
HASHTABLE_SHARE_WARN = 0.20  # overhead.hashtable.main above this share of used memory (many tiny keys)
BUFFERS_SHARE_WARN = 0.20  # clients (normal + replicas) plus replication backlog above this share
BREAKDOWN_FLOOR_BYTES = 32 * 1024 * 1024  # shares of a smaller number are noise
_MIB = 1024 * 1024


def _first(*values: Any) -> float:
    for v in values:
        if v is not None:
            return _num(v)
    return 0.0


def memory_breakdown(mem: dict, stats: dict | None) -> dict:
    """Numbers behind the finding: bytes per component plus the allocator and RSS ratios.

    ``stats`` is the MEMORY STATS reply or ``None`` when the command was refused; INFO fields then stand in."""
    stats = stats if isinstance(stats, dict) else {}
    used = _num(mem.get("used_memory"))
    return {
        "used_memory": int(used),
        "hashtable_main_bytes": int(_first(stats.get("overhead.hashtable.main"))),
        "replication_backlog_bytes": int(_first(stats.get("replication.backlog"), mem.get("mem_replication_backlog"))),
        "clients_normal_bytes": int(_first(stats.get("clients.normal"), mem.get("mem_clients_normal"))),
        "clients_replicas_bytes": int(_first(stats.get("clients.slaves"), mem.get("mem_clients_slaves"))),
        "allocator_frag_ratio": _first(mem.get("allocator_frag_ratio"), stats.get("allocator-fragmentation.ratio")),
        "mem_fragmentation_ratio": _first(mem.get("mem_fragmentation_ratio"), stats.get("fragmentation")),
    }


def memory_breakdown_findings(mem: dict, stats: dict | None) -> list[dict]:
    """At most one finding: the components over their thresholds on a single line."""
    b = memory_breakdown(mem, stats)
    used = b["used_memory"]
    parts: list[str] = []
    if b["allocator_frag_ratio"] > ALLOCATOR_FRAG_HIGH:
        parts.append(
            f"allocator_frag_ratio {b['allocator_frag_ratio']:.2f} (pages the dataset cannot reuse, "
            "activedefrag or a node replacement releases them)"
        )
    if used >= BREAKDOWN_FLOOR_BYTES:
        table = b["hashtable_main_bytes"]
        if table / used > HASHTABLE_SHARE_WARN:
            parts.append(f"main hash table overhead {table / used:.0%} ({table // _MIB} MiB; many small keys)")
        held = b["clients_normal_bytes"] + b["clients_replicas_bytes"] + b["replication_backlog_bytes"]
        if held / used > BUFFERS_SHARE_WARN:
            parts.append(
                f"client buffers plus replication backlog {held / used:.0%} ({held // _MIB} MiB: "
                f"clients {b['clients_normal_bytes'] // _MIB}, replicas {b['clients_replicas_bytes'] // _MIB}, "
                f"backlog {b['replication_backlog_bytes'] // _MIB}, slow consumers or an oversized backlog)"
            )
    if not parts:
        return []
    return [_finding("warning", "memory breakdown: " + " | ".join(parts), source="memory-breakdown")]
