"""Shard skew and hot slots: per-shard dataset size, memory, traffic and a bounded slot-count sample."""

from __future__ import annotations

import statistics
import time
from typing import Any

import redis

from ._core import _finding, _num, _s, _sorted_findings
from .fanout import (
    ClientFactory,
    _fan_out_primaries,
    _partial_nodes,
    _shard_counts,
    _unreachable_findings,
)
from .topology import TOTAL_SLOTS, parse_cluster_nodes

DEFAULT_SLOTS_PER_SHARD = 64
MAX_SLOTS_PER_SHARD = 256  # each sampled slot is one CLUSTER COUNTKEYSINSLOT, O(1) on the node
MAX_HOT_SLOTS = 10

SHARD_HOT_RATIO = 1.5
SHARD_CRITICAL_RATIO = 3.0
SHARD_MIN_KEYS = 1_000
SHARD_MIN_BYTES = 64 * 1024 * 1024
SHARD_MIN_OPS = 100.0
HOT_SLOT_RATIO = 8.0
HOT_SLOT_MIN_KEYS = 100


def _expand_slots(tokens: list[str]) -> list[int]:
    slots: list[int] = []
    for tok in tokens:
        lo, _, hi = str(tok).partition("-")
        slots.extend(range(int(lo), int(hi or lo) + 1))
    return slots


def _spread(slots: list[int], limit: int) -> list[int]:
    """At most ``limit`` slots spread evenly over the owned ones (first and last included)."""
    if len(slots) <= limit:
        return slots
    step = (len(slots) - 1) / (limit - 1) if limit > 1 else 0
    return sorted({slots[round(i * step)] for i in range(limit)})


def _shard_probe(slots_per_shard: int):
    def work(client: redis.Redis, budget: float, shards: int) -> dict:
        deadline = time.monotonic() + budget
        info = client.info()
        row: dict[str, Any] = {
            "dbsize": int(client.dbsize()),
            "used_memory": int(_num(info.get("used_memory"))),
            "ops_per_sec": _num(info.get("instantaneous_ops_per_sec")),
            "slots_owned": 0,
            "slot_counts": {},
            "partial": False,
        }
        raw = client.execute_command("CLUSTER", "NODES")
        nodes = parse_cluster_nodes(_s(raw)) if raw else []
        me = next((n for n in nodes if n.get("myself")), None)
        owned = _expand_slots(me["slots"]) if me else []
        row["slots_owned"] = len(owned)
        for slot in _spread(owned, slots_per_shard):
            if time.monotonic() >= deadline:
                row["partial"] = True
                row["partial_reason"] = f"time budget ran out after {len(row['slot_counts'])} slots"
                break
            row["slot_counts"][slot] = int(client.execute_command("CLUSTER", "COUNTKEYSINSLOT", slot))
        return row

    return work


def _shard_skew_findings(per_shard: dict[str, dict]) -> list[dict]:
    out: list[dict] = []
    for field, label, floor in (
        ("dbsize", "key count", SHARD_MIN_KEYS),
        ("used_memory", "used memory", SHARD_MIN_BYTES),
        ("ops_per_sec", "traffic (ops/sec)", SHARD_MIN_OPS),
    ):
        values = {ep: row[field] for ep, row in per_shard.items() if field in row}
        if len(values) < 2:
            continue
        mean = statistics.mean(values.values())
        if mean <= 0:
            continue
        for ep, v in values.items():
            ratio = v / mean
            if ratio < SHARD_HOT_RATIO or v < floor:
                continue
            severity = "critical" if ratio >= SHARD_CRITICAL_RATIO else "warning"
            out.append(
                _finding(
                    severity,
                    f"hot shard {ep}: {label} {v:.0f} is {ratio:.1f}x the shard average ({mean:.0f}); "
                    "a skewed key distribution or hash tags concentrate load here",
                    shard=ep,
                    category="shard-skew",
                )
            )
    return out


def _hot_slot_rows(per_shard: dict[str, dict]) -> tuple[list[dict], int]:
    counts = [(int(slot), n, ep) for ep, row in per_shard.items() for slot, n in row.get("slot_counts", {}).items()]
    if not counts:
        return [], 0
    base = max(statistics.median(n for _, n, _ in counts), 1.0)  # median: one hot slot must not lift its own bar
    hot = [
        {"slot": slot, "shard": ep, "keys": n, "times_median": round(n / base, 1)}
        for slot, n, ep in counts
        if n >= HOT_SLOT_MIN_KEYS and n / base >= HOT_SLOT_RATIO
    ]
    hot.sort(key=lambda h: (-h["keys"], h["slot"]))
    return hot, len(counts)


def cluster_hot_slots(
    r: redis.Redis,
    client_factory: ClientFactory,
    slots_per_shard: int = DEFAULT_SLOTS_PER_SHARD,
    max_workers: int = 8,
    per_node_timeout: float = 5.0,
    max_seconds: float = 15.0,
) -> dict:
    """Per-shard key count, memory and ops/sec plus CLUSTER COUNTKEYSINSLOT on an evenly spread slot sample.

    Read-only and bounded: at most ``slots_per_shard`` (cap ``MAX_SLOTS_PER_SHARD``) slot counts per primary, one
    shared deadline, a failing shard reported as unreachable without failing the call. The slot sample can miss a
    hot slot; ``slots_sampled`` says how much was covered.
    """
    started = time.monotonic()
    slots_per_shard = max(1, min(int(slots_per_shard), MAX_SLOTS_PER_SHARD))
    topo, outcomes = _fan_out_primaries(
        r, client_factory, _shard_probe(slots_per_shard), max_workers, max_seconds, per_node_timeout
    )
    if not outcomes:
        if topo.get("cluster_enabled") is False:
            return {
                **topo,
                "note": "cluster mode disabled (single shard): there is no shard or slot skew to measure",
                "findings": [],
            }
        return topo
    findings = _unreachable_findings(outcomes)
    per_shard: dict[str, dict] = {}
    for ep, o in outcomes.items():
        if o["status"] == "unreachable":
            per_shard[ep] = {"status": "unreachable", "error": o["error"]}
            continue
        data = o["data"]
        if data["partial"]:
            o["status"] = "partial"
            findings.append(
                _finding("warning", f"shard {ep} slot sample is partial: {data['partial_reason']}", shard=ep)
            )
        per_shard[ep] = {"status": o["status"], **data}
    live = {ep: row for ep, row in per_shard.items() if row["status"] != "unreachable"}
    findings += _shard_skew_findings(live)
    hot, sampled = _hot_slot_rows(live)
    for h in hot[:MAX_HOT_SLOTS]:
        findings.append(
            _finding(
                "warning",
                f"hot slot {h['slot']} on shard {h['shard']} holds {h['keys']} keys, {h['times_median']}x the "
                "median sampled slot; look for a hash tag or one key family mapped to a single slot",
                shard=h["shard"],
                category="hot-slot",
            )
        )
    for row in live.values():
        row["slots_sampled"] = len(row.pop("slot_counts", {}))
    counts = _shard_counts(outcomes)
    return {
        "cluster_enabled": True,
        "scope": "all shard primaries",
        **counts,
        "partial": counts["shards_total"] != counts["shards_ok"],
        "partial_nodes": _partial_nodes(outcomes),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "slots_total": TOTAL_SLOTS,
        "slots_sampled": sampled,
        "hot_slots": hot[:MAX_HOT_SLOTS],
        "hot_slots_total": len(hot),
        "per_shard": per_shard,
        "findings": _sorted_findings(findings),
    }
