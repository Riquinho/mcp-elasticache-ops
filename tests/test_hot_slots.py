"""node_hot_slots: per-shard skew, hot-slot sampling, bounded fan-out and the SafeRedis bounds."""

from __future__ import annotations

import time

import pytest
import redis

from mcp_elasticache_ops import dataplane
from mcp_elasticache_ops.safe_client import ReadOnlyViolation, check
from tests.fakes import FakeRedis

SEED_NODES = (
    "a1 10.0.0.1:6379@16379 master - 0 0 1 connected 0-3\nb1 10.0.0.2:6379@16379 master - 0 0 2 connected 4-7\n"
)


def _shard(myself_line: str, keys: int, counts: dict[int, int], slots: range) -> FakeRedis:
    fake = FakeRedis(
        infos={"memory": {"used_memory": 10, "instantaneous_ops_per_sec": 5}},
        data={f"k{i}": ("string", 1, -1, 1) for i in range(keys)},
    )
    fake.commands["CLUSTER NODES"] = myself_line
    for s in slots:
        fake.commands[f"CLUSTER COUNTKEYSINSLOT {s}"] = counts.get(s, 10)
    return fake


def _setup(hot_keys: int = 5000, b_keys: int = 100):
    a = _shard("a1 10.0.0.1:6379@16379 myself,master - 0 0 1 connected 0-3\n", 3000, {2: hot_keys}, range(0, 4))
    b = _shard("b1 10.0.0.2:6379@16379 myself,master - 0 0 2 connected 4-7\n", b_keys, {}, range(4, 8))
    clients = {"10.0.0.1:6379": a, "10.0.0.2:6379": b}
    seed = FakeRedis(infos={"cluster": {"cluster_enabled": 1}})
    seed.commands["CLUSTER NODES"] = SEED_NODES
    return seed, lambda host, port: clients[f"{host}:{port}"], clients


def test_skewed_shard_and_hot_slot_are_top_findings():
    seed, factory, _ = _setup()
    out = dataplane.cluster_hot_slots(seed, factory, slots_per_shard=8, max_seconds=5)
    assert out["reached"] == "reached 2/2 shards" and out["partial"] is False
    assert out["findings"][0]["severity"] in {"warning", "critical"}
    msgs = [f["message"] for f in out["findings"]]
    assert any("hot shard 10.0.0.1:6379" in m and "key count" in m for m in msgs)
    assert out["hot_slots"][0]["slot"] == 2 and out["hot_slots"][0]["keys"] == 5000
    assert any("hot slot 2 on shard 10.0.0.1:6379" in m for m in msgs)
    assert out["slots_sampled"] == 8
    assert "slot_counts" not in out["per_shard"]["10.0.0.1:6379"]


def test_balanced_cluster_has_no_findings():
    a = _shard("a1 10.0.0.1:6379@16379 myself,master - 0 0 1 connected 0-3\n", 2000, {}, range(0, 4))
    b = _shard("b1 10.0.0.2:6379@16379 myself,master - 0 0 2 connected 4-7\n", 2000, {}, range(4, 8))
    clients = {"10.0.0.1:6379": a, "10.0.0.2:6379": b}
    seed = FakeRedis(infos={"cluster": {"cluster_enabled": 1}})
    seed.commands["CLUSTER NODES"] = SEED_NODES
    out = dataplane.cluster_hot_slots(seed, lambda h, p: clients[f"{h}:{p}"], max_seconds=5)
    assert out["findings"] == [] and out["hot_slots"] == []


def test_slot_sample_is_capped_per_shard():
    seed, factory, clients = _setup()
    out = dataplane.cluster_hot_slots(seed, factory, slots_per_shard=2, max_seconds=5)
    assert out["slots_sampled"] == 4
    assert out["per_shard"]["10.0.0.1:6379"]["slots_owned"] == 4
    assert dataplane.cluster_hot_slots(seed, factory, slots_per_shard=10**6, max_seconds=5)["slots_sampled"] == 8
    from mcp_elasticache_ops.dataplane.hot_slots import _spread

    assert len(_spread(list(range(16384)), 256)) <= 256


def test_dead_shard_is_isolated_and_reported():
    seed, factory, clients = _setup()

    def boom():
        raise redis.ConnectionError("down")

    clients["10.0.0.2:6379"].commands["CLUSTER NODES"] = boom
    out = dataplane.cluster_hot_slots(seed, factory, slots_per_shard=8, max_seconds=5)
    assert out["reached"] == "reached 1/2 shards" and out["partial"] is True
    assert out["per_shard"]["10.0.0.2:6379"]["status"] == "unreachable"
    assert any("10.0.0.2:6379 unreachable" in f["message"] for f in out["findings"])


def test_hanging_shard_returns_within_budget():
    seed, factory, clients = _setup()
    clients["10.0.0.2:6379"].commands["CLUSTER NODES"] = lambda: time.sleep(3)
    t0 = time.monotonic()
    out = dataplane.cluster_hot_slots(seed, factory, slots_per_shard=8, max_seconds=1, per_node_timeout=0.5)
    assert time.monotonic() - t0 < 4
    assert out["per_shard"]["10.0.0.2:6379"]["status"] == "unreachable"
    assert out["per_shard"]["10.0.0.1:6379"]["status"] in {"ok", "partial"}


def test_standalone_returns_note():
    seed = FakeRedis(infos={"cluster": {"cluster_enabled": 0}})
    out = dataplane.cluster_hot_slots(seed, lambda h, p: seed)
    assert out["cluster_enabled"] is False and "no shard or slot skew" in out["note"]


# ------------------------------------------------------------------------- SafeRedis bounds


@pytest.mark.parametrize("slot", ["0", "16383", 5])
def test_countkeysinslot_allowed_in_range(slot):
    check(("CLUSTER", "COUNTKEYSINSLOT", slot))


@pytest.mark.parametrize(
    "args",
    [
        ("CLUSTER", "COUNTKEYSINSLOT"),
        ("CLUSTER", "COUNTKEYSINSLOT", "16384"),
        ("CLUSTER", "COUNTKEYSINSLOT", "-1"),
        ("CLUSTER", "COUNTKEYSINSLOT", "abc"),
        ("CLUSTER", "COUNTKEYSINSLOT", "1", "2"),
        ("CLUSTER", "GETKEYSINSLOT", "1", "10"),
        ("CLUSTER", "DELSLOTS", "1"),
        ("CLUSTER", "SETSLOT", "1", "STABLE"),
        ("CLUSTER", "ADDSLOTS", "1"),
    ],
)
def test_countkeysinslot_variants_refused(args):
    with pytest.raises((ReadOnlyViolation, ValueError)):
        check(args)
