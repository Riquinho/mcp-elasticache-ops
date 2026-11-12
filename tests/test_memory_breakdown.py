"""Memory breakdown finding: INFO memory plus MEMORY STATS, one merged line, wired into node_memory, node_doctor
and node_triage (so also node_cluster_triage), with the MEMORY STATS refusal as the failure mode."""

from __future__ import annotations

import pytest
import redis

from mcp_elasticache_ops import dataplane
from mcp_elasticache_ops.dataplane.memory_breakdown import memory_breakdown, memory_breakdown_findings
from tests.fakes import FakeRedis

MIB = 1024 * 1024
USED = 100 * MIB


def _mem(**kw):
    base = {
        "used_memory": USED,
        "maxmemory": 1000 * MIB,
        "used_memory_rss": 110 * MIB,
        "mem_fragmentation_ratio": 1.1,
        "allocator_frag_ratio": 1.05,
        "maxmemory_policy": "allkeys-lru",
    }
    return {**base, **kw}


def _msgs(found):
    return [f["message"] for f in found]


def test_clean_node_has_no_breakdown_finding():
    assert memory_breakdown_findings(_mem(), {"overhead.hashtable.main": 5 * MIB, "clients.normal": MIB}) == []


def test_allocator_fragmentation_above_threshold_is_named_with_the_ratio():
    (f,) = memory_breakdown_findings(_mem(allocator_frag_ratio=1.8), {})
    assert f["severity"] == "warning" and f["source"] == "memory-breakdown"
    assert "allocator_frag_ratio 1.80" in f["message"] and "activedefrag" in f["message"]


def test_allocator_ratio_exactly_at_threshold_does_not_fire():
    assert memory_breakdown_findings(_mem(allocator_frag_ratio=1.5), {}) == []


def test_hashtable_overhead_share_comes_from_memory_stats():
    (f,) = memory_breakdown_findings(_mem(), {"overhead.hashtable.main": 30 * MIB})
    assert "main hash table overhead 30% (30 MiB" in f["message"]


def test_replication_backlog_and_client_buffers_are_summed_with_a_breakdown():
    stats = {"replication.backlog": 10 * MIB, "clients.normal": 5 * MIB, "clients.slaves": 20 * MIB}
    (f,) = memory_breakdown_findings(_mem(), stats)
    assert "35%" in f["message"] and "clients 5, replicas 20, backlog 10" in f["message"]


def test_info_fields_stand_in_when_memory_stats_is_refused():
    mem = _mem(mem_replication_backlog=30 * MIB, mem_clients_normal=MIB)
    (f,) = memory_breakdown_findings(mem, None)
    assert "backlog 30" in f["message"]
    assert memory_breakdown(mem, None)["hashtable_main_bytes"] == 0


def test_all_parts_merge_into_one_line():
    stats = {"overhead.hashtable.main": 40 * MIB, "replication.backlog": 40 * MIB}
    found = memory_breakdown_findings(_mem(allocator_frag_ratio=2.0), stats)
    assert len(found) == 1
    assert found[0]["message"].count(" | ") == 2


@pytest.mark.parametrize("used", [0, 31 * MIB])
def test_shares_of_a_tiny_dataset_are_noise(used):
    stats = {"overhead.hashtable.main": 50 * MIB, "replication.backlog": 50 * MIB}
    assert memory_breakdown_findings(_mem(used_memory=used), stats) == []


def test_non_numeric_values_do_not_raise():
    assert memory_breakdown_findings(_mem(allocator_frag_ratio="n/a"), {"overhead.hashtable.main": "x"}) == []


# --- wiring ------------------------------------------------------------------------------------------------------


class _StatsRedis(FakeRedis):
    stats: dict = {}

    def memory_stats(self):
        return self.stats


def _node(stats, **mem):
    r = _StatsRedis(infos={"server": {"redis_version": "7.2.4"}, "memory": _mem(**mem), "stats": {}})
    r.stats = stats
    r.commands["MEMORY DOCTOR"] = "I can't find any memory issue in your instance."
    r.commands["LATENCY DOCTOR"] = "no latency spike was observed during the lifetime of this instance."
    return r


def test_node_memory_reports_the_finding_and_the_numbers():
    out = dataplane.memory_report(_node({"overhead.hashtable.main": 30 * MIB}))
    assert any("main hash table overhead" in m["message"] for m in out["findings"])
    assert out["breakdown"]["hashtable_main_bytes"] == 30 * MIB and len(out["breakdown_findings"]) == 1


def test_node_memory_survives_a_refused_memory_stats():
    class Refusing(_StatsRedis):
        def memory_stats(self):
            raise redis.ResponseError("unknown command 'MEMORY'")

    r = Refusing(infos={"memory": _mem(mem_replication_backlog=40 * MIB), "stats": {}})
    out = dataplane.memory_report(r)
    assert out["memory_stats"] == {"unavailable": "unknown command 'MEMORY'"}
    assert any("backlog 40" in f["message"] for f in out["findings"])


def test_node_doctor_adds_one_breakdown_line():
    out = dataplane.node_doctor(_node({"overhead.hashtable.main": 30 * MIB}))
    lines = [f for f in out["findings"] if f.get("source") == "memory-breakdown"]
    assert len(lines) == 1


def test_node_doctor_without_memory_stats_still_returns():
    class Refusing(_StatsRedis):
        def memory_stats(self):
            raise redis.ResponseError("unknown command")

    r = Refusing(infos={"server": {"redis_version": "7.1.0"}, "memory": _mem(allocator_frag_ratio=2.2)})
    r.commands["MEMORY DOCTOR"] = "I can't find any memory issue in your instance."
    r.commands["LATENCY DOCTOR"] = "no latency spike was observed during the lifetime of this instance."
    out = dataplane.node_doctor(r)
    assert any("allocator_frag_ratio 2.20" in f["message"] for f in out["findings"])


def test_node_triage_shows_the_breakdown_exactly_once():
    out = dataplane.triage(_node({"overhead.hashtable.main": 30 * MIB}), None)
    hits = [f for f in out["findings"] if "memory breakdown" in f["message"]]
    assert len(hits) == 1
