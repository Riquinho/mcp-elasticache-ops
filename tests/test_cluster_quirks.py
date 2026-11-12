"""Cluster-mode replies during failover or resharding become per-node findings; the fan-out never aborts."""

from __future__ import annotations

import pytest
import redis

from mcp_elasticache_ops import dataplane
from tests.test_dataplane_unit import _fan_factory, _fleet, _seed, _shard_client

A, B, C = "10.0.0.1:6379", "10.0.0.2:6379", "10.0.0.3:6379"

REPLIES = [
    ("MOVED", redis.exceptions.MovedError("3999 10.0.0.9:6379"), "warning"),
    ("ASK", redis.exceptions.AskError("3999 10.0.0.9:6379"), "warning"),
    ("CLUSTERDOWN", redis.exceptions.ClusterDownError("The cluster is down"), "critical"),
    ("LOADING", redis.exceptions.BusyLoadingError("Redis is loading the dataset in memory"), "warning"),
    ("TRYAGAIN", redis.exceptions.TryAgainError("Multiple keys request during rehashing of slot"), "warning"),
]


class _Raising:
    """A shard client whose every command fails with ``exc`` (the node answers, but with a cluster error)."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.closed = False

    def close(self) -> None:
        self.closed = True

    def __getattr__(self, name: str):
        def boom(*_a, **_kw):
            raise self._exc

        return boom


def _clients(exc: Exception) -> dict:
    return {A: _shard_client("a"), B: lambda: _Raising(exc), C: _shard_client("c")}


@pytest.mark.parametrize(("kind", "exc", "severity"), REPLIES, ids=[r[0] for r in REPLIES])
def test_fan_out_turns_a_cluster_reply_into_a_node_finding(kind, exc, severity):
    factory, opened = _fan_factory(_clients(exc))
    out = dataplane.cluster_keyspace_sample(_seed(), factory, sample_size=60, max_seconds=5)
    assert out["per_shard"][B]["status"] == "unreachable"
    assert out["per_shard"][B]["kind"] == kind
    assert out["per_shard"][A]["status"] == "ok" and out["per_shard"][C]["status"] == "ok"
    mine = [f for f in out["findings"] if f.get("shard") == B]
    assert mine and mine[0]["severity"] == severity and f"{kind} reply" in mine[0]["message"]
    assert out["reached"] == "reached 2/3 shards"
    assert (out["shards_ok"], out["shards_unreachable"], out["partial"]) == (2, 1, True)
    assert all(getattr(c, "closed", True) for c in opened)  # the failing client is closed too


@pytest.mark.parametrize(("kind", "exc", "severity"), REPLIES, ids=[r[0] for r in REPLIES])
def test_every_fan_out_tool_survives_a_cluster_reply(kind, exc, severity):
    # memory and slowlog read each section with a tolerant helper, so a node that errors on every command is
    # a partial shard (answered, incomplete) rather than an unreachable one; either way the call completes.
    for call in (dataplane.cluster_memory, dataplane.cluster_slowlog):
        factory, _ = _fan_factory(_clients(exc))
        out = call(_seed(), factory, max_seconds=5)
        assert out["shards_ok"] == 2 and out["shards_total"] == 3, call.__name__
        assert out["reached"].startswith("reached 3/3 shards") or out["reached"] == "reached 2/3 shards"
        assert [n["node"] for n in out["partial_nodes"]] == [B], call.__name__
        assert any(f.get("shard") == B for f in out["findings"]), call.__name__


@pytest.mark.parametrize(("kind", "exc", "severity"), REPLIES, ids=[r[0] for r in REPLIES])
def test_cluster_health_reports_the_reply_per_node(kind, exc, severity):
    topo = (
        "p1 10.0.0.1:6379@1 master - 0 0 1 connected 0-5460\n"
        "p2 10.0.0.2:6379@1 master - 0 0 2 connected 5461-10922\n"
        "p3 10.0.0.3:6379@1 master - 0 0 3 connected 10923-16383\n"
    )
    infos = {A: {"role": "master", "used_memory": 10}, B: exc, C: {"role": "master", "used_memory": 10}}
    seed, factory, _ = _fleet(topo, infos)
    out = dataplane.cluster_health(seed, factory)
    assert out["per_node"][B]["kind"] == kind
    assert out["reached"] == "reached 2/3 nodes"
    assert any(f"node {B} unreachable" in f and f"{kind} reply" in f for f in out["findings"])


def test_per_shard_output_order_is_stable_whatever_the_completion_order():
    clients = {C: _shard_client("c"), A: _shard_client("a"), B: redis.exceptions.TryAgainError("TRYAGAIN")}
    factory, _ = _fan_factory(clients)
    out = dataplane.cluster_keyspace_sample(_seed(), factory, sample_size=60, max_seconds=5)
    assert list(out["per_shard"]) == [A, B, C]
    assert list(out["per_shard"]) == sorted(out["per_shard"])


def test_a_partial_shard_is_named_in_the_reached_summary():
    clients = _clients(redis.exceptions.TryAgainError("TRYAGAIN"))
    factory, _ = _fan_factory(clients)
    out = dataplane.cluster_slowlog(_seed(), factory, max_seconds=5)
    assert out["reached"] == "reached 3/3 shards (1 partial)"


def test_all_shards_answering_reads_reached_n_of_n():
    factory, _ = _fan_factory({A: _shard_client("a"), B: _shard_client("b"), C: _shard_client("c")})
    out = dataplane.cluster_keyspace_sample(_seed(), factory, sample_size=60, max_seconds=5)
    assert out["reached"] == "reached 3/3 shards" and out["partial"] is False


def test_a_plain_error_stays_a_critical_finding_with_its_type():
    factory, _ = _fan_factory(_clients(redis.ConnectionError("connection refused")))
    out = dataplane.cluster_keyspace_sample(_seed(), factory, sample_size=60, max_seconds=5)
    assert out["per_shard"][B]["kind"] == "error"
    assert "ConnectionError: connection refused" in out["per_shard"][B]["error"]
    assert [f for f in out["findings"] if f.get("shard") == B][0]["severity"] == "critical"
