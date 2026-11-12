"""Cluster fan-out with a hung shard, reader-endpoint classification, and the read-only guard against writes."""

from __future__ import annotations

import time

import pytest
import redis

from mcp_elasticache_ops import dataplane
from mcp_elasticache_ops.connection import endpoint_kind
from mcp_elasticache_ops.safe_client import READ_ONLY_COMMANDS, ReadOnlyViolation, check
from tests.test_dataplane_unit import _fan_factory, _seed, _shard_client

A, B, C = "10.0.0.1:6379", "10.0.0.2:6379", "10.0.0.3:6379"


class _Hung:
    """A shard whose every command blocks well past the fan-out's per-node timeout."""

    def close(self) -> None:
        return None

    def __getattr__(self, name: str):
        def hang(*_a, **_kw):
            time.sleep(1.0)
            return {}

        return hang


def test_a_hung_shard_gives_a_partial_result_with_a_findings_line():
    factory, _ = _fan_factory({A: _shard_client("a"), B: _Hung, C: _shard_client("c")})
    out = dataplane.cluster_slowlog(_seed(), factory, max_seconds=0.2, per_node_timeout=0.2)
    assert out["per_shard"][B]["status"] == "unreachable"
    assert "no answer within the time budget" in out["per_shard"][B]["error"]
    assert out["per_shard"][A]["status"] == "ok" and out["per_shard"][C]["status"] == "ok"
    assert out["reached"] == "reached 2/3 shards"
    assert out["partial"] is True
    assert [n["node"] for n in out["partial_nodes"]] == [B]
    lines = [f["message"] for f in out["findings"] if f.get("shard") == B]
    assert lines and lines[0].startswith(f"shard {B} unreachable: no answer within the time budget")


def test_a_hung_shard_never_hides_the_answers_of_the_others():
    factory, _ = _fan_factory({A: _shard_client("a"), B: _Hung, C: _shard_client("c")})
    out = dataplane.cluster_keyspace_sample(_seed(), factory, sample_size=60, max_seconds=0.2, per_node_timeout=0.2)
    assert out["shards_ok"] == 2 and out["shards_unreachable"] == 1
    assert out["sampled_keys"] > 0
    assert set(out["per_shard"]) == {A, B, C}


@pytest.mark.parametrize(
    "host",
    ["rg-ro.abc123.ng.0001.use1.cache.amazonaws.com", "RG-RO.abc123.ng.0001.use1.cache.amazonaws.com"],
)
def test_reader_endpoint_names_are_classified_as_readers(host: str):
    assert endpoint_kind(host) == "reader"


def test_primary_endpoint_is_not_mistaken_for_a_reader():
    assert endpoint_kind("rg.abc123.ng.0001.use1.cache.amazonaws.com") == "primary"


@pytest.mark.parametrize(
    "args",
    [
        ("READONLY",),  # switches a connection into replica-read mode, a connection state change
        ("READWRITE",),
        ("SET", "k", "v"),
        ("DEL", "k"),
        ("FLUSHALL",),
        ("CONFIG", "SET", "maxmemory", "1"),
        ("CLUSTER", "FAILOVER"),
        ("EVAL", "return 1", "0"),
    ],
)
def test_writes_and_reader_mode_switches_are_refused(args):
    with pytest.raises(ReadOnlyViolation):
        check(args)


WRITE_VERBS = {"SET", "DEL", "UNLINK", "FLUSHALL", "FLUSHDB", "EXPIRE", "INCR", "HSET", "LPUSH", "SADD", "ZADD"}


def test_no_allowlisted_command_is_a_write_or_a_connection_mode_switch():
    head = {key.split(" ", 1)[0] for key in READ_ONLY_COMMANDS}
    assert not head & (WRITE_VERBS | {"READONLY", "READWRITE", "FAILOVER", "EVAL", "SCRIPT", "MIGRATE", "DEBUG"})
    assert not {k for k in READ_ONLY_COMMANDS if k.startswith(("CLUSTER FAIL", "CLUSTER SETSLOT", "CLIENT KILL"))}


def test_a_replica_read_connection_error_is_a_node_error_not_a_crash():
    factory, _ = _fan_factory(
        {A: _shard_client("a"), B: redis.exceptions.ReadOnlyError("READONLY You can't write"), C: _shard_client("c")}
    )
    out = dataplane.cluster_keyspace_sample(_seed(), factory, sample_size=60, max_seconds=5)
    assert out["per_shard"][B]["status"] == "unreachable"
    assert out["partial"] is True
