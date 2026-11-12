"""node_keyspace_sample include_sizes: big-collection candidates by prefix, never a value read."""

import pytest

from mcp_elasticache_ops import dataplane
from mcp_elasticache_ops.dataplane._core import LENGTH_COMMAND
from mcp_elasticache_ops.safe_client import ReadOnlyViolation, check

from .fakes import FakeRedis

VALUE_READERS = {"GET", "MGET", "HGET", "HGETALL", "HMGET", "LRANGE", "LINDEX", "SMEMBERS", "SRANDMEMBER"}
VALUE_READERS |= {"ZRANGE", "ZRANGEBYSCORE", "XRANGE", "XREAD", "GETRANGE", "SSCAN", "HSCAN", "ZSCAN", "DUMP"}
METADATA = {"TYPE", "MEMORY USAGE", "PTTL", "OBJECT", *LENGTH_COMMAND.values(), "EXISTS"}


def _info():
    return {
        "used_memory": 100,
        "maxmemory": 1000,
        "maxmemory_policy": "allkeys-lru",
    }


def _data():
    data = {f"queue:{i}": ("list", 500, -1, 25_000 + i) for i in range(3)}
    data["feed:7:items"] = ("stream", 900, -1, 400_000)
    data["small:1"] = ("hash", 80, -1, 12)
    data["blob:1"] = ("string", 90_000, -1, 90_000)  # STRLEN is bytes, not an element count
    data["tags:abc12345"] = ("set", 60, -1, 10_001)
    return data


def _sample(r, **kw):
    return dataplane.keyspace_sample(r, sample_size=1000, **kw)


def test_keyspace_sizes_flags_prefixes_over_the_threshold():
    out = _sample(FakeRedis(infos={"memory": _info()}, data=_data()), include_sizes=True, size_threshold=10_000)
    block = out["collections"]
    assert block["threshold"] == 10_000 and block["partial"] is False
    by_prefix = {p["prefix"]: p for p in block["prefixes"]}
    assert set(by_prefix) == {"queue:*", "feed:*:items", "tags:*"}
    assert by_prefix["queue:*"]["keys"] == 3 and by_prefix["queue:*"]["max_length"] == 25_002
    assert by_prefix["queue:*"]["types"] == ["list"]
    assert block["prefixes"][0]["prefix"] == "feed:*:items"  # largest first
    assert block["collections_probed"] == 6  # the string is not a collection
    messages = [f["message"] for f in out["findings"] if f.get("section") == "collections"]
    assert len(messages) == 3 and "unbounded-growth candidate" in messages[0]
    assert next(f for f in out["findings"] if "feed:*:items" in f["message"])["severity"] == "warning"


def test_keyspace_sizes_reports_prefixes_never_full_keys_or_values():
    out = _sample(FakeRedis(infos={"memory": _info()}, data=_data()), include_sizes=True, size_threshold=10_000)
    text = repr(out["collections"]) + " ".join(f["message"] for f in out["findings"])
    assert "queue:0" not in text and "tags:abc12345" not in text and "feed:7:items" not in text


def test_keyspace_sizes_is_opt_in():
    out = _sample(FakeRedis(infos={"memory": _info()}, data=_data()))
    assert "collections" not in out
    assert not any(f.get("section") == "collections" for f in out["findings"])


def test_keyspace_sizes_clean_when_nothing_exceeds_the_threshold():
    out = _sample(FakeRedis(infos={"memory": _info()}, data=_data()), include_sizes=True, size_threshold=1_000_000)
    assert out["collections"]["prefixes"] == [] and out["collections"]["prefixes_over_threshold"] == 0


def test_keyspace_sizes_never_issues_a_value_reading_command():
    r = FakeRedis(infos={"memory": _info()}, data=_data())
    _sample(r, include_sizes=True, size_threshold=10)
    issued = {cmd[0] for cmd in r.sent}
    assert issued, "the sample must have probed the keys"
    assert not issued & VALUE_READERS, issued & VALUE_READERS
    assert issued <= METADATA, issued - METADATA


def test_keyspace_sizes_adds_no_commands_over_the_plain_sample():
    plain, sized = (
        FakeRedis(infos={"memory": _info()}, data=_data()),
        FakeRedis(infos={"memory": _info()}, data=_data()),
    )
    _sample(plain)
    _sample(sized, include_sizes=True)
    assert sorted(plain.sent) == sorted(sized.sent)
    assert plain.scan_calls == sized.scan_calls


def test_keyspace_sizes_respects_the_wall_clock_budget():
    ticks = iter(range(0, 1000, 5))
    r = FakeRedis(
        infos={"memory": _info()}, data={f"q:{i}": ("list", 1, -1, 99_999) for i in range(500)}, scan_batch=10
    )
    out = dataplane.keyspace_sample(
        r, sample_size=500, max_seconds=10, clock=lambda: next(ticks), include_sizes=True, size_threshold=10
    )
    assert out["partial"] is True and out["collections"]["partial"] is True
    assert out["sampled_keys"] < 500


@pytest.mark.parametrize("command", sorted(set(LENGTH_COMMAND.values())))
def test_keyspace_sizes_length_commands_are_on_the_safe_client_allowlist(command):
    check((command, "some:key"))  # raises ReadOnlyViolation when absent


@pytest.mark.parametrize(
    "command", sorted(VALUE_READERS - {"GETRANGE", "LINDEX", "HMGET", "SRANDMEMBER", "ZRANGEBYSCORE"})
)
def test_keyspace_sizes_value_readers_stay_refused_by_the_safe_client(command):
    with pytest.raises(ReadOnlyViolation):
        check((command, "some:key", "0", "-1"))


def test_keyspace_sizes_scan_count_stays_inside_the_safe_client_cap():
    from mcp_elasticache_ops.safe_client import MAX_SCAN_COUNT

    counts = []

    class Spy(FakeRedis):
        def scan(self, cursor=0, match=None, count=10):
            counts.append(count)
            return super().scan(cursor=cursor, match=match, count=count)

    r = Spy(infos={"memory": _info()}, data=_data())
    _sample(r, include_sizes=True, scan_count=10**9)
    assert counts and max(counts) <= MAX_SCAN_COUNT
    with pytest.raises(ReadOnlyViolation):
        check(("SCAN", "0", "COUNT", str(MAX_SCAN_COUNT + 1)))


def test_keyspace_sizes_probe_each_key_once_with_one_length_command():
    r = FakeRedis(infos={"memory": _info()}, data=_data())
    _sample(r, include_sizes=True, size_threshold=1)
    lengths = [c for c in r.sent if c[0] in set(LENGTH_COMMAND.values())]
    assert len(lengths) <= len(_data())
    assert len({c[1] for c in lengths}) == len(lengths)  # never twice for the same key


def test_keyspace_sizes_memory_usage_is_not_added_by_include_sizes():
    plain = FakeRedis(infos={"memory": _info()}, data=_data())
    sized = FakeRedis(infos={"memory": _info()}, data=_data())
    _sample(plain)
    _sample(sized, include_sizes=True)
    count = lambda r: sum(1 for c in r.sent if c[0] == "MEMORY USAGE")  # noqa: E731
    assert count(sized) == count(plain)


def test_keyspace_sizes_prefix_list_is_bounded_per_collection_group():
    data = {f"p{i}:{j}": ("list", 1, -1, 50_000) for i in range(80) for j in range(2)}
    out = _sample(FakeRedis(infos={"memory": _info()}, data=data), include_sizes=True, size_threshold=10)
    block = out["collections"]
    assert block["prefixes_over_threshold"] >= len(block["prefixes"])
    assert len(block["prefixes"]) <= 50
    assert len(repr(out)) < 60_000


def test_keyspace_sizes_threshold_below_one_is_clamped_not_an_error():
    out = _sample(FakeRedis(infos={"memory": _info()}, data=_data()), include_sizes=True, size_threshold=0)
    assert out["collections"]["threshold"] >= 1


def test_keyspace_sizes_empty_keyspace_reports_nothing():
    out = _sample(FakeRedis(infos={"memory": _info()}, data={}), include_sizes=True)
    assert out["collections"]["prefixes"] == []
