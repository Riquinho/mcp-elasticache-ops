import pytest

from mcp_elasticache_ops.safe_client import READ_ONLY_COMMANDS, ReadOnlyViolation, SafeRedis, check, command_key


@pytest.mark.parametrize(
    "args,key",
    [
        (("INFO", "memory"), "INFO"),
        (("CLIENT LIST",), "CLIENT LIST"),
        (("CLIENT", "list"), "CLIENT LIST"),
        ((b"memory", b"usage", b"k"), "MEMORY USAGE"),
        (("CONFIG GET", "maxmemory"), "CONFIG GET"),
    ],
)
def test_command_key(args, key):
    assert command_key(args) == key


@pytest.mark.parametrize(
    "args",
    [
        ("SET", "k", "v"),
        ("DEL", "k"),
        ("GET", "k"),
        ("FLUSHALL",),
        ("FLUSHDB",),
        ("CONFIG SET", "maxmemory", "1"),
        ("CONFIG", "REWRITE"),
        ("CLIENT KILL", "ID", "1"),
        ("CLIENT", "PAUSE", "1000"),
        ("SLOWLOG RESET",),
        ("DEBUG", "SLEEP", "1"),
        ("SHUTDOWN",),
        ("KEYS", "*"),
        ("EVAL", "return 1", "0"),
        ("CLUSTER", "FAILOVER"),
        ("MULTI",),
        ("SCRIPT", "FLUSH"),
    ],
)
def test_rejects_writes_and_dangerous(args):
    with pytest.raises(ReadOnlyViolation):
        check(args)


def test_allowlist_has_no_writes():
    forbidden = {"SET", "DEL", "GET", "FLUSHALL", "FLUSHDB", "KEYS", "CONFIG SET", "CLIENT KILL", "DEBUG", "EVAL"}
    assert not forbidden & READ_ONLY_COMMANDS


def test_client_refuses_before_network():
    # Port 1 is never listening; a write must fail on the guard, not on connect.
    r = SafeRedis(host="127.0.0.1", port=1, socket_connect_timeout=0.2)
    with pytest.raises(ReadOnlyViolation):
        r.set("k", "v")
    with pytest.raises(ReadOnlyViolation):
        r.flushall()
    with pytest.raises(ReadOnlyViolation):
        r.pipeline(transaction=True)
    pipe = r.pipeline()
    with pytest.raises(ReadOnlyViolation):
        pipe.delete("k")
