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


@pytest.mark.parametrize(
    "args",
    [
        ("CONFIG GET", "requirepass"),
        ("CONFIG GET", "REQUIREPASS"),
        ("CONFIG GET", "masterauth"),
        ("CONFIG GET", "masteruser"),
        ("CONFIG GET", "*"),
        ("CONFIG GET", "*pass*"),
        ("CONFIG GET", "*auth"),
        ("CONFIG GET", "tls-key-file"),
        ("CONFIG GET", "tls-*"),
        ("CONFIG GET", "m?xmemory"),
        ("CONFIG GET", "maxmemory", "requirepass"),
        ("CONFIG GET", "[mr]*"),
        ("CONFIG GET", "max*"),
        ("CONFIG GET",),
        ("CONFIG", "GET", "requirepass"),
        ("CONFIG", "GET", "*"),
        ("CONFIG GET", b"requirepass"),
        ("CONFIG GET", 123),
    ],
)
def test_config_get_sensitive_or_broad_is_rejected(args):
    with pytest.raises(ReadOnlyViolation):
        check(args)


@pytest.mark.parametrize(
    "args",
    [
        ("CONFIG GET", "maxmemory"),
        ("CONFIG GET", "maxmemory*"),
        ("CONFIG GET", "maxmemory-policy"),
        ("CONFIG GET", "maxclients"),
        ("CONFIG GET", "timeout"),
        ("CONFIG GET", "latency-monitor-threshold"),
        ("CONFIG GET", "slowlog-*"),
        ("CONFIG GET", "slowlog-log-slower-than"),
        ("CONFIG GET", "appendonly"),
        ("CONFIG GET", "save"),
        ("CONFIG GET", "notify-keyspace-events"),
        ("CONFIG GET", "activedefrag"),
        ("CONFIG GET", "cluster-enabled"),
        ("CONFIG", "GET", "maxmemory"),
        ("CONFIG GET", b"maxclients"),
        ("CONFIG GET", "maxmemory", "maxclients"),
    ],
)
def test_config_get_allowed_parameters(args):
    check(args)


@pytest.mark.parametrize(
    "args",
    [
        ("INFO\nSET k v",),
        ("INFO SET k v",),
        ("INFO\tmemory",),
        (" INFO",),
        ("INFO ",),
        ("PING GET k",),
        ("CLIENT LIST SET k v",),
        ("CLIENT LIST\nFLUSHALL",),
        ("CLIENT", "LIST\nFLUSHALL"),
        ("CLIENT", "LIST SET"),
        ("CONFIG GET maxmemory",),  # no space tricks: pattern must be a separate argument
        ("",),
        (None,),
        (123,),
        (["INFO"],),
        (object(),),
    ],
)
def test_malformed_or_untyped_heads_are_rejected(args):
    with pytest.raises(ReadOnlyViolation):
        check(args)


def test_command_key_rejects_extra_tokens_and_types():
    with pytest.raises(ReadOnlyViolation):
        command_key(("INFO\nSET k v",))
    with pytest.raises(ReadOnlyViolation):
        command_key((5,))
    with pytest.raises(ReadOnlyViolation):
        command_key(())


def test_pipeline_paths_use_the_same_guard():
    r = SafeRedis(host="127.0.0.1", port=1, socket_connect_timeout=0.2)
    pipe = r.pipeline()
    for bad in (
        ("CONFIG GET", "requirepass"),
        ("CONFIG GET", "*"),
        ("CONFIG", "GET", "masterauth"),
        ("INFO\nSET k v",),
        ("SET", "k", "v"),
    ):
        with pytest.raises(ReadOnlyViolation):
            pipe.execute_command(*bad)
    with pytest.raises(ReadOnlyViolation):
        pipe.config_get("requirepass")
    with pytest.raises(ReadOnlyViolation):
        r.config_get("*")
    with pytest.raises(ReadOnlyViolation):
        r.execute_command("INFO\nSET k v")
    assert not pipe.command_stack
