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


# ---- bypass paths ---------------------------------------------------------------------------------------------


@pytest.fixture
def offline():
    return SafeRedis(host="127.0.0.1", port=1, socket_connect_timeout=0.2)


@pytest.mark.parametrize(
    "call",
    [
        lambda r: r.pubsub(),
        lambda r: r.monitor(),
        lambda r: r.register_script("return 1"),
        lambda r: r.lock("name"),
        lambda r: r.transaction(lambda p: None, "k"),
        lambda r: r.pipeline().pubsub(),
        lambda r: r.pipeline().register_script("return 1"),
        lambda r: r.pipeline().watch("k"),
        lambda r: r.pipeline().multi(),
        lambda r: r.client().eval("return 1", 0),
        lambda r: r.subscribe if False else r.execute_command("SUBSCRIBE", "c"),
    ],
)
def test_bypass_helpers_raise(offline, call):
    with pytest.raises(ReadOnlyViolation):
        call(offline)


def test_raw_connection_send_command_is_guarded(offline):
    conn = offline.connection_pool.make_connection()
    for bad in (("SET", "k", "v"), ("MONITOR",), ("PSUBSCRIBE", "*"), ("FLUSHALL",), ("CONFIG GET", "*")):
        with pytest.raises(ReadOnlyViolation):
            conn.send_command(*bad)
    with pytest.raises(ReadOnlyViolation):
        conn.send_packed_command(b"*1\r\n$8\r\nFLUSHALL\r\n")
    with pytest.raises(ReadOnlyViolation):
        conn.send_packed_command(conn.pack_command("SET", "k", "v"))


def test_single_connection_client_refused():
    with pytest.raises(ReadOnlyViolation):
        SafeRedis(host="127.0.0.1", port=1, single_connection_client=True)


def test_pipeline_staging_paths_are_guarded(offline):
    pipe = offline.pipeline()
    with pytest.raises(ReadOnlyViolation):
        pipe.pipeline_execute_command("SET", "k", "v")
    with pytest.raises(ReadOnlyViolation):
        pipe.immediate_execute_command("DEL", "k")
    # a command smuggled into the stack after staging is still refused at execute time
    pipe.command_stack.append((("FLUSHALL",), {}))
    with pytest.raises(ReadOnlyViolation):
        pipe.execute()


def test_allowed_commands_still_work_on_the_wire():
    """A tiny RESP server proves the guarded connection and pipeline do send allowed commands."""
    import socket
    import threading

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        with conn:
            while data := conn.recv(4096):
                # one reply per command in this buffer (handshake commands reply +OK)
                n = data.count(b"*")
                reply = b"+PONG\r\n" if b"PING" in data else b"+OK\r\n"
                conn.sendall(reply * max(n, 1))

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        r = SafeRedis(host="127.0.0.1", port=port, socket_timeout=2, protocol=2, client_name="x")
        assert r.ping() is True
        assert r.pipeline().ping().ping().execute() == [True, True]
    finally:
        r.close()
        srv.close()
        t.join(1)


# ---- allowlist self-test and fuzz --------------------------------------------------------------------------------


def test_allowlist_self_test_passes_and_detects_leaks(monkeypatch):
    from mcp_elasticache_ops import safe_client

    safe_client.assert_allowlist_is_readonly()
    monkeypatch.setattr(safe_client, "READ_ONLY_COMMANDS", READ_ONLY_COMMANDS | {"CONFIG SET"})
    with pytest.raises(ReadOnlyViolation):
        safe_client.assert_allowlist_is_readonly()
    monkeypatch.setattr(safe_client, "READ_ONLY_COMMANDS", READ_ONLY_COMMANDS | {"get stuff"})
    with pytest.raises(ReadOnlyViolation):
        safe_client.assert_allowlist_is_readonly()
    monkeypatch.setattr(safe_client, "READ_ONLY_COMMANDS", READ_ONLY_COMMANDS | {"PING PONG"})
    with pytest.raises(ReadOnlyViolation):
        safe_client.assert_allowlist_is_readonly()


_BAD_BASES = [
    ("CONFIG", "SET", "maxmemory", "1"),
    ("CLIENT", "KILL", "ID", "1"),
    ("SCRIPT", "FLUSH"),
    ("SCRIPT", "LOAD", "return 1"),
    ("DEBUG", "SLEEP", "1"),
    ("EVAL", "return 1", "0"),
    ("EVALSHA", "abc", "0"),
    ("FUNCTION", "LIST"),
    ("FUNCTION", "FLUSH"),
    ("ACL", "LIST"),
    ("ACL", "SETUSER", "x"),
    ("XREAD", "STREAMS", "s", "0"),
    ("SUBSCRIBE", "c"),
    ("PSUBSCRIBE", "*"),
    ("MONITOR",),
    ("SET", "k", "v"),
]


def _variants(base):
    name, *rest = base
    yield (name, *rest)
    yield (name.lower(), *rest)
    yield (name.title(), *rest)
    yield (name.encode(), *rest)
    yield (f" {name}", *rest)
    yield (f"{name} ", *rest)
    yield (f"{name}\t", *rest)
    yield (f"{name}\n", *rest)
    yield (f"{name}\x00", *rest)
    yield (f"{name}  ".replace(" ", " "), *rest)
    yield (name.replace("E", "Е").replace("S", "Ѕ"), *rest)  # cyrillic lookalikes
    yield (f"{name} {rest[0]}" if rest else name, *rest[1:])
    yield (f"{name}  {rest[0]}" if rest else name, *rest[1:])
    yield (name, *(x.lower() if isinstance(x, str) else x for x in rest))
    if rest and isinstance(rest[0], str):
        yield (name.encode(), rest[0].encode(), *rest[1:])


@pytest.mark.parametrize("base", _BAD_BASES, ids=lambda b: " ".join(b[:2]))
def test_fuzz_dangerous_commands_never_pass(base):
    for args in _variants(base):
        with pytest.raises(ReadOnlyViolation):
            check(args)


@pytest.mark.parametrize("key", sorted(READ_ONLY_COMMANDS))
def test_fuzz_allowlisted_commands_are_case_and_bytes_insensitive(key):
    name, _, sub = key.partition(" ")
    extra = ("maxmemory",) if key == "CONFIG GET" else ()
    for args in (
        (key, *extra),
        (key.lower(), *extra),
        (key.encode(), *extra),
        *([(name, sub, *extra), (name.lower().encode(), sub.lower().encode(), *extra)] if sub else []),
    ):
        check(args)


@pytest.mark.parametrize("key", sorted(READ_ONLY_COMMANDS))
def test_fuzz_allowlisted_commands_reject_whitespace_and_unicode_tricks(key):
    for bad in (
        f" {key}",
        f"{key} ",
        f"{key}\n",
        f"\t{key}",
        key.replace(" ", "  "),
        key.replace(" ", "\n"),
        key + "​",
        key.replace("I", "І"),
    ):
        if bad == key:
            continue
        with pytest.raises(ReadOnlyViolation):
            check((bad,))
