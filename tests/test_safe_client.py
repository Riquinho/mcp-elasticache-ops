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
    ("ACL", "DELUSER", "x"),
    ("ACL", "GETUSER", "x"),
    ("ACL", "LOG", "RESET"),
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
    extra = (
        ("maxmemory",)
        if key == "CONFIG GET"
        else ("get",)
        if key == "COMMAND DOCS"
        else ("5",)
        if key == "CLUSTER COUNTKEYSINSLOT"
        else ()
    )
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


# ------------------------------------------------------------------ round 03: argument guards

_OK_ARGS = [
    ("MEMORY", "USAGE", "k"),
    ("MEMORY", "USAGE", "k", "SAMPLES", "5"),
    ("memory", "usage", "k", "samples", "1"),
    ("SCAN", "0"),
    ("SCAN", "0", "MATCH", "user:*", "COUNT", "100", "TYPE", "string"),
    ("scan", "17", "count", "10"),
    ("CLIENT", "LIST"),
    ("CLIENT", "LIST", "TYPE", "pubsub"),
    ("CLIENT", "LIST", "ID", "1", "2", "3"),
    ("OBJECT", "ENCODING", "k"),
    ("OBJECT", "FREQ", "k"),
    ("OBJECT", "IDLETIME", "k"),
    ("ACL", "WHOAMI"),
    ("ACL", "LOG"),
    ("ACL", "LOG", "10"),
    ("ACL", "USERS"),
    ("acl", "log", "0"),
]


@pytest.mark.parametrize("args", _OK_ARGS, ids=lambda a: " ".join(a))
def test_dataplane_allowed_forms(args):
    check(args)


_BAD_ARGS = [
    ("MEMORY", "USAGE", "k", "SAMPLES"),  # missing count
    ("MEMORY", "USAGE", "k", "SAMPLES", "x"),
    ("MEMORY", "USAGE", "k", "FOO", "5"),
    ("MEMORY", "USAGE", "k", "SAMPLES", "5", "extra"),
    ("MEMORY", "USAGE", "k", "SAMPLES", "-1"),
    ("MEMORY", "USAGE", "k", "SAMPLES", "0"),
    ("MEMORY", "USAGE", "k", "SAMPLES", "101"),
    ("SCAN", "0", "MATCH"),
    ("SCAN", "0", "COUNT", "x"),
    ("SCAN", "0", "TYPE", "string", "DELETE", "1"),
    ("SCAN", "0", "NOVALUES", "x"),
    ("SCAN", "abc"),
    ("CLIENT", "LIST", "TYPE", "admin"),
    ("CLIENT", "LIST", "ID", "x"),
    ("CLIENT", "LIST", "KILL", "1"),
    ("OBJECT", "ENCODING", "k", "extra"),
    ("OBJECT", "HELP"),
    ("OBJECT", "FREQ", "k", "l"),
    ("ACL", "LOG", "RESET"),
    ("acl", "log", "reset"),
    ("ACL", "LOG", "10", "RESET"),
    ("ACL", "LOG", "10", "20"),
    ("ACL", "LOG", "-1"),
    ("ACL", "WHOAMI", "extra"),
    ("ACL", "SETUSER", "x", "on"),
    ("ACL", "DELUSER", "x"),
    ("ACL", "GETUSER", "x"),
    ("ACL", "LIST"),
    ("ACL", "CAT"),
    ("ACL", "GENPASS"),
    ("ACL", "SAVE"),
    ("ACL", "LOAD"),
    ("ACL",),
    ("ACL  LOG",),
    ("ACL LOG RESET",),
    ("ACL LOG\n10",),
    (b"ACL", b"LOG", b"RESET"),
    (b"ACL", b"DELUSER", b"default"),
]


@pytest.mark.parametrize("args", _BAD_ARGS, ids=lambda a: repr(a))
def test_dataplane_refused_forms(args):
    with pytest.raises(ReadOnlyViolation):
        check(args)


def test_acl_destructive_forms_are_forbidden_and_not_allowlisted():
    from mcp_elasticache_ops.safe_client import FORBIDDEN_COMMANDS

    for cmd in ("ACL SETUSER", "ACL DELUSER", "ACL LOG RESET", "ACL GETUSER", "ACL LIST"):
        assert cmd in FORBIDDEN_COMMANDS and cmd not in READ_ONLY_COMMANDS
    assert {"ACL LOG", "ACL WHOAMI"} <= READ_ONLY_COMMANDS


def test_pipeline_refuses_commands_outside_the_allowlist():
    r = SafeRedis(host="127.0.0.1", port=1, socket_connect_timeout=0.2)
    pipe = r.pipeline()
    pipe.type("k")  # allowed: queued, never sent
    for bad in (
        lambda: pipe.set("k", "v"),
        lambda: pipe.delete("k"),
        lambda: pipe.get("k"),
        lambda: pipe.execute_command("FLUSHALL"),
        lambda: pipe.execute_command("ACL", "LOG", "RESET"),
        lambda: pipe.execute_command("SCAN", "0", "DEL", "x"),
    ):
        with pytest.raises(ReadOnlyViolation):
            bad()
    # even a command stacked behind the guard's back is refused before any connection is opened
    pipe.command_stack.append((("SET", "k", "v"), {}))
    with pytest.raises(ReadOnlyViolation):
        pipe.execute()


def test_pipeline_allows_the_sampling_commands():
    r = SafeRedis(host="127.0.0.1", port=1, socket_connect_timeout=0.2)
    pipe = r.pipeline()
    pipe.type("k")
    pipe.memory_usage("k", samples=5)
    pipe.pttl("k")
    pipe.object("FREQ", "k")
    pipe.execute_command("OBJECT", "IDLETIME", "k")
    assert len(pipe.command_stack) == 5


_BOUNDARIES = [
    (("SCAN", "0", "COUNT", "1000"), ("SCAN", "0", "COUNT", "1001")),
    (("MEMORY", "USAGE", "k", "SAMPLES", "100"), ("MEMORY", "USAGE", "k", "SAMPLES", "101")),
    (("MEMORY", "USAGE", "k", "SAMPLES", "1"), ("MEMORY", "USAGE", "k", "SAMPLES", "0")),
    (("CLIENT", "LIST", "ID", *map(str, range(100))), ("CLIENT", "LIST", "ID", *map(str, range(101)))),
    (("ACL", "LOG", "128"), ("ACL", "LOG", "129")),
    (("COMMAND", "DOCS", "get"), ("COMMAND", "DOCS")),
]


@pytest.mark.parametrize("ok,bad", _BOUNDARIES, ids=lambda a: " ".join(a[:5]))
def test_bounds_accept_at_limit_reject_beyond(ok, bad):
    check(ok)
    with pytest.raises(ReadOnlyViolation):
        check(bad)


def test_bounds_apply_to_int_arguments_too():
    check(("SCAN", 0, "COUNT", 1000))
    with pytest.raises(ReadOnlyViolation):
        check(("SCAN", 0, "COUNT", 1001))


@pytest.mark.parametrize("section", ["errorstats", "latencystats", "commandstats", "ERRORSTATS", "LATENCYSTATS"])
def test_info_errorstats_and_latencystats_sections_are_allowed(section):
    check(("INFO", section))
    check((b"INFO", section.encode()))
    assert command_key(("INFO", section)) == "INFO"


# ------------------------------------------------------------------ round 11: PUBSUB introspection


@pytest.mark.parametrize(
    "args",
    [
        ("PUBSUB CHANNELS",),
        ("PUBSUB", "CHANNELS", "news.*"),
        ("PUBSUB SHARDCHANNELS", "orders:*"),
        ("PUBSUB NUMSUB",),
        ("PUBSUB NUMSUB", "a", "b"),
        ("PUBSUB", "numpat"),
    ],
)
def test_pubsub_introspection_is_allowed(args):
    check(args)


@pytest.mark.parametrize(
    "args",
    [
        ("PUBSUB",),
        ("PUBSUB HELP",),
        ("PUBSUB SHARDNUMSUB", "a"),
        ("PUBSUB CHANNELS", "a*", "b*"),
        ("PUBSUB CHANNELS", "x" * 129),
        ("PUBSUB NUMSUB", *[f"c{i}" for i in range(101)]),
        ("PUBSUB NUMSUB", "x" * 129),
        ("PUBSUB NUMPAT", "extra"),
        ("PUBLISH", "chan", "msg"),
        ("SUBSCRIBE", "chan"),
        ("PSUBSCRIBE", "chan*"),
    ],
)
def test_pubsub_unbounded_or_writing_forms_are_blocked(args):
    with pytest.raises(ReadOnlyViolation):
        check(args)


def test_pubsub_numsub_accepts_exactly_the_bound():
    check(("PUBSUB NUMSUB", *[f"c{i}" for i in range(100)]))
