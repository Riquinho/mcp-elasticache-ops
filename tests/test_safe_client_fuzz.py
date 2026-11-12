"""Property tests for the SafeRedis allowlist: nothing outside READ_ONLY_COMMANDS reaches the connection.

``hypothesis`` is a dev dependency only. Every test runs (0 skipped); the model of "reached the connection" is the
parent ``redis.Redis`` / ``Pipeline`` method that SafeRedis calls after ``check`` passes.
"""

from __future__ import annotations

import contextlib
from unittest import mock

import redis
from hypothesis import given, settings
from hypothesis import strategies as st
from redis.client import Pipeline

from mcp_elasticache_ops.safe_client import (
    FORBIDDEN_COMMANDS,
    MAX_COMMANDLOG_COUNT,
    MAX_HISTOGRAM_COMMANDS,
    MAX_HISTOGRAM_NAME_LEN,
    READ_ONLY_COMMANDS,
    ReadOnlyViolation,
    SafeRedis,
    check,
    command_key,
)

SETTINGS = settings(max_examples=200, deadline=None)

ALLOWED_KEYS = sorted(READ_ONLY_COMMANDS)
BLANKS = st.text(alphabet=" \t\r\n\x00", max_size=3)
TOKEN = st.one_of(
    st.text(max_size=12),
    st.binary(max_size=12),
    st.integers(min_value=-(10**12), max_value=10**12),
    st.floats(allow_nan=True, allow_infinity=True),
    st.none(),
    st.booleans(),
)


def _case(word: str, flips: list[bool]) -> str:
    return "".join(c.upper() if flips[i % len(flips)] else c.lower() for i, c in enumerate(word))


@st.composite
def commands(draw) -> tuple:
    """A command shaped like an allowlisted one (random case, str or bytes, blanks, extra args) or pure noise."""
    if not draw(st.booleans()):
        return tuple(draw(st.lists(TOKEN, max_size=6)))
    key = draw(st.sampled_from(ALLOWED_KEYS + sorted(FORBIDDEN_COMMANDS)))
    flips = draw(st.lists(st.booleans(), min_size=1, max_size=4))
    words = [_case(w, flips) for w in key.split(" ")]
    if draw(st.booleans()):  # "CLUSTER INFO" in one token
        words = [" ".join(words)]
    if draw(st.booleans()):
        words[0] = draw(BLANKS) + words[0]
    as_bytes = draw(st.booleans())
    head = [w.encode() if as_bytes else w for w in words]
    return (*head, *draw(st.lists(TOKEN, max_size=5)))


def _passes(args: tuple) -> bool:
    try:
        check(args)
    except ReadOnlyViolation:
        return False
    return True


@SETTINGS
@given(commands())
def test_check_only_passes_allowlisted_commands(args):
    if _passes(args):
        assert command_key(args) in READ_ONLY_COMMANDS
        assert command_key(args) not in FORBIDDEN_COMMANDS


@SETTINGS
@given(commands())
def test_execute_command_forwards_only_allowlisted_commands(args):
    client = SafeRedis(host="127.0.0.1", port=1)
    sent: list[tuple] = []
    try:
        patched = mock.patch.object(redis.Redis, "execute_command", lambda self, *a, **kw: sent.append(a))
        with patched, contextlib.suppress(ReadOnlyViolation):
            client.execute_command(*args)
    finally:
        client.close()
    if sent:
        assert command_key(sent[0]) in READ_ONLY_COMMANDS
    assert bool(sent) == _passes(args)


@SETTINGS
@given(st.lists(commands(), min_size=1, max_size=4))
def test_pipeline_queues_only_allowlisted_commands(batch):
    client = SafeRedis(host="127.0.0.1", port=1)
    queued: list[tuple] = []
    try:
        with mock.patch.object(Pipeline, "pipeline_execute_command", lambda self, *a, **kw: queued.append(a)):
            pipe = client.pipeline()
            for args in batch:
                with contextlib.suppress(ReadOnlyViolation):
                    pipe.execute_command(*args)
    finally:
        client.close()
    assert all(command_key(a) in READ_ONLY_COMMANDS for a in queued)
    assert len(queued) == sum(_passes(a) for a in batch)


@SETTINGS
@given(st.lists(commands(), min_size=1, max_size=4))
def test_pipeline_execute_rechecks_a_tampered_stack(batch):
    client = SafeRedis(host="127.0.0.1", port=1)
    try:
        pipe = client.pipeline()
        pipe.command_stack.extend((a, {}) for a in batch)  # bypass queueing: execute() must still refuse
        if all(_passes(a) for a in batch):
            return  # nothing to refuse; running it would need a live server
        try:
            pipe.execute()
        except ReadOnlyViolation:
            return
        raise AssertionError("a disallowed command in the stack was not refused")
    finally:
        client.close()


# --------------------------------------------------------------------------- bounded commands


@SETTINGS
@given(st.integers().filter(lambda n: not 1 <= n <= MAX_COMMANDLOG_COUNT), st.sampled_from(["slow", "large-request"]))
def test_commandlog_get_rejects_counts_out_of_range(count, kind):
    assert not _passes(("COMMANDLOG", "GET", count, kind))


@SETTINGS
@given(st.integers(1, MAX_COMMANDLOG_COUNT), st.sampled_from(["slow", "LARGE-REQUEST", "Large-Reply"]))
def test_commandlog_get_accepts_in_range(count, kind):
    assert _passes(("commandlog", "get", count, kind))


@SETTINGS
@given(st.text(max_size=20).filter(lambda t: t.lower() not in ("slow", "large-request", "large-reply")))
def test_commandlog_rejects_unknown_types(kind):
    assert not _passes(("COMMANDLOG", "GET", 10, kind))
    assert not _passes(("COMMANDLOG", "LEN", kind))


@SETTINGS
@given(st.sampled_from(["RESET", "HELP", "reset", "Help"]), st.lists(TOKEN, max_size=3))
def test_commandlog_never_allows_reset_or_help(sub, rest):
    assert not _passes(("COMMANDLOG", sub, *rest))


@SETTINGS
@given(
    st.lists(st.sampled_from(["get", "set", "config|get", "client"]), min_size=MAX_HISTOGRAM_COMMANDS + 1, max_size=40)
)
def test_histogram_rejects_too_many_names(names):
    assert not _passes(("LATENCY", "HISTOGRAM", *names))


@SETTINGS
@given(st.text(min_size=1, max_size=80).filter(lambda t: not t.isalnum() or len(t) > MAX_HISTOGRAM_NAME_LEN))
def test_histogram_rejects_names_that_are_not_plain_words(name):
    plain = name.isascii() and name[0].isalpha() and name.replace("_", "").isalnum()
    if plain and len(name) <= MAX_HISTOGRAM_NAME_LEN:
        return
    assert not _passes(("LATENCY", "HISTOGRAM", name))


@SETTINGS
@given(st.lists(TOKEN, min_size=1, max_size=4))
def test_cluster_links_takes_no_arguments(extra):
    assert not _passes(("CLUSTER", "LINKS", *extra))


@SETTINGS
@given(st.text(min_size=1, max_size=40), st.text(alphabet="*?[]\\", min_size=1, max_size=4))
def test_config_get_rejects_unlisted_or_wildcard_parameters(name, wild):
    assert not _passes(("CONFIG", "GET", name + wild))


@SETTINGS
@given(st.lists(TOKEN, max_size=4))
def test_forbidden_commands_never_pass_with_any_arguments(rest):
    for key in sorted(FORBIDDEN_COMMANDS):
        assert not _passes((*key.split(" "), *rest)), key
        assert not _passes((key, *rest)), key
