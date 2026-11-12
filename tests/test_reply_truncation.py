"""Huge replies from the server are cut by the safe_client guard and every data-plane consumer says so.

The fake replies are far larger than MAX_REPLY_ITEMS / MAX_REPLY_TEXT_CHARS. The consumers must stay bounded
and report ``truncated`` instead of silently dropping entries.

Mutation check (round 41): ``limit_reply`` was replaced by ``return reply`` (the guard disabled, safe_client restored
afterwards). Every test that depends on the guard then fails: the limit and pipeline tests, the client summary,
client list, commandlog, SCAN keyspace sample, SLOWLOG, MEMORY DOCTOR, INFO and server_info tests. Each consumer
test below sends its oversized reply through the same ``limit_reply``, so only the guard decides whether the
consumer sees a cut reply."""

from __future__ import annotations

import json

import pytest
from redis.client import Pipeline

from mcp_elasticache_ops.dataplane import _core as core
from mcp_elasticache_ops.dataplane import clients as clients_mod
from mcp_elasticache_ops.dataplane import doctor, health
from mcp_elasticache_ops.dataplane.keyspace import keyspace_sample
from mcp_elasticache_ops.safe_client import (
    MAX_REPLY_ITEMS,
    MAX_REPLY_TEXT_CHARS,
    SafeRedis,
    limit_reply,
    reply_truncation,
)

HUGE_ITEMS = MAX_REPLY_ITEMS * 5
HUGE_TEXT = "x" * (MAX_REPLY_TEXT_CHARS * 2)


def _client_row(i: int) -> dict:
    return {"id": str(i), "addr": f"10.0.{i // 250}.{i % 250}:6379", "name": "", "user": "default", "flags": "N"}


class HugeReplyRedis:
    """Stands in for the wire: every reply goes through the same ``limit_reply`` guard as SafeRedis."""

    def __init__(self, clients: list[dict]) -> None:
        self._clients = clients

    def info(self, *_):
        return {"maxclients": 50_000}

    def client_list(self, **_):
        return limit_reply(list(self._clients))

    def execute_command(self, *args, **_):
        if args[:2] == ("COMMANDLOG", "GET"):
            rows = [[i, 1_700_000_000, 5000 + i, ["SET", f"k{i}"], "10.0.0.1:1", ""] for i in range(HUGE_ITEMS)]
            return limit_reply(rows)
        if args[:2] == ("COMMANDLOG", "LEN"):
            return HUGE_ITEMS
        return limit_reply(["x"] * HUGE_ITEMS)


def test_limit_reply_bounds_lists_and_text_and_records_the_original_size():
    cut_list = limit_reply(list(range(HUGE_ITEMS)))
    cut_text = limit_reply(HUGE_TEXT)
    assert len(cut_list) == MAX_REPLY_ITEMS and reply_truncation(cut_list) == {"truncated": True, "total": HUGE_ITEMS}
    assert len(cut_text) == MAX_REPLY_TEXT_CHARS and reply_truncation(cut_text)["total"] == len(HUGE_TEXT)


def test_small_replies_pass_through_unmarked():
    small = [1, 2, 3]
    assert limit_reply(small) is small
    assert reply_truncation(limit_reply("ok")) is None


def test_safe_pipeline_results_are_guarded_too(monkeypatch):
    monkeypatch.setattr(Pipeline, "execute", lambda self, raise_on_error=True: [list(range(HUGE_ITEMS)), "ok"])
    pipe = SafeRedis(host="127.0.0.1", port=1).pipeline()
    first, second = pipe.execute()
    assert len(first) == MAX_REPLY_ITEMS and reply_truncation(first) is not None
    assert second == "ok" and reply_truncation(second) is None


def test_client_summary_reports_truncation_and_stays_bounded():
    clients = [_client_row(i) for i in range(HUGE_ITEMS)]
    out = clients_mod.client_summary(HugeReplyRedis(clients), clients=HugeReplyRedis(clients).client_list())
    assert out.get("truncated") is True
    assert len(json.dumps(out, default=str)) < 60_000


def test_commandlog_marks_each_cut_section_as_truncated():
    out = health.commandlog(
        HugeReplyRedis([]), count=128, info_server={"redis_version": "8.0.0", "valkey_version": "8.0.0"}
    )
    sections = [out[k] for k in ("slow", "large-request", "large-reply") if k in out]
    assert sections, "the fake answers every COMMANDLOG type"
    assert all(section.get("truncated") is True for section in sections)
    assert len(json.dumps(out, default=str)) < 60_000


@pytest.mark.parametrize("kind", ["slow"])
def test_commandlog_section_without_cut_has_no_truncated_flag(kind):
    small_rows = [[1, 1_700_000_000, 10, ["GET", "k"], "10.0.0.1:1", ""]]

    class Small(HugeReplyRedis):
        def execute_command(self, *args, **_):
            if args[:2] == ("COMMANDLOG", "GET"):
                return small_rows
            return 1

    out = health.commandlog(Small([]), count=5, info_server={"redis_version": "8.0.0", "valkey_version": "8.0.0"})
    assert "truncated" not in out[kind]


def test_limit_reply_caps_oversized_mappings_and_marks_them():
    big = {f"field{i}": i for i in range(HUGE_ITEMS)}
    cut = limit_reply(big)
    assert len(cut) == MAX_REPLY_ITEMS and reply_truncation(cut) == {"truncated": True, "total": HUGE_ITEMS}
    small = {"a": 1}
    assert limit_reply(small) is small and reply_truncation(small) is None


class ScanRedis:
    """Every SCAN batch is an oversized reply that already went through the guard."""

    def info(self, *_):
        return {"used_memory": 1024}

    def scan(self, cursor=0, match=None, count=None):
        return 0, limit_reply([f"key:{i}".encode() for i in range(HUGE_ITEMS)])

    def pipeline(self, *_, **__):
        return _Queue()

    def __getattr__(self, name):  # any other probe answers 0: the sample only needs the SCAN flag here
        if name.startswith("_"):
            raise AttributeError(name)
        return lambda *a, **k: 0


class _Queue:
    """A pipeline that answers 0 to every queued command."""

    def __init__(self):
        self.queued = 0

    def __getattr__(self, name):
        def queue(*_, **__):
            self.queued += 1
            return self

        return queue

    def execute(self, *_, **__):
        return [0] * self.queued


def test_scan_cut_batch_marks_the_keyspace_sample_truncated():
    out = keyspace_sample(ScanRedis(), sample_size=5, max_seconds=60)
    assert out.get("truncated") is True
    assert len(json.dumps(out, default=str)) < 60_000


def test_client_list_cut_reply_is_flagged_by_the_client_list_consumer():
    clients = [_client_row(i) for i in range(HUGE_ITEMS)]
    out = health.client_list(HugeReplyRedis(clients))
    assert out.get("truncated") is True
    assert len(json.dumps(out, default=str)) < 60_000


class SlowlogRedis(HugeReplyRedis):
    def slowlog_get(self, count=None):
        return limit_reply(
            [
                {"id": i, "start_time": 1_700_000_000, "duration": 5000, "command": ["GET", f"k{i}"]}
                for i in range(HUGE_ITEMS)
            ]
        )

    def slowlog_len(self):
        return HUGE_ITEMS


def test_slowlog_cut_reply_is_flagged_and_bounded():
    out = health.slowlog(SlowlogRedis([]), count=128)
    assert out.get("truncated") is True
    assert out["returned"] == MAX_REPLY_ITEMS  # the guard bounds the entries; the flag says they are not all there


class DoctorRedis(HugeReplyRedis):
    def execute_command(self, *args, **_):
        if args[:2] == ("MEMORY", "DOCTOR"):
            return limit_reply("Sam, I have a problem: " + HUGE_TEXT)
        return super().execute_command(*args)


def test_memory_doctor_cut_reply_says_it_was_cut_not_just_trimmed():
    text, err = doctor._doctor_text(DoctorRedis([]), "MEMORY", "DOCTOR")
    assert err is None
    assert "reply cut at" in text and "by the read-only client guard" in text
    assert len(text) < MAX_REPLY_TEXT_CHARS


class InfoRedis(HugeReplyRedis):
    def info(self, *_):
        return limit_reply({f"metric_{i}": i for i in range(HUGE_ITEMS)})


def test_info_cut_reply_is_noted_by_the_health_consumer():
    info, notes = health._info_all(InfoRedis([]), serverless=False)
    assert len(info) == MAX_REPLY_ITEMS
    assert any("INFO reply cut at" in n for n in notes)


def test_server_info_cut_reply_is_flagged_and_bounded():
    out = core.server_info(InfoRedis([]))
    assert out.get("truncated") is True and out["total"] == HUGE_ITEMS
    assert len(out["info"]) == MAX_REPLY_ITEMS
