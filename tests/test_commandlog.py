"""COMMANDLOG, LATENCY HISTOGRAM and CLUSTER LINKS: bounded allowlist entries and findings-first output."""

from __future__ import annotations

import json

import pytest

from mcp_elasticache_ops import dataplane
from mcp_elasticache_ops.dataplane import topology
from mcp_elasticache_ops.safe_client import READ_ONLY_COMMANDS, ReadOnlyViolation, check
from tests.fakes import FakeRedis

VALKEY8 = {"server": {"valkey_version": "8.0.1", "redis_version": "7.2.4"}}
REDIS7 = {"server": {"redis_version": "7.1.0"}}
MIB = 1024 * 1024
SEVERITIES = ["critical", "warning", "info"]


def _entry(i: int, value: int, cmd: str = "SET", addr: str = "10.1.1.1:5000") -> list:
    return [i, 1700000000 + i, value, [cmd, "secret-key", "secret-value"], addr, "app"]


def _log_client(slow=(), request=(), reply=(), infos=None, count: int = 10) -> FakeRedis:
    r = FakeRedis(infos=infos or VALKEY8)
    for kind, rows in (("slow", slow), ("large-request", request), ("large-reply", reply)):
        r.commands[f"COMMANDLOG GET {count} {kind}"] = list(rows)
        r.commands[f"COMMANDLOG LEN {kind}"] = len(rows)
    return r


# --------------------------------------------------------------------------- allowlist bounds


def test_new_commands_are_allowlisted():
    assert {"COMMANDLOG GET", "COMMANDLOG LEN", "LATENCY HISTOGRAM", "CLUSTER LINKS"} <= READ_ONLY_COMMANDS


@pytest.mark.parametrize(
    "args",
    [
        ("COMMANDLOG", "GET", 10, "slow"),
        ("commandlog", "get", "128", "LARGE-REPLY"),
        (b"COMMANDLOG", b"LEN", b"large-request"),
        ("LATENCY", "HISTOGRAM", "set"),
        ("LATENCY", "HISTOGRAM", *["get"] * 16),
        ("LATENCY", "HISTOGRAM", "config|get"),
        ("CLUSTER", "LINKS"),
    ],
)
def test_bounded_forms_pass(args):
    check(args)


@pytest.mark.parametrize(
    "args",
    [
        ("COMMANDLOG", "RESET", "slow"),
        ("COMMANDLOG", "HELP"),
        ("COMMANDLOG",),
        ("COMMANDLOG", "GET"),
        ("COMMANDLOG", "GET", 10),
        ("COMMANDLOG", "GET", 0, "slow"),
        ("COMMANDLOG", "GET", 129, "slow"),
        ("COMMANDLOG", "GET", "ten", "slow"),
        ("COMMANDLOG", "GET", 10, "everything"),
        ("COMMANDLOG", "LEN"),
        ("COMMANDLOG", "LEN", "nope"),
        ("COMMANDLOG", "LEN", "slow", "extra"),
        ("LATENCY", "HISTOGRAM"),
        ("LATENCY", "HISTOGRAM", *["get"] * 17),
        ("LATENCY", "HISTOGRAM", "get set"),
        ("LATENCY", "HISTOGRAM", "a|b|c"),
        ("LATENCY", "HISTOGRAM", "x" * 49),
        ("LATENCY", "HISTOGRAM", "*"),
        ("CLUSTER", "LINKS", "extra"),
    ],
)
def test_unbounded_or_mutating_forms_are_refused(args):
    with pytest.raises(ReadOnlyViolation):
        check(args)


# --------------------------------------------------------------------------- commandlog


def test_commandlog_findings_first_and_no_arguments_leak():
    r = _log_client(
        request=[_entry(1, 20 * MIB, "SET"), _entry(2, 2 * MIB, "HSET")],
        reply=[_entry(3, 3 * MIB, "HGETALL")],
    )
    out = dataplane.commandlog(r, 10)
    assert out["supported"] is True
    assert out["findings"][0]["severity"] == "critical"
    ranks = [SEVERITIES.index(f["severity"]) for f in out["findings"]]
    assert ranks == sorted(ranks)
    blob = json.dumps(out)
    assert "secret-key" not in blob and "secret-value" not in blob
    assert out["large-request"]["top_commands"][0] == {"command": "SET", "max_size_bytes": 20 * MIB, "entries": 1}


def test_commandlog_slow_entry_is_info_below_100ms_and_warning_above():
    fast = dataplane.commandlog(_log_client(slow=[_entry(1, 5_000)]), 10)
    slow = dataplane.commandlog(_log_client(slow=[_entry(1, 250_000)]), 10)
    assert fast["findings"][0]["severity"] == "info"
    assert slow["findings"][0]["severity"] == "warning"


def test_commandlog_empty_has_no_findings():
    out = dataplane.commandlog(_log_client(), 10)
    assert out["supported"] is True and out["findings"] == []


@pytest.mark.parametrize("infos", [REDIS7, {"server": {"valkey_version": "7.2.5"}}])
def test_commandlog_on_redis_or_old_valkey_is_a_note_not_an_error(infos):
    out = dataplane.commandlog(FakeRedis(infos=infos), 10)
    assert out["supported"] is False and out["findings"] == []
    assert "COMMANDLOG" in out["notes"][0] and "8.0" in out["notes"][0]


def test_commandlog_refused_by_the_server_is_a_note():
    out = dataplane.commandlog(FakeRedis(infos=VALKEY8), 10)  # every COMMANDLOG call raises ResponseError
    assert out["supported"] is False and out["notes"]


def test_commandlog_count_is_clamped():
    r = _log_client(count=128)
    out = dataplane.commandlog(r, 10_000)
    assert out["supported"] is True


def test_node_doctor_reports_commandlog_section():
    r = _log_client(request=[_entry(1, 20 * MIB)], infos={**VALKEY8, "commandstats": {}}, count=5)
    r.commands["MEMORY DOCTOR"] = "Sam, I have no memory problems"
    r.commands["LATENCY DOCTOR"] = "Dave, no latency spike was observed"
    out = dataplane.node_doctor(r)
    assert out["commandlog"]["status"] == "findings"
    assert any(f.get("source") == "commandlog" for f in out["findings"])


# --------------------------------------------------------------------------- latency histogram


def _hist(calls: int, p50_bucket: int, tail_bucket: int) -> dict:
    # cumulative buckets: nearly all calls land at p50_bucket, the last 0.2% in tail_bucket
    fast = calls - max(1, calls // 500)
    return {"calls": calls, "histogram_usec": {p50_bucket: fast, tail_bucket: calls}}


def _hist_client(histograms: dict[str, dict], infos=None) -> FakeRedis:
    stats = {f"cmdstat_{n}": {"calls": h["calls"], "usec": h["calls"] * 10} for n, h in histograms.items()}
    r = FakeRedis(infos={"commandstats": stats, **(infos or REDIS7)})
    key = "LATENCY HISTOGRAM " + " ".join(sorted(histograms, key=lambda n: -histograms[n]["calls"]))
    r.commands[key] = histograms
    return r


def test_histogram_tail_finding_when_p99_9_is_100x_p50():
    out = dataplane.command_tail(_hist_client({"get": _hist(10_000, 2, 8192)}))
    row = out["rows"][0]
    assert row["command"] == "get" and row["p50_usec"] == 2 and row["p99_9_usec"] == 8192
    assert out["findings"][0]["severity"] == "warning" and "GET" in out["findings"][0]["message"]


def test_histogram_flat_distribution_has_no_finding():
    out = dataplane.command_tail(_hist_client({"get": _hist(10_000, 4, 8)}))
    assert out["findings"] == [] and out["rows"][0]["tail_ratio"] == 2.0


def test_histogram_ignores_commands_with_few_calls():
    out = dataplane.command_tail(_hist_client({"get": _hist(50, 2, 8192)}))
    assert out["rows"] == [] and out["findings"] == []


def test_histogram_few_expensive_calls_do_not_crowd_out_busy_commands():
    stats = {f"cmdstat_slow{i}": {"calls": 2, "usec": 10_000_000} for i in range(10)}
    stats["cmdstat_get"] = {"calls": 10_000, "usec": 100}
    r = FakeRedis(infos={"commandstats": stats, **REDIS7})
    r.commands["LATENCY HISTOGRAM get"] = {"get": _hist(10_000, 2, 8192)}
    out = dataplane.command_tail(r)
    assert [row["command"] for row in out["rows"]] == ["get"]


def test_histogram_on_old_engine_is_a_note():
    infos = {"commandstats": {"cmdstat_get": {"calls": 500, "usec": 900}}, "server": {"redis_version": "6.2.6"}}
    out = dataplane.command_tail(FakeRedis(infos=infos))
    assert out["rows"] == [] and "LATENCY HISTOGRAM" in out["notes"][0] and "7.0" in out["notes"][0]


def test_node_latency_carries_command_tail():
    out = dataplane.latency(_hist_client({"get": _hist(10_000, 2, 8192)}), 2)
    assert out["command_tail"][0]["command"] == "get"
    assert out["findings"] and "p99.9" in out["findings"][0]["message"]


def test_histogram_resp2_flat_reply_is_parsed():
    reply = ["get", ["calls", 1000, "histogram_usec", [2, 990, 8192, 1000]]]
    r = FakeRedis(infos={"commandstats": {"cmdstat_get": {"calls": 1000, "usec": 5}}, **REDIS7})
    r.commands["LATENCY HISTOGRAM get"] = reply
    row = dataplane.command_tail(r)["rows"][0]
    assert row["p50_usec"] == 2 and row["p99_9_usec"] == 8192


# --------------------------------------------------------------------------- cluster links


def _links(*rows: tuple[str, str, int]) -> list:
    return [
        {"direction": d, "node": n, "create-time": 1, "events": "rw", "send-buffer-allocated": b, "send-buffer-used": 0}
        for n, d, b in rows
    ]


def test_cluster_links_large_send_buffer_warns_and_escalates():
    r = FakeRedis(infos=VALKEY8)
    r.commands["CLUSTER LINKS"] = _links(("a" * 40, "to", 20 * MIB), ("b" * 40, "from", 0))
    out = topology.cluster_links(r)
    assert out["supported"] and out["links"] == 2 and out["findings"][0]["severity"] == "warning"
    r.commands["CLUSTER LINKS"] = _links(("a" * 40, "to", 200 * MIB))
    assert topology.cluster_links(r)["findings"][0]["severity"] == "critical"


def test_cluster_links_small_buffers_are_quiet():
    r = FakeRedis(infos=VALKEY8)
    r.commands["CLUSTER LINKS"] = _links(("a" * 40, "to", 1024))
    assert topology.cluster_links(r)["findings"] == []


def test_cluster_links_resp2_flat_entries():
    r = FakeRedis(infos=VALKEY8)
    r.commands["CLUSTER LINKS"] = [["direction", "to", "node", "c" * 40, "send-buffer-allocated", 40 * MIB]]
    assert topology.cluster_links(r)["max_send_buffer_bytes"] == 40 * MIB


def test_cluster_links_on_redis6_is_a_note():
    r = FakeRedis(infos={"server": {"redis_version": "6.2.6"}})
    out = topology.cluster_links(r)
    assert out["supported"] is False and "7.0" in out["notes"][0] and out["findings"] == []


def test_missing_link_finding_names_the_peers():
    links = {"supported": True, "peers": ["a" * 40]}
    found = topology.missing_link_findings(links, {"a" * 40, "b" * 40}, "node x")
    assert len(found) == 1 and "bbbbbbbbbbbb" in found[0]["message"]
    assert topology.missing_link_findings(links, {"a" * 40}, "node x") == []
    assert topology.missing_link_findings({"supported": False}, {"b" * 40}, "node x") == []
