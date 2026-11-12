"""node_clients_summary: grouping, bounds, the redaction rule and the node_doctor hook."""

import json

import redis

from mcp_elasticache_ops import dataplane
from mcp_elasticache_ops.config import DEFAULT_MAX_OUTPUT_CHARS

from .fakes import FakeRedis


def _client(i, ip="10.0.0.1", **extra):
    base = {
        "id": str(i),
        "addr": f"{ip}:{40000 + i}",
        "name": "",
        "user": "default",
        "idle": "1",
        "flags": "N",
        "cmd": "get",
        "omem": "0",
        "qbuf": "0",
    }
    base.update(extra)
    return base


def _fake(clients, maxclients=10000):
    fake = FakeRedis(infos={"clients": {"connected_clients": len(clients), "maxclients": maxclients}})
    fake.clients = clients
    return fake


def test_groups_by_ip_name_user_and_flags():
    rows = [
        _client(1, "10.0.0.1", name="api", user="app", flags="b"),
        _client(2, "10.0.0.1", name="api", user="app", flags="P"),
        _client(3, "10.0.0.2", **{"lib-name": "redis-py"}, flags="x", multi="2"),
        _client(4, "10.0.0.2", flags="t"),
        _client(5, "10.0.0.3", sub="1", multi="-1"),
    ]
    out = dataplane.client_summary(_fake(rows))
    assert out["total"] == 5 and out["distinct_ips"] == 3
    assert out["top_ips"][0] == {"ip": "10.0.0.1", "count": 2, "idle_over_1h": 0}
    assert {"name": "api", "count": 2} in out["by_name"]
    assert {"name": "lib:redis-py", "count": 1} in out["by_name"]
    assert {"name": "(unnamed)", "count": 2} in out["by_name"]
    assert {"user": "app", "count": 2} in out["by_user"]
    assert out["by_flag"] == {"blocked": 1, "pubsub": 2, "multi": 1, "tracking": 1}


def test_ipv6_address_keeps_the_host_and_drops_the_port():
    out = dataplane.client_summary(_fake([_client(1, "[2001:db8::1]")]))
    assert out["top_ips"][0]["ip"] == "[2001:db8::1]"


def test_idle_clients_and_leaking_ip_are_reported():
    rows = [_client(i, "10.0.0.9", idle="7200") for i in range(25)] + [_client(99, "10.0.0.1")]
    out = dataplane.client_summary(_fake(rows))
    assert out["idle_over_1h"]["total"] == 25
    assert out["idle_over_1h"]["top_ips"][0] == {"ip": "10.0.0.9", "count": 25}
    assert out["top_ips"][0]["idle_over_1h"] == 25
    assert any(f["category"] == "idle-connections" for f in out["findings"])


def test_big_buffers_are_listed_largest_first_without_commands():
    rows = [
        _client(1, omem="50", cmd="SECRET-ARGS"),
        _client(2, qbuf=str(3 * 1024 * 1024)),
        _client(3, omem=str(64 * 1024 * 1024)),
    ]
    out = dataplane.client_summary(_fake(rows))
    assert [c["id"] for c in out["big_buffers"]["clients"]] == ["3", "2"]
    assert out["big_buffers"]["total"] == 2
    dumped = json.dumps(out)
    assert "SECRET-ARGS" not in dumped and "cmd" not in out["big_buffers"]["clients"][0]
    assert out["findings"][0]["severity"] == "warning"  # the 64 MiB output buffer


def test_near_maxclients_is_critical_above_the_critical_ratio():
    rows = [_client(i, "10.0.0.7") for i in range(98)] + [_client(200, "10.0.0.1")]
    warn = dataplane.client_summary(_fake(rows, maxclients=120))
    assert warn["used_pct"] == 82.5
    assert warn["findings"][0]["severity"] == "warning"
    assert "10.0.0.7" in warn["findings"][0]["message"]
    crit = dataplane.client_summary(_fake(rows, maxclients=100))
    assert crit["findings"][0]["severity"] == "critical"
    quiet = dataplane.client_summary(_fake(rows, maxclients=10000))
    assert not any(f["category"] == "near-maxclients" for f in quiet["findings"])
    custom = dataplane.client_summary(_fake(rows, maxclients=1000), near_pct=5)
    assert any(f["category"] == "near-maxclients" for f in custom["findings"])


def test_maxclients_falls_back_to_config_get_and_may_be_unknown():
    fake = FakeRedis(infos={"clients": {"connected_clients": 1}})
    fake.clients = [_client(1)]
    fake.config_get = lambda pattern: {"maxclients": "500"}
    assert dataplane.client_summary(fake)["maxclients"] == 500

    def refuse(pattern):
        raise redis.ResponseError("unknown command")

    fake.config_get = refuse
    out = dataplane.client_summary(fake)
    assert out["maxclients"] is None and out["used_pct"] is None


def test_empty_client_list():
    out = dataplane.client_summary(_fake([]))
    assert out["total"] == 0 and out["top_ips"] == [] and out["findings"] == []


def test_top_is_clamped_and_long_names_are_cut():
    rows = [_client(i, f"10.1.{i // 250}.{i % 250}", name="n" * 500) for i in range(300)]
    out = dataplane.client_summary(_fake(rows), top=10_000)
    assert len(out["top_ips"]) == dataplane.CLIENT_SUMMARY_MAX_TOP
    assert len(out["by_name"][0]["name"]) <= 64
    assert len(dataplane.client_summary(_fake(rows), top=0)["top_ips"]) == 1


def test_five_thousand_clients_stay_under_the_output_budget():
    rows = []
    for i in range(5000):
        rows.append(
            _client(
                i,
                f"10.{i % 40}.{i % 250}.{i % 200}",
                name=f"svc-{i % 700}",
                user=f"u{i % 90}",
                idle=str(i % 9000),
                omem=str((i % 50) * 1024 * 1024) if i % 17 == 0 else "0",
                flags="P" if i % 11 == 0 else "N",
            )
        )
    out = dataplane.client_summary(_fake(rows, maxclients=5200), top=50)
    size = len(json.dumps(out))
    assert out["total"] == 5000
    assert size < DEFAULT_MAX_OUTPUT_CHARS // 2, size
    assert len(out["top_ips"]) == 50 and len(out["big_buffers"]["clients"]) == 50
    assert out["findings"][0]["category"] == "near-maxclients"


def test_doctor_adds_client_findings_only_when_cheap():
    crowded = [_client(i, "10.0.0.7") for i in range(95)]
    fake = _fake(crowded, maxclients=100)
    fake.commands = {"MEMORY DOCTOR": b"Sam, I have no memory problems", "LATENCY DOCTOR": b"Dave, no latency spike"}
    out = dataplane.node_doctor(fake)
    assert any(f.get("category") == "near-maxclients" for f in out["findings"])
    big = _fake([_client(i, "10.0.0.7") for i in range(dataplane.CLIENT_DOCTOR_MAX + 1)], maxclients=100)
    big.commands = fake.commands
    calls: list[int] = []
    original = big.client_list
    big.client_list = lambda _type=None: calls.append(1) or original(_type)
    assert not any(f.get("category") == "near-maxclients" for f in dataplane.node_doctor(big)["findings"])
    assert calls == []  # too many connections: CLIENT LIST was never issued
