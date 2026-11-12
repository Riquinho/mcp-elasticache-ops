"""In-memory stand-ins for redis-py so dataplane logic is unit-testable without a server."""

from __future__ import annotations

import time
from typing import Any

import redis


class FakePipeline:
    def __init__(self, client: FakeRedis) -> None:
        self.client = client
        self.cmds: list[tuple] = []

    def type(self, k):
        self.cmds.append(("TYPE", k))
        return self

    def memory_usage(self, k, samples=None):
        self.cmds.append(("MEMORY USAGE", k))
        return self

    def pttl(self, k):
        self.cmds.append(("PTTL", k))
        return self

    def object(self, sub, k):
        self.cmds.append(("OBJECT", sub, k))
        return self

    def execute_command(self, *args):
        self.cmds.append(args)
        return self

    def execute(self, raise_on_error=True):
        self.client.pipeline_runs += 1
        if self.client.pipeline_delay:
            time.sleep(self.client.pipeline_delay)
        out = [self.client.run(c) for c in self.cmds]
        self.cmds = []
        return out


class FakeRedis:
    """Just enough of redis.Redis for dataplane.py. ``data`` maps key -> (type, bytes, pttl, length)."""

    def __init__(
        self,
        infos: dict[str, dict] | None = None,
        data: dict[str, tuple] | None = None,
        scan_batch: int = 10,
        scan_delay: float = 0.0,
        pipeline_delay: float = 0.0,
    ) -> None:
        self.infos = infos or {}
        self.data = data or {}
        self.scan_batch = scan_batch
        self.scan_delay = scan_delay
        self.pipeline_delay = pipeline_delay
        self.pipeline_runs = 0
        self.scan_calls = 0
        self.slowlog_entries: list[dict] = []
        self.clients: list[dict] = []
        self.commands: dict[str, Any] = {}
        self.closed = False

    def info(self, section: str | None = None) -> dict:
        if section is None:
            merged: dict = {}
            for v in self.infos.values():
                merged.update(v)
            return merged
        if section not in self.infos and section != "cluster":
            raise redis.ResponseError(f"unknown section {section}")
        return self.infos.get(section, {"cluster_enabled": 0})

    def dbsize(self) -> int:
        return len(self.data)

    def ping(self):
        return True

    def close(self):
        self.closed = True

    def scan(self, cursor=0, match=None, count=10):
        self.scan_calls += 1
        if self.scan_delay:
            time.sleep(self.scan_delay)
        keys = sorted(self.data)
        nxt = cursor + self.scan_batch
        return (0 if nxt >= len(keys) else nxt), keys[cursor:nxt]

    def pipeline(self):
        return FakePipeline(self)

    def run(self, cmd: tuple):
        name = cmd[0]
        if name == "OBJECT":
            return 5
        key = cmd[-1] if name in {"TYPE", "MEMORY USAGE", "PTTL"} else cmd[1]
        typ, size, pttl, length = self.data[key]
        return {"TYPE": typ, "MEMORY USAGE": size, "PTTL": pttl}.get(name, length)

    def slowlog_get(self, count):
        return self.slowlog_entries[:count]

    def slowlog_len(self):
        return len(self.slowlog_entries)

    def client_list(self):
        return self.clients

    def memory_stats(self):
        return {"peak.allocated": 1}

    def latency_latest(self):
        return [["command", 1700000000, 12, 40]]

    def config_get(self, pattern):
        return {"latency-monitor-threshold": "100"}

    def execute_command(self, *args):
        key = " ".join(str(a) for a in args)
        if key not in self.commands:
            raise redis.ResponseError(f"unknown command {key}")
        value = self.commands[key]
        if isinstance(value, Exception):
            raise value
        return value
