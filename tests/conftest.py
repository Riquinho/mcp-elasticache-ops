"""Shared fixtures.

Integration tests need a throwaway Redis/Valkey reachable at REDIS_TEST_URL
(see scripts/integration.sh). The fixture FLUSHES that database, so never
point it at anything you care about.
"""

from __future__ import annotations

import os

import pytest
import redis

from mcp_elasticache_ops.safe_client import SafeRedis

REDIS_TEST_URL = os.getenv("REDIS_TEST_URL")


@pytest.fixture(scope="session")
def redis_url() -> str:
    if not REDIS_TEST_URL:
        pytest.skip("REDIS_TEST_URL not set (run scripts/integration.sh)")
    return REDIS_TEST_URL


@pytest.fixture(scope="session")
def seeded(redis_url: str):
    admin = redis.Redis.from_url(redis_url, decode_responses=True)
    admin.flushdb()
    admin.config_set("slowlog-log-slower-than", "0")
    admin.config_set("latency-monitor-threshold", "1")
    admin.slowlog_reset()
    pipe = admin.pipeline(transaction=False)
    for i in range(300):
        pipe.set(f"small:{i}", "x" * 10)
    for i in range(20):
        pipe.set(f"session:{i}", "s", ex=3600)
    pipe.rpush("big:list", *[f"item-{i}" for i in range(5000)])
    pipe.hset("big:hash", mapping={f"f{i}": "v" * 50 for i in range(2000)})
    pipe.sadd("some:set", *range(100))
    pipe.zadd("some:zset", {f"m{i}": i for i in range(150)})
    pipe.set("big:string", "y" * 200_000)
    pipe.execute()
    admin.client_setname("seed-client")
    admin.get("big:string")
    yield redis_url
    admin.close()


@pytest.fixture()
def safe(seeded: str):
    r = SafeRedis.from_url(seeded, decode_responses=True, encoding_errors="backslashreplace")
    yield r
    r.close()
