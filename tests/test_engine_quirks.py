"""The quirks table: every entry parses and has a remediation, and the text lives in one module only."""

from pathlib import Path

import pytest

from mcp_elasticache_ops import quirks
from mcp_elasticache_ops.quirks import QUIRKS, in_range, parse_range, quirks_for


@pytest.mark.parametrize("q", QUIRKS, ids=lambda q: q.key)
def test_every_entry_is_complete_and_parseable(q):
    assert q.engine in quirks.ENGINES
    assert q.quirk.strip() and q.remediation.strip(), f"{q.key} needs a quirk and a remediation"
    assert parse_range(q.versions)


def test_keys_are_unique():
    assert len({q.key for q in QUIRKS}) == len(QUIRKS)


@pytest.mark.parametrize("bad", ["", "8", "=>8", ">=x", ">= 8 <"])
def test_unparseable_ranges_raise(bad):
    with pytest.raises(ValueError):
        parse_range(bad)


def test_range_matching():
    assert in_range("8.0.1", ">=8.0") and not in_range("7.2.4", ">=8.0")
    assert in_range("1.6.12", "<=1.6.12") and not in_range("1.6.12", "<1.6.12")
    assert in_range("7", ">=7.0") and not in_range("", ">=0")


def test_quirks_for_engine_and_version():
    assert "valkey-io-threads" in {q.key for q in quirks_for("valkey", "8.0.1")}
    assert "valkey-io-threads" not in {q.key for q in quirks_for("valkey", "7.2")}
    assert "memcached-1-4-tls" in {q.key for q in quirks_for("memcached", "1.4.34")}
    assert not quirks_for("memcached", "1.6.22")


def test_drift_quirks_by_parameter_and_by_range():
    by_param = quirks.drift_quirks("valkey8", "valkey8", ["io-threads"])
    assert {q.key for q, _, p in by_param} >= {"valkey-io-threads"}
    by_range = quirks.drift_quirks("valkey7", "valkey8", [])
    assert "valkey-io-threads" in {q.key for q, _, _ in by_range}
    assert quirks.drift_quirks("redis7", "redis7", ["maxmemory-policy"]) == []


def test_quirk_text_is_defined_in_one_module():
    src = Path(quirks.__file__).parent
    marker = "main thread does all of it"
    owners = [p.name for p in src.rglob("*.py") if marker in p.read_text(encoding="utf-8")]
    assert owners == ["quirks.py"]
    for p in src.rglob("*.py"):
        if p.name != "quirks.py":
            assert "all socket I/O shares the main thread" not in p.read_text(encoding="utf-8")
