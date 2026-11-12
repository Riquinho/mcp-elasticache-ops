"""Single source of truth for engine version quirks (Valkey, Redis OSS, Memcached).

Every surface that explains a version-dependent behaviour reads it from here: ``node_doctor`` and the config
findings (dataplane), ``aws_engine_versions`` (upgrade targets) and ``aws_parameter_drift`` (families on
different sides of a quirk). A quirk always carries a remediation; ``tests/test_engine_quirks.py`` fails on an
entry without one or with a version range that does not parse."""

from __future__ import annotations

import re
from dataclasses import dataclass

ENGINES = ("valkey", "redis", "memcached")
_TERM = re.compile(r"^(>=|<=|>|<|==)\s*(\d+(?:\.\d+)*)$")


def parse_version(text: object) -> tuple[int, ...]:
    """``"7.2.4"`` -> ``(7, 2, 4)``; stops at the first non-numeric part, unknown -> ``()``."""
    parts: list[int] = []
    for token in str(text or "").split("."):
        digits = re.match(r"\d+", token)
        if not digits:
            break
        parts.append(int(digits.group()))
    return tuple(parts)


def parse_range(spec: str) -> list[tuple[str, tuple[int, ...]]]:
    """``">=6.0 <7.0"`` -> ``[(">=", (6, 0)), ("<", (7, 0))]``; raises ``ValueError`` when unparseable."""
    terms = []
    for raw in spec.split():
        m = _TERM.match(raw) if raw[0] in "<>=" else None
        if not m:
            raise ValueError(f"unparseable version range {spec!r} (term {raw!r})")
        terms.append((m.group(1), parse_version(m.group(2))))
    if not terms:
        raise ValueError("empty version range")
    return terms


def _pad(v: tuple[int, ...], n: int) -> tuple[int, ...]:
    return v + (0,) * (n - len(v))


def in_range(version: object, spec: str) -> bool:
    """True when ``version`` satisfies every term of ``spec``; an unknown version never matches."""
    have = parse_version(version)
    if not have:
        return False
    for op, want in parse_range(spec):
        n = max(len(have), len(want))
        a, b = _pad(have, n), _pad(want, n)
        ok = {">=": a >= b, "<=": a <= b, ">": a > b, "<": a < b, "==": a == b}[op]
        if not ok:
            return False
    return True


@dataclass(frozen=True)
class Quirk:
    key: str
    engine: str  # one of ENGINES
    versions: str  # version range, see parse_range
    quirk: str  # what the engine does
    remediation: str  # what to do about it (never empty)
    parameters: tuple[str, ...] = ()  # parameter-group names the quirk is about (a prefix ends with "*")


QUIRKS: tuple[Quirk, ...] = (
    Quirk(
        "valkey-io-threads",
        "valkey",
        ">=8.0",
        "Valkey 8 can offload socket I/O to io-threads; with io-threads 1 the main thread does all of it",
        "if EngineCPUUtilization is high with many clients, raise io-threads in the parameter group "
        "(needs a node type with spare vCPUs) and confirm io_threads_active in INFO",
        ("io-threads",),
    ),
    Quirk(
        "valkey-lazyfree",
        "valkey",
        ">=8.0",
        "Valkey 8 defaults the lazyfree-lazy-* parameters to yes; with them off, big deletes, expiry and "
        "eviction free memory on the main thread and can stall it",
        "set the lazyfree-lazy-* parameters back to yes in the parameter group",
        ("lazyfree-lazy-*",),
    ),
    Quirk(
        "valkey-replica-lag",
        "valkey",
        ">=8.0",
        "with io-threads enabled the replica applies the replication stream on its main thread, so "
        "ReplicationLag can grow when the primary write rate is high",
        "compare ReplicationLag with EngineCPUUtilization on the replica; a bigger node type or fewer "
        "writes per shard lowers the lag",
        ("io-threads",),
    ),
    Quirk(
        "redis-functions-memory",
        "redis",
        ">=7.0",
        "Redis 7 functions and Lua scripts keep their own heap outside the dataset (used_memory_vm_functions, "
        "used_memory_lua); in cluster mode functions are per node and must be loaded on every shard",
        "check the SCRIPT FLUSH policy and function libraries; load functions on every shard "
        "(cluster mode) and prefer them over EVAL for scripts that change often",
    ),
    Quirk(
        "redis-acl-tls",
        "redis",
        ">=6.0",
        "ACL users and RBAC need Redis 6+, and ElastiCache RBAC only works with in-transit encryption (TLS)",
        "enable in-transit encryption on the replication group before attaching a user group; clients must "
        "connect with TLS and AUTH user and password",
    ),
    Quirk(
        "memcached-1-4-tls",
        "memcached",
        "<1.6.12",
        "Memcached before 1.6.12 has no in-transit encryption on ElastiCache and lacks the 1.6 threading and "
        "slab improvements",
        "upgrade to Memcached 1.6.12 or newer (a new cluster; there is no in-place upgrade across a family)",
    ),
    Quirk(
        "reserved-memory-percent",
        "redis",
        ">=0",
        "ElastiCache reserves reserved-memory-percent of node memory for non-data use (fork, buffers); on "
        "small nodes the usable maxmemory is far below the node type's memory",
        "size against maxmemory, not the node type's RAM; keep the default 25 percent (higher for write-heavy "
        "snapshotting) and use a bigger node when maxmemory is too small",
        ("reserved-memory-percent",),
    ),
    Quirk(
        "valkey-reserved-memory-percent",
        "valkey",
        ">=0",
        "ElastiCache reserves reserved-memory-percent of node memory for non-data use (fork, buffers); on "
        "small nodes the usable maxmemory is far below the node type's memory",
        "size against maxmemory, not the node type's RAM; keep the default 25 percent (higher for write-heavy "
        "snapshotting) and use a bigger node when maxmemory is too small",
        ("reserved-memory-percent",),
    ),
    Quirk(
        "replica-serve-stale-data",
        "redis",
        ">=0",
        "a replica whose link to the primary is down keeps answering reads from old data while "
        "replica-serve-stale-data is yes (default)",
        "restore the replication link, or set replica-serve-stale-data to no where stale reads are worse than errors",
        ("replica-serve-stale-data",),
    ),
)

_BY_KEY = {q.key: q for q in QUIRKS}


def get(key: str) -> Quirk:
    return _BY_KEY[key]


def text(key: str) -> str:
    """One sentence for a finding: what the engine does, then what to do."""
    q = _BY_KEY[key]
    return f"{q.quirk}; {q.remediation}"


def _matches_param(patterns: tuple[str, ...], name: str) -> bool:
    return any(name.startswith(p[:-1]) if p.endswith("*") else name == p for p in patterns)


def quirks_for(engine: str, version: object) -> list[Quirk]:
    """Quirks that apply to ``engine`` at ``version``; Valkey also inherits the Redis OSS entries below 8."""
    engine = (engine or "").lower()
    return [q for q in QUIRKS if q.engine == engine and in_range(version, q.versions)]


def quirks_for_parameter(engine: str, version: object, name: str) -> list[Quirk]:
    return [q for q in quirks_for(engine, version) if _matches_param(q.parameters, name)]


def summary(q: Quirk) -> dict:
    """Compact form for tool output."""
    return {"key": q.key, "quirk": q.quirk, "remediation": q.remediation}


def family_engine_version(family: object) -> tuple[str, str]:
    """``"valkey8"`` -> ``("valkey", "8")``, ``"memcached1.6"`` -> ``("memcached", "1.6")``; unknown -> ``("", "")``."""
    m = re.match(r"^([a-z]+)(\d+(?:\.\d+)*)$", str(family or "").lower())
    return (m.group(1), m.group(2)) if m else ("", "")


def drift_quirks(family_a: object, family_b: object, parameters: list[str]) -> list[tuple[Quirk, str, str | None]]:
    """Quirks relevant to a parameter-group comparison as ``(quirk, why, parameter)``.

    A differing parameter named by a quirk of either family, or a quirk that holds for one family and not the
    other (the groups sit on different sides of its version range)."""
    ea, va = family_engine_version(family_a)
    eb, vb = family_engine_version(family_b)
    out: list[tuple[Quirk, str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()
    for name in parameters:
        for engine, version in ((ea, va), (eb, vb)):
            for q in quirks_for_parameter(engine, version, name):
                if (q.key, name) not in seen:
                    seen.add((q.key, name))
                    out.append((q, f"{name} differs and is covered by this {q.engine} quirk", name))
    if ea and ea == eb and va != vb:
        for q in QUIRKS:
            if q.engine == ea and in_range(va, q.versions) != in_range(vb, q.versions) and (q.key, None) not in seen:
                seen.add((q.key, None))
                out.append((q, f"the families {family_a} and {family_b} fall on different sides of {q.versions}", None))
    return out
