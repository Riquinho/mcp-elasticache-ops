"""Runtime configuration, read from environment variables.

Nothing here is a secret by default; passwords/tokens come only from the
environment (or an AUTH token file) and are never logged or returned by tools.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class ConfigError(ValueError):
    """An environment variable has an unusable value."""


def _int(name: str, default: int, lo: int, hi: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None
    if not lo <= value <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}, got {value}")
    return value


def _float(name: str, default: float, lo: float, hi: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from None
    if not lo < value <= hi:
        raise ConfigError(f"{name} must be greater than {lo:g} and at most {hi:g}, got {value:g}")
    return value


@dataclass(frozen=True)
class DataPlaneConfig:
    """Connection to a Redis OSS / Valkey endpoint (primary, reader or node)."""

    host: str = "127.0.0.1"
    port: int = 6379
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    tls: bool = False
    tls_verify: bool = True
    tls_ca_file: str | None = None
    tls_check_hostname: bool = True
    use_iam_auth: bool = False
    iam_cache_name: str | None = None
    aws_region: str | None = None
    reader_host: str | None = None
    db: int = 0
    socket_timeout: float = 5.0

    @classmethod
    def from_env(cls) -> DataPlaneConfig:
        password = os.getenv("ELASTICACHE_PASSWORD") or None
        token_file = os.getenv("ELASTICACHE_PASSWORD_FILE")
        if not password and token_file:
            password = Path(token_file).read_text(encoding="utf-8").strip() or None
        cfg = cls(
            host=os.getenv("ELASTICACHE_HOST", "127.0.0.1"),
            port=_int("ELASTICACHE_PORT", 6379, 1, 65535),
            username=os.getenv("ELASTICACHE_USERNAME") or None,
            password=password,
            tls=_bool(os.getenv("ELASTICACHE_TLS")),
            tls_verify=_bool(os.getenv("ELASTICACHE_TLS_VERIFY"), default=True),
            tls_ca_file=os.getenv("ELASTICACHE_TLS_CA_FILE") or None,
            tls_check_hostname=_bool(os.getenv("ELASTICACHE_TLS_CHECK_HOSTNAME"), default=True),
            use_iam_auth=_bool(os.getenv("ELASTICACHE_USE_IAM_AUTH")),
            iam_cache_name=os.getenv("ELASTICACHE_IAM_CACHE_NAME") or None,
            aws_region=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or None,
            reader_host=os.getenv("ELASTICACHE_READER_HOST") or None,
            db=_int("ELASTICACHE_DB", 0, 0, 1_000_000),
            socket_timeout=_float("ELASTICACHE_TIMEOUT", 5.0, 0, 600),
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.use_iam_auth:
            if not self.tls:
                raise ConfigError("ELASTICACHE_USE_IAM_AUTH requires ELASTICACHE_TLS=true (IAM auth is TLS only)")
            if not self.username:
                raise ConfigError("ELASTICACHE_USE_IAM_AUTH requires ELASTICACHE_USERNAME (the ElastiCache user id)")
            if not self.iam_cache_name:
                raise ConfigError(
                    "ELASTICACHE_USE_IAM_AUTH requires ELASTICACHE_IAM_CACHE_NAME (replication group or serverless cache name)"
                )
            if self.password:
                raise ConfigError("ELASTICACHE_USE_IAM_AUTH cannot be combined with ELASTICACHE_PASSWORD")
        if self.tls_ca_file and not Path(self.tls_ca_file).is_file():
            raise ConfigError(f"ELASTICACHE_TLS_CA_FILE does not exist: {self.tls_ca_file}")


@dataclass(frozen=True)
class MemcachedConfig:
    host: str | None = None
    port: int = 11211
    timeout: float = 5.0
    nodes: tuple[tuple[str, int], ...] = ()

    @classmethod
    def from_env(cls) -> MemcachedConfig:
        return cls(
            host=os.getenv("MEMCACHED_HOST") or None,
            port=_int("MEMCACHED_PORT", 11211, 1, 65535),
            timeout=_float("ELASTICACHE_TIMEOUT", 5.0, 0, 600),
            nodes=memcached_nodes(os.getenv("MEMCACHED_NODES")),
        )


@dataclass(frozen=True)
class ControlPlaneConfig:
    """AWS side. Credentials follow the normal boto3 chain (env, profile, role)."""

    region: str | None = None
    profile: str | None = None
    enabled: bool = True
    call_timeout: float = 10.0
    max_attempts: int = 3
    regions: tuple[str, ...] = ()

    @classmethod
    def from_env(cls) -> ControlPlaneConfig:
        return cls(
            regions=aws_regions(os.getenv("ELASTICACHE_REGIONS")),
            region=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or None,
            profile=os.getenv("AWS_PROFILE") or None,
            enabled=_bool(os.getenv("ELASTICACHE_CONTROL_PLANE"), default=True),
            call_timeout=_float("AWS_CALL_TIMEOUT_SECONDS", 10.0, 0, 120),
            max_attempts=_int("AWS_MAX_ATTEMPTS", 3, 1, 10),
        )


# aws-cn-style and GovCloud names too: us-east-1, eu-central-2, us-gov-west-1, cn-north-1, us-isob-east-1
REGION_PATTERN = r"^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$"
MAX_REGIONS = 8


def aws_regions(raw: str | None) -> tuple[str, ...]:
    """Parse ``ELASTICACHE_REGIONS`` (comma-separated region names); duplicates dropped, order kept."""
    if raw is None or raw.strip() == "":
        return ()
    seen: dict[str, None] = {}
    for entry in (e.strip() for e in raw.split(",")):
        if not entry:
            continue
        if not re.fullmatch(REGION_PATTERN, entry):
            raise ConfigError(f"ELASTICACHE_REGIONS entries must be AWS region names, got {entry!r}")
        seen[entry] = None
    if len(seen) > MAX_REGIONS:
        raise ConfigError(f"ELASTICACHE_REGIONS lists {len(seen)} regions, the limit is {MAX_REGIONS}")
    return tuple(seen)


DEFAULT_MAX_OUTPUT_CHARS = 60_000


def max_output_chars() -> int:
    """``MCP_MAX_OUTPUT_CHARS``: JSON size above which a tool result is trimmed (default 60000)."""
    return _int("MCP_MAX_OUTPUT_CHARS", DEFAULT_MAX_OUTPUT_CHARS, 1_000, 5_000_000)


def _host_port(entry: str) -> tuple[str, int]:
    host, sep, port = entry.strip().rpartition(":")
    host = host.strip("[]")  # bracketed IPv6 literal
    if not sep or not host or not port.isdigit() or not 1 <= int(port) <= 65535 or any(c.isspace() for c in host):
        raise ConfigError(f"MEMCACHED_NODES entries must be host:port (port 1-65535), got {entry!r}")
    return host, int(port)


def memcached_nodes(raw: str | None) -> tuple[tuple[str, int], ...]:
    """Parse ``MEMCACHED_NODES`` (comma-separated ``host:port``); duplicates are dropped, order is kept."""
    if raw is None or raw.strip() == "":
        return ()
    entries = [e for e in raw.split(",") if e.strip()]
    if not entries:
        raise ConfigError(f"MEMCACHED_NODES has no usable entries: {raw!r}")
    seen: dict[tuple[str, int], None] = {}
    for entry in entries:
        seen[_host_port(entry)] = None
    if len(seen) > MAX_MEMCACHED_NODES:
        raise ConfigError(f"MEMCACHED_NODES lists {len(seen)} nodes, the limit is {MAX_MEMCACHED_NODES}")
    return tuple(seen)


MAX_MEMCACHED_NODES = 64
