"""Runtime configuration, read from environment variables.

Nothing here is a secret by default; passwords/tokens come only from the
environment (or an AUTH token file) and are never logged or returned by tools.
"""

from __future__ import annotations

import os
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

    @classmethod
    def from_env(cls) -> MemcachedConfig:
        return cls(
            host=os.getenv("MEMCACHED_HOST") or None,
            port=_int("MEMCACHED_PORT", 11211, 1, 65535),
            timeout=_float("ELASTICACHE_TIMEOUT", 5.0, 0, 600),
        )


@dataclass(frozen=True)
class ControlPlaneConfig:
    """AWS side. Credentials follow the normal boto3 chain (env, profile, role)."""

    region: str | None = None
    profile: str | None = None
    enabled: bool = True

    @classmethod
    def from_env(cls) -> ControlPlaneConfig:
        return cls(
            region=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or None,
            profile=os.getenv("AWS_PROFILE") or None,
            enabled=_bool(os.getenv("ELASTICACHE_CONTROL_PLANE"), default=True),
        )
