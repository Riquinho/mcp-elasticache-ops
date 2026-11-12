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


@dataclass(frozen=True)
class DataPlaneConfig:
    """Connection to a Redis OSS / Valkey endpoint (primary, reader or node)."""

    host: str = "127.0.0.1"
    port: int = 6379
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    tls: bool = False
    tls_verify: bool = True
    db: int = 0
    socket_timeout: float = 5.0

    @classmethod
    def from_env(cls) -> DataPlaneConfig:
        password = os.getenv("ELASTICACHE_PASSWORD") or None
        token_file = os.getenv("ELASTICACHE_PASSWORD_FILE")
        if not password and token_file:
            password = Path(token_file).read_text(encoding="utf-8").strip() or None
        return cls(
            host=os.getenv("ELASTICACHE_HOST", "127.0.0.1"),
            port=int(os.getenv("ELASTICACHE_PORT", "6379")),
            username=os.getenv("ELASTICACHE_USERNAME") or None,
            password=password,
            tls=_bool(os.getenv("ELASTICACHE_TLS")),
            tls_verify=_bool(os.getenv("ELASTICACHE_TLS_VERIFY"), default=True),
            db=int(os.getenv("ELASTICACHE_DB", "0")),
            socket_timeout=float(os.getenv("ELASTICACHE_TIMEOUT", "5")),
        )


@dataclass(frozen=True)
class MemcachedConfig:
    host: str | None = None
    port: int = 11211
    timeout: float = 5.0

    @classmethod
    def from_env(cls) -> MemcachedConfig:
        return cls(
            host=os.getenv("MEMCACHED_HOST") or None,
            port=int(os.getenv("MEMCACHED_PORT", "11211")),
            timeout=float(os.getenv("ELASTICACHE_TIMEOUT", "5")),
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
