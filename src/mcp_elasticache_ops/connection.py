"""Construction of the guarded Redis client from ``DataPlaneConfig`` (unit-testable)."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable
from typing import Any

import boto3
from botocore.auth import SigV4QueryAuth
from botocore.awsrequest import AWSRequest
from redis.credentials import CredentialProvider

from .config import DataPlaneConfig
from .safe_client import SafeRedis

IAM_TOKEN_TTL_SECONDS = 900


def iam_auth_token(cache_name: str, user_id: str, region: str, credentials: Any) -> str:
    """ElastiCache IAM auth token: a SigV4 presigned ``connect`` URL, computed locally.

    No AWS API is called; the token is only ever sent to the cache endpoint as its password.
    """
    request = AWSRequest(
        method="GET",
        url=f"https://{cache_name}/",
        headers={"host": cache_name},
        params={"Action": "connect", "User": user_id},
    )
    SigV4QueryAuth(credentials, "elasticache", region, expires=IAM_TOKEN_TTL_SECONDS).add_auth(request)
    assert request.url is not None
    return request.url.removeprefix("https://")


class IamCredentialProvider(CredentialProvider):
    """Yields a fresh IAM token each time redis-py (re)connects."""

    def __init__(self, cfg: DataPlaneConfig, session_factory: Callable[[], Any] = boto3.Session) -> None:
        self._cfg = cfg
        self._session_factory = session_factory

    def get_credentials(self) -> tuple[str, str]:
        assert self._cfg.username and self._cfg.iam_cache_name
        session = self._session_factory()
        creds = session.get_credentials()
        if creds is None:
            raise RuntimeError("ELASTICACHE_USE_IAM_AUTH is set but no AWS credentials were found")
        region = self._cfg.aws_region or session.region_name
        if not region:
            raise RuntimeError("ELASTICACHE_USE_IAM_AUTH needs AWS_REGION")
        token = iam_auth_token(self._cfg.iam_cache_name, self._cfg.username, region, creds.get_frozen_credentials())
        return self._cfg.username, token


def client_kwargs(cfg: DataPlaneConfig) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "host": cfg.host,
        "port": cfg.port,
        "db": cfg.db,
        "socket_timeout": cfg.socket_timeout,
        "socket_connect_timeout": cfg.socket_timeout,
        "decode_responses": True,
        "encoding_errors": "backslashreplace",
        "client_name": "mcp-elasticache-ops",
    }
    if cfg.use_iam_auth:
        kwargs["credential_provider"] = IamCredentialProvider(cfg)
    else:
        kwargs["username"] = cfg.username
        kwargs["password"] = cfg.password
    if cfg.tls:
        kwargs["ssl"] = True
        kwargs["ssl_cert_reqs"] = "required" if cfg.tls_verify else "none"
        kwargs["ssl_check_hostname"] = cfg.tls_verify and cfg.tls_check_hostname
        if cfg.tls_ca_file:
            kwargs["ssl_ca_certs"] = cfg.tls_ca_file
    return kwargs


def build_client(cfg: DataPlaneConfig, host: str | None = None, port: int | None = None) -> SafeRedis:
    """A ``SafeRedis`` for ``cfg``; ``host``/``port`` override the target (cluster fan-out)."""
    if host is not None or port is not None:
        cfg = dataclasses.replace(cfg, host=host or cfg.host, port=port or cfg.port)
    return SafeRedis(**client_kwargs(cfg))
