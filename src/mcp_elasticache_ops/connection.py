"""Construction of the guarded Redis client from ``DataPlaneConfig`` (unit-testable)."""

from __future__ import annotations

import dataclasses
import ipaddress
import re
import socket
import ssl
import time
from collections.abc import Callable
from typing import Any

import boto3
import redis
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


# ------------------------------------------------------------------ staged reachability diagnosis

_ENDPOINT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("serverless", re.compile(r"\.serverless\.[a-z0-9-]+\.cache\.amazonaws\.com(\.cn)?$", re.I)),
    ("configuration", re.compile(r"\.clustercfg\.[a-z0-9-]+\.cache\.amazonaws\.com(\.cn)?$", re.I)),
    ("node", re.compile(r"-\d{4}-\d{3}\.", re.I)),
    ("reader", re.compile(r"^[^.]+-ro\.", re.I)),
    ("primary", re.compile(r"\.cache\.amazonaws\.com(\.cn)?$", re.I)),
)


def endpoint_kind(host: str) -> str:
    """Classify an ElastiCache DNS name: serverless, configuration, node, reader, primary, or unknown."""
    for kind, pattern in _ENDPOINT_PATTERNS:
        if pattern.search(host.strip()):
            return kind
    return "unknown"


def _is_private(address: str) -> bool:
    try:
        return ipaddress.ip_address(address.split("%")[0]).is_private
    except ValueError:
        return False


def _tls_context(cfg: DataPlaneConfig, verify: bool) -> ssl.SSLContext:
    if verify and cfg.tls_verify:
        ctx = ssl.create_default_context(cafile=cfg.tls_ca_file)
        ctx.check_hostname = cfg.tls_check_hostname
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _plaintext_answers(host: str, port: int, timeout: float) -> bool:
    """True when the port answers a plain RESP ``PING`` (so TLS is not what the server expects)."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"PING\r\n")
            reply = sock.recv(64)
    except OSError:
        return False
    return reply[:1] in (b"+", b"-") and reply.endswith(b"\r\n")


def _scrub(text: str, cfg: DataPlaneConfig) -> str:
    return text.replace(cfg.password, "***") if cfg.password else text


_HINTS = {
    "dns": "The name does not resolve: check ELASTICACHE_HOST for typos, that you are in the right VPC/DNS "
    "(ElastiCache names resolve only inside the VPC or over peering/VPN) and the resolver or Route 53 setup.",
    "tcp": "The port did not accept a TCP connection: check the security group inbound rule for the client "
    "(port {port}), network ACLs, route tables, VPC peering/VPN and ELASTICACHE_PORT. A timeout usually "
    "means SG or routing; connection refused means nothing listens on that port.",
    "tls_required": "The endpoint speaks TLS but ELASTICACHE_TLS is not enabled: set ELASTICACHE_TLS=true "
    "(in-transit encryption is on).",
    "tls_mismatch": "The TLS handshake failed but the port answers in plaintext: the cache has no in-transit "
    "encryption. Set ELASTICACHE_TLS=false.",
    "tls": "The TLS handshake failed: check ELASTICACHE_TLS_CA_FILE, ELASTICACHE_TLS_VERIFY and that "
    "ELASTICACHE_HOST is the endpoint DNS name (not an IP) so the certificate hostname matches.",
    "ping": "The server accepted the connection but did not answer PING: check the endpoint type "
    "(a reader or configuration endpoint, a node mid-failover) and ELASTICACHE_TIMEOUT.",
    "auth": "The server rejected the credentials: check ELASTICACHE_USERNAME and ELASTICACHE_PASSWORD(_FILE) "
    "(or the IAM user and ELASTICACHE_IAM_CACHE_NAME) and that the user belongs to the cache's user group.",
    "noperm": "Authentication worked but the ACL user is not allowed to run PING: grant the user the "
    "read-only command set the tools need (see the README ACL section).",
    "endpoint": "Endpoint type note: {kind} endpoints behave differently; use the primary or configuration "
    "endpoint for diagnosis, and node_cluster_health for cluster-mode groups.",
}


def diagnose_connectivity(cfg: DataPlaneConfig) -> dict:
    """Staged, read-only reachability check: DNS, TCP, TLS, PING, AUTH; stops at the first failure.

    Only socket probes and ``PING`` are used. Credentials are never echoed.
    """
    host, port, timeout = cfg.host, cfg.port, cfg.socket_timeout
    kind = endpoint_kind(host)
    stages: list[dict[str, Any]] = []
    findings: list[str] = []
    failed: list[str] = []

    def record(name: str, started: float, ok: bool, detail: str, hint_key: str | None = None, **extra: Any) -> None:
        stage: dict[str, Any] = {
            "stage": name,
            "verdict": "ok" if ok else "fail",
            "ms": round((time.perf_counter() - started) * 1000, 1),
            "detail": detail,
            **extra,
        }
        stages.append(stage)
        if not ok:
            failed.append(name)
            hint = _HINTS[hint_key or name].format(port=port, kind=kind)
            stage["hint"] = hint
            findings.append(f"{name}: {detail}. {hint}")

    def finish() -> dict:
        if failed and kind in ("reader", "serverless", "configuration", "node"):
            findings.append(_HINTS["endpoint"].format(kind=kind, port=port))
        return {
            "findings": findings or [f"{host}:{port} is reachable: DNS, TCP, TLS, PING and AUTH all passed"],
            "ok": not failed,
            "failed_stage": failed[0] if failed else None,
            "endpoint": {"host": host, "port": port, "kind": kind, "tls_configured": cfg.tls},
            "stages": stages,
        }

    def oserr(exc: BaseException) -> str:
        return f"{type(exc).__name__}: {_scrub(str(exc), cfg)}"

    # 1. DNS
    started = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        record("dns", started, False, oserr(exc))
        return finish()
    addresses = sorted({str(info[4][0]) for info in infos})
    all_private = bool(addresses) and all(_is_private(a) for a in addresses)
    record("dns", started, True, f"resolved to {', '.join(addresses)}", addresses=addresses, private=all_private)
    if not all_private:
        findings.append(
            f"dns: {host} resolves to a public address; ElastiCache endpoints resolve to private IPs inside the "
            "VPC, so you may be outside it (wrong resolver, VPN or peering missing)."
        )

    # 2. TCP
    started = time.perf_counter()
    try:
        socket.create_connection((host, port), timeout=timeout).close()
    except OSError as exc:
        record("tcp", started, False, oserr(exc))
        return finish()
    record("tcp", started, True, f"connected to {host}:{port}")

    # 3. TLS
    started = time.perf_counter()
    if cfg.tls:
        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as raw,
                _tls_context(cfg, verify=True).wrap_socket(raw, server_hostname=host) as tls_sock,
            ):
                version = tls_sock.version()
        except OSError as exc:  # ssl.SSLError is an OSError
            plain = _plaintext_answers(host, port, timeout)
            record("tls", started, False, oserr(exc), "tls_mismatch" if plain else "tls", plaintext_answers=plain)
            return finish()
        record("tls", started, True, f"handshake ok ({version})")
    else:
        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as raw,
                _tls_context(cfg, verify=False).wrap_socket(raw, server_hostname=host),
            ):
                pass
        except OSError:
            record("tls", started, True, "plaintext (ELASTICACHE_TLS=false); the port does not speak TLS")
        else:
            record(
                "tls", started, False, "the port completes a TLS handshake but ELASTICACHE_TLS is false", "tls_required"
            )
            return finish()

    # 4. PING without credentials: any RESP reply, even NOAUTH, proves the server is answering
    started = time.perf_counter()
    anonymous = dataclasses.replace(cfg, username=None, password=None, use_iam_auth=False)
    needs_auth = False
    try:
        build_client(anonymous).ping()
    except redis.exceptions.AuthenticationError:
        needs_auth = True
    except redis.exceptions.ResponseError as exc:
        needs_auth = str(exc).upper().startswith(("NOAUTH", "NOPERM", "WRONGPASS"))
        if not needs_auth:
            record("ping", started, False, f"ResponseError: {_scrub(str(exc), cfg)}")
            return finish()
    except (redis.exceptions.RedisError, OSError) as exc:
        record("ping", started, False, oserr(exc))
        return finish()
    record("ping", started, True, "server answered" + (" (authentication required)" if needs_auth else " PONG"))

    # 5. AUTH with the configured credentials, verified through PING
    started = time.perf_counter()
    try:
        build_client(cfg).ping()
    except redis.exceptions.AuthenticationError as exc:
        record("auth", started, False, oserr(exc))
        return finish()
    except redis.exceptions.NoPermissionError as exc:
        record("auth", started, False, f"NOPERM: {_scrub(str(exc), cfg)}", "noperm")
        return finish()
    except (redis.exceptions.RedisError, OSError) as exc:
        record("auth", started, False, oserr(exc))
        return finish()
    has_credentials = bool(cfg.password or cfg.use_iam_auth)
    record("auth", started, True, "authenticated" if has_credentials else "no authentication required")
    if not needs_auth and has_credentials:
        findings.append("auth: the server accepted PING without credentials; it has no AUTH configured.")
    return finish()
