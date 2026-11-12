"""Config validation and guarded-client construction (no network)."""

import datetime as dt
from urllib.parse import parse_qs, urlparse

import pytest
from botocore.credentials import Credentials

from mcp_elasticache_ops.config import (
    ConfigError,
    ControlPlaneConfig,
    DataPlaneConfig,
    MemcachedConfig,
)
from mcp_elasticache_ops.connection import (
    IamCredentialProvider,
    build_client,
    client_kwargs,
    iam_auth_token,
)
from mcp_elasticache_ops.safe_client import SafeRedis

ENV_VARS = (
    "ELASTICACHE_HOST",
    "ELASTICACHE_PORT",
    "ELASTICACHE_USERNAME",
    "ELASTICACHE_PASSWORD",
    "ELASTICACHE_PASSWORD_FILE",
    "ELASTICACHE_TLS",
    "ELASTICACHE_TLS_VERIFY",
    "ELASTICACHE_TLS_CA_FILE",
    "ELASTICACHE_TLS_CHECK_HOSTNAME",
    "ELASTICACHE_USE_IAM_AUTH",
    "ELASTICACHE_IAM_CACHE_NAME",
    "ELASTICACHE_READER_HOST",
    "ELASTICACHE_DB",
    "ELASTICACHE_TIMEOUT",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "MEMCACHED_HOST",
    "MEMCACHED_PORT",
    "MEMCACHED_NODES",
    "MCP_MAX_OUTPUT_CHARS",
    "ELASTICACHE_CONTROL_PLANE",
    "AWS_PROFILE",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for v in ENV_VARS:
        monkeypatch.delenv(v, raising=False)


def test_defaults():
    cfg = DataPlaneConfig.from_env()
    assert (cfg.host, cfg.port, cfg.tls, cfg.tls_verify, cfg.use_iam_auth) == ("127.0.0.1", 6379, False, True, False)
    assert cfg.tls_check_hostname is True and cfg.reader_host is None and cfg.tls_ca_file is None


def test_new_env_vars_are_read(monkeypatch, tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    monkeypatch.setenv("ELASTICACHE_TLS", "true")
    monkeypatch.setenv("ELASTICACHE_TLS_CA_FILE", str(ca))
    monkeypatch.setenv("ELASTICACHE_TLS_CHECK_HOSTNAME", "false")
    monkeypatch.setenv("ELASTICACHE_READER_HOST", "reader.example")
    monkeypatch.setenv("AWS_REGION", "eu-west-1")
    cfg = DataPlaneConfig.from_env()
    assert cfg.tls_ca_file == str(ca) and cfg.tls_check_hostname is False
    assert cfg.reader_host == "reader.example" and cfg.aws_region == "eu-west-1"


def test_iam_env_vars(monkeypatch):
    monkeypatch.setenv("ELASTICACHE_TLS", "1")
    monkeypatch.setenv("ELASTICACHE_USE_IAM_AUTH", "yes")
    monkeypatch.setenv("ELASTICACHE_USERNAME", "iam-user")
    monkeypatch.setenv("ELASTICACHE_IAM_CACHE_NAME", "my-rg")
    cfg = DataPlaneConfig.from_env()
    assert cfg.use_iam_auth and cfg.iam_cache_name == "my-rg"


@pytest.mark.parametrize(
    "env,fragment",
    [
        ({"ELASTICACHE_PORT": "abc"}, "ELASTICACHE_PORT must be an integer"),
        ({"ELASTICACHE_PORT": "0"}, "ELASTICACHE_PORT must be between 1 and 65535"),
        ({"ELASTICACHE_PORT": "70000"}, "between 1 and 65535"),
        ({"ELASTICACHE_DB": "-1"}, "ELASTICACHE_DB"),
        ({"ELASTICACHE_TIMEOUT": "0"}, "ELASTICACHE_TIMEOUT must be greater than 0"),
        ({"ELASTICACHE_TIMEOUT": "-2"}, "ELASTICACHE_TIMEOUT"),
        ({"ELASTICACHE_TIMEOUT": "soon"}, "must be a number"),
        ({"ELASTICACHE_TLS_CA_FILE": "/definitely/not/here.pem"}, "does not exist"),
        ({"ELASTICACHE_USE_IAM_AUTH": "true"}, "requires ELASTICACHE_TLS"),
        ({"ELASTICACHE_USE_IAM_AUTH": "true", "ELASTICACHE_TLS": "true"}, "requires ELASTICACHE_USERNAME"),
        (
            {"ELASTICACHE_USE_IAM_AUTH": "true", "ELASTICACHE_TLS": "true", "ELASTICACHE_USERNAME": "u"},
            "requires ELASTICACHE_IAM_CACHE_NAME",
        ),
        (
            {
                "ELASTICACHE_USE_IAM_AUTH": "true",
                "ELASTICACHE_TLS": "true",
                "ELASTICACHE_USERNAME": "u",
                "ELASTICACHE_IAM_CACHE_NAME": "rg",
                "ELASTICACHE_PASSWORD": "p",
            },
            "cannot be combined",
        ),
    ],
)
def test_invalid_config_is_rejected(monkeypatch, env, fragment):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ConfigError, match=fragment):
        DataPlaneConfig.from_env()


def test_password_file_and_repr_hides_password(monkeypatch, tmp_path):
    f = tmp_path / "pw"
    f.write_text("s3cret\n")
    monkeypatch.setenv("ELASTICACHE_PASSWORD_FILE", str(f))
    cfg = DataPlaneConfig.from_env()
    assert cfg.password == "s3cret" and "s3cret" not in repr(cfg)


def test_memcached_and_control_plane_config(monkeypatch):
    assert MemcachedConfig.from_env() == MemcachedConfig(host=None, port=11211, timeout=5.0)
    monkeypatch.setenv("MEMCACHED_PORT", "99999")
    with pytest.raises(ConfigError):
        MemcachedConfig.from_env()
    monkeypatch.setenv("MEMCACHED_PORT", "11212")
    monkeypatch.setenv("MEMCACHED_HOST", "mc")
    monkeypatch.setenv("ELASTICACHE_CONTROL_PLANE", "false")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "sa-east-1")
    assert MemcachedConfig.from_env().port == 11212
    cp = ControlPlaneConfig.from_env()
    assert cp.enabled is False and cp.region == "sa-east-1"


# ------------------------------------------------------------ client kwargs


def test_client_kwargs_plain_password():
    kw = client_kwargs(DataPlaneConfig(host="h", port=1234, username="u", password="p", db=2))
    assert kw["host"] == "h" and kw["port"] == 1234 and kw["db"] == 2
    assert kw["username"] == "u" and kw["password"] == "p"
    assert "ssl" not in kw and "credential_provider" not in kw
    assert kw["client_name"] == "mcp-elasticache-ops"


def test_client_kwargs_tls_variants(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    kw = client_kwargs(DataPlaneConfig(tls=True, tls_ca_file=str(ca)))
    assert kw["ssl"] is True and kw["ssl_cert_reqs"] == "required"
    assert kw["ssl_check_hostname"] is True and kw["ssl_ca_certs"] == str(ca)
    kw = client_kwargs(DataPlaneConfig(tls=True, tls_check_hostname=False))
    assert kw["ssl_cert_reqs"] == "required" and kw["ssl_check_hostname"] is False
    kw = client_kwargs(DataPlaneConfig(tls=True, tls_verify=False))
    assert kw["ssl_cert_reqs"] == "none" and kw["ssl_check_hostname"] is False
    assert "ssl_ca_certs" not in kw


def test_client_kwargs_iam_uses_credential_provider_not_password():
    cfg = DataPlaneConfig(tls=True, use_iam_auth=True, username="u", iam_cache_name="rg", aws_region="us-east-1")
    kw = client_kwargs(cfg)
    assert isinstance(kw["credential_provider"], IamCredentialProvider)
    assert "password" not in kw and "username" not in kw


def test_build_client_is_guarded_and_overrides_target():
    r = build_client(DataPlaneConfig(host="a", port=1), host="b", port=2)
    try:
        assert isinstance(r, SafeRedis)
        kw = r.connection_pool.connection_kwargs
        assert (kw["host"], kw["port"]) == ("b", 2)
        with pytest.raises(Exception, match="not allowed|blocked|read-only|allowlist"):
            r.execute_command("FLUSHALL")
    finally:
        r.close()


# ----------------------------------------------------------------- IAM token

CREDS = Credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "tok")


def test_iam_auth_token_is_a_local_sigv4_presigned_url():
    token = iam_auth_token("my-rg", "iam-user", "us-east-1", CREDS)
    assert not token.startswith("https://")
    parsed = urlparse("https://" + token)
    assert parsed.netloc == "my-rg"
    q = parse_qs(parsed.query)
    assert q["Action"] == ["connect"] and q["User"] == ["iam-user"]
    assert q["X-Amz-Expires"] == ["900"]
    assert q["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
    assert "us-east-1/elasticache/aws4_request" in q["X-Amz-Credential"][0]
    assert q["X-Amz-Security-Token"] == ["tok"] and len(q["X-Amz-Signature"][0]) == 64
    assert "wJalr" not in token  # the secret key itself never appears


def test_iam_credential_provider_returns_user_and_token():
    class Session:
        region_name = None

        def get_credentials(self):
            return type("C", (), {"get_frozen_credentials": lambda self: CREDS})()

    cfg = DataPlaneConfig(tls=True, use_iam_auth=True, username="u", iam_cache_name="rg", aws_region="eu-west-1")
    user, token = IamCredentialProvider(cfg, session_factory=Session).get_credentials()
    assert user == "u" and token.startswith("rg/?")
    assert "eu-west-1" in token


def test_iam_credential_provider_errors_without_creds_or_region():
    cfg = DataPlaneConfig(tls=True, use_iam_auth=True, username="u", iam_cache_name="rg")

    class NoCreds:
        region_name = "us-east-1"

        def get_credentials(self):
            return None

    with pytest.raises(RuntimeError, match="no AWS credentials"):
        IamCredentialProvider(cfg, session_factory=NoCreds).get_credentials()

    class NoRegion:
        region_name = None

        def get_credentials(self):
            return type("C", (), {"get_frozen_credentials": lambda self: CREDS})()

    with pytest.raises(RuntimeError, match="AWS_REGION"):
        IamCredentialProvider(cfg, session_factory=NoRegion).get_credentials()


def test_token_expiry_constant_matches_elasticache_limit():
    from mcp_elasticache_ops.connection import IAM_TOKEN_TTL_SECONDS

    assert dt.timedelta(seconds=IAM_TOKEN_TTL_SECONDS) == dt.timedelta(minutes=15)


# ------------------------------------------------------- MEMCACHED_NODES / MCP_MAX_OUTPUT_CHARS


def test_memcached_nodes_default_and_parsed(monkeypatch):
    assert MemcachedConfig.from_env().nodes == ()
    monkeypatch.setenv("MEMCACHED_NODES", " a:11211, b.example.com:11212 ,a:11211,[::1]:11213")
    assert MemcachedConfig.from_env().nodes == (("a", 11211), ("b.example.com", 11212), ("::1", 11213))


@pytest.mark.parametrize("raw", ["a", "a:", ":11211", "a:0", "a:70000", "a:x", "a b:1", ","])
def test_memcached_nodes_invalid(monkeypatch, raw):
    monkeypatch.setenv("MEMCACHED_NODES", raw)
    with pytest.raises(ConfigError, match="MEMCACHED_NODES"):
        MemcachedConfig.from_env()


def test_memcached_nodes_limit(monkeypatch):
    monkeypatch.setenv("MEMCACHED_NODES", ",".join(f"h{i}:11211" for i in range(65)))
    with pytest.raises(ConfigError, match="limit"):
        MemcachedConfig.from_env()


def test_max_output_chars_default_and_override(monkeypatch):
    from mcp_elasticache_ops.config import DEFAULT_MAX_OUTPUT_CHARS, max_output_chars

    assert max_output_chars() == DEFAULT_MAX_OUTPUT_CHARS == 60000
    monkeypatch.setenv("MCP_MAX_OUTPUT_CHARS", "2500")
    assert max_output_chars() == 2500


@pytest.mark.parametrize("raw", ["abc", "10", "0", "-5", "99999999", "1.5"])
def test_max_output_chars_invalid(monkeypatch, raw):
    from mcp_elasticache_ops.config import max_output_chars

    monkeypatch.setenv("MCP_MAX_OUTPUT_CHARS", raw)
    with pytest.raises(ConfigError, match="MCP_MAX_OUTPUT_CHARS"):
        max_output_chars()


# ------------------------------------------------------- AWS call bounds


def test_aws_call_bounds_from_env(monkeypatch):
    cfg = ControlPlaneConfig.from_env()
    assert cfg.call_timeout == 10.0 and cfg.max_attempts == 3
    monkeypatch.setenv("AWS_CALL_TIMEOUT_SECONDS", "2.5")
    monkeypatch.setenv("AWS_MAX_ATTEMPTS", "5")
    cfg = ControlPlaneConfig.from_env()
    assert cfg.call_timeout == 2.5 and cfg.max_attempts == 5


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("AWS_CALL_TIMEOUT_SECONDS", "0"),
        ("AWS_CALL_TIMEOUT_SECONDS", "121"),
        ("AWS_CALL_TIMEOUT_SECONDS", "abc"),
        ("AWS_MAX_ATTEMPTS", "0"),
        ("AWS_MAX_ATTEMPTS", "11"),
        ("AWS_MAX_ATTEMPTS", "x"),
    ],
)
def test_aws_call_bounds_reject_bad_values(monkeypatch, name, value):
    monkeypatch.setenv(name, value)
    with pytest.raises(ConfigError):
        ControlPlaneConfig.from_env()


def test_elasticache_regions_parsing(monkeypatch):
    from mcp_elasticache_ops.config import ConfigError, ControlPlaneConfig, aws_regions

    assert aws_regions(None) == () and aws_regions(" ") == ()
    assert aws_regions("us-east-1, eu-west-1,us-east-1,") == ("us-east-1", "eu-west-1")
    for bad in ("us-east-1;x", "nowhere", ",".join(f"us-east-{i}" for i in range(1, 10))):
        with pytest.raises(ConfigError):
            aws_regions(bad)
    monkeypatch.setenv("ELASTICACHE_REGIONS", "us-east-1,us-west-2")
    assert ControlPlaneConfig.from_env().regions == ("us-east-1", "us-west-2")


# ------------------------------------------------------------------ node_connectivity (staged diagnosis)

import socket  # noqa: E402
import ssl  # noqa: E402

import redis  # noqa: E402

from mcp_elasticache_ops import connection  # noqa: E402

SECRET = "s3cr3t-pa55word"
PRIMARY = "my-rg.abc123.ng.0001.use1.cache.amazonaws.com"


class _FakeSock:
    def __init__(self, reply: bytes = b"") -> None:
        self.reply = reply

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def close(self):
        pass

    def settimeout(self, t):
        pass

    def sendall(self, data):
        pass

    def recv(self, n):
        return self.reply


class _FakeCtx:
    def __init__(self, fail: Exception | None) -> None:
        self.fail = fail

    def wrap_socket(self, sock, server_hostname=None):
        if self.fail:
            raise self.fail
        return _FakeTls()


class _FakeTls(_FakeSock):
    def version(self):
        return "TLSv1.3"


class _Ping:
    def __init__(self, exc: Exception | None) -> None:
        self.exc = exc

    def ping(self):
        if self.exc:
            raise self.exc
        return True


def _net(
    monkeypatch,
    *,
    ips=("10.0.1.5",),
    dns_error=None,
    tcp_error=None,
    tls_error=None,
    plaintext_reply=b"+PONG\r\n",
    anon=None,
    authed=None,
):
    """Patch DNS, TCP, TLS and the redis client. ``tls_error=None`` means the TLS handshake succeeds."""

    def getaddrinfo(host, port, **kw):
        if dns_error:
            raise dns_error
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port)) for ip in ips]

    def create_connection(addr, timeout=None):
        if tcp_error:
            raise tcp_error
        return _FakeSock(plaintext_reply)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "create_connection", create_connection)
    monkeypatch.setattr(connection, "_tls_context", lambda cfg, verify: _FakeCtx(tls_error))

    def fake_build(cfg, host=None, port=None):
        return _Ping(authed if cfg.password or cfg.username else anon)

    monkeypatch.setattr(connection, "build_client", fake_build)


def _cfg(**kw) -> DataPlaneConfig:
    return DataPlaneConfig(host=PRIMARY, **kw)


PLAIN = ssl.SSLError("not tls")  # handshake attempt against a plaintext server


def test_connectivity_dns_failure(monkeypatch):
    _net(monkeypatch, dns_error=socket.gaierror(-2, "Name or service not known"))
    out = connection.diagnose_connectivity(_cfg(password=SECRET))
    assert out["ok"] is False and out["failed_stage"] == "dns"
    assert [s["stage"] for s in out["stages"]] == ["dns"]
    assert "VPC" in out["findings"][0] and list(out)[0] == "findings"
    assert out["endpoint"]["kind"] == "primary"


def test_connectivity_tcp_refused_and_timeout(monkeypatch):
    _net(monkeypatch, tcp_error=ConnectionRefusedError("refused"))
    out = connection.diagnose_connectivity(_cfg())
    assert out["failed_stage"] == "tcp" and [s["stage"] for s in out["stages"]] == ["dns", "tcp"]
    assert "security group" in out["findings"][0]
    assert out["stages"][0]["private"] is True and out["stages"][0]["addresses"] == ["10.0.1.5"]
    _net(monkeypatch, tcp_error=TimeoutError("timed out"), ips=("54.1.2.3",))
    out = connection.diagnose_connectivity(_cfg())
    assert out["failed_stage"] == "tcp" and out["stages"][0]["private"] is False
    assert any("public address" in f for f in out["findings"])


def test_connectivity_tls_vs_plaintext_mismatch(monkeypatch):
    _net(monkeypatch, tls_error=ssl.SSLError("WRONG_VERSION_NUMBER"), plaintext_reply=b"+PONG\r\n")
    out = connection.diagnose_connectivity(_cfg(tls=True))
    assert out["failed_stage"] == "tls"
    assert out["stages"][-1]["plaintext_answers"] is True
    assert "ELASTICACHE_TLS=false" in out["findings"][0]
    # handshake fails and plaintext does not answer either: certificate/CA problem, not a mismatch
    _net(monkeypatch, tls_error=ssl.SSLError("CERTIFICATE_VERIFY_FAILED"), plaintext_reply=b"")
    out = connection.diagnose_connectivity(_cfg(tls=True))
    assert out["stages"][-1]["plaintext_answers"] is False and "TLS_CA_FILE" in out["findings"][0]


def test_connectivity_tls_required_but_disabled(monkeypatch):
    _net(monkeypatch, tls_error=None)
    out = connection.diagnose_connectivity(_cfg(tls=False))
    assert out["failed_stage"] == "tls" and "ELASTICACHE_TLS=true" in out["findings"][0]


def test_connectivity_auth_failure_never_echoes_secret(monkeypatch):
    _net(
        monkeypatch,
        tls_error=PLAIN,
        anon=redis.exceptions.AuthenticationError("Authentication required."),
        authed=redis.exceptions.AuthenticationError(f"WRONGPASS invalid {SECRET}"),
    )
    out = connection.diagnose_connectivity(_cfg(tls=False, username="app", password=SECRET))
    assert out["failed_stage"] == "auth"
    assert [s["stage"] for s in out["stages"]] == ["dns", "tcp", "tls", "ping", "auth"]
    assert out["stages"][3]["verdict"] == "ok" and "credentials" in out["findings"][0]
    assert SECRET not in repr(out)


def test_connectivity_noperm(monkeypatch):
    _net(
        monkeypatch,
        tls_error=PLAIN,
        anon=redis.exceptions.AuthenticationError("Authentication required."),
        authed=redis.exceptions.NoPermissionError("NOPERM user has no permissions to run 'ping'"),
    )
    out = connection.diagnose_connectivity(_cfg(username="app", password=SECRET))
    assert out["failed_stage"] == "auth" and "NOPERM" in out["stages"][-1]["detail"]
    assert "not allowed" in out["findings"][0]


def test_connectivity_ping_failure_and_endpoint_hint(monkeypatch):
    _net(monkeypatch, tls_error=PLAIN, anon=redis.exceptions.TimeoutError("timed out"))
    out = connection.diagnose_connectivity(DataPlaneConfig(host="c.abc.serverless.use1.cache.amazonaws.com"))
    assert out["failed_stage"] == "ping" and out["endpoint"]["kind"] == "serverless"
    assert any("Endpoint type" in f for f in out["findings"])


def test_connectivity_success_and_open_server(monkeypatch):
    _net(monkeypatch, tls_error=PLAIN, anon=redis.exceptions.AuthenticationError("NOAUTH"))
    out = connection.diagnose_connectivity(_cfg(password=SECRET))
    assert out["ok"] is True and out["failed_stage"] is None
    assert [s["verdict"] for s in out["stages"]] == ["ok"] * 5
    assert SECRET not in repr(out)
    _net(monkeypatch, tls_error=PLAIN)
    out = connection.diagnose_connectivity(_cfg(password=SECRET))
    assert out["ok"] is True and any("no AUTH configured" in f for f in out["findings"])
    out = connection.diagnose_connectivity(_cfg())
    assert out["stages"][-1]["detail"] == "no authentication required"


def test_connectivity_tls_success(monkeypatch):
    _net(monkeypatch, tls_error=None, anon=None)
    out = connection.diagnose_connectivity(_cfg(tls=True))
    assert out["ok"] is True and out["stages"][2]["detail"] == "handshake ok (TLSv1.3)"


def test_connectivity_ping_response_error(monkeypatch):
    _net(monkeypatch, tls_error=PLAIN, anon=redis.exceptions.ResponseError("LOADING busy"))
    assert connection.diagnose_connectivity(_cfg())["failed_stage"] == "ping"
    _net(monkeypatch, tls_error=PLAIN, anon=redis.exceptions.ResponseError("NOPERM x"))
    assert connection.diagnose_connectivity(_cfg(password=SECRET))["ok"] is True
    _net(monkeypatch, tls_error=PLAIN, authed=redis.exceptions.ConnectionError("reset"), anon=None)
    assert connection.diagnose_connectivity(_cfg(password=SECRET))["failed_stage"] == "auth"


@pytest.mark.parametrize(
    ("host", "kind"),
    [
        ("c.abc.serverless.use1.cache.amazonaws.com", "serverless"),
        ("c.abc.clustercfg.use1.cache.amazonaws.com", "configuration"),
        ("rg-0001-001.abc.0001.use1.cache.amazonaws.com", "node"),
        ("rg-ro.abc.ng.0001.use1.cache.amazonaws.com", "reader"),
        (PRIMARY, "primary"),
        ("localhost", "unknown"),
    ],
)
def test_endpoint_kind(host, kind):
    assert connection.endpoint_kind(host) == kind


def test_tls_context_and_scrub():
    cfg = DataPlaneConfig(tls=True, tls_check_hostname=False)
    assert connection._tls_context(cfg, verify=True).check_hostname is False
    assert connection._tls_context(cfg, verify=False).verify_mode == ssl.CERT_NONE
    assert connection._tls_context(DataPlaneConfig(tls_verify=False), verify=True).verify_mode == ssl.CERT_NONE
    assert connection._scrub("a pw b", DataPlaneConfig(password="pw")) == "a *** b"
    assert connection._is_private("not-an-ip") is False


def test_plaintext_probe(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _FakeSock(b"-NOAUTH x\r\n"))
    assert connection._plaintext_answers("h", 1, 1) is True
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: _FakeSock(b"\x15\x03"))
    assert connection._plaintext_answers("h", 1, 1) is False

    def boom(*a, **k):
        raise OSError("x")

    monkeypatch.setattr(socket, "create_connection", boom)
    assert connection._plaintext_answers("h", 1, 1) is False
