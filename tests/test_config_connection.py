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
